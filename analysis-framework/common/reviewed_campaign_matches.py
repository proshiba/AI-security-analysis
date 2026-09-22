#!/usr/bin/env python3
"""一次資料に照合済みのcampaign一致を自動相関とは独立に管理する。"""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Mapping
from urllib.parse import urlsplit
import uuid


SHA256 = re.compile(r"[0-9a-f]{64}\Z")
MD5 = re.compile(r"[0-9a-f]{32}\Z")
CAMPAIGN_ID = re.compile(r"[a-z0-9][a-z0-9-]{2,99}\Z")
STRENGTHS = {
    "exact_sha256": ("high", "public_exact_sha256_match"),
    "exact_md5_with_verified_sha256_mapping": ("high", "public_exact_md5_match"),
    "reported_domain_overlap_only": ("low", "public_reported_domain_overlap_candidate"),
}
NAMESPACE = uuid.UUID("0bc8b10f-66bc-437e-b8e0-ac164c3f04a5")


def _stix_id(kind: str, value: str) -> str:
    return f"{kind}--{uuid.uuid5(NAMESPACE, kind + ':' + value)}"


def _stix_object(kind: str, value: str, timestamp: str, **fields: Any) -> dict[str, Any]:
    return {
        "type": kind,
        "spec_version": "2.1",
        "id": _stix_id(kind, value),
        "created": timestamp,
        "modified": timestamp,
        "lang": "ja",
        **fields,
    }


def load_reviewed_campaigns(path: Path) -> list[dict[str, Any]]:
    """正本を検証し、曖昧なhash、重複帰属、根拠のないactorを拒否する。"""

    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise ValueError("reviewed campaign正本のschemaが不正")
    campaigns = data.get("campaigns")
    if not isinstance(campaigns, list):
        raise ValueError("reviewed campaign一覧が不正")
    seen_ids: set[str] = set()
    seen_hashes: set[str] = set()
    for item in campaigns:
        if not isinstance(item, dict) or not CAMPAIGN_ID.fullmatch(str(item.get("id", ""))):
            raise ValueError("campaign idが不正")
        if item["id"] in seen_ids:
            raise ValueError(f"campaign id重複: {item['id']}")
        seen_ids.add(item["id"])
        strength = item.get("match_strength")
        if strength not in STRENGTHS:
            raise ValueError(f"campaign一致根拠が不正: {item['id']}")
        url = urlsplit(str(item.get("source_url", "")))
        if url.scheme != "https" or not url.hostname or url.query or url.fragment or url.username:
            raise ValueError(f"公開source URLが不正: {item['id']}")
        if item.get("actor") and item.get("actor_attribution") != "source_attributed":
            raise ValueError(f"actor帰属境界が不正: {item['id']}")
        if not item.get("actor") and item.get("actor_attribution") != "unresolved":
            raise ValueError(f"未帰属の扱いが不正: {item['id']}")
        if item.get("activity_start") != item.get("activity_end") and bool(item.get("activity_start")) != bool(item.get("activity_end")):
            raise ValueError(f"活動日範囲が不完全: {item['id']}")
        files = item.get("files")
        if not isinstance(files, list) or not files:
            raise ValueError(f"file根拠がない: {item['id']}")
        for file in files:
            if not isinstance(file, dict) or not SHA256.fullmatch(str(file.get("sha256", ""))):
                raise ValueError(f"SHA-256が不正: {item['id']}")
            if file["sha256"] in seen_hashes:
                raise ValueError(f"同一hashのcampaign横断重複: {file['sha256']}")
            seen_hashes.add(file["sha256"])
            if "md5" in file and not MD5.fullmatch(str(file["md5"])):
                raise ValueError(f"MD5が不正: {item['id']}")
    return campaigns


def reviewed_labels_by_sha(campaigns: list[Mapping[str, Any]]) -> dict[str, list[dict[str, str]]]:
    """完全一致caseだけを返す。設定一致候補はSTIX注記に留める。"""

    labels: dict[str, list[dict[str, str]]] = {}
    for campaign in campaigns:
        if not campaign.get("family") or campaign["match_strength"] == "reported_domain_overlap_only":
            continue
        confidence, classification = STRENGTHS[str(campaign["match_strength"])]
        for file in campaign["files"]:
            labels.setdefault(str(file["sha256"]), []).append({
                "campaign_id": str(campaign["id"]),
                "confidence": confidence,
                "classification": classification,
                "actor_attribution": str(campaign["actor_attribution"]),
                "source_name": str(campaign["source_name"]),
                "source_url": str(campaign["source_url"]),
            })
    return labels


def build_reviewed_campaign_stix(
    campaigns: list[Mapping[str, Any]], reviewed_at: str
) -> dict[str, Any]:
    """検体発見日を活動日に流用せず、出典付きcampaignとFile SCOを出力する。"""

    timestamp = f"{reviewed_at}T00:00:00Z"
    objects: list[dict[str, Any]] = []
    known_actors: set[str] = set()
    for campaign in campaigns:
        campaign_id = str(campaign["id"])
        ref = [{
            "source_name": str(campaign["source_name"]),
            "url": str(campaign["source_url"]),
            "description": f"公表日: {campaign['publication_date']}",
        }]
        activity = str(campaign.get("activity_window") or "")
        description = str(campaign["description"])
        if activity:
            description += f" 活動時期: {activity}"
        campaign_object = _stix_object(
            "campaign", campaign_id, timestamp,
            name=str(campaign["name"]),
            description=description,
            confidence=80 if campaign["match_strength"] != "reported_domain_overlap_only" else 50,
            external_references=ref,
        )
        if campaign.get("activity_start"):
            campaign_object["first_seen"] = str(campaign["activity_start"]) + "T00:00:00Z"
            campaign_object["last_seen"] = str(campaign["activity_end"]) + "T23:59:59Z"
        objects.append(campaign_object)

        actor = campaign.get("actor")
        if actor:
            actor = str(actor)
            actor_id = _stix_id("intrusion-set", actor)
            if actor not in known_actors:
                objects.append(_stix_object(
                    "intrusion-set", actor, timestamp,
                    name=actor,
                    description="当該キャンペーンへの帰属は公開一次資料の評価に限定する。別名の同一性は主張しない。",
                    external_references=ref,
                ))
                known_actors.add(actor)
            objects.append(_stix_object(
                "relationship", campaign_id + ":attributed-to:" + actor, timestamp,
                relationship_type="attributed-to",
                source_ref=campaign_object["id"],
                target_ref=actor_id,
                description=f"{campaign['source_name']}による帰属。独立のactor同定ではない。",
                confidence=80,
                external_references=ref,
            ))

        for file in campaign["files"]:
            sha = str(file["sha256"])
            hashes = {"SHA-256": sha}
            if file.get("md5"):
                hashes["MD5"] = str(file["md5"])
            file_id = _stix_id("file", sha)
            objects.append({
                "type": "file",
                "id": file_id,
                "hashes": hashes,
            })
            strength = str(campaign["match_strength"])
            objects.append(_stix_object(
                "note", campaign_id + ":" + sha, timestamp,
                content=(
                    f"{file['role']}。一致根拠: {strength}。"
                    + (" 公開報告にこのSHA-256やローカルcampaign IDは掲載されず、同一campaignは低確度候補に留まる。"
                       if strength == "reported_domain_overlap_only" else "")
                ),
                object_refs=[campaign_object["id"], file_id],
                confidence=80 if strength != "reported_domain_overlap_only" else 20,
                external_references=ref,
            ))
    return {
        "type": "bundle",
        "id": _stix_id("bundle", "reviewed-public-campaigns"),
        "objects": objects,
    }
