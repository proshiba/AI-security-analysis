"""公開一次資料の完全一致とSTIX帰属境界を検証する。"""

from __future__ import annotations

import json
import csv
from pathlib import Path
import sys

import pytest


FRAMEWORK = Path(__file__).parents[1]
sys.path.insert(0, str(FRAMEWORK / "common"))

from generate_reviewed_public_campaigns import expected_documents  # noqa: E402
from correlate_campaigns import _expected_case_label_documents  # noqa: E402
from reviewed_campaign_matches import (  # noqa: E402
    build_reviewed_campaign_stix,
    load_reviewed_campaigns,
    reviewed_labels_by_sha,
)


REGISTRY = FRAMEWORK / "registry" / "reviewed_public_campaigns.json"
REPOSITORY = FRAMEWORK.parent


def test_reviewed_exact_matches_are_only_seven_cases() -> None:
    campaigns = load_reviewed_campaigns(REGISTRY)
    labels = reviewed_labels_by_sha(campaigns)
    assert len(campaigns) == 5
    assert len(labels) == 7
    assert "231d21ceefd5c70aa952e8a21523dfe6b5aae9ae6e2b71a0cdbe4e5430b4f5b3" not in labels
    assert "e66bbb6c651b5ab839434b8e62f502169f35894e28dbe9f3275911582eccd250" not in labels


def test_stix_preserves_file_and_actor_boundaries() -> None:
    campaigns = load_reviewed_campaigns(REGISTRY)
    bundle = build_reviewed_campaign_stix(campaigns, "2026-09-22")
    objects = bundle["objects"]
    assert sum(item["type"] == "campaign" for item in objects) == 5
    assert sum(item["type"] == "file" for item in objects) == 9
    assert sum(item["type"] == "intrusion-set" for item in objects) == 4
    assert sum(item["type"] == "relationship" for item in objects) == 4
    lnk = next(item for item in objects if item["type"] == "file" and item["hashes"].get("SHA-256", "").startswith("db03a346"))
    assert lnk["type"] == "file"
    assert not any(item["type"] == "malware" and "db03a346" in str(item) for item in objects)
    shadow = next(item for item in objects if item["type"] == "campaign" and "grandfoodtony" in item["name"])
    assert shadow["confidence"] == 50
    assert "first_seen" not in shadow
    assert not any(item["type"] == "relationship" and item["source_ref"] == shadow["id"] for item in objects)
    assert all("first_seen" not in item for item in objects if item["type"] == "campaign" and "2026" in item["name"])


def test_limited_output_does_not_touch_unrelated_cases() -> None:
    expected = expected_documents(REPOSITORY)
    labels = [path for path in expected if path.name == "campaign-labels.json"]
    assert len(labels) == 7
    assert all("reviewed_match" in expected[path] for path in labels)
    assert len(expected) == 8


def test_full_correlation_keeps_reviewed_exact_labels_only() -> None:
    campaigns = load_reviewed_campaigns(REGISTRY)
    reviewed = reviewed_labels_by_sha(campaigns)
    exact = "db03a34684feab7475862080f59d4d99b32c74d3a152a53b257fd1a443e8ee77"
    candidate = "231d21ceefd5c70aa952e8a21523dfe6b5aae9ae6e2b71a0cdbe4e5430b4f5b3"
    paths = {exact: Path("exact"), candidate: Path("candidate")}
    documents = _expected_case_label_documents(
        {"labels": {}, "safety": {"samples_executed": False}},
        paths,
        reviewed,
    )
    matched = json.loads(documents[Path("exact/campaign-labels.json")])
    unresolved = json.loads(documents[Path("candidate/campaign-labels.json")])
    assert matched["status"] == "reviewed_match"
    assert matched["labels"][0]["classification"] == "public_exact_sha256_match"
    assert matched["reviewed_rule_source"] == "registry/reviewed_public_campaigns.json"
    assert unresolved["status"] == "no_strong_match"
    assert unresolved["labels"] == []


def test_duplicate_hash_fails_closed(tmp_path: Path) -> None:
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    data["campaigns"][1]["files"][0]["sha256"] = data["campaigns"][0]["files"][0]["sha256"]
    path = tmp_path / "duplicate.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="重複"):
        load_reviewed_campaigns(path)


def test_local_primary_source_transcriptions_match_reviewed_data() -> None:
    campaigns = {item["id"]: item for item in load_reviewed_campaigns(REGISTRY)}
    jpcert_csv = REPOSITORY / "analysis-results/research/campaigns/spyglace/apt-c60-2026/jpcert-ioc-files.csv"
    with jpcert_csv.open(encoding="utf-8-sig", newline="") as stream:
        published = {
            row["sha256"] for row in csv.DictReader(stream)
            if row["content"] == "SpyGlace v3.1.15"
        }
    spyglace = campaigns["jpcert-apt-c60-spyglace-2026"]
    assert {item["sha256"] for item in spyglace["files"]} <= published

    trueconf = campaigns["kaspersky-head-mare-trueconf-202607"]["files"][0]
    local_iocs = json.loads((
        REPOSITORY / "analysis-results/research/campaigns/head-mare-trueconf-202607/iocs.json"
    ).read_text(encoding="utf-8"))
    assert any(
        isinstance(item, dict)
        and item.get("md5") == trueconf["md5"]
        and item.get("sha256") == trueconf["sha256"]
        for item in local_iocs.get("files", [])
    )
