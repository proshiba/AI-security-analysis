#!/usr/bin/env python3
"""一次資料に照合したcampaignだけを対象限定で公開・検証する。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from reviewed_campaign_matches import (
    build_reviewed_campaign_stix,
    load_reviewed_campaigns,
    reviewed_labels_by_sha,
)


def expected_documents(repository: Path) -> dict[Path, str]:
    """既存の自動ラベルを保護して、完全一致7ケースとSTIXだけ生成する。"""

    registry = repository / "analysis-framework/registry/reviewed_public_campaigns.json"
    raw = json.loads(registry.read_text(encoding="utf-8"))
    campaigns = load_reviewed_campaigns(registry)
    by_sha = reviewed_labels_by_sha(campaigns)
    family_by_sha = {
        file["sha256"]: campaign["family"]
        for campaign in campaigns
        for file in campaign["files"]
    }
    result: dict[Path, str] = {}
    for sha, reviewed in sorted(by_sha.items()):
        family = family_by_sha[sha]
        matches = list((repository / "analysis-results/malware" / family).glob(
            f"versions/*/cases/{sha}/campaign-labels.json"
        ))
        if len(matches) != 1:
            raise ValueError(f"review済みcaseが一意でない: {sha}")
        path = matches[0]
        if (path.parent / "report.json").is_file():
            raise ValueError(f"封印済みreportのcaseは個別の再封印が必要: {sha}")
        payload: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1 or payload.get("sha256") != sha:
            raise ValueError(f"caseラベルのschema/hashが不正: {sha}")
        labels = payload.get("labels")
        if not isinstance(labels, list):
            raise ValueError(f"caseラベル一覧が不正: {sha}")
        reviewed_ids = {item["campaign_id"] for item in reviewed}
        payload["labels"] = [
            item for item in labels
            if not isinstance(item, dict) or item.get("campaign_id") not in reviewed_ids
        ] + reviewed
        payload["status"] = "reviewed_match"
        payload["rule_source"] = "registry/campaign_fingerprints.json"
        payload["reviewed_rule_source"] = "registry/reviewed_public_campaigns.json"
        result[path] = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    bundle_path = repository / "analysis-results/stix/reviewed-campaigns/bundle.json"
    result[bundle_path] = json.dumps(
        build_reviewed_campaign_stix(campaigns, raw["reviewed_at"]),
        ensure_ascii=False,
        indent=2,
    ) + "\n"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="公開一次資料と完全一致するcampaignだけを限定更新します。")
    parser.add_argument("--repository", type=Path, default=Path(__file__).resolve().parents[2])
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--write", action="store_true", help="対象7ケースとSTIX bundleを書き込みます")
    mode.add_argument("--check", action="store_true", help="対象7ケースとSTIX bundleを照合します")
    args = parser.parse_args()
    expected = expected_documents(args.repository.resolve())
    mismatches = []
    for path, content in expected.items():
        if (path.read_text(encoding="utf-8") if path.is_file() else None) != content:
            mismatches.append(path)
            if args.write:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8", newline="\n")
    print(json.dumps({"status": "written" if args.write else "checked", "mismatches": [str(path) for path in mismatches]}, ensure_ascii=False))
    return 1 if args.check and mismatches else 0


if __name__ == "__main__":
    raise SystemExit(main())
