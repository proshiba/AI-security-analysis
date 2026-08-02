#!/usr/bin/env python3
"""MaxMindエンリッチ済みC2監視JSONからGeo/AS Markdown節を生成する。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def render_maxmind_section(result: dict[str, Any]) -> str:
    metadata = result.get("maxmind") if isinstance(result.get("maxmind"), dict) else {}
    rows: list[str] = []
    for item in result.get("results", []):
        if not isinstance(item, dict):
            continue
        enrichment = item.get("maxmind") if isinstance(item.get("maxmind"), dict) else {}
        for record in enrichment.get("records", []):
            if not isinstance(record, dict):
                continue
            geo = record.get("geo") if isinstance(record.get("geo"), dict) else {}
            asn = record.get("as") if isinstance(record.get("as"), dict) else {}
            location = " / ".join(
                value
                for value in (geo.get("country_name"), geo.get("subdivision_name"), geo.get("city_name"))
                if value
            ) or "未取得"
            as_text = (
                f"AS{asn.get('autonomous_system_number')} / {asn.get('autonomous_system_organization') or '組織名未取得'}"
                if asn.get("autonomous_system_number")
                else "未取得"
            )
            rows.append(
                f"| `{item.get('host')}:{item.get('port')}` | `{record.get('ip')}` | {location} | {as_text} |"
            )
    city = metadata.get("city_database") if isinstance(metadata.get("city_database"), dict) else {}
    asn_db = metadata.get("asn_database") if isinstance(metadata.get("asn_database"), dict) else {}
    freshness = (
        metadata.get("freshness_policy")
        if isinstance(metadata.get("freshness_policy"), dict)
        else {}
    )
    stale_after = freshness.get("stale_after_refresh") or {}
    lines = [
        "## MaxMind Geo/ASエンリッチ", "",
        f"- IP照合: `{metadata.get('matched_count', 0)}/{metadata.get('lookup_count', 0)}`",
        f"- GeoLite2 City DB構築時刻: `{city.get('build_time_utc') or '未取得'}`",
        f"- GeoLite2 ASN DB構築時刻: `{asn_db.get('build_time_utc') or '未取得'}`",
        f"- 公式checksum照合: City `{city.get('official_checksum_verified') is True}` / ASN `{asn_db.get('official_checksum_verified') is True}`",
        f"- ライブチェック前鮮度確認: `{freshness.get('checked_before_live_check') is True}` / 上限 `{freshness.get('maximum_build_age_hours') or '未指定'}`時間",
        f"- 鮮度超過による更新: `{freshness.get('refresh_performed') is True}` / 更新後も公開最新版が24時間超: `{freshness.get('latest_available_still_stale') is True}`",
        f"- 更新後の鮮度超過: City `{stale_after.get('GeoLite2-City') is True}` / ASN `{stale_after.get('GeoLite2-ASN') is True}`",
        f"- MaxMind帰属表記（原文）: {metadata.get('attribution') or 'GeoLite2 Data created by MaxMind'}", "",
        "| C2 endpoint | 観測IP | Geo | AS |", "|---|---|---|---|",
        *(rows or ["| - | - | 対象となるglobal IPなし | - |"]), "",
        "> GeoLite2は概略位置情報です。個人・世帯・住所の識別やC2稼働確証には使用しません。", "",
    ]
    return "\n".join(lines)


def insert_section(readme: str, section: str) -> str:
    start = "<!-- maxmind-enrichment:start -->"
    end = "<!-- maxmind-enrichment:end -->"
    block = f"{start}\n{section.rstrip()}\n{end}"
    if start in readme and end in readme:
        return readme[: readme.index(start)] + block + readme[readme.index(end) + len(end) :]
    marker = "## 安全境界"
    if marker in readme:
        return readme.replace(marker, block + "\n\n" + marker, 1)
    return readme.rstrip() + "\n\n" + block + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--readme", type=Path, required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()
    result = json.loads(args.results.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        parser.error("results JSON rootはobjectである必要があります")
    rendered = insert_section(args.readme.read_text(encoding="utf-8"), render_maxmind_section(result))
    if args.write:
        args.readme.write_text(rendered, encoding="utf-8")
    print(json.dumps({"readme": str(args.readme), "written": args.write}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
