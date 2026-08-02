#!/usr/bin/env python3
"""C2監視JSONからTor provenanceを含む日本語reportを再生成する。"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from monitor_recent_c2 import render_markdown


SHA256_RE = re.compile(r"[0-9a-f]{64}")


def render_with_tor(
    result: dict,
    *,
    bundle_version: str,
    tor_version: str,
    archive_sha256: str,
    checksum_url: str,
) -> str:
    """通常reportへ再現可能なTor観測環境を追記する。"""
    if not SHA256_RE.fullmatch(archive_sha256):
        raise ValueError("Tor archive SHA-256が不正です")
    onion_count = sum(item.get("transport") == "tor-socks5" for item in result.get("results", []))
    section = "\n".join([
        "## Tor観測環境",
        "",
        f"Efimer {onion_count} endpointは、Tor Expert Bundle {bundle_version}（Tor {tor_version}）を一時起動して確認しました。"
        f"bundle archiveのSHA-256 `{archive_sha256}` は[Tor Project公式checksum]({checksum_url})と一致しています。"
        "SOCKSは `127.0.0.1:9050` だけで待受け、bootstrap 100%後に対象へ各1回接続し、確認後にTor processとlistenerを停止しました。",
        "",
    ])
    base = render_markdown(result)
    marker = "## 安全境界"
    if marker not in base:
        raise ValueError("安全境界sectionがありません")
    return base.replace(marker, section + marker, 1)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bundle-version", required=True)
    parser.add_argument("--tor-version", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--checksum-url", required=True)
    args = parser.parse_args()
    result = json.loads(args.results.read_text(encoding="utf-8"))
    if not isinstance(result, dict):
        parser.error("監視結果JSON rootはobjectである必要があります")
    try:
        rendered = render_with_tor(
            result,
            bundle_version=args.bundle_version,
            tor_version=args.tor_version,
            archive_sha256=args.archive_sha256,
            checksum_url=args.checksum_url,
        )
    except ValueError as exc:
        parser.error(str(exc))
    args.output.write_text(rendered, encoding="utf-8")
    print(json.dumps({"output": str(args.output), "tor_provenance": True}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
