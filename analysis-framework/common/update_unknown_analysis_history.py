#!/usr/bin/env python3
"""Append idempotent static unknown-batch entries to ``analysis_history.yaml``."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re

SHA256 = re.compile(r"^[0-9a-f]{64}$")


def yaml_scalar(value: str) -> str:
    """Encode a string as a YAML-compatible JSON double-quoted scalar."""
    return json.dumps(value, ensure_ascii=False)


def render_history_entries(summary: dict, result_root: str, analyzed_at: str) -> list[tuple[str, str]]:
    """Render one conservative history entry for every successful batch case."""
    entries: list[tuple[str, str]] = []
    root = result_root.rstrip("/")
    for case in summary.get("cases") or []:
        if "error" in case:
            continue
        sha256 = str(case.get("sha256") or "").lower()
        if not SHA256.fullmatch(sha256):
            raise ValueError(f"invalid SHA-256 in summary: {sha256}")
        attribution = case.get("attribution") or {}
        family = str(attribution.get("family") or "unknown")
        confidence = str(attribution.get("confidence") or "low")
        supported = family != "unknown" and confidence in {"medium", "high"}
        malware_type = family if supported else "Unclassified"
        if supported:
            note = f"{confidence.title()}-confidence static family attribution; extracted network values remain unconfirmed candidates. No sample execution or infrastructure contact."
        elif family != "unknown":
            note = f"Provisional low-confidence {family} lead; not treated as confirmed family attribution or C2. No sample execution or infrastructure contact."
        else:
            note = "No defensible family attribution from bounded static evidence. No sample execution or infrastructure contact."
        file_type = str((case.get("source") or {}).get("file_type") or "unknown")
        lines = [
            f"  - malware_type: {yaml_scalar(malware_type)}",
            f"    analyzed_at: {analyzed_at}",
            f"    sample_sha256: {sha256}",
            "    analysis_level: static_family_attribution",
            "    campaign_type: malwarebazaar_unsigned_newest_batch",
            "    matched_patterns:",
            f"      - {yaml_scalar('family:' + family)}",
            f"      - {yaml_scalar('confidence:' + confidence)}",
            f"      - {yaml_scalar('format:' + file_type)}",
            "    c2: []",
            f"    notes: {yaml_scalar(note)}",
            f"    result_path: {root}/cases/{sha256}/",
        ]
        entries.append((sha256, "\n".join(lines)))
    return entries


def append_missing_entries(history_path: Path, entries: list[tuple[str, str]]) -> int:
    """Append only hashes not already recorded and return the appended count."""
    current = history_path.read_text(encoding="utf-8-sig")
    additions = [entry for sha256, entry in entries if f"sample_sha256: {sha256}" not in current]
    if not additions:
        return 0
    history_path.write_text(
        current.rstrip() + "\n\n" + "\n\n".join(additions) + "\n",
        encoding="utf-8",
    )
    return len(additions)


def build_parser() -> argparse.ArgumentParser:
    """Build the analysis-history update command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary", required=True, type=Path)
    parser.add_argument("--history", required=True, type=Path)
    parser.add_argument("--result-root", required=True)
    parser.add_argument("--analyzed-at", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Append missing summary cases to the requested history file."""
    args = build_parser().parse_args(argv)
    summary = json.loads(args.summary.read_text(encoding="utf-8"))
    entries = render_history_entries(summary, args.result_root, args.analyzed_at)
    count = append_missing_entries(args.history, entries)
    print(json.dumps({"entries": len(entries), "appended": count}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
