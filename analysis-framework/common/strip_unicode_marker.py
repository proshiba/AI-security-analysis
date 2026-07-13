#!/usr/bin/env python3
from __future__ import annotations
import argparse
import collections
import re
from pathlib import Path
from malware_io import decode_text, read_single_aes_zip_member, safe_output_name, safety_metadata, sha256_bytes, write_json

QUOTED = re.compile(r'(["\'])(.*?)(?<!\\)\1', re.S)
APPEND = re.compile(r'(?m)(?:this\.)?([A-Za-z_$][\w$]*)\s*\+=\s*(["\'])(.*?)(?<!\\)\2\s*;', re.S)
URL = re.compile(r'https?://[^\s"\'<>]+', re.I)

def main() -> int:
    parser = argparse.ArgumentParser(description="Remove repeated Unicode junk markers and rebuild concatenated strings.")
    parser.add_argument("--outer-zip", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    args = parser.parse_args()
    member = read_single_aes_zip_member(args.outer_zip, password=args.password)
    source = decode_text(member.data)[0]
    strings = [match.group(2) for match in QUOTED.finditer(source)]
    candidates = [value for value in strings if 8 <= len(value) <= 80 and sum(ord(char) > 127 for char in value) / len(value) > 0.6]
    marker, _ = collections.Counter(candidates).most_common(1)[0] if candidates else ("", 0)
    clean = source.replace(marker, "") if marker else source
    groups: dict[str, list[str]] = collections.defaultdict(list)
    for match in APPEND.finditer(clean):
        groups[match.group(1)].append(match.group(3))
    args.output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = []
    for name, value in sorted(((name, "".join(parts)) for name, parts in groups.items()), key=lambda item: len(item[1]), reverse=True):
        if len(value) < 40:
            continue
        filename = safe_output_name(name, 60) + ".rebuilt.txt"
        (args.output_dir / filename).write_text(value, encoding="utf-8", errors="replace")
        artifacts.append({"variable": name, "length": len(value), "sha256": sha256_bytes(value.encode(errors="replace")), "file": filename, "urls": sorted(set(URL.findall(value))), "preview": value[:500]})
    result = {"schema_version": 2, "member": member.name, "sha256": member.sha256, "marker": marker, "marker_occurrences": source.count(marker) if marker else 0, "rebuilt": artifacts[:100], **safety_metadata()}
    write_json(args.output_dir / "unicode-marker.json", result)
    print({"member": member.name, "marker_length": len(marker), "marker_occurrences": result["marker_occurrences"], "rebuilt_count": len(artifacts)})
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
