#!/usr/bin/env python3
"""Convert a saved public Triage HTML report into normalized text and evidence."""
from __future__ import annotations
import argparse
from html.parser import HTMLParser
import html
import re
from pathlib import Path
from malware_io import sha256_bytes, write_json

class TextParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts: list[str] = []

    def handle_data(self, data: str) -> None:
        self.parts.append(data)

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--html", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    raw_bytes = args.html.read_bytes()
    raw = raw_bytes.decode("utf-8", errors="replace")
    parsed = TextParser()
    parsed.feed(raw)
    lines = []
    for part in parsed.parts:
        line = " ".join(html.unescape(part).split())
        if line:
            lines.append(line)
    text = "\n".join(lines)
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "triage-text.txt").write_text(text, encoding="utf-8")
    endpoint_pattern = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}")
    url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.I)
    path_pattern = re.compile(r"[A-Za-z]:\\[^\r\n\"<>]{1,300}\.(?:exe|dll|js|vbs|hta|ps1|bat|cmd)", re.I)
    contexts = [{"endpoint": match.group(), "context": text[max(0, match.start() - 350):match.end() + 350]} for match in endpoint_pattern.finditer(text)]
    result = {
        "schema_version": 2,
        "source_html_sha256": sha256_bytes(raw_bytes),
        "endpoints": sorted(set(endpoint_pattern.findall(text))),
        "urls": sorted(set(url_pattern.findall(text)))[:1000],
        "process_paths": sorted(set(path_pattern.findall(text)))[:1000],
        "endpoint_contexts": contexts[:500],
        "executed_locally": False,
    }
    write_json(args.output_dir / "triage-evidence.json", result)
    print({"endpoints": result["endpoints"], "paths": len(result["process_paths"])})
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
