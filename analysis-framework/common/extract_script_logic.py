from __future__ import annotations
import argparse
import re
from pathlib import Path
from malware_io import decode_text, read_single_aes_zip_member, safety_metadata, write_json

KEYWORDS = re.compile(r"(?i)(createobject|activexobject|wscript|shellapplication|shell\.application|shellexecute|\.run\s*\(|\.exec\s*\(|powershell|cmd\.exe|mshta|xmlhttp|adodb|download(data|string|file)|frombase64|string|appdomain|\.load\s*\(|eval\s*\(|fromcharcode|opentextfile|readall|write(text)?|getobject|execquery|win32_|scriptfullname|environment|specialfolders)")
COMMENT = re.compile(r"^\s*(?:'|//|/\*|\*|<!--)")
QUOTED = re.compile(r"(['\"])(.{4,300}?)\1")

def main() -> int:
    parser = argparse.ArgumentParser(description="Extract executable-looking script logic without execution.")
    parser.add_argument("--outer-zip", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    parser.add_argument("--max-lines", type=int, default=500)
    args = parser.parse_args()
    member = read_single_aes_zip_member(args.outer_zip, password=args.password)
    text, encoding = decode_text(member.data)
    logical, strings = [], []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or COMMENT.match(stripped):
            continue
        if KEYWORDS.search(stripped):
            logical.append({"line": number, "text": stripped[:1200]})
        for match in QUOTED.finditer(stripped):
            value = match.group(2)
            if KEYWORDS.search(value) and value not in strings:
                strings.append(value[:1200])
        if len(logical) >= args.max_lines:
            break
    write_json(args.output, {"schema_version": 2, "member": member.name, "sha256": member.sha256, "encoding": encoding, "source_lines": len(text.splitlines()), "logic_lines": logical, "embedded_behavior_strings": strings[:200], **safety_metadata()})
    print(f"wrote {len(logical)} logic lines from {member.name}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
