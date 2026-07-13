from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import pyzipper

KEYWORDS = re.compile(
    r"(?i)(createobject|activexobject|wscript|shellapplication|shell\.application|shellexecute|"
    r"\.run\s*\(|\.exec\s*\(|powershell|cmd\.exe|mshta|xmlhttp|adodb|download(data|string|file)|"
    r"frombase64|string|appdomain|\.load\s*\(|eval\s*\(|fromcharcode|opentextfile|readall|"
    r"write(text)?|getobject|execquery|win32_|scriptfullname|environment|specialfolders)"
)
COMMENT = re.compile(r"^\s*(?:'|//|/\*|\*|<!--)")
QUOTED = re.compile(r"(['\"])(.{4,300}?)\1")


def decode(raw: bytes) -> tuple[str, str]:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace"), "utf-16"
    for enc in ("utf-8-sig", "utf-16-le", "cp1252"):
        try:
            text = raw.decode(enc)
            if enc != "utf-16-le" or text.count("\x00") < max(2, len(text) // 100):
                return text, enc
        except UnicodeError:
            pass
    return raw.decode("utf-8", errors="replace"), "utf-8-replace"


def main() -> int:
    ap = argparse.ArgumentParser(description="Extract executable-looking logic from a script in a MalwareBazaar AES ZIP without executing it.")
    ap.add_argument("--outer-zip", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--password", default="infected")
    ap.add_argument("--max-lines", type=int, default=500)
    args = ap.parse_args()
    with pyzipper.AESZipFile(args.outer_zip) as zf:
        members = [m for m in zf.infolist() if not m.is_dir()]
        if len(members) != 1:
            raise SystemExit("expected exactly one top-level member")
        raw = zf.read(members[0], pwd=args.password.encode())
    text, encoding = decode(raw)
    logical: list[dict] = []
    strings: list[str] = []
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
    result = {
        "schema_version": 1,
        "member": members[0].filename,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "encoding": encoding,
        "source_lines": len(text.splitlines()),
        "logic_lines": logical,
        "embedded_behavior_strings": strings[:200],
        "executed": False,
        "network_contacted": False,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {len(logical)} logic lines from {members[0].filename}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
