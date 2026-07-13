from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import pyzipper

ASSIGN = re.compile(r"(?i)^\s*(?:set\s+)?([A-Za-z_]\w*)\s*=\s*(.+)$")
IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
SINK = re.compile(r"(?i)(\.run\s*\(|\.exec\s*\(|shellexecute\s*\(|createobject\s*\(|execquery\s*\()")
BUILTINS = {"set", "createobject", "getobject", "true", "false", "nothing", "select", "from", "where", "name"}


def decode(raw: bytes) -> str:
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def main() -> int:
    ap = argparse.ArgumentParser(description="Trace VBS variables feeding process/object sinks without executing the script.")
    ap.add_argument("--outer-zip", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--password", default="infected")
    args = ap.parse_args()
    with pyzipper.AESZipFile(args.outer_zip) as zf:
        members = [m for m in zf.infolist() if not m.is_dir()]
        raw = zf.read(members[0], pwd=args.password.encode())
    lines = decode(raw).splitlines()
    assignments: dict[str, list[dict]] = {}
    sinks: list[dict] = []
    for num, line in enumerate(lines, 1):
        if line.lstrip().startswith("'"):
            continue
        match = ASSIGN.match(line)
        if match:
            assignments.setdefault(match.group(1).lower(), []).append({"line": num, "expression": match.group(2).strip()[:2000]})
        if SINK.search(line):
            sinks.append({"line": num, "text": line.strip()[:2000]})
    for sink in sinks:
        needed = [x.lower() for x in IDENT.findall(sink["text"]) if x.lower() not in BUILTINS]
        traced = {}
        frontier = needed
        for _ in range(4):
            next_frontier = []
            for name in frontier:
                candidates = [a for a in assignments.get(name, []) if a["line"] < sink["line"]]
                if not candidates or name in traced:
                    continue
                selected = candidates[-1]
                traced[name] = selected
                next_frontier.extend(x.lower() for x in IDENT.findall(selected["expression"]) if x.lower() not in BUILTINS)
            frontier = next_frontier
        sink["variable_trace"] = traced
    result = {"member": members[0].filename, "sinks": sinks, "executed": False, "network_contacted": False}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"traced {len(sinks)} sinks")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
