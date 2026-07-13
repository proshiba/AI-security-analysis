from __future__ import annotations
import argparse
import re
from pathlib import Path
from malware_io import decode_text, read_single_aes_zip_member, safety_metadata, write_json

ASSIGN = re.compile(r"(?i)^\s*(?:set\s+)?([A-Za-z_]\w*)\s*=\s*(.+)$")
IDENT = re.compile(r"\b[A-Za-z_]\w*\b")
SINK = re.compile(r"(?i)(\.run\s*\(|\.exec\s*\(|shellexecute\s*\(|createobject\s*\(|execquery\s*\()")
BUILTINS = {"set", "createobject", "getobject", "true", "false", "nothing", "select", "from", "where", "name"}

def main() -> int:
    parser = argparse.ArgumentParser(description="Trace VBS variables feeding execution/object sinks.")
    parser.add_argument("--outer-zip", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    args = parser.parse_args()
    member = read_single_aes_zip_member(args.outer_zip, password=args.password)
    lines = decode_text(member.data)[0].splitlines()
    assignments: dict[str, list[dict]] = {}
    sinks: list[dict] = []
    for number, line in enumerate(lines, 1):
        if line.lstrip().startswith("'"):
            continue
        match = ASSIGN.match(line)
        if match:
            assignments.setdefault(match.group(1).lower(), []).append({"line": number, "expression": match.group(2).strip()[:2000]})
        if SINK.search(line):
            sinks.append({"line": number, "text": line.strip()[:2000]})
    for sink in sinks:
        frontier = [value.lower() for value in IDENT.findall(sink["text"]) if value.lower() not in BUILTINS]
        traced = {}
        for _ in range(4):
            next_frontier = []
            for name in frontier:
                candidates = [item for item in assignments.get(name, []) if item["line"] < sink["line"]]
                if not candidates or name in traced:
                    continue
                selected = candidates[-1]
                traced[name] = selected
                next_frontier.extend(value.lower() for value in IDENT.findall(selected["expression"]) if value.lower() not in BUILTINS)
            frontier = next_frontier
        sink["variable_trace"] = traced
    write_json(args.output, {"schema_version": 2, "member": member.name, "sha256": member.sha256, "sinks": sinks, **safety_metadata()})
    print(f"traced {len(sinks)} sinks")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
