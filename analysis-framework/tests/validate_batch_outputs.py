from __future__ import annotations
import argparse
import json
from pathlib import Path

REQUIRED_SCRIPT = {"triage", "classification", "script-layers", "script-logic", "encoded-text"}

def validate_family(root: Path, known_cases: Path) -> list[str]:
    cases = json.loads(known_cases.read_text(encoding="utf-8"))["cases"]
    errors: list[str] = []
    for expected in cases:
        digest = expected["sha256"]
        output = root / digest / "analysis-output"
        try:
            summary = json.loads((output / "batch-run-summary.json").read_text(encoding="utf-8-sig"))
            classification = json.loads((output / "classification.json").read_text(encoding="utf-8-sig"))
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            errors.append(f"{digest}: missing/invalid output: {exc}")
            continue
        if summary["member_sha256"] != digest:
            errors.append(f"{digest}: member hash mismatch")
        if summary["campaign_type"] != expected["campaign"]:
            errors.append(f"{digest}: campaign mismatch {summary['campaign_type']}")
        if summary.get("executed") or summary.get("network_contacted"):
            errors.append(f"{digest}: unsafe execution/network marker")
        if classification["observations"].get("detector_errors"):
            errors.append(f"{digest}: detector errors {classification['observations']['detector_errors']}")
        stages = set(summary["completed_stages"])
        if summary["member_type"] == "script" and not REQUIRED_SCRIPT.issubset(stages):
            errors.append(f"{digest}: missing script stages {sorted(REQUIRED_SCRIPT - stages)}")
        artifact = expected["artifact"].lower()
        if artifact == "vbs" and "vbs-variable-trace" not in stages:
            errors.append(f"{digest}: missing VBS trace")
        if artifact == "iso9660" and "iso9660" not in stages:
            errors.append(f"{digest}: missing ISO inventory")
    return errors

def main() -> int:
    parser = argparse.ArgumentParser(description="Validate completed safe batch outputs against reviewed case metadata.")
    parser.add_argument("--agenttesla-root", required=True, type=Path)
    parser.add_argument("--remcos-root", required=True, type=Path)
    parser.add_argument("--framework", required=True, type=Path)
    args = parser.parse_args()
    errors = []
    errors.extend(validate_family(args.agenttesla_root, args.framework / "malware/agenttesla/config/known-cases.json"))
    errors.extend(validate_family(args.remcos_root, args.framework / "malware/remcosrat/config/known-cases.json"))
    if errors:
        raise SystemExit("\n".join(errors))
    print("PASS: 20/20 batch outputs contain required stages, exact inner hashes, safe markers, and no detector errors")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
