#!/usr/bin/env python3
"""Generate thin detector wrappers and declarative definitions for a reviewed batch."""

from __future__ import annotations

import argparse
from collections import defaultdict
import json
from pathlib import Path
import re
import sys

REPO = Path(__file__).parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from extractors.profiled_family import load_profiles, normalize_family  # noqa: E402


def family_items(manifest: dict, profiles: dict[str, dict]) -> dict[str, list[dict]]:
    """Group manifest items by normalized requested signature and validate hashes."""
    grouped: dict[str, list[dict]] = defaultdict(list)
    for item in manifest.get("items") or []:
        family = normalize_family(str(item.get("requested_signature") or ""), profiles)
        digest = str(item.get("sha256") or "").lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"invalid SHA-256 for {family}")
        grouped[family].append(item)
    return {family: sorted(items, key=lambda item: item["sha256"]) for family, items in sorted(grouped.items())}


def detector_source(family: str, display_name: str) -> str:
    """Render a documented thin wrapper around the shared detector."""
    return f'''"""Profile-defined static detector for {display_name}."""

from __future__ import annotations

from pathlib import Path

from profiled_family_detector import detect_family


def detect(data: bytes, path: Path) -> dict:
    """Match reviewed hashes or a corroborated {display_name} static profile."""
    return detect_family("{family}", data, path)
'''


def malware_definition(family: str, profile: dict) -> str:
    """Render one family classification definition."""
    markers = ", ".join(json.dumps(marker) for marker in profile["markers"][:3])
    return f'''api_version: asa/v1alpha1
kind: MalwareAnalysisDefinition
metadata: {{id: {family}, display_name: {profile["display_name"]}, version: 1.0.0}}
classification:
  family:
    threshold: 70
    rules:
      - {{id: reviewed-family-hint, weight: 100, when: {{fact: classification.family_hint, equals: {family}}}}}
      - {{id: structural-marker-cluster, weight: 75, when: {{fact: static.strings_ci, contains_any: [{markers}]}}}}
  campaigns:
    - {{id: script_delivery, pipeline: {family}.config, threshold: 70, rules: [{{id: hint, weight: 100, when: {{fact: classification.campaign_hint, equals: script_delivery}}}}]}}
    - {{id: direct_or_wrapper, pipeline: {family}.config, threshold: 70, rules: [{{id: hint, weight: 100, when: {{fact: classification.campaign_hint, equals: reviewed_direct_payload_or_wrapper}}}}]}}
fallback_pipeline: {family}.config
'''


def workflow_definition(family: str, profile: dict) -> str:
    """Render one static-only workflow using the shared family config step."""
    return f'''api_version: asa/v1alpha1
kind: AnalysisPipeline
metadata: {{id: {family}.config, display_name: {profile["display_name"]} static workflow, version: 1.0.0}}
capabilities: [filesystem.sample.read]
steps:
  - {{id: intake, uses: "intake.submission@^1"}}
  - {{id: inventory, uses: "containers.inventory@^1", needs: [intake]}}
  - {{id: unpack, uses: "static.unpack.inspect@^1", needs: [inventory], on_error: partial}}
  - {{id: strings, uses: "static.strings.extract@^1", needs: [unpack]}}
  - {{id: config, uses: "family.{family}.config@^1", needs: [strings], on_error: partial}}
  - {{id: report, uses: "reporting.case_report@^1", needs: [config], on_error: partial}}
'''


def family_readme(profile: dict) -> str:
    """Render concise family-tool documentation without unsupported C2 claims."""
    return f'''# {profile["display_name"]} static analysis

Category: `{profile["category"]}`. Expected transport: {profile["transport"]}.

The detector and config extractor share `extractors/profiles/windows_family_profiles.json`. Literal endpoints are candidates until the profile-specific confirmation condition is met: {profile["confirmation"]}

The generic emulator is loopback-only, emits synthetic identities, and never returns commands. Samples and recovered payloads are not executed by this workflow.
'''


def write_text(path: Path, value: str) -> None:
    """Write normalized UTF-8 text after creating the parent directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value.replace("\r\n", "\n"), encoding="utf-8")


def update_registry(path: Path, grouped: dict[str, list[dict]], profiles: dict[str, dict]) -> None:
    """Add generated families to the central detector registry without dropping entries."""
    value = json.loads(path.read_text(encoding="utf-8-sig")) if path.is_file() else {"schema_version": 3, "malware_types": {}}
    malware_types = value.setdefault("malware_types", {})
    for family, items in grouped.items():
        malware_types[family] = {
            "description": f"{profiles[family]['display_name']} reviewed payloads and delivery chains",
            "detector": f"malware/{family}/detect.py",
            "campaign_registry": f"malware/{family}/campaigns.json",
            "known_sample_sha256": sorted(item["sha256"] for item in items),
        }
    write_text(path, json.dumps(value, ensure_ascii=False, indent=2) + "\n")

def scaffold(manifest_path: Path, repository: Path) -> dict:
    """Generate family modules, campaign registries, and YAML definitions."""
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    profiles = load_profiles(repository / "extractors" / "profiles" / "windows_family_profiles.json")
    grouped = family_items(manifest, profiles)
    framework = repository / "analysis-framework"
    for family, items in grouped.items():
        profile = profiles[family]
        hashes = [item["sha256"] for item in items]
        base = framework / "malware" / family
        write_text(base / "detect.py", detector_source(family, profile["display_name"]))
        write_text(base / "README.md", family_readme(profile))
        write_text(
            base / "campaigns.json",
            json.dumps(
                {
                    "schema_version": 1,
                    "classification_principle": "Family, delivery wrapper, and operator campaign are independent dimensions.",
                    "known_sample_sha256": hashes,
                    "patterns": {
                        "script_delivery": "Script or document wrapper requiring bounded layer recovery.",
                        "direct_or_wrapper": "Direct payload, container, or protected wrapper from the reviewed batch.",
                    },
                },
                indent=2,
            )
            + "\n",
        )
        write_text(framework / "definitions" / "malware" / f"{family}.yaml", malware_definition(family, profile))
        write_text(framework / "definitions" / "workflows" / f"{family}.yaml", workflow_definition(family, profile))
    update_registry(framework / "registry" / "malware_types.json", grouped, profiles)
    return {"families": len(grouped), "samples": sum(map(len, grouped.values())), "family_counts": {key: len(value) for key, value in grouped.items()}}


def build_parser() -> argparse.ArgumentParser:
    """Build the deterministic scaffolding command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--repository", type=Path, default=REPO)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Generate all declared family scaffolding and print counts."""
    args = build_parser().parse_args(argv)
    print(json.dumps(scaffold(args.manifest, args.repository), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
