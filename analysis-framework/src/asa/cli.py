"""CLI for validating definitions and compiling dry-run plans."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .compiler import compile_plan
from .loader import index_definitions, load_definition_tree
from .models import AnalysisPlan, MalwareDefinition, PipelineDefinition, PolicyDefinition


def build_parser() -> argparse.ArgumentParser:
    """Build the stable command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--definitions", required=True, type=Path)
    plan = commands.add_parser("plan")
    plan.add_argument("--definitions", required=True, type=Path)
    plan.add_argument("--facts", required=True, type=Path)
    plan.add_argument("--policy", default="offline-default")
    plan.add_argument("--output", type=Path)
    return parser


def validate_definitions(root: Path) -> dict[str, int]:
    """Load all definitions and return counts by kind."""
    definitions = load_definition_tree(root)
    return {
        "malware": len(index_definitions(definitions, MalwareDefinition)),
        "pipelines": len(index_definitions(definitions, PipelineDefinition)),
        "policies": len(index_definitions(definitions, PolicyDefinition)),
    }


def create_plan(root: Path, facts_path: Path, policy_id: str) -> AnalysisPlan:
    """Compile one plan from JSON discovery facts."""
    definitions = load_definition_tree(root)
    malware = list(index_definitions(definitions, MalwareDefinition).values())
    pipelines = index_definitions(definitions, PipelineDefinition)
    policies = index_definitions(definitions, PolicyDefinition)
    if policy_id not in policies:
        raise ValueError(f"unknown policy: {policy_id}")
    facts = json.loads(facts_path.read_text(encoding="utf-8"))
    return compile_plan(malware, pipelines, policies[policy_id], facts)


def main(argv: list[str] | None = None) -> int:
    """Run the selected command without executing a malware sample."""
    args = build_parser().parse_args(argv)
    if args.command == "validate":
        result = validate_definitions(args.definitions)
    else:
        result = create_plan(args.definitions, args.facts, args.policy).model_dump(mode="json")
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
