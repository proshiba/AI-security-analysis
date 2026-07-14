"""Offline analysis CLI backed by the declarative DAG runner."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .runner import run_analysis


def build_parser() -> argparse.ArgumentParser:
    """Build the offline runtime command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", required=True, type=Path)
    parser.add_argument("--definitions", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--policy", default="offline-default")
    parser.add_argument("--password", default="infected")
    parser.add_argument("--family-hint")
    parser.add_argument("--campaign-hint")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Execute one offline analysis without sample execution or network contact."""
    args = build_parser().parse_args(argv)
    result = run_analysis(
        args.sample, args.definitions, args.output, args.policy, args.password, args.family_hint, args.campaign_hint
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["plan_status"] in {"ready", "needs_review"} else 30


if __name__ == "__main__":
    raise SystemExit(main())
