"""Unified CLI and dispatcher for all supported malware config extractors."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable

from extractors.agenttesla import extract as extract_agenttesla
from extractors.remcosrat import extract as extract_remcosrat
from extractors.unclassified.mx_go import extract as extract_mx_go
from extractors.valleyrat import extract as extract_valleyrat
from extractors.venomrat import extract as extract_venomrat

Extractor = Callable[[bytes, str], dict]
EXTRACTORS: dict[str, Extractor] = {
    "agenttesla": extract_agenttesla,
    "remcosrat": extract_remcosrat,
    "valleyrat": extract_valleyrat,
    "venomrat": extract_venomrat,
    "mx-go": extract_mx_go,
}
ALIASES = {"remcos": "remcosrat", "venom": "venomrat", "mx_go": "mx-go"}


def normalize_family(value: str) -> str:
    """Normalize accepted family aliases to definition IDs."""
    lowered = value.strip().lower()
    return ALIASES.get(lowered, lowered)


def get_extractor(family: str) -> Extractor:
    """Return a supported extractor or raise a clear error."""
    normalized = normalize_family(family)
    if normalized not in EXTRACTORS:
        raise ValueError(
            f"unsupported family: {family}; supported: {', '.join(sorted(EXTRACTORS))}"
        )
    return EXTRACTORS[normalized]


def extract_file(family: str, sample: Path) -> dict:
    """Read a sample once and run its offline family extractor."""
    return get_extractor(family)(sample.read_bytes(), sample.name)


def build_parser() -> argparse.ArgumentParser:
    """Build the unified extractor CLI parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--family", required=True)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run one extractor and write deterministic JSON."""
    args = build_parser().parse_args(argv)
    result = extract_file(args.family, args.input)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": str(args.output),
                "family": result["family"],
                "findings": len(result["findings"]),
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
