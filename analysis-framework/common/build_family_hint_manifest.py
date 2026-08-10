#!/usr/bin/env python3
"""公開済み解析summaryからSHA-256 keyed family hint manifestを生成する。"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
CLASSIFIERS_ROOT = FRAMEWORK_ROOT / "classifiers"
for value in (str(FRAMEWORK_ROOT), str(CLASSIFIERS_ROOT)):
    if value not in sys.path:
        sys.path.insert(0, value)

import classify_sample
from analysis_contract import load_json_object_strict


def build_manifest(path: Path, *, source: str) -> dict[str, Any]:
    """publication summaryを読み、外部metadata候補だけをstrict manifestへ変換する。"""

    document = load_json_object_strict(path)
    return classify_sample.family_hint_manifest_from_publication_summary(
        document,
        source=source,
    )


def write_manifest(path: Path, manifest: dict[str, Any]) -> None:
    """検証済みmanifestを同一directory内の一時fileからatomicに置換する。"""

    normalized = classify_sample.normalize_family_hint_manifest(manifest)
    payload = (
        json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError:
        Path(temporary).unlink(missing_ok=True)
        raise


def build_parser() -> argparse.ArgumentParser:
    """日本語helpを持つCLI parserを生成する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publication-summary", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--source",
        default="malwarebazaar_publication_summary",
        help="hintの由来。family確定証拠には使用されません。",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理し、変換件数をJSONで返す。"""

    args = build_parser().parse_args(argv)
    manifest = build_manifest(args.publication_summary, source=args.source)
    write_manifest(args.output, manifest)
    print(
        json.dumps(
            {
                "samples": len(manifest["samples"]),
                "hints": sum(len(items) for items in manifest["samples"].values()),
                "output": args.output.name,
                "ai_used": False,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
