#!/usr/bin/env python3
"""公開summaryまたは取得metadataからSHA-256 keyed family hintを生成する。"""

from __future__ import annotations

import argparse
import importlib
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

classify_sample = importlib.import_module("classify_sample")
load_json_object_strict = importlib.import_module(
    "analysis_contract"
).load_json_object_strict
metadata_family_candidates = importlib.import_module(
    "malwarebazaar_family_labels"
).metadata_family_candidates

MAX_COLLECTION_ITEMS = 4096


def build_manifest(path: Path, *, source: str) -> dict[str, Any]:
    """publication summaryを読み、外部metadata候補だけをstrict manifestへ変換する。"""

    document = load_json_object_strict(path)
    return classify_sample.family_hint_manifest_from_publication_summary(
        document,
        source=source,
    )


def _collection_items(document: dict[str, Any]) -> tuple[str, list[Any]]:
    """公開collectionまたはprivate lookupから一意なitem列を取得する。"""

    fields = [field for field in ("acquisition_items", "items") if field in document]
    if len(fields) != 1:
        raise ValueError("metadata manifest must contain exactly one item list")
    field = fields[0]
    items = document[field]
    if not isinstance(items, list):
        raise TypeError(f"metadata manifest {field} must be a list")
    if len(items) > MAX_COLLECTION_ITEMS:
        raise ValueError("metadata manifest exceeds the item count limit")
    return field, items


def _exact_item_sha256(item: dict[str, Any], metadata: dict[str, Any], *, location: str) -> str:
    """itemとprovider metadataのSHA-256を照合してexact digestを返す。"""

    values = []
    for label, value in (
        ("sha256", item.get("sha256")),
        ("metadata.sha256_hash", metadata.get("sha256_hash")),
    ):
        if value is None:
            continue
        if not isinstance(value, str) or classify_sample.SHA256_RE.fullmatch(value.lower()) is None:
            raise ValueError(f"{location}.{label} is not a SHA-256")
        values.append(value.lower())
    if not values:
        raise ValueError(f"{location} has family metadata without an exact SHA-256")
    if len(set(values)) != 1:
        raise ValueError(f"{location} SHA-256 fields do not match")
    return values[0]


def build_collection_manifest(path: Path, *, source: str) -> dict[str, Any]:
    """取得metadataを、帰属に使わないexact-SHA検証候補へ変換する。"""

    document = load_json_object_strict(path)
    field, items = _collection_items(document)
    samples: dict[str, list[dict[str, str]]] = {}
    for index, raw_item in enumerate(items):
        location = f"{field}[{index}]"
        if not isinstance(raw_item, dict):
            raise TypeError(f"{location} must be an object")
        if raw_item.get("found") is False:
            continue
        metadata = raw_item.get("metadata")
        if metadata is None:
            continue
        if not isinstance(metadata, dict):
            raise TypeError(f"{location}.metadata must be an object")
        candidates = metadata_family_candidates(metadata)
        if not candidates:
            continue
        digest = _exact_item_sha256(raw_item, metadata, location=location)
        for candidate in candidates:
            hint = {
                "family": candidate["family"],
                "source": source,
                "provenance": f"metadata-manifest:{candidate['basis']}",
                "confidence": "unverified",
                "label": candidate["label"],
            }
            observed_at = metadata.get("first_seen")
            if isinstance(observed_at, str) and observed_at:
                hint["observed_at"] = observed_at
            samples.setdefault(digest, []).append(hint)
    return classify_sample.normalize_family_hint_manifest(
        {"schema_version": 1, "samples": samples}
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
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--publication-summary", type=Path)
    inputs.add_argument(
        "--collection-manifest",
        type=Path,
        help="取得時のacquisition_itemsまたはprivate lookup itemsを含むJSON。",
    )
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--source",
        default=None,
        help="hintの由来。family確定証拠には使用されません。",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理し、変換件数をJSONで返す。"""

    args = build_parser().parse_args(argv)
    if args.publication_summary is not None:
        source = args.source or "malwarebazaar_publication_summary"
        manifest = build_manifest(args.publication_summary, source=source)
    else:
        source = args.source or "malwarebazaar_collection_manifest"
        manifest = build_collection_manifest(
            args.collection_manifest,
            source=source,
        )
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
