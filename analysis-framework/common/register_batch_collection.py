#!/usr/bin/env python3
"""分類済みbatchを固定case metadataとcollection manifestへ安全に登録する。"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
from typing import Any

from result_layout import (
    SAFE_ID_RE,
    SHA256_RE,
    canonical_collection_manifest_path,
    canonical_malware_case_path,
)


class BatchRegistrationError(ValueError):
    """分類または既存公開情報が固定レイアウト契約に反する場合の例外。"""


def _read_object(path: Path, default: dict[str, Any]) -> dict[str, Any]:
    if not path.exists():
        return default
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise BatchRegistrationError(f"JSON object required: {path}")
    return value


def _atomic_write(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    handle = tempfile.NamedTemporaryFile(
        prefix=".batch-", suffix=".tmp", dir=path.parent, delete=False
    )
    temporary = Path(handle.name)
    try:
        with handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def register_batch(
    repository: Path,
    classification_path: Path,
    collection_id: str,
    *,
    write: bool = False,
) -> dict[str, Any]:
    """分類JSONのcaseを検証し、metadataとmanifestを冪等に同期する。"""

    if not SAFE_ID_RE.fullmatch(collection_id):
        raise BatchRegistrationError("unsafe collection ID")
    root = repository.resolve()
    results = root / "analysis-results"
    classification = _read_object(classification_path.resolve(), {})
    samples = classification.get("samples")
    if not isinstance(samples, list) or not samples:
        raise BatchRegistrationError("classification samples are required")

    documents: dict[Path, dict[str, Any]] = {}
    case_ids: set[str] = set()
    families: set[str] = set()
    for item in samples:
        if not isinstance(item, dict):
            raise BatchRegistrationError("classification sample must be an object")
        digest = str(item.get("sha256", "")).lower()
        family = str(item.get("family", "")).lower()
        version = str(item.get("version") or "unknown")
        if not SHA256_RE.fullmatch(digest):
            raise BatchRegistrationError(f"invalid SHA-256: {digest}")
        case_path = canonical_malware_case_path(results, family, digest, version)
        if not case_path.is_dir():
            raise BatchRegistrationError(f"canonical case is missing: {case_path}")
        metadata_path = case_path / "metadata.json"
        metadata = _read_object(metadata_path, {})
        canonical = case_path.relative_to(root).as_posix()
        expected = {
            "case_id": f"sha256:{digest}",
            "sha256": digest,
            "case_kind": "unclassified" if family == "unclassified" else "malware",
            "family": family,
            "canonical_path": canonical,
        }
        for key, value in expected.items():
            if key in metadata and metadata[key] != value:
                raise BatchRegistrationError(f"metadata {key} mismatch: {digest}")
        version_value = metadata.get("malware_version")
        if version_value is None:
            version_value = {
                "status": "unknown" if version == "unknown" else "reported",
                "reported": None if version == "unknown" else version,
                "normalized_key": version,
                "confidence": "none" if version == "unknown" else "source_reported",
                "reason": (
                    "no_approved_sample_specific_version_evidence"
                    if version == "unknown"
                    else "classification_reported_version"
                ),
                "evidence": [],
            }
        if version_value.get("normalized_key") != version:
            raise BatchRegistrationError(f"metadata version mismatch: {digest}")
        collections = metadata.get("collections") or []
        if not isinstance(collections, list):
            raise BatchRegistrationError(f"invalid collections: {digest}")
        metadata.update(
            {
                "schema_version": 1,
                **expected,
                "collections": sorted({*collections, collection_id}),
                "malware_version": version_value,
            }
        )
        documents[metadata_path] = metadata
        case_ids.add(f"sha256:{digest}")
        families.add(family)

    manifest_path = canonical_collection_manifest_path(results, collection_id)
    existing_manifest = _read_object(
        manifest_path,
        {
            "schema_version": 1,
            "collection_id": collection_id,
            "cases": [],
            "family_sources": [],
        },
    )
    if existing_manifest.get("schema_version") != 1:
        raise BatchRegistrationError("unsupported collection schema")
    if existing_manifest.get("collection_id") != collection_id:
        raise BatchRegistrationError("collection ID mismatch")
    old_ids = {
        item.get("case_id")
        for item in existing_manifest.get("cases", [])
        if isinstance(item, dict)
    }
    if None in old_ids:
        raise BatchRegistrationError("invalid existing collection case")
    manifest = {
        "schema_version": 1,
        "collection_id": collection_id,
        "family_sources": existing_manifest.get("family_sources", []),
        "cases": [{"case_id": value} for value in sorted(old_ids | case_ids)],
    }
    documents[manifest_path] = manifest

    if write:
        for path, value in documents.items():
            _atomic_write(path, value)
    return {
        "collection_id": collection_id,
        "cases": len(case_ids),
        "families": sorted(families),
        "documents": len(documents),
        "write_performed": write,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("classification", type=Path)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument("--collection-id", required=True)
    parser.add_argument("--write", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = register_batch(
        args.repository,
        args.classification,
        args.collection_id,
        write=args.write,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
