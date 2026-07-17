#!/usr/bin/env python3
"""固定レイアウトへcaseを公開し、catalogとcollectionを同期する。

このmoduleは生成済みの公開JSON／Markdownだけを扱う。検体を開かず、
実行、CPU／CILエミュレーション、外部通信を行わない。
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import tempfile
from typing import Iterable

from result_layout import (
    FAMILY_RE,
    SAFE_ID_RE,
    SHA256_RE,
    canonical_collection_manifest_path,
    canonical_malware_case_path,
    resolve_catalog_case_path,
)


class PublicationError(ValueError):
    """公開先または既存indexが固定レイアウト契約を満たさない場合の例外。"""


@dataclass(frozen=True)
class PublicationContext:
    """collectionのfamily集約先とcanonical case rootの関係を保持する。"""

    repository: Path
    results_root: Path
    collection_id: str
    family: str
    aggregate_root: Path


def detect_publication_context(
    aggregate_root: Path, family: str
) -> PublicationContext | None:
    """canonicalなcollection sourceならcontextを返し、それ以外はNoneを返す。"""

    aggregate = aggregate_root.resolve()
    if not FAMILY_RE.fullmatch(family):
        raise PublicationError(f"unsafe family identifier: {family!r}")
    results_root = next(
        (parent for parent in (aggregate, *aggregate.parents) if parent.name == "analysis-results"),
        None,
    )
    if results_root is None:
        return None
    try:
        relative = aggregate.relative_to(results_root)
    except ValueError as exc:
        raise PublicationError("aggregate root escaped analysis-results") from exc
    if len(relative.parts) != 4 or relative.parts[0] != "collections" or relative.parts[2] != "sources":
        raise PublicationError(
            "result aggregate must use collections/<collection-id>/sources/<family>"
        )
    collection_id, path_family = relative.parts[1], relative.parts[3]
    if not SAFE_ID_RE.fullmatch(collection_id):
        raise PublicationError(f"unsafe collection identifier: {collection_id!r}")
    if path_family != family:
        raise PublicationError(
            f"aggregate family mismatch: path={path_family!r}, data={family!r}"
        )
    return PublicationContext(
        repository=results_root.parent,
        results_root=results_root,
        collection_id=collection_id,
        family=family,
        aggregate_root=aggregate,
    )


def publication_case_path(
    aggregate_root: Path, family: str, sha256: str
) -> tuple[Path, PublicationContext | None]:
    """case公開先を返し、canonical collection外ではlegacy互換先を返す。"""

    digest = sha256.lower()
    if not SHA256_RE.fullmatch(digest):
        raise PublicationError(f"unsafe SHA-256: {sha256!r}")
    context = detect_publication_context(aggregate_root, family)
    if context is None:
        return aggregate_root.resolve() / "cases" / digest, None
    try:
        case = resolve_catalog_case_path(
            context.results_root,
            digest,
            family=family,
            fallback_version_key="unknown",
        )
    except Exception as exc:
        raise PublicationError(f"cannot resolve canonical case {digest}: {exc}") from exc
    return case, context


def _read_json_document(path: Path, default: dict) -> tuple[dict, bytes | None]:
    if not path.exists():
        return default, None
    if path.is_symlink() or not path.is_file():
        raise PublicationError(f"index is not a regular file: {path}")
    source = path.read_bytes()
    try:
        value = json.loads(source.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublicationError(f"invalid JSON index: {path}") from exc
    if not isinstance(value, dict):
        raise PublicationError(f"JSON index must be an object: {path}")
    return value, source


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _replace_documents(documents: dict[Path, tuple[bytes | None, bytes]]) -> None:
    """複数JSONをstale検査付きで置換し、失敗時は全てrollbackする。"""

    temporary: dict[Path, Path] = {}
    replaced: list[Path] = []
    try:
        for path, (before, content) in documents.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            current = path.read_bytes() if path.exists() else None
            if current != before:
                raise PublicationError(f"index changed during publication: {path}")
            with tempfile.NamedTemporaryFile(
                prefix=".t-", suffix=".tmp", dir=path.parent, delete=False
            ) as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
                temporary[path] = Path(handle.name)
        for path in documents:
            os.replace(temporary[path], path)
            replaced.append(path)
    except Exception:
        for path in reversed(replaced):
            before = documents[path][0]
            if before is None:
                if path.exists():
                    path.unlink()
            else:
                with tempfile.NamedTemporaryFile(
                    prefix=".r-",
                    suffix=".tmp",
                    dir=path.parent,
                    delete=False,
                ) as handle:
                    handle.write(before)
                    handle.flush()
                    os.fsync(handle.fileno())
                    rollback = Path(handle.name)
                os.replace(rollback, path)
        raise
    finally:
        for path in temporary.values():
            if path.exists():
                path.unlink()


def register_publication_cases(
    context: PublicationContext,
    case_paths: Iterable[Path],
) -> dict[str, int | str]:
    """case metadata、catalog、collection membershipを一つの更新として同期する。"""

    normalized: dict[str, Path] = {}
    for raw_path in case_paths:
        path = raw_path.resolve()
        try:
            relative = path.relative_to(context.results_root)
        except ValueError as exc:
            raise PublicationError("case path escaped analysis-results") from exc
        digest = path.name.lower()
        if not SHA256_RE.fullmatch(digest):
            raise PublicationError(f"unsafe case directory: {path}")
        if not path.is_dir() or path.is_symlink():
            raise PublicationError(f"case is not a regular directory: {path}")
        if digest in normalized and normalized[digest] != path:
            raise PublicationError(f"duplicate case identity has multiple paths: {digest}")
        normalized[digest] = path

    catalog_path = context.results_root / "catalog" / "cases.json"
    collection_path = canonical_collection_manifest_path(
        context.results_root, context.collection_id
    )
    catalog, catalog_before = _read_json_document(
        catalog_path, {"schema_version": 1, "cases": {}}
    )
    collection, collection_before = _read_json_document(
        collection_path,
        {
            "schema_version": 1,
            "collection_id": context.collection_id,
            "cases": [],
            "family_sources": [],
        },
    )
    if catalog.get("schema_version") != 1 or not isinstance(catalog.get("cases"), dict):
        raise PublicationError("unsupported catalog schema")
    if collection.get("schema_version") != 1:
        raise PublicationError("unsupported collection schema")
    if collection.get("collection_id") != context.collection_id:
        raise PublicationError("collection ID mismatch")
    if not isinstance(collection.get("cases"), list):
        raise PublicationError("collection cases must be a list")
    if not isinstance(collection.get("family_sources"), list):
        raise PublicationError("collection family_sources must be a list")

    documents: dict[Path, tuple[bytes | None, bytes]] = {}
    for digest, path in sorted(normalized.items()):
        metadata_path = path / "metadata.json"
        metadata, metadata_before = _read_json_document(metadata_path, {})
        for key, expected in (
            ("schema_version", 1),
            ("sha256", digest),
            ("case_id", f"sha256:{digest}"),
            ("case_kind", "malware"),
        ):
            if key in metadata and metadata[key] != expected:
                raise PublicationError(f"metadata {key} mismatch for {digest}")
        existing_family = metadata.get("family")
        if existing_family not in (None, context.family):
            raise PublicationError(f"metadata family mismatch for {digest}")
        version = metadata.get("malware_version")
        if version is not None and not isinstance(version, dict):
            raise PublicationError(f"invalid malware_version for {digest}")
        if version is None:
            version = {
                "status": "unknown",
                "reported": None,
                "normalized_key": "unknown",
                "confidence": "none",
                "reason": "no_approved_sample_specific_version_evidence",
                "evidence": [],
            }
        if version.get("status") not in {"confirmed", "reported", "unknown"}:
            raise PublicationError(f"invalid malware_version status for {digest}")
        version_key = str(version.get("normalized_key") or "unknown")
        expected_path = canonical_malware_case_path(
            context.results_root, context.family, digest, version_key
        )
        if path != expected_path:
            raise PublicationError(
                f"case path does not match metadata version for {digest}"
            )
        existing_collections = metadata.get("collections") or []
        if not isinstance(existing_collections, list) or not all(
            isinstance(value, str) and SAFE_ID_RE.fullmatch(value)
            for value in existing_collections
        ):
            raise PublicationError(f"invalid collections metadata for {digest}")
        collections = sorted(
            {
                *existing_collections,
                context.collection_id,
            }
        )
        canonical_path = path.relative_to(context.repository).as_posix()
        if "canonical_path" in metadata and metadata["canonical_path"] != canonical_path:
            raise PublicationError(f"metadata canonical_path mismatch for {digest}")
        metadata.update(
            {
                "schema_version": 1,
                "sha256": digest,
                "case_id": f"sha256:{digest}",
                "case_kind": "malware",
                "family": context.family,
                "canonical_path": canonical_path,
                "collections": collections,
                "malware_version": version,
            }
        )
        documents[metadata_path] = (metadata_before, _json_bytes(metadata))
        entry = (catalog["cases"] or {}).get(digest)
        new_entry = {
            **(entry if isinstance(entry, dict) else {}),
            "case_id": f"sha256:{digest}",
            "family": context.family,
            "case_kind": "malware",
            "version_key": version_key,
            "canonical_path": canonical_path,
        }
        if isinstance(entry, dict):
            if entry.get("family") != context.family:
                raise PublicationError(f"catalog family mismatch for {digest}")
            if entry.get("canonical_path") != canonical_path:
                raise PublicationError(f"catalog path mismatch for {digest}")
        catalog["cases"][digest] = new_entry

    case_ids: set[str] = set()
    for item in collection["cases"]:
        case_id = item.get("case_id") if isinstance(item, dict) else None
        if not isinstance(case_id, str) or not case_id.startswith("sha256:"):
            raise PublicationError("invalid collection case identity")
        digest = case_id.removeprefix("sha256:")
        if not SHA256_RE.fullmatch(digest):
            raise PublicationError("invalid collection case hash")
        case_ids.add(case_id)
    case_ids.update(f"sha256:{digest}" for digest in normalized)
    collection["cases"] = [{"case_id": value} for value in sorted(case_ids)]
    source_map: dict[str, str] = {}
    for item in collection["family_sources"]:
        family = item.get("family") if isinstance(item, dict) else None
        source = item.get("path") if isinstance(item, dict) else None
        if (
            not isinstance(family, str)
            or not FAMILY_RE.fullmatch(family)
            or source != f"sources/{family}"
        ):
            raise PublicationError("invalid collection family source")
        source_map[family] = source
    source_map[context.family] = context.aggregate_root.relative_to(
        collection_path.parent
    ).as_posix()
    collection["family_sources"] = [
        {"family": family, "path": source_map[family]}
        for family in sorted(source_map)
    ]
    documents[catalog_path] = (catalog_before, _json_bytes(catalog))
    documents[collection_path] = (collection_before, _json_bytes(collection))
    _replace_documents(documents)
    return {
        "cases": len(normalized),
        "collection_id": context.collection_id,
        "collection_memberships": len(collection["cases"]),
    }
