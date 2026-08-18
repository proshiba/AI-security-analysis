#!/usr/bin/env python3
"""明示SHA-256だけのcatalog再分類を検証し、catalog単体へatomic適用する。"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Iterable

import analysis_contract

from result_layout import (
    FAMILY_RE,
    SHA256_RE,
    VERSION_KEY_RE,
    LayoutPlanError,
    build_layout_plan,
)


SCHEMA_VERSION = 1
MODE = "targeted_catalog_reclassification_plan"
CATALOG_RELATIVE = "analysis-results/catalog/cases.json"
CATALOG_ENTRY_KEYS = {
    "canonical_path",
    "case_id",
    "case_kind",
    "family",
    "version_key",
}
OLD_ENTRY_KEYS = CATALOG_ENTRY_KEYS | {"attribution_status"}


class TargetedCatalogError(ValueError):
    """targeted catalog更新の安全条件を満たさない場合に送出する。"""


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise TargetedCatalogError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return path.is_symlink() or bool(attributes & 0x400)


def _load_json_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_file() or _is_reparse_point(path):
        raise TargetedCatalogError(f"{label} must be a regular file: {path}")
    raw = path.read_bytes()
    try:
        value = json.loads(
            raw.decode("utf-8-sig"), object_pairs_hook=_reject_duplicate_keys
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TargetedCatalogError(f"invalid {label}: {path}") from error
    if not isinstance(value, dict):
        raise TargetedCatalogError(f"{label} must be an object: {path}")
    return value, raw


def _render_json(value: dict[str, Any], newline: str = "\n") -> bytes:
    text = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if newline == "\r\n":
        text = text.replace("\n", "\r\n")
    elif newline != "\n":
        raise TargetedCatalogError(f"unsupported catalog newline: {newline!r}")
    return text.encode("utf-8")


def _catalog_newline(raw: bytes) -> str:
    if b"\r\n" in raw:
        without_crlf = raw.replace(b"\r\n", b"")
        if b"\r" in without_crlf or b"\n" in without_crlf:
            raise TargetedCatalogError("catalog uses mixed or unsupported newlines")
        return "\r\n"
    if b"\r" in raw:
        raise TargetedCatalogError("catalog uses unsupported CR newlines")
    return "\n"


def _contained_path(repository: Path, relative: str, label: str) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise TargetedCatalogError(f"invalid {label}: {relative!r}")
    candidate = repository / relative
    try:
        candidate.resolve(strict=False).relative_to(repository)
        lexical = candidate.relative_to(repository).as_posix()
    except (OSError, ValueError) as error:
        raise TargetedCatalogError(f"{label} escapes repository: {relative}") from error
    if lexical != relative:
        raise TargetedCatalogError(f"non-canonical {label}: {relative}")
    return candidate


def _validate_allowlist(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, str) or not SHA256_RE.fullmatch(value):
            raise TargetedCatalogError(f"invalid SHA-256 allowlist entry: {value!r}")
        if value in seen:
            raise TargetedCatalogError(f"duplicate SHA-256 allowlist entry: {value}")
        seen.add(value)
        result.append(value)
    if not result:
        raise TargetedCatalogError("at least one --sha256 is required")
    return tuple(result)


def _case_tree_fingerprint(case_root: Path) -> str:
    if not case_root.is_dir() or _is_reparse_point(case_root):
        raise TargetedCatalogError(f"new case directory is unavailable: {case_root}")
    digest = hashlib.sha256()
    paths = [case_root, *case_root.rglob("*")]
    for path in sorted(
        paths, key=lambda item: item.relative_to(case_root).as_posix().casefold()
    ):
        if _is_reparse_point(path):
            raise TargetedCatalogError(f"case tree contains a reparse point: {path}")
        relative = path.relative_to(case_root).as_posix()
        if path.is_dir():
            digest.update(b"D\0" + relative.encode("utf-8") + b"\0")
            continue
        if not path.is_file():
            raise TargetedCatalogError(f"case tree contains a non-regular entry: {path}")
        content = path.read_bytes()
        digest.update(b"F\0" + relative.encode("utf-8") + b"\0")
        digest.update(str(len(content)).encode("ascii") + b"\0")
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def _walk_strings(value: Any):
    if isinstance(value, dict):
        for child in value.values():
            yield from _walk_strings(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_strings(child)
    elif isinstance(value, str):
        yield value


def _validate_collections(
    repository: Path,
    digest: str,
    old_path: str,
    new_path: str,
    metadata: dict[str, Any],
    layout_case: dict[str, Any] | None,
    layout_collections: list[dict[str, Any]] | None,
) -> tuple[list[str], dict[str, str]]:
    expected_ids = metadata.get("collections")
    if (
        not isinstance(expected_ids, list)
        or any(not isinstance(item, str) or not item for item in expected_ids)
        or len(expected_ids) != len(set(expected_ids))
    ):
        raise TargetedCatalogError(f"invalid metadata collection IDs for {digest}")
    expected = set(expected_ids)
    if layout_case is not None and set(layout_case.get("collections") or []) != expected:
        raise TargetedCatalogError(f"layout case collection mismatch for {digest}")

    case_id = f"sha256:{digest}"
    if layout_collections is not None:
        planned = {
            str(collection.get("collection_id"))
            for collection in layout_collections
            if any(
                isinstance(member, dict) and member.get("case_id") == case_id
                for member in (collection.get("cases") or [])
            )
        }
        if planned != expected:
            raise TargetedCatalogError(
                f"layout collection membership mismatch for {digest}"
            )

    actual: set[str] = set()
    bindings: dict[str, str] = {}
    collections_root = repository / "analysis-results" / "collections"
    for manifest_path in sorted(collections_root.glob("*/manifest.json")):
        manifest, raw = _load_json_object(manifest_path, "collection manifest")
        relative = manifest_path.relative_to(repository).as_posix()
        bindings[relative] = hashlib.sha256(raw).hexdigest()
        collection_id = manifest.get("collection_id")
        if not isinstance(collection_id, str) or collection_id != manifest_path.parent.name:
            raise TargetedCatalogError(f"invalid collection identity: {relative}")
        members = manifest.get("cases") or []
        if not isinstance(members, list):
            raise TargetedCatalogError(f"invalid collection cases: {relative}")
        occurrences = sum(
            isinstance(member, dict) and member.get("case_id") == case_id
            for member in members
        )
        if occurrences > 1:
            raise TargetedCatalogError(
                f"duplicate collection membership for {digest}: {relative}"
            )
        if occurrences == 1:
            actual.add(collection_id)
        for value in _walk_strings(manifest):
            normalized = value.replace("\\", "/")
            if normalized == old_path:
                raise TargetedCatalogError(
                    f"collection retains old path for {digest}: {relative}"
                )
            if f"/cases/{digest}" in normalized and normalized != new_path:
                raise TargetedCatalogError(
                    f"collection has a non-canonical case path for {digest}: {relative}"
                )
    if actual != expected:
        raise TargetedCatalogError(f"collection membership mismatch for {digest}")
    return sorted(actual), bindings


def _normalise_family_label(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    return "".join(character for character in value.casefold() if character.isalnum())


def _validate_classified_family_correction(
    case_root: Path,
    digest: str,
    old_family: str,
    new_family: str,
    metadata: dict[str, Any],
    report: dict[str, Any],
) -> dict[str, Any]:
    """内部静的証拠で裏付けた既知family間の訂正だけを許可する。"""

    attribution = metadata.get("attribution")
    basis = attribution.get("basis") if isinstance(attribution, dict) else None
    reported_signature = (
        attribution.get("reported_signature") if isinstance(attribution, dict) else None
    )
    if (
        not isinstance(basis, str)
        or not basis.startswith("internal_")
        or _normalise_family_label(reported_signature)
        != _normalise_family_label(old_family)
    ):
        raise TargetedCatalogError(
            f"classified family correction lacks internal attribution proof for {digest}"
        )

    report_classification = report.get("classification")
    if (
        not isinstance(report_classification, dict)
        or report_classification.get("family") != new_family
        or report_classification.get("selected_family") != new_family
        or report_classification.get("selected_families") != [new_family]
        or report_classification.get("selection_basis") != "type_detector_structure"
        or report_classification.get("classification_conflicts") != []
    ):
        raise TargetedCatalogError(
            f"classified family correction report proof is incomplete for {digest}"
        )

    classification, classification_raw = _load_json_object(
        case_root / "classification.json", "classification artifact"
    )
    detections = classification.get("all_type_detections")
    reviewed_detections = [
        item
        for item in detections or []
        if isinstance(item, dict)
        and item.get("malware_type") == new_family
        and item.get("attribution_basis") == "type_detector_structure"
        and item.get("malware_type_confidence") in {"medium", "high"}
        and isinstance(item.get("detection"), dict)
        and item["detection"].get("matched") is True
    ]
    if (
        classification.get("selected_families") != [new_family]
        or classification.get("attribution_basis") != "type_detector_structure"
        or classification.get("classification_conflicts") != []
        or len(reviewed_detections) != 1
    ):
        raise TargetedCatalogError(
            f"classified family correction detector proof is incomplete for {digest}"
        )

    handlers = report.get("handler_executions")
    reviewed_handlers = [
        item
        for item in handlers or []
        if isinstance(item, dict)
        and item.get("status") == "succeeded"
        and isinstance(item.get("handler_id"), str)
        and item["handler_id"].startswith(f"{new_family}:")
        and item.get("selected_layer_sha256") == digest
        and isinstance(item.get("selected_evidence"), dict)
        and item["selected_evidence"].get("sufficient") is True
        and isinstance(item["selected_evidence"].get("tier"), int)
        and not isinstance(item["selected_evidence"].get("tier"), bool)
        and item["selected_evidence"]["tier"] >= 3
    ]
    if len(reviewed_handlers) != 1:
        raise TargetedCatalogError(
            f"classified family correction handler proof is incomplete for {digest}"
        )
    handler = reviewed_handlers[0]
    return {
        "attribution_basis": basis,
        "classification_sha256": hashlib.sha256(classification_raw).hexdigest(),
        "handler_id": handler["handler_id"],
        "handler_tier": handler["selected_evidence"]["tier"],
        "reported_signature": reported_signature,
    }


def _validate_target_state(
    repository: Path,
    digest: str,
    old: Any,
    new: Any,
    *,
    layout_case: dict[str, Any] | None = None,
    layout_collections: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    def catalog_identity(record: Any, label: str) -> tuple[str, str, str, str]:
        if not isinstance(record, dict):
            raise TargetedCatalogError(f"unexpected {label} catalog identity for {digest}")
        family = record.get("family")
        version = record.get("version_key")
        case_kind = record.get("case_kind")
        if family == "unclassified":
            path = (
                "analysis-results/malware/unclassified/versions/unknown/cases/"
                f"{digest}"
            )
            expected = {
                "attribution_status": record.get("attribution_status"),
                "canonical_path": path,
                "case_id": f"sha256:{digest}",
                "case_kind": "unclassified",
                "family": "unclassified",
                "version_key": "unknown",
            }
            if (
                set(record) != OLD_ENTRY_KEYS
                or record.get("attribution_status") not in {"unresolved", "provisional"}
                or record != expected
            ):
                raise TargetedCatalogError(
                    f"unexpected {label} catalog identity for {digest}"
                )
            return family, "unknown", case_kind, path
        if (
            set(record) != CATALOG_ENTRY_KEYS
            or not isinstance(family, str)
            or not FAMILY_RE.fullmatch(family)
            or not isinstance(version, str)
            or not VERSION_KEY_RE.fullmatch(version)
            or case_kind != "malware"
        ):
            raise TargetedCatalogError(f"unexpected {label} catalog identity for {digest}")
        path = f"analysis-results/malware/{family}/versions/{version}/cases/{digest}"
        expected = {
            "canonical_path": path,
            "case_id": f"sha256:{digest}",
            "case_kind": "malware",
            "family": family,
            "version_key": version,
        }
        if record != expected:
            raise TargetedCatalogError(f"unexpected {label} catalog identity for {digest}")
        return family, version, case_kind, path

    old_family, _old_version, _old_kind, old_path = catalog_identity(old, "old")
    family, version, case_kind, new_path = catalog_identity(new, "desired")
    classified_family_correction = (
        old_family != "unclassified"
        and family != "unclassified"
        and old_family != family
    )
    if (
        (old_family == "unclassified") == (family == "unclassified")
        and not classified_family_correction
    ):
        raise TargetedCatalogError(
            f"unsupported reclassification direction for {digest}"
        )
    if os.path.lexists(_contained_path(repository, old_path, "old case path")):
        raise TargetedCatalogError(f"old case path still exists for {digest}: {old_path}")
    if layout_case is not None and (
        layout_case.get("sha256") != digest
        or layout_case.get("source") != new_path
        or layout_case.get("target") != new_path
        or layout_case.get("family") != family
        or (layout_case.get("malware_version") or {}).get("normalized_key") != version
    ):
        raise TargetedCatalogError(f"layout case identity mismatch for {digest}")

    case_root = _contained_path(repository, new_path, "new case path")
    report, report_raw = _load_json_object(case_root / "report.json", "case report")
    integrity_errors = analysis_contract.case_integrity_errors(
        case_root,
        report,
        expected_digest=digest,
        require_resumable=False,
    )
    if integrity_errors:
        raise TargetedCatalogError(
            f"case integrity failed for {digest}: {integrity_errors[0]}"
        )
    metadata, metadata_raw = _load_json_object(case_root / "metadata.json", "case metadata")
    metadata_version = metadata.get("malware_version")
    if (
        metadata.get("schema_version") != 1
        or metadata.get("sha256") != digest
        or metadata.get("case_id") != f"sha256:{digest}"
        or metadata.get("case_kind") != case_kind
        or metadata.get("family") != family
        or metadata.get("canonical_path") != new_path
        or not isinstance(metadata_version, dict)
        or metadata_version.get("normalized_key") != version
        or (
            family == "unclassified"
            and metadata.get("attribution_status") != new.get("attribution_status")
        )
    ):
        raise TargetedCatalogError(f"new case metadata identity mismatch for {digest}")
    correction_evidence = None
    if classified_family_correction:
        try:
            correction_evidence = _validate_classified_family_correction(
                case_root,
                digest,
                old_family,
                family,
                metadata,
                report,
            )
        except TargetedCatalogError as error:
            raise TargetedCatalogError(
                f"unsupported reclassification direction for {digest}: {error}"
            ) from error
    memberships, manifest_bindings = _validate_collections(
        repository,
        digest,
        old_path,
        new_path,
        metadata,
        layout_case,
        layout_collections,
    )
    return {
        "sha256": digest,
        "old": copy.deepcopy(old),
        "new": copy.deepcopy(new),
        "old_path": old_path,
        "new_path": new_path,
        "metadata_sha256": hashlib.sha256(metadata_raw).hexdigest(),
        "report_sha256": hashlib.sha256(report_raw).hexdigest(),
        "case_tree_fingerprint": _case_tree_fingerprint(case_root),
        "collections": memberships,
        "collection_manifest_sha256s": manifest_bindings,
        "reclassification_kind": (
            "classified_family_correction"
            if classified_family_correction
            else "attribution_boundary_change"
        ),
        "correction_evidence": correction_evidence,
    }


def build_targeted_reclassification_plan(
    repository: Path,
    sha256_allowlist: Iterable[str],
    *,
    layout_plan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """layout planとの差分を明示allowlistへ限定したread-only計画を返す。"""

    root = repository.resolve()
    allowed = _validate_allowlist(sha256_allowlist)
    layout = build_layout_plan(root) if layout_plan is None else layout_plan
    if layout.get("errors"):
        raise LayoutPlanError(f"layout preflight failed: {layout['errors'][0]}")
    if layout.get("move_map"):
        raise TargetedCatalogError("pending layout moves are not allowed")
    catalog_plan = layout.get("catalog") or {}
    if catalog_plan.get("path") != CATALOG_RELATIVE:
        raise TargetedCatalogError("unexpected layout catalog path")
    desired = catalog_plan.get("document")
    if not isinstance(desired, dict) or not isinstance(desired.get("cases"), dict):
        raise TargetedCatalogError("invalid desired catalog")

    catalog_path = _contained_path(root, CATALOG_RELATIVE, "catalog path")
    current, current_raw = _load_json_object(catalog_path, "catalog")
    catalog_newline = _catalog_newline(current_raw)
    if current_raw != _render_json(current, catalog_newline):
        raise TargetedCatalogError("catalog bytes are not canonical")
    if (
        current.get("schema_version") != SCHEMA_VERSION
        or desired.get("schema_version") != SCHEMA_VERSION
        or not isinstance(current.get("cases"), dict)
    ):
        raise TargetedCatalogError("unsupported catalog schema")
    current_cases = current["cases"]
    desired_cases = desired["cases"]
    for digest in allowed:
        if digest not in current_cases or digest not in desired_cases:
            raise TargetedCatalogError(f"target is missing from catalog plan: {digest}")

    all_digests = set(current_cases) | set(desired_cases)
    differences = sorted(
        digest
        for digest in all_digests
        if current_cases.get(digest) != desired_cases.get(digest)
    )
    if differences != sorted(allowed):
        unexpected = sorted(set(differences) - set(allowed))
        missing = sorted(set(allowed) - set(differences))
        raise TargetedCatalogError(
            f"catalog diff is not exactly allowlisted (unexpected={unexpected}, missing={missing})"
        )

    layout_cases: dict[str, dict[str, Any]] = {}
    for case in layout.get("cases") or []:
        digest = case.get("sha256")
        if digest in layout_cases:
            raise TargetedCatalogError(f"duplicate layout case: {digest}")
        layout_cases[digest] = case
    updates = []
    for digest in allowed:
        if digest not in layout_cases:
            raise TargetedCatalogError(f"target is missing from layout cases: {digest}")
        updates.append(
            _validate_target_state(
                root,
                digest,
                current_cases[digest],
                desired_cases[digest],
                layout_case=layout_cases[digest],
                layout_collections=layout.get("collections") or [],
            )
        )

    output = copy.deepcopy(current)
    for update in updates:
        output["cases"][update["sha256"]] = copy.deepcopy(update["new"])
    if output != desired:
        raise TargetedCatalogError("non-target catalog content differs from layout plan")
    output_raw = _render_json(output, catalog_newline)
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": MODE,
        "write_performed": False,
        "catalog": CATALOG_RELATIVE,
        "catalog_input_sha256": hashlib.sha256(current_raw).hexdigest(),
        "catalog_output_sha256": hashlib.sha256(output_raw).hexdigest(),
        "catalog_newline": "crlf" if catalog_newline == "\r\n" else "lf",
        "target_sha256s": list(allowed),
        "unchanged_catalog_cases": len(current_cases) - len(allowed),
        "updates": updates,
        "invariants": {
            "catalog_only": True,
            "layout_moves": 0,
            "non_target_catalog_differences": 0,
            "non_target_catalog_bytes_preserved": True,
            "old_case_paths_absent": True,
            "new_case_metadata_verified": True,
            "case_semantic_artifact_integrity_verified": True,
            "collection_references_verified": True,
        },
    }


def _revalidate_update(repository: Path, update: dict[str, Any]) -> None:
    digest = update.get("sha256")
    if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
        raise TargetedCatalogError("invalid update SHA-256")
    current = _validate_target_state(
        repository, digest, update.get("old"), update.get("new")
    )
    immutable = {
        "old_path",
        "new_path",
        "metadata_sha256",
        "report_sha256",
        "case_tree_fingerprint",
        "collections",
        "collection_manifest_sha256s",
        "reclassification_kind",
        "correction_evidence",
    }
    if any(current[key] != update.get(key) for key in immutable):
        raise TargetedCatalogError(f"target inputs changed after planning: {digest}")


def _atomic_replace(path: Path, content: bytes, expected_sha256: str) -> None:
    if hashlib.sha256(path.read_bytes()).hexdigest() != expected_sha256:
        raise TargetedCatalogError("catalog changed immediately before atomic replace")
    handle = tempfile.NamedTemporaryFile(
        prefix=".targeted-catalog-", suffix=".tmp", dir=path.parent, delete=False
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


def apply_targeted_reclassification_plan(
    repository: Path, plan: dict[str, Any]
) -> dict[str, Any]:
    """計画時入力を再検証し、catalog一つだけをatomic replaceする。"""

    root = repository.resolve()
    if plan.get("schema_version") != SCHEMA_VERSION or plan.get("mode") != MODE:
        raise TargetedCatalogError("unsupported targeted catalog plan")
    if plan.get("write_performed"):
        raise TargetedCatalogError("targeted catalog plan was already applied")
    allowed = _validate_allowlist(plan.get("target_sha256s") or [])
    if plan.get("catalog") != CATALOG_RELATIVE:
        raise TargetedCatalogError("unexpected catalog path in plan")
    updates = plan.get("updates")
    if not isinstance(updates, list) or [item.get("sha256") for item in updates] != list(allowed):
        raise TargetedCatalogError("plan updates do not match the allowlist")

    catalog_path = _contained_path(root, CATALOG_RELATIVE, "catalog path")
    current, current_raw = _load_json_object(catalog_path, "catalog")
    input_sha256 = hashlib.sha256(current_raw).hexdigest()
    if input_sha256 != plan.get("catalog_input_sha256"):
        raise TargetedCatalogError("catalog changed after planning")
    newline_name = plan.get("catalog_newline")
    if newline_name not in {"lf", "crlf"}:
        raise TargetedCatalogError("invalid catalog newline in plan")
    catalog_newline = "\r\n" if newline_name == "crlf" else "\n"
    if _catalog_newline(current_raw) != catalog_newline:
        raise TargetedCatalogError("catalog newline changed after planning")
    if current_raw != _render_json(current, catalog_newline):
        raise TargetedCatalogError("catalog bytes are not canonical")
    for update in updates:
        digest = update["sha256"]
        if (current.get("cases") or {}).get(digest) != update.get("old"):
            raise TargetedCatalogError(f"old catalog record changed after planning: {digest}")
        _revalidate_update(root, update)

    output = copy.deepcopy(current)
    for update in updates:
        output["cases"][update["sha256"]] = copy.deepcopy(update["new"])
    output_raw = _render_json(output, catalog_newline)
    if hashlib.sha256(output_raw).hexdigest() != plan.get("catalog_output_sha256"):
        raise TargetedCatalogError("planned catalog output changed")
    _atomic_replace(catalog_path, output_raw, input_sha256)
    result = copy.deepcopy(plan)
    result["write_performed"] = True
    return result


def build_parser() -> argparse.ArgumentParser:
    """targeted catalog CLIの引数parserを返す。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path.cwd())
    parser.add_argument(
        "--sha256",
        action="append",
        required=True,
        help="再分類を許可するSHA-256。targetごとに明示的に繰り返す",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="計画時入力の再検証後、catalog一つだけをatomic replaceする",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """既定dry-runを表示し、--write指定時だけcatalogへ適用する。"""

    args = build_parser().parse_args(argv)
    plan = build_targeted_reclassification_plan(args.repository, args.sha256)
    result = (
        apply_targeted_reclassification_plan(args.repository, plan)
        if args.write
        else plan
    )
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
