#!/usr/bin/env python3
"""解析成果物の固定レイアウトを、検体に触れず計画・検証する。

このモジュールは公開済み成果物のファイル名と JSON だけを読み取る。
検体の実行、CPU/CIL エミュレーション、外部通信は一切行わない。
"""

from __future__ import annotations

from collections import defaultdict
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Iterable


SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
FAMILY_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
VERSION_KEY_RE = re.compile(r"^(?:unknown|v[a-z0-9][a-z0-9.-]{0,47})$")
SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
COLLECTION_RE = re.compile(
    r"^(?:refresh|vx-underground|malwarebazaar|malwarebazaar-unknown)-\d{8}$"
)
MARKDOWN_LINK_RE = re.compile(r"(!?\[[^\]]*\]\()([^)]+)(\))")
HISTORY_PATH_RE = re.compile(
    r"^(?P<prefix>\s*result_path:\s*[\"']?)(?P<path>[^\"'\r\n]+?)(?P<suffix>[\"']?\s*)$",
    re.MULTILINE,
)

_EXCLUDED_TREES = {".git", ".work", ".cache", ".venv", "node_modules", "__pycache__"}
_RESULT_ROOT_DIRECTORY_ALLOWLIST = {"_shared", "catalog", "collections", "malware", "research"}
_RESULT_ROOT_FILE_ALLOWLIST = {"AGENTS.md", "IOC-INDEX.md", "README.md"}
_FINGERPRINT_METHOD = "sha256_relative_path_nul_size_u64_content_v1"
_VERSION_SOURCES: dict[
    str,
    tuple[tuple[str, tuple[str | int, ...], str, str, str, str], ...],
] = {
    "amadey": (
        ("analysis.json", ("config", "config", "version"), "$.config.config.version", "confirmed", "sample_specific_static_family_config", "high"),
        (
            "analysis.json",
            ("config", "config", "selected_layer_config", "config", "version"),
            "$.config.config.selected_layer_config.config.version",
            "confirmed",
            "sample_specific_static_family_config",
            "high",
        ),
    ),
    "latrodectus": (
        ("analysis.json", ("config", "config", "version"), "$.config.config.version", "confirmed", "sample_specific_static_family_config", "high"),
        (
            "analysis.json",
            ("config", "config", "selected_layer_config", "config", "version"),
            "$.config.config.selected_layer_config.config.version",
            "confirmed",
            "sample_specific_static_family_config",
            "high",
        ),
    ),
    "purehvnc": (("config.json", ("config", "version_candidates", 0), "$.config.version_candidates[0]", "confirmed", "terminal_managed_static_config", "high"),),
    "remcosrat": (("indicators.json", ("version",), "$.version", "confirmed", "family_config_or_process_attributed_evidence", "high"),),
    "spyglace": (("config.json", ("config", "version"), "$.config.version", "confirmed", "sample_specific_static_family_config", "high"),),
    "venomrat": (("indicators.json", ("version",), "$.version", "reported", "external_sandbox_process_attributed_report", "medium"),),
    "xmrig": (("config.json", ("version",), "$.version", "confirmed", "sample_embedded_version_and_official_release_match", "high"),),
}
_VERSION_VALUE_RE = {
    "amadey": re.compile(r"^\d+\.\d+$"),
    "latrodectus": re.compile(r"^\d+\.\d+\.\d+$"),
    "purehvnc": re.compile(r"^\d+\.\d+\.\d+$"),
    "remcosrat": re.compile(r"^\d+\.\d+\.\d+ Pro$"),
    "spyglace": re.compile(r"^\d+\.\d+\.\d+$"),
    "venomrat": re.compile(r"^\d+\.\d+\.\d+$"),
    "xmrig": re.compile(r"^\d+\.\d+\.\d+$"),
}


class LayoutPlanError(ValueError):
    """レイアウト計画が fail-closed 条件を満たさない場合の例外。"""


def _relative(path: Path, repository: Path) -> str:
    return path.resolve().relative_to(repository.resolve()).as_posix()


def _require_contained(path: Path, root: Path, label: str) -> Path:
    resolved = path.resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError as exc:
        raise LayoutPlanError(f"{label} must stay within {root}") from exc
    return resolved


def canonical_malware_case_path(
    results_root: Path,
    family: str,
    sha256: str,
    version_key: str = "unknown",
) -> Path:
    """malware case の固定深さ path を検証して返す。"""

    root = results_root.resolve()
    if not FAMILY_RE.fullmatch(family):
        raise LayoutPlanError(f"unsafe family identifier: {family!r}")
    if not VERSION_KEY_RE.fullmatch(version_key):
        raise LayoutPlanError(f"unsafe malware version key: {version_key!r}")
    if not SHA256_RE.fullmatch(sha256):
        raise LayoutPlanError(f"unsafe SHA-256: {sha256!r}")
    return _require_contained(
        root / "malware" / family / "versions" / version_key / "cases" / sha256,
        root,
        "canonical malware case",
    )


def canonical_collection_root(results_root: Path, collection_id: str) -> Path:
    """collection ID を検証し、collection root を返す。"""

    root = results_root.resolve()
    if not SAFE_ID_RE.fullmatch(collection_id):
        raise LayoutPlanError(f"unsafe collection identifier: {collection_id!r}")
    return _require_contained(
        root / "collections" / collection_id,
        root,
        "canonical collection",
    )


def canonical_collection_source_path(
    results_root: Path, collection_id: str, family: str
) -> Path:
    """collection 内の family 別集約 path を返す。"""

    if not FAMILY_RE.fullmatch(family):
        raise LayoutPlanError(f"unsafe family identifier: {family!r}")
    return canonical_collection_root(results_root, collection_id) / "sources" / family


def canonical_collection_manifest_path(
    results_root: Path, collection_id: str
) -> Path:
    """collection manifest の固定 path を返す。"""

    return canonical_collection_root(results_root, collection_id) / "manifest.json"


def canonical_static_hard_case_report_path(results_root: Path) -> Path:
    """静的解析 hard-case report の research path を返す。"""

    root = results_root.resolve()
    return _require_contained(
        root / "research" / "audits" / "static-hard-cases" / "deep-static-triage.json",
        root,
        "static hard-case report",
    )


def resolve_catalog_case_path(
    results_root: Path,
    sha256: str,
    *,
    family: str | None = None,
    fallback_version_key: str = "unknown",
) -> Path:
    """catalog に登録済みの case path を返し、未作成時だけ固定 path に戻す。"""

    root = results_root.resolve()
    if not SHA256_RE.fullmatch(sha256):
        raise LayoutPlanError(f"unsafe SHA-256: {sha256!r}")
    catalog_path = root / "catalog" / "cases.json"
    if catalog_path.is_file():
        catalog = _safe_json(catalog_path)
        entry = (catalog.get("cases") or {}).get(sha256) if isinstance(catalog, dict) else None
        if not isinstance(entry, dict):
            if family is not None:
                return canonical_malware_case_path(
                    root, family, sha256, fallback_version_key
                )
            raise LayoutPlanError(f"case is missing from catalog: {sha256}")
        if family is not None and entry.get("family") != family:
            raise LayoutPlanError(f"catalog family mismatch for {sha256}")
        raw_path = entry.get("canonical_path")
        if not isinstance(raw_path, str):
            raise LayoutPlanError(f"catalog path is missing for {sha256}")
        repository = root.parent
        candidate = _require_contained(
            repository / raw_path,
            root,
            "catalog case path",
        )
        if candidate.name.lower() != sha256:
            raise LayoutPlanError(f"catalog path hash mismatch for {sha256}")
        return candidate
    if family is None:
        raise LayoutPlanError(f"catalog is unavailable and family was not supplied: {sha256}")
    return canonical_malware_case_path(root, family, sha256, fallback_version_key)


def _safe_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None


def _nested(value: Any, keys: tuple[str | int, ...]) -> Any:
    current = value
    for key in keys:
        if isinstance(key, int):
            if not isinstance(current, list) or key >= len(current):
                return None
            current = current[key]
        else:
            if not isinstance(current, dict) or key not in current:
                return None
            current = current[key]
    return current


def _version_key(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9.-]+", "-", value.strip().lower()).strip(".-")
    key = f"v{normalized}"
    if not VERSION_KEY_RE.fullmatch(key):
        raise LayoutPlanError(f"unsafe malware version key: {value!r}")
    return key


def resolve_malware_version(
    case_directory: Path, family: str, repository: Path
) -> dict[str, Any]:
    """許可した family 固有 JSON pointer だけから版を保守的に返す。

    schema、runtime、依存 package、packer、PE/.NET file version は探索対象に
    しない。値が衝突する場合も `unknown` とする。
    """

    case_directory = _require_contained(case_directory, repository, "case directory")
    family = family.lower()
    evidence: list[dict[str, Any]] = []
    candidates: set[str] = set()
    matcher = _VERSION_VALUE_RE.get(family)
    for filename, keys, pointer, status, basis, confidence in _VERSION_SOURCES.get(family, ()):
        path = case_directory / filename
        document = _safe_json(path)
        if family == "purehvnc" and pointer == "$.config.version_candidates[0]":
            version_candidates = _nested(document, ("config", "version_candidates"))
            if not isinstance(version_candidates, list) or len(version_candidates) != 1:
                continue
        value = _nested(document, keys)
        if not isinstance(value, str) or matcher is None or not matcher.fullmatch(value):
            continue
        candidates.add(value)
        evidence.append(
            {
                # metadata.json は case と一緒に移動するため、根拠 artifact は
                # 移行前の repository path ではなく case-relative path に固定する。
                "artifact": path.relative_to(case_directory).as_posix(),
                "json_pointer": pointer,
                "status": status,
                "basis": basis,
                "confidence": confidence,
                "value": value,
                "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    evidence.sort(key=lambda item: (item["artifact"], item["json_pointer"]))
    if len(candidates) != 1:
        return {
            "status": "unknown",
            "reported": None,
            "normalized_key": "unknown",
            "confidence": "none",
            "reason": (
                "conflicting_approved_version_evidence"
                if len(candidates) > 1
                else "no_approved_sample_specific_version_evidence"
            ),
            "evidence": evidence,
        }
    value = next(iter(candidates))
    statuses = {item["status"] for item in evidence}
    status = "confirmed" if statuses == {"confirmed"} else "reported"
    confidence = "high" if status == "confirmed" else "medium"
    return {
        "status": status,
        "reported": value,
        "normalized_key": _version_key(value),
        "confidence": confidence,
        "reason": evidence[0]["basis"],
        "evidence": evidence,
    }


def _case_context(case_directory: Path, results_root: Path) -> tuple[str, list[str], str | None]:
    relative = case_directory.relative_to(results_root)
    parts = list(relative.parts)
    try:
        cases_index = parts.index("cases")
    except ValueError as exc:
        raise LayoutPlanError(f"SHA directory is not below cases/: {relative}") from exc
    if cases_index + 1 != len(parts) - 1:
        raise LayoutPlanError(f"SHA directory has an unsupported case shape: {relative}")
    if parts[0] == "malware":
        if cases_index != 4 or len(parts) != 6 or parts[2] != "versions":
            raise LayoutPlanError(f"canonical case has an invalid depth: {relative}")
        family = parts[1]
        legacy = []
    elif (
        len(parts) == 6
        and tuple(parts[:5])
        == (
            "research",
            "supply-chain",
            "npm",
            "axios-plain-crypto-js-2026",
            "cases",
        )
    ):
        family = "npm-supply-chain"
        legacy = []
    else:
        family = parts[0].lower().replace("_", "-")
        legacy = parts[1:cases_index]
    if not FAMILY_RE.fullmatch(family):
        raise LayoutPlanError(f"unsafe family identifier: {family!r}")
    collection = next((item for item in legacy if COLLECTION_RE.fullmatch(item)), None)
    return family, legacy, collection


def _metadata_collection_ids(case_directory: Path) -> list[str]:
    """既存case metadataのcollection IDを検証して決定順で返す。"""

    path = case_directory / "metadata.json"
    if not path.exists():
        return []
    document = _safe_json(path)
    if not isinstance(document, dict):
        raise LayoutPlanError(f"invalid case metadata: {path}")
    values = document.get("collections", [])
    if not isinstance(values, list) or not all(
        isinstance(value, str) and SAFE_ID_RE.fullmatch(value)
        for value in values
    ):
        raise LayoutPlanError(f"invalid collection IDs in case metadata: {path}")
    return sorted(set(values))


def _existing_collection_documents(results_root: Path) -> dict[str, dict[str, Any]]:
    """既存collection manifestをfail-closedで読み、ID別に返す。"""

    documents: dict[str, dict[str, Any]] = {}
    collections_root = results_root / "collections"
    if not collections_root.exists():
        return documents
    for path in sorted(collections_root.glob("*/manifest.json")):
        collection_id = path.parent.name
        if not SAFE_ID_RE.fullmatch(collection_id):
            raise LayoutPlanError(f"unsafe existing collection ID: {collection_id!r}")
        document = _safe_json(path)
        if (
            not isinstance(document, dict)
            or document.get("schema_version") != SCHEMA_VERSION
            or document.get("collection_id") != collection_id
            or not isinstance(document.get("cases"), list)
            or not isinstance(document.get("family_sources"), list)
        ):
            raise LayoutPlanError(f"invalid collection manifest: {path}")
        case_ids: set[str] = set()
        for item in document["cases"]:
            case_id = item.get("case_id") if isinstance(item, dict) else None
            if not isinstance(case_id, str) or not case_id.startswith("sha256:"):
                raise LayoutPlanError(f"invalid collection case identity: {path}")
            digest = case_id.removeprefix("sha256:")
            if not SHA256_RE.fullmatch(digest):
                raise LayoutPlanError(f"invalid collection case hash: {path}")
            case_ids.add(digest)
        family_sources: set[tuple[str, str]] = set()
        for item in document["family_sources"]:
            if not isinstance(item, dict):
                raise LayoutPlanError(f"invalid collection family source: {path}")
            family, source = item.get("family"), item.get("path")
            if (
                not isinstance(family, str)
                or not FAMILY_RE.fullmatch(family)
                or source != f"sources/{family}"
            ):
                raise LayoutPlanError(f"invalid collection family source: {path}")
            family_sources.add((family, source))
        documents[collection_id] = {
            "cases": case_ids,
            "family_sources": family_sources,
        }
    return documents


def _tree_fingerprint(path: Path, excluded_cases: set[Path] | None = None) -> str:
    digest = hashlib.sha256()
    excluded_cases = {
        Path(os.path.abspath(item)) for item in (excluded_cases or set())
    }
    if path.is_file():
        content = path.read_bytes()
        digest.update(path.name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
        return digest.hexdigest()
    for item in sorted(path.rglob("*"), key=lambda value: value.as_posix().casefold()):
        if not item.is_file():
            continue
        absolute = Path(os.path.abspath(item))
        if absolute in excluded_cases or any(parent in excluded_cases for parent in absolute.parents):
            continue
        content = item.read_bytes()
        digest.update(item.relative_to(path).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(content)
    return digest.hexdigest()


def _path_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


class _PathMapper:
    def __init__(self, repository: Path, moves: Iterable[dict[str, Any]]) -> None:
        self.repository = repository.resolve()
        prefixes = []
        for item in moves:
            source = Path(os.path.abspath(self.repository / item["source"]))
            target = Path(os.path.abspath(self.repository / item["target"]))
            prefixes.append((str(source).casefold(), str(source), target))
        self.prefixes = sorted(prefixes, key=lambda item: len(item[1]), reverse=True)
        self.cache: dict[str, Path] = {}

    def map(self, path: Path) -> Path:
        absolute = Path(os.path.abspath(path))
        text = str(absolute)
        folded = text.casefold()
        cached = self.cache.get(folded)
        if cached is not None:
            return cached
        separators = (os.sep, os.altsep) if os.altsep else (os.sep,)
        for source_folded, source, target in self.prefixes:
            if folded == source_folded:
                result = target
            elif any(folded.startswith(source_folded + separator) for separator in separators):
                suffix = text[len(source) :].lstrip("\\/")
                result = target / Path(suffix)
            else:
                continue
            self.cache[folded] = result
            return result
        self.cache[folded] = absolute
        return absolute


def _move_record(
    repository: Path,
    source: Path,
    target: Path,
    kind: str,
    stage: int,
    excluded_cases: set[Path] | None = None,
) -> dict[str, Any]:
    source_absolute = Path(os.path.abspath(source))
    relevant_exclusions = sorted(
        (
            Path(os.path.abspath(case))
            for case in (excluded_cases or set())
            if source_absolute == Path(os.path.abspath(case))
            or source_absolute in Path(os.path.abspath(case)).parents
        ),
        key=lambda path: str(path).casefold(),
    )
    return {
        "stage": stage,
        "kind": kind,
        "source": _relative(source, repository),
        "target": target.resolve().relative_to(repository.resolve()).as_posix(),
        "source_fingerprint": _tree_fingerprint(source, set(relevant_exclusions)),
        "fingerprint_method": _FINGERPRINT_METHOD,
        "fingerprint_excluded_case_sources": [
            _relative(path, repository) for path in relevant_exclusions
        ],
    }


def _research_moves(repository: Path, results_root: Path) -> list[dict[str, Any]]:
    moves: list[dict[str, Any]] = []
    research = results_root / "research"
    for name in ("news", "supply-chain", "vulnerabilities"):
        source = results_root / name
        if source.is_dir():
            for child in sorted(source.iterdir(), key=lambda value: value.name.casefold()):
                moves.append(
                    _move_record(
                        repository,
                        child,
                        research / name / child.name,
                        "research",
                        2,
                    )
                )
    for source in sorted(results_root.glob("static-*-202*")):
        if source.is_dir():
            moves.append(
                _move_record(
                    repository,
                    source,
                    research / "audits" / source.name,
                    "research_audit",
                    2,
                )
            )
    static_hard = results_root / "static-hard-cases"
    if static_hard.is_dir():
        moves.append(
            _move_record(
                repository,
                static_hard,
                research / "audits" / static_hard.name,
                "research_audit",
                2,
            )
        )
    unpacking = results_root / "UNPACKING-REASSESSMENT-2026-07-15.md"
    if unpacking.is_file():
        moves.append(
            _move_record(
                repository,
                unpacking,
                research / "audits" / "unpacking-reassessment-20260715.md",
                "research_audit_document",
                2,
            )
        )
    refresh = results_root / "REFRESH-2026-07-15.md"
    if refresh.is_file():
        moves.append(
            _move_record(
                repository,
                refresh,
                results_root / "collections" / "refresh-20260715" / "REPORT.md",
                "collection_report",
                2,
            )
        )
    for campaigns in sorted(results_root.glob("*/campaigns")):
        # 正規化後の `research/campaigns/<family>/<campaign>` を
        # legacy の `<family>/campaigns/<campaign>` と再解釈しない。
        if campaigns.parent == research:
            continue
        family = campaigns.parent.name
        for campaign in sorted(path for path in campaigns.iterdir() if path.is_dir()):
            moves.append(
                _move_record(
                    repository,
                    campaign,
                    research / "campaigns" / family / campaign.name,
                    "research_campaign",
                    2,
                )
            )
    atlascross = results_root / "atlascross"
    if atlascross.is_dir():
        for child in sorted(atlascross.iterdir(), key=lambda value: value.name.casefold()):
            if child.name == "campaigns":
                continue
            moves.append(
                _move_record(
                    repository,
                    child,
                    results_root / "malware" / "atlascross" / child.name,
                    "family_artifact_without_case",
                    2,
                )
            )
    return moves


def _artifact_moves(
    repository: Path,
    results_root: Path,
    cases: list[dict[str, Any]],
    case_paths: dict[str, Path],
) -> list[dict[str, Any]]:
    moves: list[dict[str, Any]] = []
    families: dict[str, Path] = {}
    family_targets: dict[str, Path] = {}
    run_roots: dict[tuple[str, str], Path] = {}
    special_groups: dict[tuple[str, str], Path] = {}
    for case in cases:
        source = case_paths[case["sha256"]]
        relative = source.relative_to(results_root)
        canonical_supply_chain = (
            len(relative.parts) == 6
            and tuple(relative.parts[:5])
            == (
                "research",
                "supply-chain",
                "npm",
                "axios-plain-crypto-js-2026",
                "cases",
            )
        )
        if relative.parts[0] == "malware" or canonical_supply_chain:
            continue
        family = case["family"]
        top = results_root / relative.parts[0]
        families[family] = top
        family_targets[family] = (
            results_root
            / "research"
            / "supply-chain"
            / "npm"
            / "axios-plain-crypto-js-2026"
            if case["case_kind"] == "supply_chain_payload"
            else results_root / "malware" / family
        )
        _, legacy, collection = _case_context(source, results_root)
        if collection:
            run_roots[(family, collection)] = top.joinpath(*legacy)
        elif legacy:
            special_groups[(family, "/".join(legacy))] = top.joinpath(*legacy)

    excluded = set(case_paths.values())
    for (family, collection), source in sorted(run_roots.items()):
        target = canonical_collection_source_path(results_root, collection, family)
        moves.append(
            _move_record(
                repository, source, target, "collection_source", 2, excluded
            )
        )
    for (family, group), source in sorted(special_groups.items()):
        target = results_root / "malware" / family / "groups" / Path(group)
        moves.append(
            _move_record(repository, source, target, "legacy_group", 2, excluded)
        )

    reserved = {"cases", "campaigns"}
    run_sources = {path.resolve() for path in run_roots.values()}
    group_sources = {path.resolve() for path in special_groups.values()}
    for family, top in sorted(families.items()):
        target_root = family_targets[family]
        for child in sorted(top.iterdir(), key=lambda value: value.name.casefold()):
            if child.name in reserved or child.resolve() in run_sources | group_sources:
                continue
            if child.is_dir() and child.name.startswith(
                ("refresh-", "vx-underground-", "malwarebazaar-")
            ):
                continue
            moves.append(
                _move_record(
                    repository,
                    child,
                    target_root / child.name,
                    "family_artifact",
                    2,
                    excluded,
                )
            )
    return moves


def _collision_findings(
    repository: Path, moves: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    errors: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    targets: dict[str, list[str]] = defaultdict(list)
    for move in moves:
        targets[move["target"].casefold()].append(move["source"])
    for target, sources in sorted(targets.items()):
        if len(sources) > 1:
            errors.append(
                {"code": "duplicate_move_target", "target": target, "sources": sorted(sources)}
            )
    source_paths = {(repository / item["source"]).resolve() for item in moves}
    for move in moves:
        target = repository / move["target"]
        if not target.exists() or target.resolve() in source_paths:
            continue
        target_fingerprint = _tree_fingerprint(target)
        finding = {
            "code": "target_exists",
            "source": move["source"],
            "target": move["target"],
            "source_fingerprint": move["source_fingerprint"],
            "target_fingerprint": target_fingerprint,
            "content_conflict": target_fingerprint != move["source_fingerprint"],
        }
        errors.append(finding)
        if finding["content_conflict"]:
            conflicts.append(finding)
    return errors, conflicts


def _overlapping_move_errors(
    repository: Path, moves: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    staged = [
        (item, Path(os.path.abspath(repository / item["source"])))
        for item in moves
        if item["stage"] > 1
    ]
    for index, (first, first_path) in enumerate(staged):
        for second, second_path in staged[index + 1 :]:
            if first["stage"] != second["stage"]:
                continue
            if first_path == second_path or first_path in second_path.parents or second_path in first_path.parents:
                errors.append(
                    {
                        "code": "overlapping_same_stage_move_sources",
                        "first": first["source"],
                        "second": second["source"],
                        "stage": first["stage"],
                    }
                )
    return errors


def _target_path_findings(
    repository: Path,
    moves: list[dict[str, Any]],
    case_sources: set[Path],
    maximum: int,
) -> tuple[int, list[dict[str, Any]]]:
    longest = 0
    errors: list[dict[str, Any]] = []
    for move in moves:
        source = repository / move["source"]
        target = repository / move["target"]
        files = [source] if source.is_file() else [path for path in source.rglob("*") if path.is_file()]
        for path in files:
            absolute = Path(os.path.abspath(path))
            if move["kind"] != "case" and (
                absolute in case_sources
                or any(parent in case_sources for parent in absolute.parents)
            ):
                continue
            future = target if source.is_file() else target / path.relative_to(source)
            future = Path(os.path.abspath(future))
            length = len(str(future))
            longest = max(longest, length)
            if length > maximum:
                errors.append(
                    {
                        "code": "target_path_too_long",
                        "source": _relative(path, repository),
                        "target": future.relative_to(repository.resolve()).as_posix(),
                        "length": length,
                        "maximum": maximum,
                    }
                )
    return longest, errors


def _iter_repository_files(repository: Path, suffix: str) -> Iterable[Path]:
    for current, directories, filenames in os.walk(repository):
        directories[:] = sorted(
            directory
            for directory in directories
            if directory not in _EXCLUDED_TREES
        )
        base = Path(current)
        for filename in sorted(filenames):
            if filename.endswith(suffix):
                yield base / filename


def _split_link_target(raw: str) -> tuple[str, str, bool] | None:
    value = raw.strip()
    angle = value.startswith("<") and ">" in value
    if angle:
        target = value[1 : value.index(">")]
        trailer = value[value.index(">") + 1 :]
    else:
        match = re.match(r"(\S+)(.*)", value, re.DOTALL)
        if not match:
            return None
        target, trailer = match.groups()
    if not target or target.startswith(("#", "http://", "https://", "mailto:", "data:")):
        return None
    return target, trailer, angle


def _markdown_updates(repository: Path, mapper: _PathMapper) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = []
    for path in sorted(_iter_repository_files(repository, ".md")):
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        future_file = mapper.map(path)
        for match in MARKDOWN_LINK_RE.finditer(text):
            parsed = _split_link_target(match.group(2))
            if parsed is None:
                continue
            target, trailer, angle = parsed
            base, separator, fragment = target.partition("#")
            if not base:
                continue
            old_target = (
                repository / base.lstrip("/")
                if base.startswith("/")
                else path.parent / base
            ).resolve()
            new_target = mapper.map(old_target)
            if old_target == new_target and path.resolve() == future_file:
                continue
            new_base = os.path.relpath(new_target, future_file.parent).replace("\\", "/")
            if base.endswith("/") and not new_base.endswith("/"):
                new_base += "/"
            new_target_text = new_base + (separator + fragment if separator else "")
            replacement = (
                f"<{new_target_text}>{trailer}" if angle else f"{new_target_text}{trailer}"
            )
            if replacement == match.group(2):
                continue
            updates.append(
                {
                    "file": _relative(path, repository),
                    "future_file": future_file.relative_to(repository.resolve()).as_posix(),
                    "line": text.count("\n", 0, match.start()) + 1,
                    "old": match.group(2),
                    "new": replacement,
                }
            )
    return updates


def _history_updates(repository: Path, mapper: _PathMapper) -> list[dict[str, Any]]:
    path = repository / "analysis_history.yaml"
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8-sig")
    updates: list[dict[str, Any]] = []
    for match in HISTORY_PATH_RE.finditer(text):
        raw = match.group("path").strip()
        trailing = raw.endswith("/")
        old = (repository / raw.rstrip("/")).resolve()
        new = mapper.map(old)
        if old == new:
            continue
        value = new.relative_to(repository.resolve()).as_posix() + ("/" if trailing else "")
        updates.append(
            {
                "file": "analysis_history.yaml",
                "line": text.count("\n", 0, match.start()) + 1,
                "old": raw,
                "new": value,
            }
        )
    return updates


def _walk_strings(value: Any, pointer: str = "$") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_strings(child, f"{pointer}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_strings(child, f"{pointer}[{index}]")
    elif isinstance(value, str):
        yield pointer, value


def _json_reference_updates(
    repository: Path, results_root: Path, mapper: _PathMapper
) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = []
    for path in sorted(results_root.rglob("*.json")):
        if any(SHA256_RE.fullmatch(parent.name.lower()) for parent in path.parents):
            # case 内の相対参照は case と一緒に移動するため通常は不変。
            pass
        document = _safe_json(path)
        if document is None:
            continue
        future_file = mapper.map(path)
        for pointer, value in _walk_strings(document):
            lowered = value.lower().replace("\\", "/")
            if value.startswith(("http://", "https://")):
                continue
            if not (
                lowered.startswith(("analysis-results/", "cases/", "../"))
                or "/cases/" in lowered
            ):
                continue
            old = (
                repository / value
                if lowered.startswith("analysis-results/")
                else path.parent / value
            ).resolve()
            new = mapper.map(old)
            if old == new:
                continue
            if lowered.startswith("analysis-results/"):
                replacement = new.relative_to(repository).as_posix()
            else:
                replacement = os.path.relpath(new, future_file.parent).replace("\\", "/")
            updates.append(
                {
                    "file": _relative(path, repository),
                    "future_file": future_file.relative_to(repository.resolve()).as_posix(),
                    "json_pointer": pointer,
                    "old": value,
                    "new": replacement,
                }
            )
    return updates


def _render_checksum_manifest(path: Path) -> str:
    """manifest自身を除く配下fileの決定的なSHA-256一覧を返す。"""

    rows = []
    for item in sorted(
        (
            candidate
            for candidate in path.parent.rglob("*")
            if candidate.is_file() and candidate != path
        ),
        key=lambda value: value.as_posix().casefold(),
    ):
        rows.append(
            f"{hashlib.sha256(item.read_bytes()).hexdigest()}  "
            f"{item.relative_to(path.parent).as_posix()}"
        )
    return "\n".join(rows) + ("\n" if rows else "")


def _manifest_updates(
    repository: Path,
    mapper: _PathMapper,
    changed_paths: Iterable[str] = (),
) -> list[dict[str, Any]]:
    updates: list[dict[str, Any]] = []
    changed = [Path(os.path.abspath(repository / value)) for value in changed_paths]
    for path in sorted(repository.glob("analysis-results/**/manifest.sha256")):
        lines = [line for line in path.read_text(encoding="utf-8", errors="replace").splitlines() if line]
        future = mapper.map(path)
        affected_reference = any(
            candidate == path.parent or path.parent in candidate.parents
            for candidate in changed
        )
        current = path.read_text(encoding="utf-8", errors="replace")
        if (
            not mapper.prefixes
            and not affected_reference
            and current == _render_checksum_manifest(path)
        ):
            continue
        updates.append(
            {
                "path": _relative(path, repository),
                "future_path": future.relative_to(repository.resolve()).as_posix(),
                "action": "regenerate_after_all_moves_and_reference_updates",
                "current_entries": len(lines),
            }
        )
    return updates


def _case_metadata(case: dict[str, Any]) -> dict[str, Any]:
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "case_id": f"sha256:{case['sha256']}",
        "sha256": case["sha256"],
        "case_kind": case["case_kind"],
        "family": case["family"],
        "malware_version": case["malware_version"],
        "collections": case["collections"],
        "canonical_path": case["target"],
    }
    for key in ("attribution_status", "provisional_cluster_id"):
        if case.get(key) is not None:
            metadata[key] = case[key]
    return metadata


def _catalog_case(case: dict[str, Any]) -> dict[str, Any]:
    entry = {
        "case_id": f"sha256:{case['sha256']}",
        "family": case["family"],
        "case_kind": case["case_kind"],
        "version_key": case["malware_version"]["normalized_key"],
        "canonical_path": case["target"],
    }
    for key in ("attribution_status", "provisional_cluster_id"):
        if case.get(key) is not None:
            entry[key] = case[key]
    return entry


def _unclassified_attribution(
    case_directory: Path, legacy_segments: list[str]
) -> tuple[str, str | None]:
    """未分類 case の保守的な帰属状態と provisional cluster を返す。"""

    cluster = "mx-go" if "mx-go" in legacy_segments else None
    if cluster:
        return "provisional", cluster
    metadata = _safe_json(case_directory / "metadata.json")
    if isinstance(metadata, dict):
        status = str(metadata.get("attribution_status") or "")
        recorded_cluster = str(metadata.get("provisional_cluster_id") or "")
        if status in {"unresolved", "provisional"} and (
            not recorded_cluster or FAMILY_RE.fullmatch(recorded_cluster)
        ):
            return status, recorded_cluster or None
    document = _safe_json(case_directory / "case.json")
    attribution = document.get("attribution") if isinstance(document, dict) else None
    family = str((attribution or {}).get("family") or "unknown").strip().lower()
    if family not in {"", "none", "unknown", "unclassified"} and FAMILY_RE.fullmatch(family):
        return "provisional", family
    return "unresolved", None


def build_layout_plan(repository: Path, maximum_path_length: int = 220) -> dict[str, Any]:
    """現在の成果物から決定的な移行計画を構築し、書込み前条件を返す。"""

    repository = repository.resolve()
    results_root = _require_contained(repository / "analysis-results", repository, "results root")
    if not results_root.is_dir():
        raise LayoutPlanError("repository must contain analysis-results")
    if maximum_path_length < 160:
        raise LayoutPlanError("maximum path length must be at least 160")

    source_directories = sorted(
        (
            path.resolve()
            for path in results_root.rglob("*")
            if path.is_dir() and SHA256_RE.fullmatch(path.name.lower())
        ),
        key=lambda value: value.as_posix().casefold(),
    )
    by_hash: dict[str, list[Path]] = defaultdict(list)
    for path in source_directories:
        by_hash[path.name.lower()].append(path)
    errors: list[dict[str, Any]] = []
    for digest, paths in sorted(by_hash.items()):
        if len(paths) > 1:
            errors.append(
                {
                    "code": "duplicate_sha256",
                    "sha256": digest,
                    "sources": [_relative(path, repository) for path in paths],
                }
            )

    cases: list[dict[str, Any]] = []
    case_paths: dict[str, Path] = {}
    collection_members: dict[str, list[str]] = defaultdict(list)
    case_moves: list[dict[str, Any]] = []
    for source in source_directories:
        digest = source.name.lower()
        if digest in case_paths:
            continue
        family, legacy, collection = _case_context(source, results_root)
        source_relative = source.relative_to(results_root)
        source_top = source_relative.parts[0]
        canonical_supply_chain = (
            len(source_relative.parts) == 6
            and tuple(source_relative.parts[:5])
            == (
                "research",
                "supply-chain",
                "npm",
                "axios-plain-crypto-js-2026",
                "cases",
            )
        )
        if source_top == "npm-supply-chain" or canonical_supply_chain:
            case_kind = "supply_chain_payload"
        elif family == "unclassified":
            case_kind = "unclassified"
        else:
            case_kind = "malware"
        if case_kind == "supply_chain_payload":
            version = {
                "status": "not_applicable",
                "reported": None,
                "normalized_key": None,
                "confidence": "none",
                "reason": "case_is_a_supply_chain_payload_not_a_malware_family_release",
                "evidence": [],
            }
            target = (
                results_root
                / "research"
                / "supply-chain"
                / "npm"
                / "axios-plain-crypto-js-2026"
                / "cases"
                / digest
            ).resolve()
        else:
            version = resolve_malware_version(source, family, repository)
            version_key = version["normalized_key"]
            target = canonical_malware_case_path(
                results_root, family, digest, version_key
            )
        collections = sorted(
            {
                *([collection] if collection else []),
                *_metadata_collection_ids(source),
            }
        )
        case = {
            "sha256": digest,
            "case_kind": case_kind,
            "family": family,
            "legacy_segments": legacy,
            "source": _relative(source, repository),
            "target": target.relative_to(repository).as_posix(),
            "malware_version": version,
            "collections": collections,
        }
        if case_kind == "unclassified":
            attribution_status, provisional_cluster = _unclassified_attribution(
                source, legacy
            )
            case["attribution_status"] = attribution_status
            if provisional_cluster:
                case["provisional_cluster_id"] = provisional_cluster
        cases.append(case)
        case_paths[digest] = source
        for collection_id in collections:
            collection_members[collection_id].append(digest)
        if source != target:
            case_moves.append(
                _move_record(repository, source, target, "case", 1)
            )
    cases.sort(key=lambda item: item["sha256"])
    case_moves.sort(key=lambda item: item["source"])

    artifact_moves = _artifact_moves(repository, results_root, cases, case_paths)
    research_moves = _research_moves(repository, results_root)
    moves = sorted(
        case_moves + artifact_moves + research_moves,
        key=lambda item: (item["stage"], item["source"].casefold(), item["target"].casefold()),
    )
    collision_errors, content_conflicts = _collision_findings(repository, moves)
    errors.extend(collision_errors)
    errors.extend(_overlapping_move_errors(repository, moves))
    longest, length_errors = _target_path_findings(
        repository, moves, set(case_paths.values()), maximum_path_length
    )
    errors.extend(length_errors)
    move_sources = [Path(os.path.abspath(repository / item["source"])) for item in moves]
    for path in sorted(results_root.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(results_root)
        if len(relative.parts) == 1 and relative.name in _RESULT_ROOT_FILE_ALLOWLIST:
            continue
        if relative.parts[0] in _RESULT_ROOT_DIRECTORY_ALLOWLIST:
            continue
        absolute = Path(os.path.abspath(path))
        if any(source == absolute or source in absolute.parents for source in move_sources):
            continue
        errors.append(
            {"code": "unplanned_result_root_artifact", "path": _relative(path, repository)}
        )
    errors.sort(key=lambda item: json.dumps(item, sort_keys=True))

    existing_collections = _existing_collection_documents(results_root)
    collections = []
    for collection_id in sorted(set(collection_members) | set(existing_collections)):
        hashes = collection_members.get(collection_id, [])
        members = sorted(set(hashes))
        collection_root = canonical_collection_root(results_root, collection_id)
        source_moves = [
            item
            for item in artifact_moves
            if item["kind"] == "collection_source"
            and Path(item["target"]).parent.parent.name == collection_id
        ]
        source_families = {Path(item["target"]).name for item in source_moves}
        existing_sources_root = collection_root / "sources"
        if existing_sources_root.is_dir():
            for child in existing_sources_root.iterdir():
                if not child.is_dir():
                    continue
                if not FAMILY_RE.fullmatch(child.name):
                    raise LayoutPlanError(
                        f"unsafe existing collection family: {child.name!r}"
                    )
                source_families.add(child.name)
        family_sources = [
            {"family": family, "path": f"sources/{family}"}
            for family in sorted(source_families)
        ]
        existing = existing_collections.get(collection_id)
        if existing is not None:
            if existing["cases"] != set(members):
                errors.append(
                    {
                        "code": "collection_membership_mismatch",
                        "collection_id": collection_id,
                        "metadata_only": sorted(set(members) - existing["cases"]),
                        "manifest_only": sorted(existing["cases"] - set(members)),
                    }
                )
            planned_sources = {
                (item["family"], item["path"]) for item in family_sources
            }
            if existing["family_sources"] != planned_sources:
                errors.append(
                    {
                        "code": "collection_family_sources_mismatch",
                        "collection_id": collection_id,
                    }
                )
        collections.append(
            {
                "collection_id": collection_id,
                "manifest_path": canonical_collection_manifest_path(
                    results_root, collection_id
                ).relative_to(repository).as_posix(),
                "source_directories": sorted(
                    {
                        item["source"]
                        for item in artifact_moves
                        if item["kind"] == "collection_source"
                        and f"/{collection_id}" in item["source"]
                    }
                ),
                "family_sources": family_sources,
                "cases": [{"case_id": f"sha256:{digest}"} for digest in members],
            }
        )

    errors.sort(key=lambda item: json.dumps(item, sort_keys=True))

    catalog = {
        "schema_version": SCHEMA_VERSION,
        "cases": {
            case["sha256"]: _catalog_case(case)
            for case in cases
        },
    }
    malware_cases = [case for case in cases if case["case_kind"] == "malware"]
    unclassified_cases = [
        case for case in cases if case["case_kind"] == "unclassified"
    ]
    versioned_cases = malware_cases + unclassified_cases
    confirmed = sum(case["malware_version"]["status"] == "confirmed" for case in versioned_cases)
    reported = sum(case["malware_version"]["status"] == "reported" for case in versioned_cases)
    resolved_versions = confirmed + reported
    mapper = _PathMapper(repository, moves)
    markdown_updates = _markdown_updates(repository, mapper)
    json_updates = _json_reference_updates(repository, results_root, mapper)
    history_updates = _history_updates(repository, mapper)
    manifest_updates = _manifest_updates(
        repository,
        mapper,
        (
            *(
                item.get("future_file") or item["file"]
                for item in markdown_updates
            ),
            *(
                item.get("future_file") or item["file"]
                for item in json_updates
            ),
            *(item["file"] for item in history_updates),
        ),
    )

    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "static_repository_layout_plan",
        "write_performed": False,
        "repository": ".",
        "target_case_schema": (
            "analysis-results/malware/<family>/versions/<version-key>/cases/<sha256>"
        ),
        "counts": {
            "case_directories": len(source_directories),
            "malware_cases": len(malware_cases),
            "unclassified_cases": len(unclassified_cases),
            "provisional_unclassified_cases": sum(
                case.get("attribution_status") == "provisional"
                for case in unclassified_cases
            ),
            "unresolved_unclassified_cases": sum(
                case.get("attribution_status") == "unresolved"
                for case in unclassified_cases
            ),
            "supply_chain_payload_cases": sum(
                case["case_kind"] == "supply_chain_payload" for case in cases
            ),
            "unique_case_hashes": len(by_hash),
            "case_moves": len(case_moves),
            "artifact_moves": len(artifact_moves),
            "research_moves": len(research_moves),
            "resolved_malware_versions": resolved_versions,
            "confirmed_malware_versions": confirmed,
            "reported_malware_versions": reported,
            "unknown_malware_versions": len(malware_cases) - resolved_versions,
            "unknown_unclassified_versions": len(unclassified_cases),
            "unknown_versioned_cases": len(versioned_cases) - resolved_versions,
            "collections": len(collections),
            "collection_memberships": sum(len(item["cases"]) for item in collections),
            "markdown_link_updates": len(markdown_updates),
            "json_reference_updates": len(json_updates),
            "history_path_updates": len(history_updates),
            "checksum_manifests_to_regenerate": len(manifest_updates),
            "preflight_errors": len(errors),
            "content_conflicts": len(content_conflicts),
        },
        "limits": {
            "maximum_path_length": maximum_path_length,
            "longest_planned_path": longest,
        },
        "errors": errors,
        "content_conflicts": content_conflicts,
        "cases": [{**case, "metadata": _case_metadata(case)} for case in cases],
        "move_map": moves,
        "collections": collections,
        "catalog": {
            "path": "analysis-results/catalog/cases.json",
            "document": catalog,
        },
        "reference_update_plan": {
            "markdown": markdown_updates,
            "json": json_updates,
            "history": history_updates,
            "checksum_manifests": manifest_updates,
        },
        "postconditions": {
            "all_malware_cases_use_fixed_depth": not errors,
            "supply_chain_payload_uses_research_namespace": not errors,
            "result_root_directory_allowlist": sorted(_RESULT_ROOT_DIRECTORY_ALLOWLIST),
            "expected_case_count": len(source_directories),
            "expected_unique_sha256": len(by_hash),
            "expected_duplicate_sha256": sum(
                max(0, len(paths) - 1) for paths in by_hash.values()
            ),
            "expected_move_collisions": len(collision_errors),
            "expected_content_conflicts": len(content_conflicts),
            "expected_collection_memberships": sum(
                len(item["cases"]) for item in collections
            ),
            "samples_opened": False,
            "sample_execution": False,
            "cpu_or_cil_emulation": False,
            "network_contacted": False,
        },
    }


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    temporary.replace(path)


def _remove_empty_descendants(path: Path) -> None:
    if not path.is_dir():
        return
    for child in sorted(
        (item for item in path.rglob("*") if item.is_dir()),
        key=lambda item: len(item.parts),
        reverse=True,
    ):
        try:
            child.rmdir()
        except OSError:
            pass


def _apply_text_updates(
    repository: Path, updates: list[dict[str, Any]], future_key: str
) -> None:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for update in updates:
        grouped[update.get(future_key) or update["file"]].append(update)
    for relative, items in sorted(grouped.items()):
        path = _require_contained(repository / relative, repository, "reference update")
        text = path.read_text(encoding="utf-8-sig")
        for item in items:
            old, new = item["old"], item["new"]
            if old not in text:
                raise LayoutPlanError(f"planned reference is no longer present: {relative}: {old}")
            text = text.replace(old, new, 1)
        path.write_text(text, encoding="utf-8", newline="\n")


def _regenerate_manifest(path: Path) -> None:
    path.write_text(
        _render_checksum_manifest(path), encoding="utf-8", newline="\n"
    )


def _write_bytes_atomic(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".rollback-tmp")
    temporary.write_bytes(value)
    temporary.replace(path)


def apply_layout_plan(repository: Path, plan: dict[str, Any]) -> dict[str, Any]:
    """preflight 済み計画を明示的に適用し、固定深さの事後条件を検査する。"""

    repository = repository.resolve()
    if plan.get("errors"):
        raise LayoutPlanError("refusing to apply a plan with preflight errors")
    if plan.get("schema_version") != SCHEMA_VERSION:
        raise LayoutPlanError("unsupported layout plan schema")

    # Revalidate the immutable input contract before making any directory,
    # metadata, text, or manifest change. Artifact moves reproduce the exact
    # case-subtree exclusions used while planning; each excluded case is
    # independently fingerprinted by its stage-1 case move.
    for move in plan.get("move_map") or []:
        source = _require_contained(repository / move["source"], repository, "move source")
        target = _require_contained(repository / move["target"], repository, "move target")
        if move.get("fingerprint_method") != _FINGERPRINT_METHOD:
            raise LayoutPlanError(f"unsupported source fingerprint method: {move['source']}")
        if not source.exists():
            raise LayoutPlanError(f"move source disappeared: {move['source']}")
        if target.exists():
            raise LayoutPlanError(f"move target appeared: {move['target']}")
        exclusions: set[Path] = set()
        for relative in move.get("fingerprint_excluded_case_sources") or []:
            excluded = _require_contained(
                repository / relative, repository, "fingerprint exclusion"
            )
            if not SHA256_RE.fullmatch(excluded.name.lower()) or not _path_under(
                excluded, source
            ):
                raise LayoutPlanError(
                    f"invalid fingerprint exclusion for {move['source']}: {relative}"
                )
            exclusions.add(excluded)
        actual = _tree_fingerprint(source, exclusions)
        if actual != move.get("source_fingerprint"):
            raise LayoutPlanError(f"stale source fingerprint: {move['source']}")

    moved: list[tuple[Path, Path]] = []
    generated: list[Path] = []
    results_root = repository / "analysis-results"
    original_directories = {
        Path(os.path.abspath(path))
        for path in (results_root, *results_root.rglob("*"))
        if path.is_dir()
    }
    original_files = {
        Path(os.path.abspath(path)) for path in results_root.rglob("*") if path.is_file()
    }
    references = plan["reference_update_plan"]
    backup_relatives = {
        item["file"]
        for group in ("markdown", "json", "history")
        for item in references[group]
    }
    backup_relatives.update(item["path"] for item in references["checksum_manifests"])
    original_bytes = {
        relative: (repository / relative).read_bytes()
        for relative in sorted(backup_relatives)
        if (repository / relative).is_file()
    }
    try:
        for move in plan["move_map"]:
            source = _require_contained(repository / move["source"], repository, "move source")
            target = _require_contained(repository / move["target"], repository, "move target")
            if move["stage"] > 1:
                _remove_empty_descendants(source)
            if not source.exists():
                raise LayoutPlanError(f"move source disappeared: {move['source']}")
            if target.exists():
                raise LayoutPlanError(f"move target appeared: {move['target']}")
            target.parent.mkdir(parents=True, exist_ok=True)
            source.rename(target)
            moved.append((source, target))

        for case in plan["cases"]:
            target = _require_contained(repository / case["target"], repository, "case target")
            metadata_path = target / "metadata.json"
            if metadata_path.exists():
                if _safe_json(metadata_path) != case["metadata"]:
                    raise LayoutPlanError(
                        f"existing metadata differs from plan: {metadata_path}"
                    )
            else:
                _write_json(metadata_path, case["metadata"])
                generated.append(metadata_path)

        catalog_path = _require_contained(
            repository / plan["catalog"]["path"], repository, "catalog path"
        )
        if catalog_path.exists():
            if _safe_json(catalog_path) != plan["catalog"]["document"]:
                raise LayoutPlanError(f"existing catalog differs from plan: {catalog_path}")
        else:
            _write_json(catalog_path, plan["catalog"]["document"])
            generated.append(catalog_path)

        for collection in plan["collections"]:
            manifest = _require_contained(
                repository / collection["manifest_path"], repository, "collection manifest"
            )
            document = {
                "schema_version": SCHEMA_VERSION,
                "collection_id": collection["collection_id"],
                "family_sources": collection["family_sources"],
                "cases": collection["cases"],
            }
            if manifest.exists():
                if _safe_json(manifest) != document:
                    raise LayoutPlanError(
                        f"existing collection differs from plan: {manifest}"
                    )
            else:
                _write_json(manifest, document)
                generated.append(manifest)

        _apply_text_updates(repository, references["markdown"], "future_file")
        _apply_text_updates(repository, references["json"], "future_file")
        _apply_text_updates(repository, references["history"], "file")
        for manifest in references["checksum_manifests"]:
            path = _require_contained(
                repository / manifest["future_path"], repository, "checksum manifest"
            )
            _regenerate_manifest(path)

        for child in sorted(path for path in results_root.iterdir() if path.is_dir()):
            if child.name in _RESULT_ROOT_DIRECTORY_ALLOWLIST:
                continue
            _remove_empty_descendants(child)
            try:
                child.rmdir()
            except OSError:
                pass
        post_cases = [
            path
            for path in results_root.rglob("*")
            if path.is_dir() and SHA256_RE.fullmatch(path.name.lower())
        ]
        invalid = []
        for path in post_cases:
            parts = path.relative_to(results_root).parts
            malware_shape = (
                len(parts) == 6
                and parts[0] == "malware"
                and parts[2] == "versions"
                and parts[4] == "cases"
            )
            supply_chain_shape = (
                len(parts) == 6
                and parts[:5] == (
                    "research",
                    "supply-chain",
                    "npm",
                    "axios-plain-crypto-js-2026",
                    "cases",
                )
            )
            if not malware_shape and not supply_chain_shape:
                invalid.append(path.relative_to(results_root).as_posix())
        unexpected_root_directories = sorted(
            path.name
            for path in results_root.iterdir()
            if path.is_dir() and path.name not in _RESULT_ROOT_DIRECTORY_ALLOWLIST
        )
        unexpected_root_files = sorted(
            path.name
            for path in results_root.iterdir()
            if path.is_file() and path.name not in _RESULT_ROOT_FILE_ALLOWLIST
        )
        if (
            invalid
            or len(post_cases) != plan["counts"]["case_directories"]
            or unexpected_root_directories
            or unexpected_root_files
        ):
            raise LayoutPlanError(
                "postcondition failed "
                f"(invalid={invalid[:5]}, cases={len(post_cases)}, "
                f"root_dirs={unexpected_root_directories}, root_files={unexpected_root_files})"
            )
    except Exception:
        for path in reversed(generated):
            try:
                path.unlink()
            except OSError:
                pass
        for source, target in reversed(moved):
            if target.exists() and not source.exists():
                source.parent.mkdir(parents=True, exist_ok=True)
                target.rename(source)
        for relative, value in original_bytes.items():
            _write_bytes_atomic(repository / relative, value)
        for path in sorted(
            (candidate for candidate in results_root.rglob("*") if candidate.is_file()),
            key=lambda candidate: len(candidate.parts),
            reverse=True,
        ):
            absolute = Path(os.path.abspath(path))
            if absolute not in original_files and path.name.endswith((".tmp", ".rollback-tmp")):
                try:
                    path.unlink()
                except OSError:
                    pass
        for path in sorted(
            (candidate for candidate in results_root.rglob("*") if candidate.is_dir()),
            key=lambda candidate: len(candidate.parts),
            reverse=True,
        ):
            if Path(os.path.abspath(path)) in original_directories:
                continue
            try:
                path.rmdir()
            except OSError:
                pass
        raise
    result = dict(plan)
    result["write_performed"] = True
    return result
