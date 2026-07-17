#!/usr/bin/env python3
"""Run bounded, static-only triage over an inventory of difficult samples.

The orchestrator deliberately treats malware bytes as ephemeral in-memory data.
It can authenticate MalwareBazaar AES ZIPs and pass recovered layers between
static parsers, but it never executes, emulates, contacts infrastructure, or
writes a raw or recovered artifact.  Its only persistent products are a
sanitized JSON report and a Markdown summary.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
from typing import Any, Mapping, Sequence

import yaml

REPOSITORY = Path(__file__).resolve().parents[2]
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from malware_io import (  # noqa: E402
    ArchiveValidationError,
    read_single_aes_zip_member,
)
from unpackers.static_control_flow import (  # noqa: E402
    DEFAULT_MAX_BLOCK_BYTES,
    DEFAULT_MAX_BLOCKS,
    DEFAULT_MAX_INSTRUCTIONS,
    analyze_code_region,
    analyze_pe_control_flow,
)
from unpackers.static_unpacker import unpack_bytes  # noqa: E402


SCHEMA_VERSION = 1
DEFAULT_MAX_DEPTH = 3
DEFAULT_MAX_NODES = 64
DEFAULT_MAX_INPUT_SIZE = 256 * 1024 * 1024
DEFAULT_MAX_TOTAL_LAYER_BYTES = 512 * 1024 * 1024
DEFAULT_MARKER_SCAN_BYTES = 32 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DOTNET_METADATA_TOKEN = re.compile(r"^0x[0-9a-fA-F]{8}$")
_PUBLIC_DOCUMENT_SUFFIXES = {".csv", ".json", ".md", ".yaml", ".yml"}
_OMITTED_KEYS = {
    "blocks",
    "cwd",
    "directory",
    "input",
    "input_root",
    "local_path",
    "output",
    "output_root",
    "path",
    "paths",
    "source_path",
    "zip_path",
}
_LOCAL_PATH = re.compile(
    r"(?:(?<![A-Za-z0-9+.-])[A-Za-z]:[\\/]|\\\\[^\\]+[\\/]|(?:^|\s)/(?:home|tmp|users|var)/)",
    re.IGNORECASE,
)
_SENSITIVE_KEY_PARTS = {
    "authorization",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "creds",
    "passwd",
    "password",
    "passwords",
    "pwd",
    "secret",
    "secrets",
    "session",
    "token",
    "tokens",
}
_SENSITIVE_COMPACT_KEYS = {
    "aeskey", "apikey", "authkey", "privatekey", "rc4key",
    "secretkey", "sessionkey", "accesskey", "clientkey",
    "decryptionkey", "encryptionkey", "signingkey",
}
_MARKERS: tuple[tuple[str, tuple[bytes, ...]], ...] = (
    ("KoiVM", (b"koivm",)),
    ("ConfuserEx", (b"confuserex", b"confusedbyattribute")),
    ("Themida", (b"themida",)),
    ("WinLicense", (b"winlicense",)),
    ("VMProtect", (b"vmprotect",)),
    ("Enigma", (b"enigma", b"enigma protector", b"enigma virtual box")),
    (".NET Reactor", (b".net reactor", b"eziriz")),
    ("SmartAssembly", (b"smartassembly", b"powered by smartassembly")),
    ("nsPack", (b"nspack", b".nsp")),
    ("UPX", (b"upx!", b"$info: this file is packed with the upx")),
)


def _normalize_hash(value: object, field: str) -> str:
    """Return a validated lowercase SHA-256 value."""

    digest = str(value).strip().lower()
    if not _SHA256.fullmatch(digest):
        raise ValueError(f"{field} must be a 64-character hexadecimal SHA-256")
    return digest


def _string_list(value: object, field: str) -> list[str]:
    """Normalize a YAML sequence of scalar values to strings."""

    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    return [str(item).strip() for item in value if str(item).strip()]


def _hash_list(value: object, field: str) -> list[str]:
    """Normalize and deduplicate a YAML sequence of SHA-256 values."""

    if value is None:
        return []
    if not isinstance(value, list):
        raise ValueError(f"{field} must be a list")
    result: list[str] = []
    for index, item in enumerate(value):
        digest = _normalize_hash(item, f"{field}[{index}]")
        if digest not in result:
            result.append(digest)
    return result


def _raw_code_layers(value: object, field: str) -> dict[str, int]:
    """Validate an explicit raw-layer SHA-256 to x86 bitness mapping."""

    if value is None:
        return {}
    if not isinstance(value, Mapping):
        raise ValueError(f"{field} must be a mapping")
    result: dict[str, int] = {}
    for digest_value, bits_value in value.items():
        digest = _normalize_hash(digest_value, f"{field} key")
        try:
            bits = int(bits_value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{field}[{digest}] must be 32 or 64") from exc
        if bits not in {32, 64}:
            raise ValueError(f"{field}[{digest}] must be 32 or 64")
        result[digest] = bits
    return dict(sorted(result.items()))


def _normalize_case(value: Mapping[str, Any], index: int) -> dict[str, Any]:
    """Normalize one expanded inventory case."""

    digest = _normalize_hash(value.get("sha256"), f"cases[{index}].sha256")
    normalized = {
        "sha256": digest,
        "group_id": str(value.get("group_id") or "").strip() or None,
        "family": str(value.get("family") or "unknown").strip() or "unknown",
        "category": str(value.get("category") or "hard_static").strip() or "hard_static",
        "priority": value.get("priority", "unspecified"),
        "blockers": _string_list(value.get("blockers"), f"cases[{index}].blockers"),
        "expected_children": _hash_list(
            value.get("expected_children"), f"cases[{index}].expected_children"
        ),
        "raw_code_layers": _raw_code_layers(
            value.get("raw_code_layers"), f"cases[{index}].raw_code_layers"
        ),
    }
    return normalized


def load_inventory(path: Path) -> dict[str, Any]:
    """Load a UTF-8 YAML inventory and require a mapping document."""

    document = yaml.safe_load(Path(path).read_text(encoding="utf-8-sig"))
    if not isinstance(document, dict):
        raise ValueError("inventory must contain a YAML mapping")
    return document


def expand_inventory(document: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Expand group hashes into cases, applying matching case overrides.

    Supported groups contain ``id``, ``family``, ``category``, ``priority``,
    ``blockers`` and ``hashes``.  An optional entry in ``cases`` with the same
    ``sha256`` replaces whichever of those defaults it explicitly supplies and
    may add ``expected_children`` or ``raw_code_layers``.
    """

    groups = document.get("groups", [])
    cases = document.get("cases", [])
    if not isinstance(groups, list) or not isinstance(cases, list):
        raise ValueError("groups and cases must be lists")

    expanded: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for group_index, group in enumerate(groups):
        if not isinstance(group, Mapping):
            raise ValueError(f"groups[{group_index}] must be a mapping")
        hashes = _hash_list(group.get("hashes"), f"groups[{group_index}].hashes")
        defaults = {
            "group_id": str(group.get("id") or f"group-{group_index + 1}"),
            "family": group.get("family", "unknown"),
            "category": group.get("category", "hard_static"),
            "priority": group.get("priority", "unspecified"),
            "blockers": group.get("blockers", []),
            "expected_children": group.get("expected_children", []),
            "raw_code_layers": group.get("raw_code_layers", {}),
        }
        for digest in hashes:
            if digest in expanded:
                raise ValueError(f"duplicate group hash: {digest}")
            expanded[digest] = {**defaults, "sha256": digest}
            order.append(digest)

    override_hashes: set[str] = set()
    for case_index, case in enumerate(cases):
        if not isinstance(case, Mapping):
            raise ValueError(f"cases[{case_index}] must be a mapping")
        digest = _normalize_hash(case.get("sha256"), f"cases[{case_index}].sha256")
        if digest in override_hashes:
            raise ValueError(f"duplicate case override: {digest}")
        override_hashes.add(digest)
        merged = dict(expanded.get(digest, {"sha256": digest}))
        for key in (
            "family",
            "category",
            "priority",
            "blockers",
            "expected_children",
            "raw_code_layers",
        ):
            if key in case:
                merged[key] = case[key]
        if "group_id" in case:
            merged["group_id"] = case["group_id"]
        if digest not in expanded:
            order.append(digest)
        expanded[digest] = merged

    return [_normalize_case(expanded[digest], index) for index, digest in enumerate(order)]


def index_local_samples(roots: Sequence[Path]) -> dict[str, list[dict[str, Any]]]:
    """Index hash-named raw files and ``<sha256>.zip`` archives under roots.

    Paths are returned only for internal acquisition and are never copied into
    the public report.  Symlinks and obvious report-document suffixes are
    excluded.  File contents are authenticated against the requested hash later.
    """

    index: dict[str, list[dict[str, Any]]] = {}
    seen_paths: set[str] = set()
    for root_value in roots:
        root = Path(root_value)
        if not root.is_dir():
            continue
        try:
            entries = root.rglob("*")
            for path in entries:
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                except OSError:
                    continue
                suffix = path.suffix.lower()
                if suffix == ".zip" and _SHA256.fullmatch(path.stem.lower()):
                    digest = path.stem.lower()
                    source_kind = "aes_zip"
                elif _SHA256.fullmatch(path.name.lower()):
                    digest = path.name.lower()
                    source_kind = "raw_file"
                elif (
                    suffix not in _PUBLIC_DOCUMENT_SUFFIXES
                    and _SHA256.fullmatch(path.stem.lower())
                ):
                    digest = path.stem.lower()
                    source_kind = "raw_file"
                else:
                    continue
                identity = str(path.resolve()).casefold()
                if identity in seen_paths:
                    continue
                seen_paths.add(identity)
                index.setdefault(digest, []).append(
                    {"path": path, "source_kind": source_kind}
                )
        except OSError:
            continue
    for locations in index.values():
        locations.sort(
            key=lambda item: (
                0 if item["source_kind"] == "aes_zip" else 1,
                str(item["path"]).casefold(),
            )
        )
    return dict(sorted(index.items()))


def _bounded_marker_probe(data: bytes, max_scan_bytes: int) -> bytes:
    """Return deterministic first/middle/last windows for marker matching."""

    if max_scan_bytes <= 0:
        raise ValueError("max_scan_bytes must be positive")
    if len(data) <= max_scan_bytes:
        return data.lower()
    window = max(1, max_scan_bytes // 3)
    middle = max(0, (len(data) - window) // 2)
    return (data[:window] + data[middle : middle + window] + data[-window:]).lower()


def scan_protector_markers(
    data: bytes, *, max_scan_bytes: int = DEFAULT_MARKER_SCAN_BYTES
) -> list[str]:
    """Return recognized protector/obfuscator markers from bounded byte windows."""

    probe = _bounded_marker_probe(data, max_scan_bytes)
    matches: list[str] = []
    for name, needles in _MARKERS:
        found = False
        for needle in needles:
            wide = b"\x00".join(bytes((byte,)) for byte in needle) + b"\x00"
            if needle.lower() in probe or wide.lower() in probe:
                found = True
                break
        if found:
            matches.append(name)
    return matches


def _contextual_markers(
    markers: Sequence[str], unpack: Mapping[str, Any], kind: str
) -> list[str]:
    """Reject short-marker coincidences unless PE structure corroborates them."""

    selected = set(markers)
    if "UPX" in selected:
        pe = unpack.get("pe") if isinstance(unpack, Mapping) else None
        pe = pe if isinstance(pe, Mapping) else {}
        exact = {str(value).upper() for value in pe.get("packer_markers", [])}
        section_names = {
            str(item.get("name", "")).upper()
            for item in pe.get("sections", [])
            if isinstance(item, Mapping)
        }
        packed_classification = pe.get("classification") in {
            "packed_or_protected",
            "suspected_packed",
            "virtualized_or_packed",
        }
        corroborated = any(
            name.startswith(("UPX0", "UPX1", "UPX2")) for name in section_names
        ) or ("UPX!" in exact and packed_classification)
        if kind != "pe" or not corroborated:
            selected.discard("UPX")
    return sorted(selected)


def _has_structural_stub_evidence(
    pe: Mapping[str, Any], context: Mapping[str, Any]
) -> bool:
    """Return whether layout/classification corroborates a protector stub."""

    if str(pe.get("classification", "")) in {
        "managed_loader_or_obfuscated",
        "packed_or_protected",
        "self_extracting_container",
        "suspected_packed",
        "virtualized_or_packed",
    }:
        return True
    if any(
        container.get(field) is True
        for container in (pe, context)
        for field in (
            "containerized",
            "packing_suspected",
            "structural_packer_evidence",
            "virtualized_shape",
        )
    ):
        return True
    zero_raw = pe.get("zero_raw_virtual_sections")
    if not isinstance(zero_raw, list):
        zero_raw = context.get("zero_raw_virtual_sections", 0)
    if isinstance(zero_raw, list):
        zero_raw_count = len(zero_raw)
    elif isinstance(zero_raw, int):
        zero_raw_count = zero_raw
    else:
        zero_raw_count = 0
    entry_high_entropy = bool(context.get("entrypoint_high_entropy"))
    imports = context.get("imports", pe.get("imports"))
    low_import_surface = isinstance(imports, int) and imports <= 2
    return entry_high_entropy and low_import_surface and zero_raw_count >= 4


def _normalize_report_findings(report: dict[str, Any]) -> dict[str, Any]:
    """Normalize marker provenance and downgrade known stub CFG confounders."""

    cases = report.get("cases", [])
    if not isinstance(cases, list):
        return report
    for case in cases:
        if not isinstance(case, dict):
            continue
        for node in case.get("nodes", []):
            if not isinstance(node, dict):
                continue
            unpack = node.get("unpack") if isinstance(node.get("unpack"), dict) else {}
            node["markers"] = _contextual_markers(
                node.get("markers", []), unpack, str(node.get("format", "unknown"))
            )
            pe = unpack.get("pe") if isinstance(unpack.get("pe"), dict) else {}
            control_flow = node.get("control_flow")
            if not isinstance(control_flow, dict):
                continue
            context = control_flow.get("static_context")
            context = context if isinstance(context, dict) else {}
            if "UPX" not in node["markers"]:
                for marker_container in (pe, context):
                    values = marker_container.get("packer_markers")
                    if isinstance(values, list):
                        marker_container["packer_markers"] = [
                            value
                            for value in values
                            if str(value).upper() != "UPX!"
                        ]
            evidence_markers = {
                str(value).upper()
                for value in (
                    list(node.get("markers", []))
                    + list(pe.get("packer_markers", []))
                    + list(context.get("packer_markers", []))
                )
            }
            stub_markers = evidence_markers.intersection(
                {
                    "UPX", "UPX!", "MPRESS", "THEMIDA", "WINLICENSE",
                    "VMPROTECT", "ENIGMA", "NSPACK", "NULLSOFT",
                }
            )
            structural_stub = _has_structural_stub_evidence(pe, context)
            if not stub_markers or not structural_stub:
                continue
            message = (
                "known packer/protector/container stub confounder: "
                + ", ".join(sorted(stub_markers))
            )
            techniques = control_flow.get("techniques")
            if not isinstance(techniques, dict):
                continue
            for name in ("control_flow_flattening", "indirect_branch_obfuscation"):
                assessment = techniques.get(name)
                if isinstance(assessment, dict) and assessment.get("status") == "suspected":
                    assessment["status"] = "confounded"
                    assessment.setdefault("evidence", []).append(message)
            if stub_markers.intersection({"UPX", "UPX!", "MPRESS", "NULLSOFT"}):
                assessment = techniques.get("virtual_machine_or_protector_dispatch")
                if isinstance(assessment, dict) and assessment.get("status") == "suspected":
                    assessment["status"] = "confounded"
                    assessment.setdefault("evidence", []).append(message)
    report["summary"] = _summary(cases)
    return report


def _is_sensitive_key(key: str) -> bool:
    """Return whether a mapping key conventionally contains secret material."""

    separated = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", key)
    normalized = re.sub(r"[^a-z0-9]+", "_", separated.lower()).strip("_")
    parts = set(normalized.split("_")) if normalized else set()
    if parts.intersection(_SENSITIVE_KEY_PARTS):
        return True
    if normalized == "key":
        return True
    compact = re.sub(r"[^a-z0-9]", "", key.lower())
    return any(marker in compact for marker in _SENSITIVE_COMPACT_KEYS)


def _sanitize_public(value: Any, key: str | None = None) -> Any:
    """Remove secrets, basic-block listings, paths, bytes and local paths."""

    if key:
        lowered = key.lower()
        metadata_token = (
            lowered == "token"
            and isinstance(value, str)
            and bool(_DOTNET_METADATA_TOKEN.fullmatch(value.strip()))
        )
        if (
            lowered in _OMITTED_KEYS
            or lowered.endswith(("_path", "_paths"))
            or (_is_sensitive_key(lowered) and not metadata_token)
        ):
            return None
    if isinstance(value, Mapping):
        clean: dict[str, Any] = {}
        for item_key, item_value in value.items():
            name = str(item_key)
            sanitized = _sanitize_public(item_value, name)
            if sanitized is not None:
                clean[name] = sanitized
        return clean
    if isinstance(value, (list, tuple)):
        return [item for entry in value if (item := _sanitize_public(entry)) is not None]
    if isinstance(value, Path):
        return None
    if isinstance(value, (bytes, bytearray, memoryview)):
        return "[binary-omitted]"
    if isinstance(value, str) and _LOCAL_PATH.search(value):
        return "[local-path-omitted]"
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _load_matching_sample(
    digest: str,
    locations: Sequence[Mapping[str, Any]],
    *,
    password: str,
    max_input_size: int,
) -> tuple[bytes | None, str | None, list[dict[str, str]]]:
    """Load the first candidate whose authenticated content matches a hash."""

    attempts: list[dict[str, str]] = []
    for location in locations:
        path = Path(location["path"])
        source_kind = str(location["source_kind"])
        if source_kind == "aes_zip":
            try:
                member = read_single_aes_zip_member(
                    path, password=password, max_member_size=max_input_size
                )
            except (ArchiveValidationError, OSError) as exc:
                attempts.append(
                    {
                        "source_kind": source_kind,
                        "status": "archive_read_failed",
                        "error": type(exc).__name__,
                    }
                )
                continue
            if member.sha256 == digest:
                return member.data, source_kind, attempts
            attempts.append(
                {"source_kind": source_kind, "status": "archive_member_hash_mismatch"}
            )
            continue
        try:
            size = path.stat().st_size
            if size > max_input_size:
                attempts.append({"source_kind": source_kind, "status": "size_limit"})
                continue
            data = path.read_bytes()
        except OSError as exc:
            attempts.append(
                {
                    "source_kind": source_kind,
                    "status": "raw_read_failed",
                    "error": type(exc).__name__,
                }
            )
            continue
        if hashlib.sha256(data).hexdigest() != digest:
            attempts.append({"source_kind": source_kind, "status": "raw_hash_mismatch"})
            continue
        return data, source_kind, attempts
    return None, None, attempts


def _static_layer_analysis(
    data: bytes,
    digest: str,
    raw_code_layers: Mapping[str, int],
    *,
    max_blocks: int,
    max_instructions: int,
    max_block_bytes: int,
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """Run static unpacking and optional bounded control-flow analysis."""

    report, artifacts = unpack_bytes(data, f"{digest}.bin")
    kind = str(report.get("format", "unknown"))
    markers = _contextual_markers(scan_protector_markers(data), report, kind)
    control_flow: dict[str, Any] | None = None
    if kind == "pe":
        control_flow = analyze_pe_control_flow(
            data,
            max_blocks=max_blocks,
            max_instructions=max_instructions,
            max_block_bytes=max_block_bytes,
        )
    elif digest in raw_code_layers:
        control_flow = analyze_code_region(
            data,
            bits=raw_code_layers[digest],
            max_blocks=max_blocks,
            max_instructions=max_instructions,
            max_block_bytes=max_block_bytes,
        )
    return {
        "format": kind,
        "markers": markers,
        "unpack": _sanitize_public(report),
        "control_flow": _sanitize_public(control_flow) if control_flow else None,
    }, artifacts


def analyze_case(
    case: Mapping[str, Any],
    locations: Sequence[Mapping[str, Any]],
    *,
    password: str = "infected",
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_input_size: int = DEFAULT_MAX_INPUT_SIZE,
    max_total_layer_bytes: int = DEFAULT_MAX_TOTAL_LAYER_BYTES,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_block_bytes: int = DEFAULT_MAX_BLOCK_BYTES,
) -> dict[str, Any]:
    """Analyze one inventory case using only bounded in-memory static operations."""

    if (
        max_depth < 0
        or max_nodes < 1
        or max_input_size < 1
        or max_total_layer_bytes < 1
    ):
        raise ValueError("max_depth must be non-negative and size/node budgets positive")
    normalized = _normalize_case(case, 0)
    digest = normalized["sha256"]
    data, source_kind, attempts = _load_matching_sample(
        digest,
        locations,
        password=password,
        max_input_size=max_input_size,
    )
    result: dict[str, Any] = {
        "case": normalized,
        "status": "not_found" if not locations else "input_error",
        "source_kind": source_kind,
        "acquisition_attempts": attempts,
        "nodes": [],
        "budgets": {
            "max_depth": max_depth,
            "max_nodes": max_nodes,
            "max_input_size": max_input_size,
            "max_total_layer_bytes": max_total_layer_bytes,
            "max_total_layer_bytes_accounting": {
                "scope": "sum_of_unique_layer_payload_bytes_admitted_to_analysis_queue",
                "includes_root_when_admitted": True,
                "is_peak_process_memory_limit": False,
                "includes_unpacker_internal_temporary_allocations": False,
            },
            "max_blocks": max_blocks,
            "max_instructions": max_instructions,
            "max_block_bytes": max_block_bytes,
        },
        "budget_usage": {
            "scheduled_layer_bytes": 0,
            "scheduled_layers": 0,
        },
        "budget_limited": False,
        "expected_children": {
            "declared": normalized["expected_children"],
            "observed": [],
            "missing": normalized["expected_children"],
            "all_observed": not normalized["expected_children"],
        },
        "executed": False,
        "emulated": False,
        "network_contacted": False,
        "raw_artifacts_written": False,
    }
    if data is None:
        return _sanitize_public(result)

    if len(data) > max_total_layer_bytes:
        result["status"] = "partial"
        result["budget_limited"] = True
        result["budget_stop"] = {
            "reason": "root_total_byte_limit",
            "root_size": len(data),
            "root_was_unpacked": False,
        }
        return _sanitize_public(result)

    result["status"] = "analyzed"
    queue: list[tuple[int, str, str, bytes]] = [(0, "root", digest, data)]
    scheduled = {digest}
    scheduled_bytes = len(data)
    observed = {digest}
    budget_limited = False
    while queue:
        depth, relation, layer_hash, layer_data = queue.pop(0)
        node: dict[str, Any] = {
            "sha256": layer_hash,
            "size": len(layer_data),
            "depth": depth,
            "relation": relation,
            "children": [],
        }
        try:
            static, artifacts = _static_layer_analysis(
                layer_data,
                layer_hash,
                normalized["raw_code_layers"],
                max_blocks=max_blocks,
                max_instructions=max_instructions,
                max_block_bytes=max_block_bytes,
            )
            node.update(static)
        except Exception as exc:  # parser libraries expose heterogeneous exceptions
            node.update(
                {
                    "format": "unknown",
                    "markers": scan_protector_markers(layer_data),
                    "analysis_error": type(exc).__name__,
                }
            )
            artifacts = []
            result["status"] = "partial"

        for artifact_kind, artifact in artifacts:
            child_hash = hashlib.sha256(artifact).hexdigest()
            observed.add(child_hash)
            child = {
                "kind": str(artifact_kind),
                "sha256": child_hash,
                "size": len(artifact),
                "analysis": "duplicate",
            }
            if child_hash not in scheduled:
                if len(artifact) > max_input_size:
                    child["analysis"] = "size_limit"
                    budget_limited = True
                elif scheduled_bytes + len(artifact) > max_total_layer_bytes:
                    child["analysis"] = "total_byte_limit"
                    budget_limited = True
                elif depth >= max_depth:
                    child["analysis"] = "depth_limit"
                    budget_limited = True
                elif len(scheduled) >= max_nodes:
                    child["analysis"] = "node_limit"
                    budget_limited = True
                else:
                    child["analysis"] = "queued"
                    scheduled.add(child_hash)
                    scheduled_bytes += len(artifact)
                    queue.append((depth + 1, str(artifact_kind), child_hash, artifact))
            node["children"].append(child)
        result["nodes"].append(node)

    expected = normalized["expected_children"]
    missing = [value for value in expected if value not in observed]
    result["expected_children"] = {
        "declared": expected,
        "observed": [value for value in expected if value in observed],
        "missing": missing,
        "all_observed": not missing,
    }
    result["budget_limited"] = budget_limited
    result["budget_usage"] = {
        "scheduled_layer_bytes": scheduled_bytes,
        "scheduled_layers": len(scheduled),
    }
    return _sanitize_public(result)


def _summary(cases: Sequence[Mapping[str, Any]]) -> dict[str, int]:
    """Count public case and layer outcomes."""

    analyzed = sum(item.get("status") in {"analyzed", "partial"} for item in cases)
    missing_expected = sum(
        bool(item.get("expected_children", {}).get("missing")) for item in cases
    )
    marker_cases = sum(
        any(node.get("markers") for node in item.get("nodes", [])) for item in cases
    )
    return {
        "total": len(cases),
        "analyzed": analyzed,
        "partial": sum(item.get("status") == "partial" for item in cases),
        "not_found": sum(item.get("status") == "not_found" for item in cases),
        "input_errors": sum(item.get("status") == "input_error" for item in cases),
        "layers_analyzed": sum(len(item.get("nodes", [])) for item in cases),
        "budget_limited_cases": sum(bool(item.get("budget_limited")) for item in cases),
        "protector_marker_cases": marker_cases,
        "expected_children_missing_cases": missing_expected,
    }


def run_inventory(
    document: Mapping[str, Any],
    roots: Sequence[Path],
    *,
    password: str = "infected",
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_input_size: int = DEFAULT_MAX_INPUT_SIZE,
    max_total_layer_bytes: int = DEFAULT_MAX_TOTAL_LAYER_BYTES,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_block_bytes: int = DEFAULT_MAX_BLOCK_BYTES,
) -> dict[str, Any]:
    """Analyze all expanded inventory cases against hash-indexed local roots."""

    cases = expand_inventory(document)
    sample_index = index_local_samples(roots)
    results = [
        analyze_case(
            case,
            sample_index.get(case["sha256"], []),
            password=password,
            max_depth=max_depth,
            max_nodes=max_nodes,
            max_input_size=max_input_size,
            max_total_layer_bytes=max_total_layer_bytes,
            max_blocks=max_blocks,
            max_instructions=max_instructions,
            max_block_bytes=max_block_bytes,
        )
        for case in cases
    ]
    report = {
        "schema_version": SCHEMA_VERSION,
        "analysis_mode": "bounded_static_only",
        "safety": {
            "executed": False,
            "emulated": False,
            "network_contacted": False,
            "raw_artifacts_written": False,
            "persistent_outputs": ["json", "markdown"],
        },
        "summary": _summary(results),
        "cases": results,
    }
    return _sanitize_public(report)


def _markdown(value: object) -> str:
    """Escape one scalar for a compact Markdown table cell."""

    if value is None or value == "":
        return "-"
    if isinstance(value, list):
        value = ", ".join(str(item) for item in value) or "-"
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(report: Mapping[str, Any]) -> str:
    """Render a sanitized human-readable summary without raw bytes or paths."""

    report = _normalize_report_findings(_sanitize_public(report))
    summary = report.get("summary", {})
    lines = [
        "# Deep static triage",
        "",
        "This report was produced without sample execution, emulation, network contact, or raw-artifact persistence.",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "|---|---:|",
    ]
    for key in (
        "total",
        "analyzed",
        "partial",
        "not_found",
        "input_errors",
        "layers_analyzed",
        "budget_limited_cases",
        "protector_marker_cases",
        "expected_children_missing_cases",
    ):
        lines.append(f"| {_markdown(key)} | {_markdown(summary.get(key, 0))} |")
    lines.extend(
        [
            "",
            "## Cases",
            "",
            "| SHA-256 | Family | Category | Status | Layers | Markers | Missing expected layers |",
            "|---|---|---|---|---:|---|---|",
        ]
    )
    for item in report.get("cases", []):
        case = item.get("case", {})
        markers = sorted(
            {
                marker
                for node in item.get("nodes", [])
                for marker in node.get("markers", [])
            }
        )
        missing = item.get("expected_children", {}).get("missing", [])
        lines.append(
            "| "
            + " | ".join(
                _markdown(value)
                for value in (
                    case.get("sha256"),
                    case.get("family"),
                    case.get("category"),
                    item.get("status"),
                    len(item.get("nodes", [])),
                    markers,
                    missing,
                )
            )
            + " |"
        )
    lines.extend(["", "## Case details", ""])
    for item in report.get("cases", []):
        case = item.get("case", {})
        lines.extend(
            [
                f"### {_markdown(case.get('sha256'))}",
                "",
                f"- Family: {_markdown(case.get('family'))}",
                f"- Priority: {_markdown(case.get('priority'))}",
                f"- Blockers: {_markdown(case.get('blockers', []))}",
                f"- Status: {_markdown(item.get('status'))}",
                f"- Budget limited: {_markdown(item.get('budget_limited', False))}",
            ]
        )
        for node in item.get("nodes", []):
            control_flow = node.get("control_flow") or {}
            techniques = control_flow.get("techniques", {})
            native_routing = [
                f"{name}:{assessment.get('status')}"
                for name, assessment in techniques.items()
                if assessment.get("status") in {"suspected", "confounded"}
            ]
            managed = (
                node.get("unpack", {}).get("pe", {}).get("managed_il_triage") or {}
            )
            managed_routing = [
                name
                for name, assessment in managed.get("techniques", {}).items()
                if assessment.get("status") == "suspected"
            ]
            lines.append(
                f"- Layer {_markdown(node.get('sha256'))}: "
                f"format={_markdown(node.get('format'))}; "
                f"markers={_markdown(node.get('markers', []))}; "
                f"native-routing={_markdown(native_routing)}; "
                f"managed-routing={_markdown(managed_routing)}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def write_public_report(
    report: Mapping[str, Any], output_dir: Path
) -> tuple[Path, Path]:
    """Write only sanitized JSON and Markdown products to an output directory."""

    clean = _normalize_report_findings(_sanitize_public(report))
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "deep-static-triage.json"
    markdown_path = output_dir / "deep-static-triage.md"
    json_path.write_text(
        json.dumps(clean, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    markdown_path.write_text(render_markdown(clean), encoding="utf-8")
    return json_path, markdown_path


def build_parser() -> argparse.ArgumentParser:
    """Build the static-only batch command-line parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", required=True, type=Path)
    parser.add_argument("--root", required=True, action="append", type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--password", default="infected")
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_DEPTH)
    parser.add_argument("--max-nodes", type=int, default=DEFAULT_MAX_NODES)
    parser.add_argument("--max-input-size", type=int, default=DEFAULT_MAX_INPUT_SIZE)
    parser.add_argument("--max-total-layer-bytes", type=int, default=DEFAULT_MAX_TOTAL_LAYER_BYTES)
    parser.add_argument("--max-blocks", type=int, default=DEFAULT_MAX_BLOCKS)
    parser.add_argument("--max-instructions", type=int, default=DEFAULT_MAX_INSTRUCTIONS)
    parser.add_argument("--max-block-bytes", type=int, default=DEFAULT_MAX_BLOCK_BYTES)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run inventory triage and publish sanitized JSON/Markdown reports."""

    args = build_parser().parse_args(argv)
    document = load_inventory(args.inventory)
    report = run_inventory(
        document,
        args.root,
        password=args.password,
        max_depth=args.max_depth,
        max_nodes=args.max_nodes,
        max_input_size=args.max_input_size,
        max_total_layer_bytes=args.max_total_layer_bytes,
        max_blocks=args.max_blocks,
        max_instructions=args.max_instructions,
        max_block_bytes=args.max_block_bytes,
    )
    write_public_report(report, args.output_dir)
    print(
        json.dumps(
            {
                "status": "complete",
                "json": "deep-static-triage.json",
                "markdown": "deep-static-triage.md",
                "summary": report["summary"],
            },
            ensure_ascii=False,
        )
    )
    return 0 if not report["summary"]["input_errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
