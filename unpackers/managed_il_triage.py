#!/usr/bin/env python3
"""Bounded, execution-free .NET metadata and CIL triage.

The module treats the input as an inert byte string.  It never asks the CLR to
load an assembly, executes or emulates CIL, extracts a resource to disk, or
performs network I/O.  Technique assessments are conservative prioritization
hints and are not protector attribution.
"""

from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager
from functools import wraps
import hashlib
from itertools import islice
import json
import logging
import math
from pathlib import Path
import struct
from typing import Any
import warnings

try:
    import dnfile
except ImportError:  # pragma: no cover - dependency status is tested by patching
    dnfile = None

try:
    from dncil.cil.body.reader import read_method_body_from_bytes
except ImportError:  # pragma: no cover - dependency status is tested by patching
    read_method_body_from_bytes = None


DEFAULT_MAX_INPUT_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_TYPES = 4_096
DEFAULT_MAX_METHODS = 20_000
DEFAULT_MAX_INSTRUCTIONS = 200_000
DEFAULT_MAX_METHOD_BYTES = 256 * 1024
DEFAULT_MAX_METADATA_STRINGS = 40_000
DEFAULT_MAX_METADATA_STRING_BYTES = 8 * 1024 * 1024
DEFAULT_MAX_METADATA_SCAN_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_RESOURCES = 1_024
DEFAULT_MAX_RESOURCE_BYTES = 64 * 1024 * 1024
DEFAULT_DISPATCHER_SWITCH_TARGETS = 16
MAX_NAME_LENGTH = 512
INSTRUCTION_BUDGET_NOTE = (
    "max_instructions is enforced after dncil parses one method; "
    "max_method_bytes is the pre-parse byte bound"
)

_BRANCHES = {
    "br",
    "br.s",
    "brfalse",
    "brfalse.s",
    "brtrue",
    "brtrue.s",
    "beq",
    "beq.s",
    "bge",
    "bge.s",
    "bge.un",
    "bge.un.s",
    "bgt",
    "bgt.s",
    "bgt.un",
    "bgt.un.s",
    "ble",
    "ble.s",
    "ble.un",
    "ble.un.s",
    "blt",
    "blt.s",
    "blt.un",
    "blt.un.s",
    "bne.un",
    "bne.un.s",
    "leave",
    "leave.s",
    "switch",
}
_CALLS = {"call", "callvirt", "newobj"}
_MARKERS = {
    "koi_vm": ("koivm.runtime", "koivm"),
    "confuserex": ("confuserex", "confusedbyattribute", "confuser.runtime"),
    "dotnet_reactor": (".net reactor", "eziriz", "powered by .net reactor"),
    "smartassembly": ("smartassembly", "smartassembly.attributes", "poweredbyattribute"),
}
_SCAN_STREAM_TYPES = {"MetaDataTables", "StringsHeap", "UserStringHeap"}
_REVIEWED_NON_CFF_DISPATCHERS = {
    (
        "da590d16a8738a6c5f055fffcdcb49870e088d37e040bf1fc1880cbf9b3faa51",
        "definitions.<getdefinitions>d__16",
        "movenext",
    ): "compiler_generated_iterator_state_machine",
    (
        "da590d16a8738a6c5f055fffcdcb49870e088d37e040bf1fc1880cbf9b3faa51",
        "commands.controlstuff",
        "input",
    ): "application_command_dispatch",
}


def _dependency_report() -> dict[str, str | None]:
    return {
        "dnfile": getattr(dnfile, "__version__", None) if dnfile else None,
        "dncil": "available" if read_method_body_from_bytes else None,
    }


def _base_result(size: int) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "analysis": "bounded_static_managed_il_triage",
        "analysis_mode": "static_byte_parsing_only",
        "status": "not_started",
        "input_size": size,
        "sha256": None,
        "dependencies": _dependency_report(),
        "executed": False,
        "emulated": False,
        "network_contacted": False,
        "clr_loaded": False,
        "raw_resources_published": False,
        "budget_exhausted": [],
        "types": [],
        "methods": [],
        "dispatcher_candidates": [],
        "malformed_method_bodies": [],
        "resources": [],
        "marker_hits": [],
        "techniques": {},
        "static_method_plan": [],
    }


def _safe_text(value: Any, limit: int = MAX_NAME_LENGTH) -> str:
    try:
        text = str(value) if value is not None else ""
    except Exception:
        return "<unprintable>"
    text = "".join(character if character >= " " else "?" for character in text)
    return text[:limit]


@contextmanager
def _contained_parser_diagnostics():
    """Discard parser warnings/logs for this bounded analysis scope only."""
    names = {"dnfile", "pefile"}
    names.update(
        name
        for name, value in logging.Logger.manager.loggerDict.items()
        if isinstance(value, logging.Logger)
        and (name.startswith("dnfile.") or name.startswith("pefile."))
    )
    states = []
    for name in sorted(names):
        logger = logging.getLogger(name)
        states.append((logger, list(logger.handlers), logger.propagate, logger.level, logger.disabled))
        logger.handlers = [logging.NullHandler()]
        logger.propagate = False
        logger.setLevel(logging.CRITICAL + 1)
        logger.disabled = False
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            yield
    finally:
        for logger, handlers, propagate, level, disabled in states:
            logger.handlers = handlers
            logger.propagate = propagate
            logger.setLevel(level)
            logger.disabled = disabled


def _contain_parser_diagnostics(function):
    """Decorate a parser entry point with contained diagnostics."""
    @wraps(function)
    def wrapper(*args, **kwargs):
        with _contained_parser_diagnostics():
            return function(*args, **kwargs)

    return wrapper


def _row_count(table: Any) -> int | None:
    """Read a declared row count without materializing rows."""
    if table is None:
        return 0
    try:
        return max(0, int(getattr(table, "num_rows")))
    except (AttributeError, TypeError, ValueError):
        pass
    rows = getattr(table, "rows", None)
    if rows is None:
        return 0
    try:
        return len(rows)
    except (TypeError, ValueError):
        return None


def _bounded_rows(table: Any, limit: int) -> tuple[list[Any], int, bool, str | None]:
    """Read at most ``limit + 1`` rows and report a typed iteration error."""
    declared = _row_count(table)
    source = getattr(table, "rows", None)
    if source is None:
        return [], declared or 0, False, None
    sampled: list[Any] = []
    try:
        sampled.extend(islice(iter(source), limit + 1))
    except Exception as error:
        return sampled[:limit], max(declared or 0, len(sampled)), True, type(error).__name__
    truncated = len(sampled) > limit or (declared is not None and declared > limit)
    bounded = sampled[:limit]
    return bounded, max(declared or 0, len(bounded)), truncated, None


def _table(pe: Any, name: str) -> Any:
    return getattr(getattr(getattr(pe, "net", None), "mdtables", None), name, None)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    size = len(data)
    return round(-sum((count / size) * math.log2(count / size) for count in counts.values()), 4)


def _metadata_names(
    pe: Any,
    max_strings: int,
    max_bytes: int,
) -> tuple[list[str], dict[str, Any]]:
    names: list[str] = []
    used = 0
    exhausted = False
    fields = {
        "TypeDef": ("TypeNamespace", "TypeName"),
        "TypeRef": ("TypeNamespace", "TypeName"),
        "MethodDef": ("Name",),
        "MemberRef": ("Name",),
        "Assembly": ("Name",),
        "AssemblyRef": ("Name",),
        "Module": ("Name",),
        "ModuleRef": ("Name",),
        "ManifestResource": ("Name",),
    }
    table_errors: list[dict[str, str]] = []
    for table_name, row_fields in fields.items():
        remaining = max_strings - len(names)
        rows, _, truncated, table_error = _bounded_rows(_table(pe, table_name), max(1, remaining))
        exhausted = exhausted or truncated
        if table_error:
            table_errors.append({"table": table_name, "error": table_error})
        for row in rows:
            for field in row_fields:
                try:
                    value = _safe_text(getattr(row, field, ""))
                except Exception as error:
                    table_errors.append({"table": table_name, "error": type(error).__name__})
                    continue
                if not value:
                    continue
                encoded_size = len(value.encode("utf-8", errors="replace"))
                if len(names) >= max_strings or used + encoded_size > max_bytes:
                    exhausted = True
                    break
                names.append(value)
                used += encoded_size
            if exhausted and len(names) >= max_strings:
                break
        if len(names) >= max_strings or used >= max_bytes:
            break
    return names, {
        "metadata_names_scanned": len(names),
        "metadata_name_bytes_scanned": used,
        "metadata_name_budget_exhausted": exhausted,
        "metadata_table_errors": table_errors[:32],
        "metadata_table_errors_truncated": len(table_errors) > 32,
    }


def _scan_markers(
    data: bytes,
    pe: Any,
    names: list[str],
    max_scan_bytes: int,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    sources: dict[str, set[str]] = {name: set() for name in _MARKERS}
    name_blob = "\n".join(names).lower()
    for marker, terms in _MARKERS.items():
        if any(term in name_blob for term in terms):
            sources[marker].add("metadata_names")

    scanned = 0
    truncated = False
    metadata = getattr(getattr(pe, "net", None), "metadata", None)
    streams = getattr(metadata, "streams", {})
    values = streams.values() if hasattr(streams, "values") else []
    for stream in sorted(values, key=lambda value: int(getattr(value, "file_offset", 0) or 0)):
        stream_type = type(stream).__name__
        if stream_type not in _SCAN_STREAM_TYPES:
            continue
        offset = int(getattr(stream, "file_offset", -1) or -1)
        try:
            declared_size = int(stream.struct.Size)
        except (AttributeError, TypeError, ValueError):
            continue
        if offset < 0 or offset >= len(data) or declared_size <= 0:
            continue
        remaining = max_scan_bytes - scanned
        if remaining <= 0:
            truncated = True
            break
        length = min(declared_size, remaining, len(data) - offset)
        chunk = data[offset : offset + length].lower()
        scanned += length
        if length < declared_size:
            truncated = True
        for marker, terms in _MARKERS.items():
            for term in terms:
                encoded = term.encode("ascii", errors="ignore")
                if encoded and (encoded in chunk or term.encode("utf-16le") in chunk):
                    sources[marker].add(stream_type)
                    break
    hits = [
        {"marker": marker, "sources": sorted(found)}
        for marker, found in sources.items()
        if found
    ]
    return hits, {
        "metadata_stream_bytes_scanned": scanned,
        "metadata_stream_budget_exhausted": truncated,
    }


def _method_owner_map(type_rows: list[Any], max_references: int) -> tuple[dict[int, str], bool]:
    owners: dict[int, str] = {}
    exhausted = False
    for row in type_rows:
        try:
            full_name = ".".join(
                value
                for value in (
                    _safe_text(getattr(row, "TypeNamespace", "")),
                    _safe_text(getattr(row, "TypeName", "")),
                )
                if value
            )
            remaining = max_references - len(owners)
            references = list(islice(iter(getattr(row, "MethodList", ()) or ()), remaining + 1))
        except Exception:
            continue
        if len(references) > remaining:
            exhausted = True
        for reference in references[:remaining]:
            try:
                index = int(getattr(reference, "row_index", reference))
            except (TypeError, ValueError):
                continue
            owners[index] = full_name
        if len(owners) >= max_references:
            exhausted = True
            break
    return owners, exhausted


def _method_extent(data: bytes, offset: int) -> tuple[int, int]:
    """Return declared CIL header and code sizes, raising on malformed headers."""
    if not 0 <= offset < len(data):
        raise ValueError("method RVA maps outside input")
    first = data[offset]
    kind = first & 0x03
    if kind == 0x02:
        return 1, first >> 2
    if kind != 0x03 or offset + 12 > len(data):
        raise ValueError("invalid or truncated CIL method header")
    flags_and_size = struct.unpack_from("<H", data, offset)[0]
    header_size = ((flags_and_size >> 12) & 0x0F) * 4
    if header_size < 12 or offset + header_size > len(data):
        raise ValueError("invalid fat CIL header size")
    code_size = struct.unpack_from("<I", data, offset + 4)[0]
    return header_size, code_size


def _instruction_metrics(instructions: list[Any]) -> dict[str, int]:
    metrics = {
        "instructions": 0,
        "branches": 0,
        "switches": 0,
        "switch_targets": 0,
        "max_switch_targets": 0,
        "calls": 0,
        "calli": 0,
        "ldstr": 0,
        "constant_loads": 0,
    }
    for instruction in instructions:
        name = _safe_text(getattr(getattr(instruction, "opcode", None), "name", "")).lower()
        metrics["instructions"] += 1
        if name in _BRANCHES:
            metrics["branches"] += 1
        if name == "switch":
            try:
                targets = len(getattr(instruction, "operand", ()) or ())
            except TypeError:
                targets = 0
            metrics["switches"] += 1
            metrics["switch_targets"] += targets
            metrics["max_switch_targets"] = max(metrics["max_switch_targets"], targets)
        elif name in _CALLS:
            metrics["calls"] += 1
        elif name == "calli":
            metrics["calli"] += 1
        elif name == "ldstr":
            metrics["ldstr"] += 1
        elif name.startswith("ldc."):
            metrics["constant_loads"] += 1
    return metrics


def _high_fanout_switch_count(instructions: list[Any], threshold: int) -> int:
    """Count switch instructions meeting a target-fanout threshold."""
    count = 0
    for instruction in instructions:
        name = _safe_text(getattr(getattr(instruction, "opcode", None), "name", "")).lower()
        if name != "switch":
            continue
        try:
            targets = len(getattr(instruction, "operand", ()) or ())
        except TypeError:
            targets = 0
        count += int(targets >= threshold)
    return count


def _resource_inventory(
    data: bytes,
    pe: Any,
    max_resources: int,
    max_resource_bytes: int,
) -> tuple[list[dict[str, Any]], dict[str, int], list[str]]:
    table = _table(pe, "ManifestResource")
    rows, declared, truncated, table_error = _bounded_rows(table, max_resources)
    resources: list[dict[str, Any]] = []
    used = 0
    exhausted: list[str] = []
    if truncated:
        exhausted.append("resources")
    if table_error:
        exhausted.append("resource_table_parse_error")
    try:
        base_rva = int(pe.net.struct.ResourcesRva)
    except (AttributeError, TypeError, ValueError):
        base_rva = 0

    for index, row in enumerate(rows, 1):
        item: dict[str, Any] = {
            "index": index,
            "name": _safe_text(getattr(row, "Name", "")),
            "kind": "external" if getattr(row, "Implementation", None) is not None else "internal",
            "declared_size": None,
            "sha256": None,
            "entropy": None,
            "status": "not_hashed",
        }
        if item["kind"] == "external":
            item["status"] = "external_reference"
            resources.append(item)
            continue
        try:
            header_rva = base_rva + int(row.Offset)
            header_offset = int(pe.get_offset_from_rva(header_rva))
            if not 0 <= header_offset <= len(data) - 4:
                raise ValueError("resource header outside input")
            declared_size = struct.unpack_from("<I", data, header_offset)[0]
            item["declared_size"] = declared_size
            data_offset = header_offset + 4
            if declared_size > len(data) - data_offset:
                raise ValueError("resource data truncated")
            if declared_size > max_resource_bytes - used:
                item["status"] = "resource_byte_budget_exceeded"
                exhausted.append("resource_bytes")
            else:
                content = data[data_offset : data_offset + declared_size]
                item["sha256"] = hashlib.sha256(content).hexdigest()
                item["entropy"] = _entropy(content)
                item["status"] = "hashed_full_resource"
                used += declared_size
        except Exception as error:
            item["status"] = "malformed_resource"
            item["parse_error"] = type(error).__name__
        resources.append(item)
    return resources, {
        "resources_declared": declared,
        "resources_enumerated": len(resources),
        "resource_bytes_hashed": used,
    }, sorted(set(exhausted))


def _technique(status: str, confidence: str, evidence: list[str]) -> dict[str, Any]:
    return {
        "status": status,
        "confidence": confidence,
        "evidence": evidence,
        "interpretation": "bounded_static_prioritization_hint_not_protector_attribution",
    }


def _known_semantic_dispatch_shape(candidate: dict[str, Any]) -> str | None:
    """Recognize reviewed non-CFF methods without trusting attacker-chosen names."""

    sample_sha256 = _safe_text(candidate.get("sample_sha256", "")).lower()
    owner = _safe_text(candidate.get("owner", "")).lower()
    name = _safe_text(candidate.get("name", "")).lower()
    return _REVIEWED_NON_CFF_DISPATCHERS.get((sample_sha256, owner, name))


def _assess_techniques(
    marker_hits: list[dict[str, Any]],
    counts: dict[str, int],
    dispatchers: list[dict[str, Any]],
    resources: list[dict[str, Any]],
) -> dict[str, Any]:
    found = {item["marker"]: item for item in marker_hits}
    techniques: dict[str, Any] = {}
    for marker in _MARKERS:
        if marker in found:
            techniques[marker] = _technique(
                "suspected",
                "medium",
                [f"marker present in {', '.join(found[marker]['sources'])}"],
            )
        else:
            techniques[marker] = _technique("not_observed", "none", [])

    marker_support = sorted(found)
    reviewed_dispatchers = [
        (candidate, _known_semantic_dispatch_shape(candidate))
        for candidate in dispatchers
        if _known_semantic_dispatch_shape(candidate)
    ]
    actionable_dispatchers = [
        candidate
        for candidate in dispatchers
        if not _known_semantic_dispatch_shape(candidate)
    ]
    high_fanout_switches = sum(
        max(1, int(candidate.get("high_fanout_switches", 1)))
        for candidate in actionable_dispatchers
    )
    if high_fanout_switches >= 2:
        techniques["managed_control_flow_flattening"] = _technique(
            "suspected",
            "medium",
            [
                f"{high_fanout_switches} high-fanout switches occur across "
                f"{len(actionable_dispatchers)} candidate method(s)"
            ],
        )
    elif high_fanout_switches == 1 and marker_support:
        techniques["managed_control_flow_flattening"] = _technique(
            "suspected",
            "medium",
            [
                "one high-fanout switch is independently supported by protector marker(s): "
                + ", ".join(marker_support)
            ],
        )
    elif high_fanout_switches == 1:
        techniques["managed_control_flow_flattening"] = _technique(
            "inconclusive",
            "low",
            ["one high-fanout switch is insufficient without an independent protector marker"],
        )
    elif reviewed_dispatchers:
        shapes = sorted({str(shape) for _, shape in reviewed_dispatchers})
        techniques["managed_control_flow_flattening"] = _technique(
            "inconclusive",
            "low",
            [
                f"excluded {len(reviewed_dispatchers)} reviewed semantic dispatch shape(s): "
                + ", ".join(shapes)
            ],
        )
    else:
        techniques["managed_control_flow_flattening"] = _technique("not_observed", "none", [])

    parsed = max(1, counts.get("methods_parsed", 0))
    proxies = counts.get("proxy_method_candidates", 0)
    if proxies >= 3 and proxies / parsed >= 0.20:
        techniques["method_proxy_obfuscation"] = _technique(
            "suspected",
            "low",
            [f"{proxies}/{parsed} parsed methods are small single-call candidates"],
        )
    else:
        techniques["method_proxy_obfuscation"] = _technique("not_observed", "none", [])

    instructions = max(1, counts.get("instructions_counted", 0))
    constants = counts.get("constant_loads", 0)
    if constants >= 64 and constants / instructions >= 0.25:
        techniques["constant_obfuscation"] = _technique(
            "suspected",
            "low",
            [f"{constants}/{instructions} counted instructions load constants"],
        )
    else:
        techniques["constant_obfuscation"] = _technique("not_observed", "none", [])

    high_entropy = [
        item
        for item in resources
        if item.get("status") == "hashed_full_resource"
        and (item.get("declared_size") or 0) >= 4_096
        and (item.get("entropy") or 0.0) >= 7.2
    ]
    if len(high_entropy) >= 2:
        techniques["resource_obfuscation"] = _technique(
            "suspected",
            "medium",
            [f"{len(high_entropy)} resource(s) are at least 4 KiB with entropy >= 7.2"],
        )
    elif len(high_entropy) == 1 and marker_support:
        techniques["resource_obfuscation"] = _technique(
            "suspected",
            "medium",
            [
                "one high-entropy resource is independently supported by protector marker(s): "
                + ", ".join(marker_support)
            ],
        )
    elif len(high_entropy) == 1:
        techniques["resource_obfuscation"] = _technique(
            "inconclusive",
            "low",
            ["one high-entropy resource is insufficient without an independent protector marker"],
        )
    else:
        techniques["resource_obfuscation"] = _technique("not_observed", "none", [])
    return techniques


@_contain_parser_diagnostics
def analyze_managed_pe(
    data: bytes,
    *,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_types: int = DEFAULT_MAX_TYPES,
    max_methods: int = DEFAULT_MAX_METHODS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_method_bytes: int = DEFAULT_MAX_METHOD_BYTES,
    max_metadata_strings: int = DEFAULT_MAX_METADATA_STRINGS,
    max_metadata_string_bytes: int = DEFAULT_MAX_METADATA_STRING_BYTES,
    max_metadata_scan_bytes: int = DEFAULT_MAX_METADATA_SCAN_BYTES,
    max_resources: int = DEFAULT_MAX_RESOURCES,
    max_resource_bytes: int = DEFAULT_MAX_RESOURCE_BYTES,
    dispatcher_switch_targets: int = DEFAULT_DISPATCHER_SWITCH_TARGETS,
) -> dict[str, Any]:
    """Statically inventory a managed PE under explicit parsing budgets.

    ``data`` is never CLR-loaded, executed, emulated, or written to disk.  CIL
    method bodies are parsed from bounded byte slices and resources are only
    represented by metadata, SHA-256, and entropy.  A partial result is returned
    when a budget is exhausted or an individual method is malformed.

    ``max_method_bytes`` bounds the exact header-plus-declared-code slice before
    dncil parses a method. ``max_instructions`` is applied only after dncil has
    constructed that method's instruction collection; the returned report records
    this parser-boundary limitation explicitly.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    budgets = {
        "max_input_bytes": max_input_bytes,
        "max_types": max_types,
        "max_methods": max_methods,
        "max_instructions": max_instructions,
        "max_method_bytes": max_method_bytes,
        "max_metadata_strings": max_metadata_strings,
        "max_metadata_string_bytes": max_metadata_string_bytes,
        "max_metadata_scan_bytes": max_metadata_scan_bytes,
        "max_resources": max_resources,
        "max_resource_bytes": max_resource_bytes,
        "dispatcher_switch_targets": dispatcher_switch_targets,
    }
    if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in budgets.values()):
        raise ValueError("all budgets must be positive integers")

    result = _base_result(len(data))
    result["budgets"] = {**budgets, "instruction_budget_semantics": INSTRUCTION_BUDGET_NOTE}
    result["limitations"] = [INSTRUCTION_BUDGET_NOTE]
    if len(data) > max_input_bytes:
        result["status"] = "input_budget_exceeded"
        result["budget_exhausted"] = ["input_bytes"]
        result["static_method_plan"] = plan_managed_methods(result)
        return result
    result["sha256"] = hashlib.sha256(data).hexdigest()
    if dnfile is None or read_method_body_from_bytes is None:
        result["status"] = "dependency_missing"
        result["static_method_plan"] = plan_managed_methods(result)
        return result
    try:
        pe = dnfile.dnPE(data=data, clr_lazy_load=True)
    except Exception as error:
        result["status"] = "parse_failed"
        result["parse_error"] = type(error).__name__
        result["static_method_plan"] = plan_managed_methods(result)
        return result
    if not getattr(pe, "net", None) or not getattr(pe.net, "mdtables", None):
        result["status"] = "not_managed_pe"
        result["static_method_plan"] = plan_managed_methods(result)
        return result

    budget_exhausted: list[str] = []
    metadata_table_errors: list[dict[str, str]] = []
    type_table = _table(pe, "TypeDef")
    type_rows, types_declared, type_truncated, type_error = _bounded_rows(type_table, max_types)
    if type_truncated:
        budget_exhausted.append("types")
    if type_error:
        metadata_table_errors.append({"table": "TypeDef", "error": type_error})
    owners, owner_truncated = _method_owner_map(type_rows, max_methods)
    if owner_truncated:
        budget_exhausted.append("method_owner_references")
    for index, row in enumerate(type_rows, 1):
        method_list = getattr(row, "MethodList", ()) or ()
        result["types"].append(
            {
                "token": f"0x02{index:06x}",
                "namespace": _safe_text(getattr(row, "TypeNamespace", "")),
                "name": _safe_text(getattr(row, "TypeName", "")),
                "method_references": len(method_list) if hasattr(method_list, "__len__") else None,
            }
        )

    names, name_metrics = _metadata_names(pe, max_metadata_strings, max_metadata_string_bytes)
    if name_metrics["metadata_name_budget_exhausted"]:
        budget_exhausted.append("metadata_names")
    marker_hits, scan_metrics = _scan_markers(data, pe, names, max_metadata_scan_bytes)
    if scan_metrics["metadata_stream_budget_exhausted"]:
        budget_exhausted.append("metadata_stream_bytes")
    result["marker_hits"] = marker_hits
    result["metadata_scan"] = {**name_metrics, **scan_metrics}

    resources, resource_counts, resource_budgets = _resource_inventory(
        data, pe, max_resources, max_resource_bytes
    )
    result["resources"] = resources
    budget_exhausted.extend(resource_budgets)

    method_table = _table(pe, "MethodDef")
    method_rows, methods_declared, method_truncated, method_error = _bounded_rows(
        method_table, max_methods
    )
    if method_truncated:
        budget_exhausted.append("methods")
    if method_error:
        metadata_table_errors.append({"table": "MethodDef", "error": method_error})
    totals = {
        "types_declared": types_declared,
        "types_enumerated": len(type_rows),
        "methods_declared": methods_declared,
        "methods_enumerated": len(method_rows),
        "methods_with_body": 0,
        "methods_parsed": 0,
        "methods_without_body": 0,
        "malformed_method_bodies": 0,
        "instructions_counted": 0,
        "branches": 0,
        "switches": 0,
        "switch_targets": 0,
        "calls": 0,
        "calli": 0,
        "ldstr": 0,
        "constant_loads": 0,
        "proxy_method_candidates": 0,
        **resource_counts,
    }

    for index, row in enumerate(method_rows, 1):
        name = _safe_text(getattr(row, "Name", ""))
        try:
            rva = int(getattr(row, "Rva", 0) or 0)
        except (TypeError, ValueError):
            rva = 0
        method: dict[str, Any] = {
            "token": f"0x06{index:06x}",
            "owner": owners.get(index, ""),
            "name": name,
            "rva": hex(rva),
            "parse_status": "no_body",
        }
        if not rva:
            totals["methods_without_body"] += 1
            result["methods"].append(method)
            continue
        totals["methods_with_body"] += 1
        if totals["instructions_counted"] >= max_instructions:
            method["parse_status"] = "instruction_budget_exceeded"
            budget_exhausted.append("instructions")
            result["methods"].append(method)
            continue
        try:
            offset = int(pe.get_offset_from_rva(rva))
            header_size, code_size = _method_extent(data, offset)
            method["declared_code_size"] = code_size
            if header_size + code_size > max_method_bytes:
                method["parse_status"] = "method_byte_budget_exceeded"
                budget_exhausted.append("method_bytes")
                result["methods"].append(method)
                continue
            if offset + header_size + code_size > len(data):
                raise ValueError("declared CIL body extends beyond input")
            body = read_method_body_from_bytes(data[offset : offset + header_size + code_size])
            parsed_instructions = list(getattr(body, "instructions", ()) or ())
            remaining = max_instructions - totals["instructions_counted"]
            counted = parsed_instructions[:remaining]
            metrics = _instruction_metrics(counted)
            method.update(metrics)
            method["body_size"] = int(getattr(body, "size", header_size + code_size))
            method["parse_status"] = "parsed"
            if len(parsed_instructions) > len(counted):
                method["parse_status"] = "parsed_partial_instruction_budget"
                budget_exhausted.append("instructions")
            totals["methods_parsed"] += 1
            for key in (
                "branches",
                "switches",
                "switch_targets",
                "calls",
                "calli",
                "ldstr",
                "constant_loads",
            ):
                totals[key] += metrics[key]
            totals["instructions_counted"] += metrics["instructions"]
            proxy = (
                name not in {".ctor", ".cctor"}
                and metrics["instructions"] <= 8
                and metrics["calls"] + metrics["calli"] == 1
                and metrics["switches"] == 0
                and metrics["branches"] <= 1
            )
            method["proxy_candidate"] = proxy
            if proxy:
                totals["proxy_method_candidates"] += 1
            if metrics["max_switch_targets"] >= dispatcher_switch_targets:
                candidate = {
                    "token": method["token"],
                    "sample_sha256": result["sha256"],
                    "owner": method["owner"],
                    "name": method["name"],
                    "max_switch_targets": metrics["max_switch_targets"],
                    "instruction_count": metrics["instructions"],
                    "reason": "high_fanout_switch_candidate_not_confirmed_flattening",
                }
                candidate["semantic_shape_review"] = (
                    _known_semantic_dispatch_shape(candidate) or "unclassified"
                )
                result["dispatcher_candidates"].append(candidate)
        except Exception as error:
            method["parse_status"] = "malformed_body"
            method["parse_error"] = type(error).__name__
            totals["malformed_method_bodies"] += 1
            result["malformed_method_bodies"].append(
                {
                    "token": method["token"],
                    "owner": method["owner"],
                    "name": method["name"],
                    "rva": method["rva"],
                    "parse_error": type(error).__name__,
                }
            )
        result["methods"].append(method)

    metadata_table_errors.extend(result["metadata_scan"].get("metadata_table_errors", []))
    result["metadata_table_errors"] = metadata_table_errors[:32]
    result["metadata_table_errors_truncated"] = len(metadata_table_errors) > 32
    result["counts"] = totals
    result["techniques"] = _assess_techniques(
        marker_hits, totals, result["dispatcher_candidates"], resources
    )
    result["budget_exhausted"] = sorted(set(budget_exhausted))
    result["status"] = "analyzed_partial_budget" if result["budget_exhausted"] else "analyzed"
    result["static_method_plan"] = plan_managed_methods(result)
    return result


def plan_managed_methods(result: dict[str, Any]) -> list[dict[str, Any]]:
    """Return an ordered, static-only deep-analysis plan for a triage result."""
    plan: list[dict[str, Any]] = []
    safety = [
        "do_not_CLR_load_or_execute",
        "do_not_emulate_CIL",
        "do_not_contact_network",
        "keep_recovered_bytes_in_memory_or_quarantine_only",
    ]

    def add(method: str, reason: str, expected: str) -> None:
        plan.append(
            {
                "order": len(plan) + 1,
                "method": method,
                "reason": reason,
                "expected_output": expected,
                "safety_constraints": safety,
            }
        )

    status = result.get("status")
    if status in {"dependency_missing", "parse_failed", "not_managed_pe", "input_budget_exceeded"}:
        add(
            "metadata_integrity_and_cross_parser_validation",
            f"managed parsing did not complete ({status})",
            "validated CLR header/stream boundaries or an explicit non-managed conclusion",
        )
        return plan

    add(
        "metadata_token_and_il_inventory_review",
        "establish trustworthy TypeDef/MethodDef ownership and malformed-body boundaries",
        "reviewed token map, method-body coverage, and bounded parse gaps",
    )
    techniques = result.get("techniques", {})
    suspected = lambda name: techniques.get(name, {}).get("status") == "suspected"
    if suspected("koi_vm"):
        add(
            "koi_vm_runtime_and_vm_data_mapping",
            "KoiVM marker material was observed but does not by itself prove virtualization",
            "static runtime type map, VM-data resource hashes, handler candidates, and unresolved limits",
        )
    protector_markers = [
        name for name in ("confuserex", "dotnet_reactor", "smartassembly") if suspected(name)
    ]
    if protector_markers:
        add(
            "protector_specific_metadata_pattern_review",
            f"marker candidates: {', '.join(protector_markers)}",
            "marker provenance and protector-specific static hypotheses without attribution",
        )
    if suspected("managed_control_flow_flattening"):
        add(
            "il_dispatcher_state_variable_recovery",
            "high-fanout switch methods may be flattened dispatchers",
            "switch target graph, state definitions/uses, opaque-edge pruning, and reconstructed CFG",
        )
    if suspected("method_proxy_obfuscation"):
        add(
            "proxy_call_graph_collapse",
            "many small single-call methods may obscure call relationships",
            "token-preserving proxy map and collapsed static call graph",
        )
    if suspected("constant_obfuscation"):
        add(
            "constant_dataflow_and_pure_transform_reconstruction",
            "constant-load density suggests values may be assembled through IL dataflow",
            "SSA-like constant propagation and reviewed pure-transform pseudocode without CLR execution",
        )
    if suspected("resource_obfuscation") or result.get("resources"):
        add(
            "resource_reference_and_decryption_dataflow",
            "embedded resource hashes should be linked to GetManifestResourceStream and transform callers",
            "resource-to-method xrefs, static transform parameters, hashes, entropy, and recovery limits",
        )
    add(
        "independent_static_decompiler_cross_check",
        "cross-check dncil token/branch counts before accepting reconstructed logic",
        "agreement and conflicts among raw IL, a static decompiler, and manual metadata review",
    )
    return plan


def _reject_input_output_alias(input_path: Path, output_path: Path) -> None:
    """Reject output paths resolving to the same file as the inert input."""
    source = input_path.resolve(strict=True)
    destination = output_path.resolve(strict=False)
    aliases = source == destination
    if output_path.exists():
        try:
            aliases = aliases or input_path.samefile(output_path)
        except OSError:
            pass
    if aliases:
        raise ValueError("input and output must not resolve to the same file")


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser for bounded managed-IL triage."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="managed PE to read as inert bytes")
    parser.add_argument("--output", required=True, type=Path, help="JSON report path")
    parser.add_argument("--max-input-bytes", type=int, default=DEFAULT_MAX_INPUT_BYTES)
    parser.add_argument("--max-types", type=int, default=DEFAULT_MAX_TYPES)
    parser.add_argument("--max-methods", type=int, default=DEFAULT_MAX_METHODS)
    parser.add_argument("--max-instructions", type=int, default=DEFAULT_MAX_INSTRUCTIONS)
    parser.add_argument("--max-method-bytes", type=int, default=DEFAULT_MAX_METHOD_BYTES)
    parser.add_argument("--max-metadata-strings", type=int, default=DEFAULT_MAX_METADATA_STRINGS)
    parser.add_argument("--max-metadata-string-bytes", type=int, default=DEFAULT_MAX_METADATA_STRING_BYTES)
    parser.add_argument("--max-metadata-scan-bytes", type=int, default=DEFAULT_MAX_METADATA_SCAN_BYTES)
    parser.add_argument("--max-resources", type=int, default=DEFAULT_MAX_RESOURCES)
    parser.add_argument("--max-resource-bytes", type=int, default=DEFAULT_MAX_RESOURCE_BYTES)
    parser.add_argument(
        "--dispatcher-switch-targets", type=int, default=DEFAULT_DISPATCHER_SWITCH_TARGETS
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run static managed-IL triage and write a metadata-only JSON report."""
    parser = build_parser()
    args = parser.parse_args(argv)
    _reject_input_output_alias(args.input, args.output)
    budgets = {
        "max_input_bytes": args.max_input_bytes,
        "max_types": args.max_types,
        "max_methods": args.max_methods,
        "max_instructions": args.max_instructions,
        "max_method_bytes": args.max_method_bytes,
        "max_metadata_strings": args.max_metadata_strings,
        "max_metadata_string_bytes": args.max_metadata_string_bytes,
        "max_metadata_scan_bytes": args.max_metadata_scan_bytes,
        "max_resources": args.max_resources,
        "max_resource_bytes": args.max_resource_bytes,
        "dispatcher_switch_targets": args.dispatcher_switch_targets,
    }
    if args.input.stat().st_size > args.max_input_bytes:
        result = _base_result(args.input.stat().st_size)
        result["status"] = "input_budget_exceeded"
        result["budgets"] = {
            **budgets,
            "instruction_budget_semantics": INSTRUCTION_BUDGET_NOTE,
        }
        result["limitations"] = [INSTRUCTION_BUDGET_NOTE]
        result["budget_exhausted"] = ["input_bytes"]
        result["static_method_plan"] = plan_managed_methods(result)
    else:
        result = analyze_managed_pe(args.input.read_bytes(), **budgets)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "output": str(args.output),
                "status": result["status"],
                "methods": result.get("counts", {}).get("methods_enumerated", 0),
                "executed": False,
                "emulated": False,
                "network_contacted": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
