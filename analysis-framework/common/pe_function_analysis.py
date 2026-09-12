#!/usr/bin/env python3
"""PEの代表関数候補とprocess挙動を有界な静的解析だけで整理する。"""

from __future__ import annotations

import hashlib
import re
from collections import deque
from collections.abc import Mapping, Sequence
from typing import Any

try:
    import pefile
except ImportError:  # pragma: no cover - dependency state is returned in the report
    pefile = None

from unpackers import static_control_flow

SCHEMA_VERSION = 1
MAX_INPUT_BYTES = 128 * 1024 * 1024
MAX_PROGRAMS = 8
MAX_IMPORTS = 4_096
MAX_DISCOVERED_FUNCTIONS = 64
MAX_REPRESENTATIVE_FUNCTIONS = 16
MAX_FUNCTION_BLOCKS = 256
MAX_FUNCTION_INSTRUCTIONS = 4_096
MAX_FUNCTION_BLOCK_BYTES = 2_048
MAX_TOTAL_FUNCTION_INSTRUCTIONS = 50_000
MAX_AGGREGATE_CALL_SITES = 512
_EXECUTE = 0x20000000
_SAFE_IDENTIFIER = re.compile(r"[^A-Za-z0-9_.$?@#-]+")


_BEHAVIOR_RULES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    (
        "process_creation",
        re.compile(
            r"(?i)^(?:createprocess(?:asuser|withlogon|withtoken)?[aw]?|"
            r"shellexecute(?:ex)?[aw]?|winexec)$"
        ),
        "process起動APIに到達する静的call-siteまたはimportを確認しました。",
    ),
    (
        "remote_process_access_or_injection",
        re.compile(
            r"(?i)^(?:openprocess|virtualallocex|virtualprotectex|"
            r"writeprocessmemory|readprocessmemory|createremotethread(?:ex)?|"
            r"ntcreatethreadex|queueuserapc|ntqueueapcthread|setthreadcontext|"
            r"resumethread|ntmapviewofsection|mapviewoffile(?:ex)?|"
            r"unmapviewoffile|ntunmapviewofsection)$"
        ),
        "別processへのaccess、remote memory、またはthread実行に関係するAPIを確認しました。",
    ),
    (
        "memory_allocation_or_protection",
        re.compile(
            r"(?i)^(?:virtualalloc|virtualprotect|heapalloc|heaprealloc|"
            r"rtlallocateheap|ntallocatevirtualmemory|ntprotectvirtualmemory)$"
        ),
        "local memoryの確保または保護属性変更に関係するAPIを確認しました。",
    ),
    (
        "process_discovery_or_control",
        re.compile(
            r"(?i)^(?:createtoolhelp32snapshot|process32(?:first|next)[aw]?|"
            r"enumprocesses|enumprocessmodules|queryfullprocessimagename[aw]?|"
            r"terminateprocess|ntqueryinformationprocess)$"
        ),
        "process列挙、照会、または制御に関係するAPIを確認しました。",
    ),
    (
        "persistence_capability",
        re.compile(
            r"(?i)^(?:reg(?:create|open|set|delete)value?(?:ex)?[aw]?|"
            r"createservice[aw]?|startservice[aw]?|openscmanager[aw]?|"
            r"changeserviceconfig[aw]?|cocreateinstance)$"
        ),
        "永続化に利用され得るregistryまたはservice APIを確認しました。",
    ),
    (
        "network_communication",
        re.compile(
            r"(?i)^(?:wsastartup|socket|connect|send|recv|select|getaddrinfo|"
            r"gethostbyname|inet_addr|dnsquery[aw]?|internet[a-z0-9_]*[aw]?|"
            r"winhttp[a-z0-9_]*[aw]?|urldownloadtofile[aw]?)$"
        ),
        "network初期化、名前解決、または送受信APIを確認しました。",
    ),
    (
        "file_activity",
        re.compile(
            r"(?i)^(?:createfile[aw]?|readfile|writefile|deletefile[aw]?|"
            r"movefile(?:ex)?[aw]?|copyfile(?:ex)?[aw]?|findfirstfile[aw]?|"
            r"findnextfile[aw]?|setfileattributes[aw]?)$"
        ),
        "fileの作成、読書き、列挙、移動、または削除APIを確認しました。",
    ),
    (
        "anti_analysis_timing_or_debug",
        re.compile(
            r"(?i)^(?:isdebuggerpresent|checkremotedebuggerpresent|"
            r"outputdebugstring[aw]?|queryperformancecounter|gettickcount(?:64)?|"
            r"sleep(?:ex)?)$"
        ),
        "debugger確認または時間差に利用され得るAPIを確認しました。",
    ),
)


def _safe_identifier(value: object, default: str) -> str:
    """PE由来の識別子を制御文字や区切り文字のない有界値へ変換する。"""

    if isinstance(value, bytes):
        text = value.decode("ascii", errors="replace")
    else:
        try:
            text = str(value or "")
        except Exception:  # noqa: BLE001 - attacker-controlled __str__ boundary
            return default
    text = _SAFE_IDENTIFIER.sub("_", text).strip("._-")[:256]
    return text or default


def _network_api_module_matches(module_name: str, api_name: str) -> bool:
    """一般名のcustom exportをnetwork APIと誤認しないようmoduleを照合する。"""

    module = module_name.casefold()
    api = api_name.casefold()
    if api.startswith("winhttp"):
        return module == "winhttp.dll"
    if api.startswith("internet"):
        return module == "wininet.dll"
    if api.startswith("dnsquery"):
        return module == "dnsapi.dll"
    if api.startswith("urldownloadtofile"):
        return module == "urlmon.dll"
    return module in {"ws2_32.dll", "wsock32.dll"}


def _behavior_categories(module_name: str, api_name: str) -> list[str]:
    """moduleとAPI名の組に該当する挙動候補IDを返す。"""

    output: list[str] = []
    for identifier, pattern, _ in _BEHAVIOR_RULES:
        if not pattern.fullmatch(api_name):
            continue
        if identifier == "network_communication" and not _network_api_module_matches(
            module_name,
            api_name,
        ):
            continue
        output.append(identifier)
    return output


def _parse_import_target(value: object) -> tuple[str, str]:
    """静的CFGのimport labelを公開可能なmodule/APIへ分離する。"""

    raw = str(value or "")
    module, separator, api = raw.partition("!")
    if not separator:
        api = module
        module = "unknown_module"
    return _safe_identifier(module, "unknown_module"), _safe_identifier(api, "unknown_api")


def _base_program(program_selector: str, relationship: str, depth: int) -> dict[str, Any]:
    return {
        "program_selector": program_selector,
        "relationship": relationship,
        "depth": depth,
        "status": "not_started",
        "architecture": "unknown",
        "entry_point": None,
        "imports": [],
        "import_count": 0,
        "import_inventory_truncated": False,
        "function_inventory": [],
        "representative_functions": [],
        "call_sites": [],
        "process_behavior": [],
        "coverage": {
            "discovered_function_count": 0,
            "attempted_function_count": 0,
            "unattempted_function_count": 0,
            "representative_function_count": 0,
            "all_discovered_functions_attempted": False,
            "call_site_inventory_truncated": False,
            "function_discovery_truncated": False,
            "function_analysis_budget_exhausted": False,
        },
        "completion_contract": {
            "satisfies_reviewed_function_analysis_gate": False,
            "requires_independent_reviewed_function_logic": True,
            "reason": "bounded_disassembly_candidate_evidence_is_not_reviewed_function_logic",
        },
        "safety": {
            "sample_executed": False,
            "sample_emulated": False,
            "network_contacted": False,
            "raw_pseudocode_exported": False,
        },
    }


def _pe_layout(data: bytes) -> dict[str, Any]:
    """PE mappingとimport thunkを静的解析用の内部表現へ変換する。"""

    if pefile is None:
        return {"status": "dependency_unavailable", "error_type": "ImportError"}
    try:
        image = pefile.PE(data=data, fast_load=True)
    except Exception as error:  # noqa: BLE001 - pefile parser boundary
        return {"status": "parse_failed", "error_type": type(error).__name__}
    try:
        machine = int(image.FILE_HEADER.Machine)
        bits = {0x14C: 32, 0x8664: 64}.get(machine)
        if bits is None:
            return {"status": "unsupported_architecture", "machine": hex(machine)}
        entry_point = int(image.OPTIONAL_HEADER.AddressOfEntryPoint)
        mappings: list[tuple[int, int, int]] = []
        for section in image.sections:
            start = int(section.VirtualAddress)
            raw_offset = int(section.PointerToRawData)
            raw_size = min(int(section.SizeOfRawData), max(0, len(data) - raw_offset))
            virtual_size = int(section.Misc_VirtualSize)
            executable = bool(int(section.Characteristics) & _EXECUTE)
            if raw_size and (executable or start <= entry_point < start + max(raw_size, virtual_size)):
                mappings.append((start, raw_offset, raw_size))

        import_parse_status = "not_attempted"
        try:
            image.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            import_parse_status = "parsed"
        except Exception:  # noqa: BLE001 - partial PE import tables are expected
            import_parse_status = "parse_failed"
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
        import_entries: list[dict[str, Any]] = []
        known_targets: dict[int, str] = {}
        raw_import_count = 0
        for descriptor in getattr(image, "DIRECTORY_ENTRY_IMPORT", []):
            module = _safe_identifier(getattr(descriptor, "dll", b""), "unknown_module")
            for imported in getattr(descriptor, "imports", []):
                raw_import_count += 1
                raw_name = getattr(imported, "name", None)
                api = _safe_identifier(
                    raw_name if raw_name else f"ordinal_{getattr(imported, 'ordinal', 'unknown')}",
                    "unknown_api",
                )
                try:
                    address = int(imported.address)
                except (AttributeError, TypeError, ValueError):
                    address = -1
                label = f"{module}!{api}"
                if address >= 0:
                    known_targets[address] = label
                    if address >= image_base:
                        known_targets[address - image_base] = label
                if len(import_entries) < MAX_IMPORTS:
                    import_entries.append({"module": module, "api": api})
        return {
            "status": "parsed",
            "bits": bits,
            "entry_point": entry_point,
            "mappings": sorted(set(mappings)),
            "imports": import_entries,
            "import_count": raw_import_count,
            "import_inventory_truncated": raw_import_count > len(import_entries),
            "import_parse_status": import_parse_status,
            "known_targets": known_targets,
            "is_dotnet": bool(image.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress),
        }
    except Exception as error:  # noqa: BLE001 - malformed optional headers are parser failures
        return {"status": "parse_failed", "error_type": type(error).__name__}
    finally:
        close = getattr(image, "close", None)
        if callable(close):
            close()


def _call_sites(function_id: str, metrics: Mapping[str, Any]) -> list[dict[str, Any]]:
    """一関数のimport call/jump siteを安全な機械可読recordへ変換する。"""

    output: list[dict[str, Any]] = []
    values = metrics.get("indirect_transfer_sites", [])
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        return output
    for item in values:
        if not isinstance(item, Mapping) or item.get("classification") != "reviewed_import_thunk":
            continue
        module, api = _parse_import_target(item.get("target"))
        output.append(
            {
                "function_id": function_id,
                "address": str(item.get("address") or "unknown"),
                "transfer_kind": str(item.get("kind") or "indirect_transfer"),
                "target_module": module,
                "target_api": api,
                "behavior_candidates": _behavior_categories(module, api),
                "confidence": "confirmed_static_reachable_import_thunk_reference",
                "runtime_execution_confirmed": False,
            }
        )
    return output


def _direct_targets(metrics: Mapping[str, Any]) -> list[str]:
    """mapped executable領域を指すdirect call targetだけを返す。"""

    values = metrics.get("direct_call_sites", [])
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes, bytearray)):
        return []
    return list(
        dict.fromkeys(
            str(item.get("target"))
            for item in values
            if isinstance(item, Mapping)
            and item.get("classification") == "mapped_internal_candidate"
            and isinstance(item.get("target"), str)
        )
    )


def _role_for_record(record: Mapping[str, Any], *, entry_point: bool) -> tuple[str, str]:
    categories = {
        category
        for site in record.get("import_call_sites", [])
        if isinstance(site, Mapping)
        for category in site.get("behavior_candidates", [])
        if isinstance(category, str)
    }
    if entry_point:
        return "entrypoint", "confirmed_address_role_only"
    if categories.intersection(
        {
            "process_creation",
            "remote_process_access_or_injection",
            "memory_allocation_or_protection",
        }
    ):
        return "process_or_memory_operation_candidate", "automated_reachable_api_callsite_candidate"
    if "network_communication" in categories:
        return "network_communication_candidate", "automated_reachable_api_callsite_candidate"
    if "persistence_capability" in categories:
        return "persistence_candidate", "automated_reachable_api_callsite_candidate"
    if "file_activity" in categories:
        return "file_operation_candidate", "automated_reachable_api_callsite_candidate"
    if "anti_analysis_timing_or_debug" in categories:
        return "anti_analysis_candidate", "automated_reachable_api_callsite_candidate"
    return "general_internal_logic_candidate", "automated_static_structure_only"


def _selection_score(record: Mapping[str, Any], *, entry_id: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    if record.get("function_id") == entry_id:
        score += 10_000
        reasons.append("entry_point")
    call_sites = record.get("import_call_sites", [])
    behavior_count = sum(
        len(item.get("behavior_candidates", []))
        for item in call_sites
        if isinstance(item, Mapping)
    )
    if behavior_count:
        score += 3_000 + min(1_000, behavior_count * 100)
        reasons.append("reachable_behavior_api_callsite")
    in_degree = len(record.get("callers", []))
    out_degree = len(record.get("callees", []))
    if in_degree or out_degree:
        score += min(2_000, (in_degree + out_degree) * 100)
        reasons.append(f"call_graph_centrality:in={in_degree},out={out_degree}")
    instructions = int(record.get("control_flow", {}).get("instruction_count", 0))
    if instructions:
        score += min(1_500, instructions)
        if instructions >= 64:
            reasons.append("large_function_candidate")
    if not reasons:
        reasons.append("reachable_context_candidate")
    return score, reasons


def _select_representatives(records: list[dict[str, Any]], entry_id: str) -> list[dict[str, Any]]:
    """entry、挙動role、中心性、規模から決定的な代表候補を選ぶ。"""

    ranked: list[dict[str, Any]] = []
    for record in records:
        score, reasons = _selection_score(record, entry_id=entry_id)
        record["selection"] = {
            "selected": False,
            "score": score,
            "reasons": reasons,
        }
        ranked.append(record)
    ranked.sort(key=lambda item: (-int(item["selection"]["score"]), str(item["function_id"])))
    selected: dict[str, dict[str, Any]] = {}
    role_order = (
        "entrypoint",
        "process_or_memory_operation_candidate",
        "network_communication_candidate",
        "persistence_candidate",
        "file_operation_candidate",
        "anti_analysis_candidate",
    )
    for role in role_order:
        match = next((item for item in ranked if item.get("role") == role), None)
        if match is not None:
            selected[str(match["function_id"])] = match
    for item in ranked:
        if len(selected) >= MAX_REPRESENTATIVE_FUNCTIONS:
            break
        selected.setdefault(str(item["function_id"]), item)
    for item in records:
        item["selection"]["selected"] = str(item["function_id"]) in selected
    return [item for item in ranked if item["selection"]["selected"]]


def _process_behavior(
    imports: Sequence[Mapping[str, Any]],
    call_sites: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """import-only能力とentry到達call-siteを混同せず挙動候補を集約する。"""

    output: list[dict[str, Any]] = []
    for identifier, pattern, description in _BEHAVIOR_RULES:
        imported_apis = sorted(
            {
                str(item.get("api"))
                for item in imports
                if isinstance(item, Mapping)
                and pattern.fullmatch(str(item.get("api") or ""))
                and (
                    identifier != "network_communication"
                    or _network_api_module_matches(
                        str(item.get("module") or "unknown_module"),
                        str(item.get("api") or ""),
                    )
                )
            }
        )
        observed = [
            dict(item)
            for item in call_sites
            if isinstance(item, Mapping)
            and identifier in item.get("behavior_candidates", [])
        ]
        if not imported_apis and not observed:
            continue
        assessment = "reachable_call_site_observed" if observed else "import_only_capability"
        output.append(
            {
                "behavior": identifier,
                "assessment": assessment,
                "summary_ja": description,
                "apis": sorted(set(imported_apis) | {str(item["target_api"]) for item in observed}),
                "function_ids": sorted({str(item["function_id"]) for item in observed}),
                "call_site_count": len(observed),
                "call_sites": observed,
                "confidence": (
                    "confirmed_static_reachable_callsite_not_runtime_execution"
                    if observed
                    else "confirmed_import_presence_not_execution"
                ),
                "runtime_execution_confirmed": False,
            }
        )
    return output


def analyze_pe(
    data: bytes,
    *,
    program_selector: str,
    relationship: str,
    depth: int,
) -> dict[str, Any]:
    """一つのPEを実行せず、代表関数候補とprocess挙動候補を抽出する。"""

    result = _base_program(program_selector, relationship, depth)
    if not isinstance(data, bytes):
        raise TypeError("data must be immutable bytes")
    if len(data) > MAX_INPUT_BYTES:
        result["status"] = "input_budget_exceeded"
        return result
    layout = _pe_layout(data)
    if layout.get("status") != "parsed":
        result["status"] = str(layout.get("status") or "parse_failed")
        if layout.get("error_type"):
            result["error_type"] = str(layout["error_type"])
        return result

    bits = int(layout["bits"])
    entry_point = int(layout["entry_point"])
    result["architecture"] = f"x86-{bits}"
    result["entry_point"] = hex(entry_point)
    result["imports"] = layout["imports"]
    result["import_count"] = int(layout["import_count"])
    result["import_inventory_truncated"] = bool(layout["import_inventory_truncated"])
    result["import_parse_status"] = str(layout["import_parse_status"])
    result["managed_pe"] = bool(layout["is_dotnet"])

    queue: deque[int] = deque([entry_point])
    queued = {entry_point}
    attempted: list[dict[str, Any]] = []
    total_instructions = 0
    discovery_truncated = False
    call_site_discovery_truncated = False
    while queue and len(attempted) < MAX_DISCOVERED_FUNCTIONS:
        function_address = queue.popleft()
        remaining = MAX_TOTAL_FUNCTION_INSTRUCTIONS - total_instructions
        if remaining <= 0:
            discovery_truncated = True
            break
        function_id = f"pe-rva:{hex(function_address)}"
        try:
            analysis = static_control_flow._analyze_mapped_code(
                data,
                list(layout["mappings"]),
                function_address,
                bits,
                {
                    "format": "pe_function_candidate",
                    "is_dotnet": bool(layout["is_dotnet"]),
                    "imports": int(layout["import_count"]),
                    "entrypoint_high_entropy": False,
                    "high_entropy_executable_sections": [],
                    "packer_markers": [],
                    "virtualized_shape": False,
                },
                MAX_FUNCTION_BLOCKS,
                min(MAX_FUNCTION_INSTRUCTIONS, remaining),
                MAX_FUNCTION_BLOCK_BYTES,
                dict(layout["known_targets"]),
            )
        except Exception as error:  # noqa: BLE001 - Capstone parser boundary
            analysis = {"status": "analysis_failed", "error_type": type(error).__name__}
        metrics = analysis.get("metrics") if isinstance(analysis.get("metrics"), Mapping) else {}
        call_site_discovery_truncated = call_site_discovery_truncated or bool(
            metrics.get("direct_call_site_inventory_truncated")
            or metrics.get("indirect_transfer_site_inventory_truncated")
        )
        instruction_count = int(metrics.get("instructions") or 0)
        total_instructions += instruction_count
        sites = _call_sites(function_id, metrics)
        direct_targets = _direct_targets(metrics)
        record: dict[str, Any] = {
            "function_id": function_id,
            "address_or_token": hex(function_address),
            "role": "unclassified_candidate",
            "role_confidence": "automated_static_structure_only",
            "summary_ja": "候補entryから到達可能なcodeを上限付きで再帰disassemblyした結果です。",
            "logic_steps_ja": [
                "候補entryから到達可能な基本blockを静的に列挙します。",
                "direct call targetとimport thunk参照を分離して記録します。",
                "未解決の間接遷移と解析上限を未完了理由として保持します。",
            ],
            "callers": [],
            "callees": [f"pe-rva:{target}" for target in direct_targets],
            "api_calls": sorted({str(item["target_api"]) for item in sites}),
            "import_call_sites": sites,
            "control_flow": {
                "basic_block_count": int(metrics.get("basic_blocks") or 0),
                "instruction_count": instruction_count,
                "conditional_branch_count": int(metrics.get("conditional_branches") or 0),
                "strongly_connected_component_count": int(
                    metrics.get("strongly_connected_components") or 0
                ),
                "call_count": int(metrics.get("calls") or 0),
                "unresolved_indirect_transfer_count": int(metrics.get("unexplained_indirect_transfers") or 0),
            },
            "analysis_attempt": {
                "status": str(analysis.get("status") or "analysis_failed"),
                "method": "bounded_capstone_recursive_cfg",
                "body_scope": "candidate_entry_reachable_cfg_until_return_or_budget",
                "error_type": str(analysis.get("error_type")) if analysis.get("error_type") else None,
                "next_step_ja": (
                    "Ghidra MCPで明示的なprogram selectorを指定し、関数境界、call graph、"
                    "逆コンパイル結果、引数と戻り値の利用を確認してください。"
                ),
            },
        }
        role, confidence = _role_for_record(record, entry_point=function_address == entry_point)
        record["role"] = role
        record["role_confidence"] = confidence
        attempted.append(record)
        for target in direct_targets:
            try:
                address = int(target, 16)
            except ValueError:
                continue
            if address not in queued:
                if len(queued) >= MAX_DISCOVERED_FUNCTIONS:
                    discovery_truncated = True
                    continue
                queued.add(address)
                queue.append(address)
    if queue:
        discovery_truncated = True

    by_id = {str(item["function_id"]): item for item in attempted}
    for item in attempted:
        for callee in item["callees"]:
            if callee in by_id:
                by_id[callee]["callers"].append(str(item["function_id"]))
    for item in attempted:
        item["callers"] = sorted(set(item["callers"]))
        item["callees"] = sorted({callee for callee in item["callees"] if callee in by_id})

    entry_id = f"pe-rva:{hex(entry_point)}"
    representatives = _select_representatives(attempted, entry_id)
    aggregate_sites = [
        dict(site)
        for record in attempted
        for site in record["import_call_sites"]
    ]
    retained_sites = aggregate_sites[:MAX_AGGREGATE_CALL_SITES]
    result["function_inventory"] = [
        {
            "function_id": item["function_id"],
            "address_or_token": item["address_or_token"],
            "analysis_status": item["analysis_attempt"]["status"],
            "role": item["role"],
            "instruction_count": item["control_flow"]["instruction_count"],
            "caller_count": len(item["callers"]),
            "callee_count": len(item["callees"]),
            "import_call_site_count": len(item["import_call_sites"]),
            "selected_as_representative": item["selection"]["selected"],
        }
        for item in attempted
    ]
    attempted_ids = {str(item["function_id"]) for item in attempted}
    result["function_inventory"].extend(
        {
            "function_id": f"pe-rva:{hex(address)}",
            "address_or_token": hex(address),
            "analysis_status": "not_attempted_global_budget",
            "role": "unclassified_candidate",
            "instruction_count": 0,
            "caller_count": 0,
            "callee_count": 0,
            "import_call_site_count": 0,
            "selected_as_representative": False,
        }
        for address in sorted(queued)
        if f"pe-rva:{hex(address)}" not in attempted_ids
    )
    result["representative_functions"] = representatives
    result["call_sites"] = retained_sites
    result["process_behavior"] = _process_behavior(layout["imports"], retained_sites)
    result["coverage"] = {
        "discovered_function_count": len(queued),
        "attempted_function_count": len(attempted),
        "unattempted_function_count": max(0, len(queued) - len(attempted)),
        "representative_function_count": len(representatives),
        "all_discovered_functions_attempted": len(attempted) == len(queued) and not discovery_truncated,
        "call_site_inventory_truncated": (
            call_site_discovery_truncated or len(aggregate_sites) > len(retained_sites)
        ),
        "function_discovery_truncated": discovery_truncated or call_site_discovery_truncated,
        "function_analysis_budget_exhausted": (
            total_instructions >= MAX_TOTAL_FUNCTION_INSTRUCTIONS
            or any(item["analysis_attempt"]["status"] == "budget_exhausted" for item in attempted)
        ),
        "total_instruction_count": total_instructions,
    }
    result["selection_policy"] = {
        "name": "entry_behavior_callgraph_size_candidates",
        "maximum_representative_functions": MAX_REPRESENTATIVE_FUNCTIONS,
        "dimensions": [
            "entry_point",
            "reachable_behavior_api_callsite",
            "call_graph_centrality",
            "function_size",
        ],
        "addresses_are_candidates_not_validated_function_boundaries": True,
    }
    partial = (
        result["import_parse_status"] != "parsed"
        or result["import_inventory_truncated"]
        or result["coverage"]["call_site_inventory_truncated"]
        or result["coverage"]["function_discovery_truncated"]
        or result["coverage"]["function_analysis_budget_exhausted"]
        or any(item["analysis_attempt"]["status"] != "analyzed" for item in attempted)
    )
    result["status"] = "candidate_evidence_partial" if partial else "candidate_evidence_collected"
    return result


def _selected_layer_indices(layers: Sequence[Any]) -> tuple[list[int], int]:
    """rootを保持しつつ深いPE層を優先する決定的な解析対象集合を返す。"""

    eligible = [
        index
        for index, layer in enumerate(layers)
        if isinstance(getattr(layer, "data", None), bytes)
        and layer.data.startswith(b"MZ")
    ]
    if len(eligible) <= MAX_PROGRAMS:
        return eligible, len(eligible)
    selected: list[int] = []
    if 0 in eligible:
        selected.append(0)
    ranked = sorted(
        eligible,
        key=lambda index: (-int(getattr(layers[index], "depth", 0)), index),
    )
    for index in ranked:
        if index not in selected:
            selected.append(index)
        if len(selected) >= MAX_PROGRAMS:
            break
    return selected, len(eligible)


def build_static_layer_report(
    programs: Sequence[Mapping[str, Any]],
    *,
    eligible_pe_layer_count: int,
    assessment_only: bool = False,
) -> dict[str, Any]:
    """事前選択済みPEの解析結果を、安全契約付きの集計へ変換する。"""

    if (
        isinstance(eligible_pe_layer_count, bool)
        or not isinstance(eligible_pe_layer_count, int)
        or eligible_pe_layer_count < 0
        or eligible_pe_layer_count < len(programs)
        or len(programs) > MAX_PROGRAMS
        or (assessment_only and (programs or eligible_pe_layer_count))
        or any(not isinstance(item, Mapping) for item in programs)
    ):
        raise ValueError("preselected PE program report contract is invalid")
    document: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "analysis_mode": "bounded_static_disassembly_only",
        "status": "not_run_assessment_only" if assessment_only else "not_applicable",
        "programs": [],
        "counts": {
            "eligible_pe_layer_count": 0,
            "selected_pe_layer_count": 0,
            "analyzed_program_count": 0,
            "representative_function_candidate_count": 0,
            "import_count": 0,
            "call_site_count": 0,
            "process_behavior_count": 0,
        },
        "program_selection": {
            "policy": "root_then_deepest_then_discovery_order",
            "maximum_programs": MAX_PROGRAMS,
            "truncated": False,
            "artifact_name_or_hash_specific_exception_used": False,
        },
        "completion_contract": {
            "satisfies_reviewed_function_analysis_gate": False,
            "blocker_must_be_retained_without_independent_reviewed_functions": True,
            "required_gate": "validate_function_analysis.py",
            "reason": "automated_candidate_evidence_requires_independent_function_review",
        },
        "safety": {
            "sample_executed": False,
            "sample_emulated": False,
            "network_contacted": False,
            "raw_pseudocode_exported": False,
            "raw_endpoint_or_config_exported": False,
            "source_name_exported": False,
        },
    }
    if assessment_only:
        return document
    document["programs"] = [dict(item) for item in programs]
    counts = document["counts"]
    counts["eligible_pe_layer_count"] = eligible_pe_layer_count
    counts["selected_pe_layer_count"] = len(programs)
    document["program_selection"]["truncated"] = eligible_pe_layer_count > len(programs)
    counts["analyzed_program_count"] = sum(
        str(item.get("status", "")).startswith("candidate_evidence_") for item in programs
    )
    counts["representative_function_candidate_count"] = sum(
        len(item.get("representative_functions", [])) for item in programs
    )
    counts["import_count"] = sum(int(item.get("import_count") or 0) for item in programs)
    counts["call_site_count"] = sum(len(item.get("call_sites", [])) for item in programs)
    counts["process_behavior_count"] = sum(len(item.get("process_behavior", [])) for item in programs)
    if programs:
        partial = document["program_selection"]["truncated"] or any(
            item.get("status") != "candidate_evidence_collected" for item in programs
        )
        document["status"] = "candidate_evidence_partial" if partial else "candidate_evidence_collected"
    return document


def analyze_static_layers(
    layers: Sequence[Any],
    *,
    assessment_only: bool = False,
) -> dict[str, Any]:
    """one-shotのPE層を上限付きで解析し、公開可能な集計を返す。"""

    if assessment_only:
        return build_static_layer_report(
            [],
            eligible_pe_layer_count=0,
            assessment_only=True,
        )
    selected, eligible_count = _selected_layer_indices(layers)
    programs = []
    for index in selected:
        layer = layers[index]
        data = layer.data
        digest = hashlib.sha256(data).hexdigest()
        program = analyze_pe(
            data,
            program_selector=f"sha256:{digest}",
            relationship="root_program" if index == 0 else "statically_recovered_program",
            depth=int(getattr(layer, "depth", 0)),
        )
        programs.append(program)
    return build_static_layer_report(
        programs,
        eligible_pe_layer_count=eligible_count,
    )
