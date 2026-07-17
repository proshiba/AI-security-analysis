#!/usr/bin/env python3
"""Bounded, execution-free control-flow triage for native PE and raw code.

The module deliberately performs disassembly only.  It never maps a sample as an
executable, emulates instructions, resolves network infrastructure, or mutates a
binary.  Its technique labels are conservative prioritization hints, not proof
that a particular commercial protector or obfuscator was used.
"""

from __future__ import annotations

import argparse
from collections import Counter, deque
import hashlib
import json
import math
from pathlib import Path
import re
from typing import Any

try:
    import capstone
    from capstone import x86_const
except ImportError:  # pragma: no cover - exercised through dependency status
    capstone = None
    x86_const = None

try:
    import pefile
except ImportError:  # pragma: no cover - exercised through dependency status
    pefile = None

DEFAULT_MAX_INPUT_BYTES = 256 * 1024 * 1024

DEFAULT_MAX_BLOCKS = 4096
DEFAULT_MAX_INSTRUCTIONS = 50_000
DEFAULT_MAX_BLOCK_BYTES = 4096
MAX_EVIDENCE = 32
_EXECUTE = 0x20000000
_UNCONDITIONAL_JUMPS = {"jmp", "ljmp"}
_STOP_MNEMONICS = {"hlt", "ud2", "int3", "sysret", "sysexit", "iret", "iretd", "iretq"}
_ANTI_ANALYSIS_MNEMONICS = {"cpuid", "rdtsc", "rdtscp", "sidt", "sgdt", "sldt", "str", "in", "out"}
_STACK_POINTERS = {"sp", "esp", "rsp"}


def _entropy(data: bytes | memoryview) -> float:
    """Return Shannon entropy for a bounded byte view."""
    if not data:
        return 0.0
    view = bytes(data)
    if len(view) > 3 * 1024 * 1024:
        window = 1024 * 1024
        middle = max(0, (len(view) - window) // 2)
        view = view[:window] + view[middle : middle + window] + view[-window:]
    counts = Counter(view)
    total = len(view)
    return round(-sum((count / total) * math.log2(count / total) for count in counts.values()), 4)


def _dependency_report() -> dict[str, Any]:
    """Describe optional parser/disassembler availability."""
    return {
        "capstone": getattr(capstone, "__version__", None) if capstone else None,
        "pefile": getattr(pefile, "__version__", None) if pefile else None,
    }


def _disassembler(bits: int):
    """Create a detailed x86 Capstone disassembler for *bits*."""
    if capstone is None:
        return None
    mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
    engine = capstone.Cs(capstone.CS_ARCH_X86, mode)
    engine.detail = True
    return engine


def _mapped_slice(
    data: bytes,
    mappings: list[tuple[int, int, int]],
    address: int,
    limit: int,
) -> bytes:
    """Return bytes mapped at a virtual address without copying whole sections."""
    for start, file_offset, length in mappings:
        if start <= address < start + length:
            relative = address - start
            available = min(limit, length - relative)
            return data[file_offset + relative : file_offset + relative + available]
    return b""


def _mapped_address(mappings: list[tuple[int, int, int]], address: int) -> bool:
    """Return whether an address lies in a mapped executable byte interval."""
    return any(start <= address < start + length for start, _, length in mappings)


def _direct_target(instruction: Any) -> int | None:
    """Return the immediate target of a branch/call, if one exists."""
    try:
        if instruction.operands and instruction.operands[0].type == x86_const.X86_OP_IMM:
            return int(instruction.operands[0].imm)
    except (AttributeError, IndexError, TypeError):
        return None
    return None


def _same_register_operands(op_str: str) -> bool:
    """Recognize two identical simple register operands."""
    operands = [value.strip().lower() for value in op_str.split(",")]
    if len(operands) != 2:
        return False
    register = re.fullmatch(r"(?:r(?:1[0-5]|[0-9])(?:d|w|b)?|[re]?(?:ax|bx|cx|dx|si|di|bp|sp)|[abcd][lh])", operands[0])
    return bool(register and operands[0] == operands[1])


def _constant_branch_evidence(previous: Any | None, branch: Any) -> dict[str, Any] | None:
    """Identify a small, provable set of immediately constant x86 branches."""
    if previous is None:
        return None
    branch_name = branch.mnemonic.lower()
    producer = previous.mnemonic.lower()
    if producer not in {"xor", "sub", "cmp"} or not _same_register_operands(previous.op_str):
        return None
    if branch_name in {"je", "jz"}:
        outcome = "always_taken"
    elif branch_name in {"jne", "jnz"}:
        outcome = "never_taken"
    else:
        return None
    return {
        "branch_address": hex(int(branch.address)),
        "producer_address": hex(int(previous.address)),
        "producer": f"{previous.mnemonic} {previous.op_str}".strip(),
        "branch": f"{branch.mnemonic} {branch.op_str}".strip(),
        "proved_outcome": outcome,
        "scope": "adjacent_flag_producer_only",
    }


def _stack_pointer_write(instruction: Any) -> bool:
    """Recognize explicit unusual writes or exchanges involving SP/ESP/RSP."""
    mnemonic = instruction.mnemonic.lower()
    operands = [value.strip().lower() for value in instruction.op_str.split(",")]
    if mnemonic in {"mov", "lea", "xchg"} and operands:
        return operands[0] in _STACK_POINTERS or (mnemonic == "xchg" and any(value in _STACK_POINTERS for value in operands))
    return False


def _strongly_connected_components(
    nodes: set[int], adjacency: dict[int, set[int]]
) -> list[list[int]]:
    """Return iterative Kosaraju components without recursion or graph packages."""
    reverse: dict[int, set[int]] = {node: set() for node in nodes}
    for source in nodes:
        for target in adjacency.get(source, set()):
            if target in nodes:
                reverse[target].add(source)

    visited: set[int] = set()
    finish_order: list[int] = []
    for start in sorted(nodes):
        if start in visited:
            continue
        visited.add(start)
        stack: list[tuple[int, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                finish_order.append(node)
                continue
            stack.append((node, True))
            for successor in sorted(adjacency.get(node, set()), reverse=True):
                if successor in nodes and successor not in visited:
                    visited.add(successor)
                    stack.append((successor, False))

    components: list[list[int]] = []
    assigned: set[int] = set()
    for start in reversed(finish_order):
        if start in assigned:
            continue
        component: list[int] = []
        stack = [start]
        assigned.add(start)
        while stack:
            node = stack.pop()
            component.append(node)
            for predecessor in reverse.get(node, set()):
                if predecessor not in assigned:
                    assigned.add(predecessor)
                    stack.append(predecessor)
        components.append(sorted(component))
    return components


def _technique(status: str, confidence: str, score: int, evidence: list[str]) -> dict[str, Any]:
    """Build one normalized conservative technique assessment."""
    return {
        "status": status,
        "confidence": confidence,
        "score": max(0, min(100, int(score))),
        "evidence": evidence,
        "interpretation": "prioritization_hint_not_protector_attribution",
    }


def _assess_techniques(metrics: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
    """Convert CFG and PE observations into explainable technique hypotheses."""
    blocks = metrics["basic_blocks"]
    branches = metrics["branch_instructions"]
    max_indegree = metrics["max_indegree"]
    hub_ratio = metrics["hub_incoming_edge_ratio"]
    largest_scc = metrics["largest_scc"]
    complexity_density = metrics["cyclomatic_complexity"] / max(1, blocks)

    cff_score = 0
    cff_evidence: list[str] = []
    if blocks >= 12:
        cff_score += 10
        cff_evidence.append(f"reachable blocks={blocks}")
    if max_indegree >= 4:
        cff_score += min(30, 15 + (max_indegree - 4) * 3)
        cff_evidence.append(f"dispatcher-like maximum indegree={max_indegree}")
    if hub_ratio >= 0.20:
        cff_score += min(25, round(hub_ratio * 80))
        cff_evidence.append(f"hub receives {hub_ratio:.1%} of known CFG edges")
    if largest_scc >= 4:
        cff_score += min(20, 8 + largest_scc)
        cff_evidence.append(f"largest strongly connected component={largest_scc}")
    if complexity_density >= 0.25:
        cff_score += 15
        cff_evidence.append(f"cyclomatic/block density={complexity_density:.2f}")
    cff_status = "suspected" if cff_score >= 55 else "not_observed"

    opaque_count = len(metrics["constant_branch_evidence"])
    opaque_score = min(100, opaque_count * 35)
    opaque_status = "suspected" if opaque_count else "not_observed"
    opaque_evidence = [
        f"{item['branch_address']} {item['proved_outcome']} after {item['producer']}"
        for item in metrics["constant_branch_evidence"][:8]
    ]

    indirect = metrics["indirect_branches"] + metrics["indirect_calls"]
    indirect_ratio = indirect / max(1, branches + metrics["calls"])
    indirect_score = 0
    indirect_evidence: list[str] = []
    if indirect >= 3:
        indirect_score += min(55, indirect * 8)
        indirect_evidence.append(f"indirect control transfers={indirect}")
    if indirect_ratio >= 0.10:
        indirect_score += min(35, round(indirect_ratio * 100))
        indirect_evidence.append(f"indirect transfer ratio={indirect_ratio:.1%}")
    if metrics["unresolved_successors"]:
        indirect_score += 10
        indirect_evidence.append(f"unresolved successors={metrics['unresolved_successors']}")
    indirect_status = "suspected" if indirect_score >= 45 else "not_observed"

    overlap_count = metrics["overlapping_instruction_events"]
    decode_failures = metrics["decode_failures"]
    anti_score = min(60, overlap_count * 15) + min(30, decode_failures * 3)
    anti_evidence: list[str] = []
    if overlap_count:
        anti_evidence.append(f"overlapping instruction/target events={overlap_count}")
    if decode_failures:
        anti_evidence.append(f"reachable decode failures={decode_failures}")
    if metrics["stop_mnemonics"]:
        anti_score += min(10, sum(metrics["stop_mnemonics"].values()) * 2)
        anti_evidence.append(f"trap/stop mnemonics={metrics['stop_mnemonics']}")
    anti_status = "suspected" if anti_score >= 30 else "not_observed"

    vm_score = 0
    vm_evidence: list[str] = []
    if indirect_status == "suspected":
        vm_score += 25
        vm_evidence.extend(indirect_evidence[:2])
    if context.get("entrypoint_high_entropy"):
        vm_score += 20
        vm_evidence.append("entrypoint lies in a high-entropy executable section")
    import_count = context.get("imports")
    if isinstance(import_count, int) and import_count <= 2:
        vm_score += 15
        vm_evidence.append(f"very small import surface={import_count}")
    anti_count = sum(metrics["anti_analysis_mnemonics"].values())
    if anti_count:
        vm_score += min(20, 5 + anti_count * 3)
        vm_evidence.append(f"anti-analysis-sensitive instructions={metrics['anti_analysis_mnemonics']}")
    if metrics["stack_pointer_writes"]:
        vm_score += min(15, metrics["stack_pointer_writes"] * 3)
        vm_evidence.append(f"explicit stack-pointer mutations={metrics['stack_pointer_writes']}")
    if overlap_count:
        vm_score += min(15, overlap_count * 3)
    if context.get("virtualized_shape"):
        vm_score += 20
        vm_evidence.append("PE layout matches the existing virtualized-shape heuristic")
    vm_status = "suspected" if vm_score >= 55 else "not_observed"

    managed_score = 65 if context.get("is_dotnet") and context.get("high_entropy_executable_sections") else 0
    managed_evidence = []
    if managed_score:
        managed_evidence.append("CLR metadata present with high-entropy executable code/resource carrier")

    # A normal managed PE commonly reaches the CLR through a one-instruction
    # native import thunk.  Treating that indirect jump as an obfuscating
    # dispatcher is a category error: the code to inspect is CIL/resources,
    # not the native bootstrap.  Preserve an explicit, machine-readable
    # distinction between "not observed" and "not evaluable here".
    clr_entry_thunk = bool(
        context.get("is_dotnet")
        and blocks <= 2
        and metrics["instructions"] <= 4
    )
    if clr_entry_thunk:
        thunk_evidence = "bounded native entry is a CLR bootstrap thunk; route to managed IL/resource analysis"
        cff_status = "not_evaluable"
        cff_evidence = [thunk_evidence]
        indirect_status = "not_evaluable"
        indirect_evidence = [thunk_evidence]
        anti_status = "not_evaluable"
        anti_evidence = [thunk_evidence]
        vm_status = "not_evaluable"
        vm_evidence = [thunk_evidence]

    # Known packer, protector, and container stubs have dispatcher-like loops
    # and sparse imports of their own.  Those observations route to layer
    # recovery; they do not prove classic CFF in the protected payload.
    stub_markers = {
        str(value).upper()
        for value in context.get("packer_markers", [])
        if str(value).upper()
        in {
            "UPX!",
            "MPRESS",
            "THEMIDA",
            "WINLICENSE",
            "VMPROTECT",
            "ENIGMA",
            "NSPACK",
            "NULLSOFT",
        }
    }
    stub_structure_corroborated = bool(
        context.get("stub_structure_corroborated")
        or context.get("entrypoint_high_entropy")
        or context.get("virtualized_shape")
    )
    if stub_markers and stub_structure_corroborated and not clr_entry_thunk:
        marker_text = ", ".join(sorted(stub_markers))
        confounder = f"entry CFG is confounded by a known packer/protector/container stub: {marker_text}"
        if cff_status == "suspected":
            cff_status = "confounded"
            cff_evidence.append(confounder)
        if indirect_status == "suspected":
            indirect_status = "confounded"
            indirect_evidence.append(confounder)
        # A compressor/SFX dispatcher is not VM evidence.  Protector markers
        # retain a VM routing hypothesis when independent VM metrics exist.
        compression_or_container = stub_markers.intersection({"UPX!", "MPRESS", "NULLSOFT"})
        if vm_status == "suspected" and compression_or_container:
            vm_status = "confounded"
            vm_evidence.append(confounder)

    return {
        "control_flow_flattening": _technique(cff_status, "medium" if cff_score >= 75 else "low", cff_score, cff_evidence),
        "provable_local_opaque_predicates": _technique(opaque_status, "high" if opaque_count else "none", opaque_score, opaque_evidence),
        "indirect_branch_obfuscation": _technique(indirect_status, "medium" if indirect_score >= 70 else "low", indirect_score, indirect_evidence),
        "anti_disassembly_or_overlapping_code": _technique(anti_status, "medium" if anti_score >= 60 else "low", anti_score, anti_evidence),
        "virtual_machine_or_protector_dispatch": _technique(vm_status, "medium" if vm_score >= 75 else "low", vm_score, vm_evidence),
        "managed_loader_obfuscation": _technique("suspected" if managed_score else "not_observed", "low" if managed_score else "none", managed_score, managed_evidence),
    }


def plan_static_methods(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    """Return an ordered, execution-free method plan for an analysis result."""
    techniques = analysis.get("techniques", {})
    context = analysis.get("static_context", {})
    plan: list[dict[str, Any]] = [
        {
            "order": 1,
            "method": "bounded_recursive_cfg_baseline",
            "purpose": "Separate reachable code from data and record unresolved indirect successors.",
            "success_evidence": "stable block/edge inventory within explicit budgets",
        }
    ]

    def suspected(name: str) -> bool:
        return techniques.get(name, {}).get("status") == "suspected"

    if suspected("anti_disassembly_or_overlapping_code"):
        plan.append({
            "order": 0,
            "method": "recursive_disassembly_with_context_repairs",
            "purpose": "Validate branch targets, split overlapping streams, and avoid linear-sweep data decoding.",
            "success_evidence": "conflicting instruction boundaries are enumerated and each path has an explicit context",
        })
    if suspected("provable_local_opaque_predicates"):
        plan.append({
            "order": 0,
            "method": "backward_flag_slice_and_predicate_proof",
            "purpose": "Prove branch outcomes from SSA/P-code definitions before pruning an edge.",
            "success_evidence": "predicate is constant for all values reaching the branch; otherwise retain both edges",
        })
    if suspected("control_flow_flattening"):
        plan.extend([
            {
                "order": 0,
                "method": "dispatcher_and_state_variable_recovery",
                "purpose": "Rank high-indegree SCC hubs and slice assignments to the dispatcher state.",
                "success_evidence": "state values map original blocks to deterministic successor blocks",
            },
            {
                "order": 0,
                "method": "abstract_interpretation_then_bounded_smt",
                "purpose": "Propagate constants/ranges first; send only residual predicates to an offline solver.",
                "success_evidence": "all pruned transitions have reproducible proofs and a before/after CFG diff",
            },
        ])
    if suspected("indirect_branch_obfuscation"):
        plan.append({
            "order": 0,
            "method": "backward_slice_indirect_targets",
            "purpose": "Recover jump-table bases, index bounds, and target transforms without executing code.",
            "success_evidence": "every added target is backed by a table entry or a solved expression",
        })
    if suspected("virtual_machine_or_protector_dispatch"):
        plan.append({
            "order": 0,
            "method": "static_vm_handler_table_and_semantic_clustering",
            "purpose": "Identify fetch/decode/dispatch loops, recover handler addresses, and group handlers by data-flow semantics.",
            "success_evidence": "bytecode format and handler effects are documented; unsupported runtime-derived state remains unresolved",
        })
    if suspected("managed_loader_obfuscation") or context.get("is_dotnet"):
        plan.append({
            "order": 0,
            "method": "managed_metadata_il_and_resource_dataflow",
            "purpose": "Recover manifest resources and build IL CFG/constant propagation before inspecting native stubs.",
            "success_evidence": "resource decoder inputs and IL call chain are reproduced from metadata and method bodies",
        })
    if context.get("packer_markers"):
        plan.append({
            "order": 0,
            "method": "protector_version_specific_static_recipe",
            "purpose": "Treat marker strings as routing hints and validate the version/layout before applying a recipe.",
            "success_evidence": "recovered image has coherent sections/imports/relocations and a new SHA-256",
        })
    plan.append({
        "order": 0,
        "method": "ghidra_pcode_ssa_validation",
        "purpose": "Cross-check repaired edges, definitions, references, and decompiler output with an explicit program selector.",
        "success_evidence": "renames/comments and CFG claims are tied to addresses; arbitrary Ghidra script execution remains disabled",
    })
    for index, item in enumerate(plan, start=1):
        item["order"] = index
    return plan


def _analyze_mapped_code(
    data: bytes,
    mappings: list[tuple[int, int, int]],
    entry_address: int,
    bits: int,
    context: dict[str, Any],
    max_blocks: int,
    max_instructions: int,
    max_block_bytes: int,
) -> dict[str, Any]:
    """Build a bounded recursive-descent CFG over explicitly mapped code bytes."""
    dependencies = _dependency_report()
    if capstone is None:
        return {
            "schema_version": 1,
            "status": "dependency_unavailable",
            "dependencies": dependencies,
            "executed": False,
            "emulated": False,
            "network_contacted": False,
            "static_context": context,
            "techniques": {},
            "method_plan": [],
        }
    if bits not in {32, 64}:
        raise ValueError("bits must be 32 or 64")
    if min(max_blocks, max_instructions, max_block_bytes) <= 0:
        raise ValueError("analysis budgets must be positive")
    if not _mapped_address(mappings, entry_address):
        return {
            "schema_version": 1,
            "status": "entrypoint_unmapped",
            "dependencies": dependencies,
            "executed": False,
            "emulated": False,
            "network_contacted": False,
            "entry_address": hex(entry_address),
            "static_context": context,
            "techniques": {},
            "method_plan": [],
        }

    engine = _disassembler(bits)
    frontier = deque([entry_address])
    queued = {entry_address}
    blocks: dict[int, dict[str, Any]] = {}
    edges: set[tuple[int, int, str]] = set()
    instruction_starts: dict[int, int] = {}
    byte_owner: dict[int, int] = {}
    branch_targets: set[int] = set()
    opaque_evidence: list[dict[str, Any]] = []
    overlap_evidence: list[dict[str, Any]] = []
    mnemonics: Counter[str] = Counter()
    anti_mnemonics: Counter[str] = Counter()
    stop_mnemonics: Counter[str] = Counter()
    instruction_count = 0
    decode_failures = 0
    conditional_branches = 0
    unconditional_branches = 0
    indirect_branches = 0
    calls = 0
    indirect_calls = 0
    returns = 0
    stack_pointer_writes = 0
    unresolved_successors = 0
    budget_exhausted = False

    def enqueue(target: int, source: int, edge_kind: str) -> None:
        nonlocal unresolved_successors
        if not _mapped_address(mappings, target):
            unresolved_successors += 1
            return
        owner = byte_owner.get(target)
        if owner is not None and owner != target and len(overlap_evidence) < MAX_EVIDENCE:
            overlap_evidence.append({"source": hex(source), "target": hex(target), "containing_instruction": hex(owner), "kind": "branch_target_inside_instruction"})
        edges.add((source, target, edge_kind))
        branch_targets.add(target)
        if target not in queued and target not in blocks:
            frontier.append(target)
            queued.add(target)

    while frontier and len(blocks) < max_blocks and instruction_count < max_instructions:
        start = frontier.popleft()
        if start in blocks:
            continue
        code = _mapped_slice(data, mappings, start, max_block_bytes)
        if not code:
            decode_failures += 1
            continue
        block_instruction_count = 0
        block_end = start
        terminator = "decode_stop"
        previous = None
        terminated = False
        for instruction in engine.disasm(code, start):
            if instruction_count >= max_instructions:
                budget_exhausted = True
                break
            if instruction.address != block_end:
                decode_failures += 1
                break
            owner_conflicts = {
                byte_owner[address]
                for address in range(instruction.address, instruction.address + instruction.size)
                if address in byte_owner and byte_owner[address] != instruction.address
            }
            if owner_conflicts and len(overlap_evidence) < MAX_EVIDENCE:
                overlap_evidence.append({
                    "address": hex(int(instruction.address)),
                    "existing_instruction_starts": [hex(value) for value in sorted(owner_conflicts)],
                    "kind": "overlapping_decode",
                })
            instruction_starts[instruction.address] = instruction.size
            for address in range(instruction.address, instruction.address + instruction.size):
                byte_owner.setdefault(address, instruction.address)
            instruction_count += 1
            block_instruction_count += 1
            block_end = instruction.address + instruction.size
            mnemonic = instruction.mnemonic.lower()
            mnemonics[mnemonic] += 1
            if mnemonic in _ANTI_ANALYSIS_MNEMONICS:
                anti_mnemonics[mnemonic] += 1
            if _stack_pointer_write(instruction):
                stack_pointer_writes += 1

            is_jump = instruction.group(capstone.CS_GRP_JUMP)
            is_call = instruction.group(capstone.CS_GRP_CALL)
            is_return = instruction.group(capstone.CS_GRP_RET)
            if is_call:
                calls += 1
                if _direct_target(instruction) is None:
                    indirect_calls += 1
            if is_jump:
                target = _direct_target(instruction)
                if mnemonic in _UNCONDITIONAL_JUMPS:
                    unconditional_branches += 1
                    if target is None:
                        indirect_branches += 1
                        unresolved_successors += 1
                    else:
                        enqueue(target, start, "jump")
                else:
                    conditional_branches += 1
                    proof = _constant_branch_evidence(previous, instruction)
                    if proof and len(opaque_evidence) < MAX_EVIDENCE:
                        opaque_evidence.append(proof)
                    if target is None:
                        indirect_branches += 1
                        unresolved_successors += 1
                    else:
                        enqueue(target, start, "conditional_taken")
                    enqueue(block_end, start, "conditional_fallthrough")
                terminator = f"{instruction.mnemonic} {instruction.op_str}".strip()
                terminated = True
                break
            if is_return:
                returns += 1
                terminator = instruction.mnemonic
                terminated = True
                break
            if mnemonic in _STOP_MNEMONICS or instruction.group(capstone.CS_GRP_INT):
                stop_mnemonics[mnemonic] += 1
                terminator = instruction.mnemonic
                terminated = True
                break
            previous = instruction
        if block_instruction_count == 0:
            decode_failures += 1
        elif not terminated and instruction_count < max_instructions:
            next_bytes = _mapped_slice(data, mappings, block_end, 1)
            if next_bytes and block_end - start >= max_block_bytes:
                enqueue(block_end, start, "budget_split")
                terminator = "max_block_bytes"
            elif next_bytes:
                decode_failures += 1
                terminator = "undecodable_or_truncated"
        blocks[start] = {
            "address": hex(start),
            "end": hex(block_end),
            "size": max(0, block_end - start),
            "instruction_count": block_instruction_count,
            "terminator": terminator,
        }

    if frontier or len(blocks) >= max_blocks or instruction_count >= max_instructions:
        budget_exhausted = True

    known_nodes = set(blocks)
    adjacency: dict[int, set[int]] = {node: set() for node in known_nodes}
    indegree: Counter[int] = Counter()
    for source, target, _ in edges:
        if source in known_nodes and target in known_nodes:
            adjacency[source].add(target)
    for targets in adjacency.values():
        indegree.update(targets)
    components = _strongly_connected_components(known_nodes, adjacency)
    largest_scc = max((len(value) for value in components), default=0)
    known_edges = sum(len(value) for value in adjacency.values())
    max_indegree = max(indegree.values(), default=0)
    hub = min((node for node in known_nodes if indegree[node] == max_indegree), default=None)
    hub_ratio = (max_indegree / known_edges) if known_edges else 0.0
    cyclomatic = max(0, known_edges - len(known_nodes) + (2 if known_nodes else 0))
    dispatcher_candidates = []
    component_by_node = {
        node: len(component)
        for component in components
        for node in component
    }
    for node in sorted(known_nodes, key=lambda value: (-indegree[value], value))[:16]:
        incoming_ratio = indegree[node] / max(1, known_edges)
        score = min(40, indegree[node] * 7) + min(25, round(incoming_ratio * 100))
        score += 20 if component_by_node.get(node, 0) >= 4 else 0
        score += 15 if len(adjacency.get(node, set())) >= 2 else 0
        if indegree[node] >= 3 or score >= 45:
            dispatcher_candidates.append({
                "address": hex(node),
                "score": min(100, score),
                "indegree": indegree[node],
                "outdegree": len(adjacency.get(node, set())),
                "scc_size": component_by_node.get(node, 1),
                "incoming_edge_ratio": round(incoming_ratio, 4),
            })

    metrics = {
        "basic_blocks": len(blocks),
        "known_edges": known_edges,
        "instructions": instruction_count,
        "branch_instructions": conditional_branches + unconditional_branches,
        "conditional_branches": conditional_branches,
        "unconditional_branches": unconditional_branches,
        "indirect_branches": indirect_branches,
        "calls": calls,
        "indirect_calls": indirect_calls,
        "returns": returns,
        "unresolved_successors": unresolved_successors,
        "decode_failures": decode_failures,
        "overlapping_instruction_events": len(overlap_evidence),
        "overlap_evidence": overlap_evidence,
        "constant_branch_evidence": opaque_evidence,
        "anti_analysis_mnemonics": dict(sorted(anti_mnemonics.items())),
        "stop_mnemonics": dict(sorted(stop_mnemonics.items())),
        "stack_pointer_writes": stack_pointer_writes,
        "cyclomatic_complexity": cyclomatic,
        "strongly_connected_components": len(components),
        "largest_scc": largest_scc,
        "max_indegree": max_indegree,
        "hub_address": hex(hub) if hub is not None else None,
        "hub_incoming_edge_ratio": round(hub_ratio, 4),
        "dispatcher_candidates": dispatcher_candidates,
        "top_mnemonics": dict(mnemonics.most_common(24)),
    }
    techniques = _assess_techniques(metrics, context)
    result = {
        "schema_version": 1,
        "status": "budget_exhausted" if budget_exhausted else "analyzed",
        "dependencies": dependencies,
        "architecture": f"x86-{bits}",
        "entry_address": hex(entry_address),
        "budgets": {
            "max_blocks": max_blocks,
            "max_instructions": max_instructions,
            "max_block_bytes": max_block_bytes,
            "exhausted": budget_exhausted,
        },
        "executed": False,
        "emulated": False,
        "network_contacted": False,
        "static_context": context,
        "metrics": metrics,
        "techniques": techniques,
        "blocks": [blocks[address] for address in sorted(blocks)],
    }
    result["method_plan"] = plan_static_methods(result)
    return result


def analyze_code_region(
    data: bytes,
    *,
    bits: int = 64,
    base_address: int = 0,
    entry_offset: int = 0,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_block_bytes: int = DEFAULT_MAX_BLOCK_BYTES,
) -> dict[str, Any]:
    """Analyze a raw x86 code region using bounded recursive disassembly only."""
    if max_input_bytes < 1:
        raise ValueError("max_input_bytes must be positive")
    if len(data) > max_input_bytes:
        return {
            "schema_version": 1,
            "status": "input_budget_exceeded",
            "size": len(data),
            "budgets": {"max_input_bytes": max_input_bytes, "exhausted": True},
            "executed": False,
            "emulated": False,
            "network_contacted": False,
            "techniques": {},
            "method_plan": [],
        }
    if not data:
        raise ValueError("data must not be empty")
    if not 0 <= entry_offset < len(data):
        raise ValueError("entry_offset is outside data")
    context = {
        "format": "raw_code",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "is_dotnet": False,
        "imports": None,
        "entrypoint_high_entropy": _entropy(data) >= 7.2,
        "high_entropy_executable_sections": ["raw"] if _entropy(data) >= 7.2 else [],
        "packer_markers": [],
        "virtualized_shape": False,
    }
    return _analyze_mapped_code(
        data,
        [(base_address, 0, len(data))],
        base_address + entry_offset,
        bits,
        context,
        max_blocks,
        max_instructions,
        max_block_bytes,
    )


def analyze_pe_control_flow(
    data: bytes,
    *,
    max_blocks: int = DEFAULT_MAX_BLOCKS,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_block_bytes: int = DEFAULT_MAX_BLOCK_BYTES,
) -> dict[str, Any]:
    """Analyze the reachable native entry CFG of a PE without loading or running it."""
    if max_input_bytes < 1:
        raise ValueError("max_input_bytes must be positive")
    if len(data) > max_input_bytes:
        return {
            "schema_version": 1,
            "status": "input_budget_exceeded",
            "size": len(data),
            "budgets": {"max_input_bytes": max_input_bytes, "exhausted": True},
            "executed": False,
            "emulated": False,
            "network_contacted": False,
            "techniques": {},
            "method_plan": [],
        }
    dependencies = _dependency_report()
    if pefile is None:
        return {
            "schema_version": 1,
            "status": "dependency_unavailable",
            "dependencies": dependencies,
            "executed": False,
            "emulated": False,
            "network_contacted": False,
            "techniques": {},
            "method_plan": [],
        }
    try:
        image = pefile.PE(data=data, fast_load=False)
    except (pefile.PEFormatError, ValueError) as exc:
        return {
            "schema_version": 1,
            "status": "parse_failed",
            "error": type(exc).__name__,
            "dependencies": dependencies,
            "executed": False,
            "emulated": False,
            "network_contacted": False,
            "techniques": {},
            "method_plan": [],
        }
    machine = int(image.FILE_HEADER.Machine)
    bits_by_machine = {0x14C: 32, 0x8664: 64}
    bits = bits_by_machine.get(machine)
    if bits is None:
        return {
            "schema_version": 1,
            "status": "unsupported_architecture",
            "machine": hex(machine),
            "dependencies": dependencies,
            "executed": False,
            "emulated": False,
            "network_contacted": False,
            "techniques": {},
            "method_plan": [],
        }

    entrypoint = int(image.OPTIONAL_HEADER.AddressOfEntryPoint)
    mappings: list[tuple[int, int, int]] = []
    section_inventory: list[dict[str, Any]] = []
    entry_section = None
    high_entropy_exec: list[str] = []
    zero_raw_virtual = 0
    image_file_end = min(len(data), int(image.OPTIONAL_HEADER.SizeOfHeaders))
    for section in image.sections:
        name = section.Name.rstrip(b"\0").decode(errors="replace")
        start = int(section.VirtualAddress)
        raw_offset = int(section.PointerToRawData)
        raw_size = min(int(section.SizeOfRawData), max(0, len(data) - raw_offset))
        image_file_end = max(image_file_end, raw_offset + raw_size)
        virtual_size = int(section.Misc_VirtualSize)
        executable = bool(int(section.Characteristics) & _EXECUTE)
        section_entropy = _entropy(memoryview(data)[raw_offset : raw_offset + raw_size]) if raw_size else 0.0
        if raw_size == 0 and virtual_size >= 4096:
            zero_raw_virtual += 1
        if executable and raw_size:
            mappings.append((start, raw_offset, raw_size))
            if section_entropy >= 7.2:
                high_entropy_exec.append(name)
        if start <= entrypoint < start + max(raw_size, virtual_size):
            entry_section = name
            if raw_size and not executable:
                mappings.append((start, raw_offset, raw_size))
        section_inventory.append({
            "name": name,
            "rva": hex(start),
            "raw_size": raw_size,
            "virtual_size": virtual_size,
            "executable": executable,
            "entropy": section_entropy,
        })
    imports = sum(len(entry.imports) for entry in getattr(image, "DIRECTORY_ENTRY_IMPORT", []))
    import_names = sorted({
        (item.name or b"").decode(errors="replace")
        for entry in getattr(image, "DIRECTORY_ENTRY_IMPORT", [])
        for item in entry.imports
        if item.name
    })[:256]
    marker_probe = data[: min(len(data), image_file_end, 32 * 1024 * 1024)].lower()
    markers = [
        marker.decode()
        for marker in (
            b"UPX!",
            b"MPRESS",
            b"Themida",
            b"WinLicense",
            b"VMProtect",
            b"Enigma",
            b"nsPack",
            b"Nullsoft",
        )
        if marker.lower() in marker_probe
    ]
    is_dotnet = bool(image.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)
    entry_high_entropy = entry_section in high_entropy_exec
    virtualized_shape = imports <= 2 and zero_raw_virtual >= 4 and entry_high_entropy
    normalized_section_names = {name.upper() for name in (item["name"] for item in section_inventory)}
    known_stub_section = any(
        name.startswith(("UPX", ".MPRESS", ".THEMIDA", ".VMP", ".ENIGMA", ".NSP"))
        for name in normalized_section_names
    )
    stub_structure_corroborated = bool(
        entry_high_entropy or virtualized_shape or zero_raw_virtual or known_stub_section
    )
    context = {
        "format": "pe",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "machine": hex(machine),
        "is_dotnet": is_dotnet,
        "imports": imports,
        "import_names": import_names,
        "entrypoint_rva": hex(entrypoint),
        "entrypoint_section": entry_section,
        "entrypoint_high_entropy": entry_high_entropy,
        "high_entropy_executable_sections": high_entropy_exec,
        "zero_raw_virtual_sections": zero_raw_virtual,
        "packer_markers": markers,
        "stub_structure_corroborated": stub_structure_corroborated,
        "virtualized_shape": virtualized_shape,
        "sections": section_inventory,
        "large_file_structural_mode": len(data) > 32 * 1024 * 1024,
    }
    return _analyze_mapped_code(
        data,
        sorted(set(mappings)),
        entrypoint,
        bits,
        context,
        max_blocks,
        max_instructions,
        max_block_bytes,
    )


def build_parser() -> argparse.ArgumentParser:
    """Build the execution-free control-flow triage command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--raw-bits", type=int, choices=(32, 64))
    parser.add_argument("--entry-offset", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--base-address", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--max-blocks", type=int, default=DEFAULT_MAX_BLOCKS)
    parser.add_argument("--max-instructions", type=int, default=DEFAULT_MAX_INSTRUCTIONS)
    parser.add_argument("--max-input-bytes", type=int, default=DEFAULT_MAX_INPUT_BYTES)
    parser.add_argument("--max-block-bytes", type=int, default=DEFAULT_MAX_BLOCK_BYTES)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Analyze one PE or raw code file and emit JSON without executing it."""
    args = build_parser().parse_args(argv)
    if args.output and args.input.resolve() == args.output.resolve():
        raise ValueError("input and output paths must differ")
    common = {
        "max_blocks": args.max_blocks,
        "max_instructions": args.max_instructions,
        "max_block_bytes": args.max_block_bytes,
        "max_input_bytes": args.max_input_bytes,
    }
    input_size = args.input.stat().st_size
    if args.max_input_bytes < 1:
        raise ValueError("max_input_bytes must be positive")
    if input_size > args.max_input_bytes:
        result = {
            "schema_version": 1,
            "status": "input_budget_exceeded",
            "size": input_size,
            "budgets": {"max_input_bytes": args.max_input_bytes, "exhausted": True},
            "executed": False,
            "emulated": False,
            "network_contacted": False,
            "techniques": {},
            "method_plan": [],
        }
    elif args.raw_bits:
        data = args.input.read_bytes()
        result = analyze_code_region(
            data,
            bits=args.raw_bits,
            base_address=args.base_address,
            entry_offset=args.entry_offset,
            **common,
        )
    else:
        data = args.input.read_bytes()
        result = analyze_pe_control_flow(data, **common)
    rendered = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(json.dumps({"output": str(args.output), "status": result["status"]}))
    else:
        print(rendered, end="")
    failures = {
        "parse_failed", "dependency_unavailable", "input_budget_exceeded"
    }
    return 0 if result["status"] not in failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
