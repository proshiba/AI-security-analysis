"""Unit tests for bounded execution-free control-flow triage."""

from __future__ import annotations

import json
from pathlib import Path
import struct

import pytest

from unpackers import static_control_flow as control_flow


def minimal_pe(code: bytes, *, machine: int = 0x14C) -> bytes:
    """Build a small PE32 fixture whose entry point contains *code*."""
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 4, 0x200)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<I", data, optional + 24, 0x2000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200 : 0x200 + len(code)] = code
    return bytes(data)


def marked_pe(code: bytes, marker: bytes) -> bytes:
    """Return a PE fixture with a non-executable protector marker."""
    data = bytearray(minimal_pe(code))
    data[0x380 : 0x380 + len(marker)] = marker
    return bytes(data)


def test_raw_cfg_and_provable_local_predicate() -> None:
    """Recover both edges and prove an adjacent XOR/JNE predicate is false."""
    result = control_flow.analyze_code_region(b"\x31\xc0\x75\x02\xc3\x90\xc3", bits=32)
    assert result["status"] == "analyzed"
    assert result["executed"] is False and result["emulated"] is False
    assert result["metrics"]["basic_blocks"] == 3
    assert result["metrics"]["constant_branch_evidence"][0]["proved_outcome"] == "never_taken"
    assert result["techniques"]["provable_local_opaque_predicates"]["confidence"] == "high"


def test_overlap_budget_and_validation() -> None:
    """Expose conflicting branch boundaries and enforce public budgets."""
    result = control_flow.analyze_code_region(b"\x75\x01\xb8\x90\xc3\x00\x00\xc3", bits=32)
    assert result["metrics"]["overlapping_instruction_events"] >= 1
    bounded = control_flow.analyze_code_region(b"\x75\x01\xc3\xc3", bits=32, max_blocks=1)
    assert bounded["status"] == "budget_exhausted"
    duplicate_edge = control_flow.analyze_code_region(b"\x74\x00\xc3", bits=32)
    assert duplicate_edge["metrics"]["known_edges"] == 1
    assert duplicate_edge["metrics"]["max_indegree"] == 1
    assert duplicate_edge["metrics"]["hub_incoming_edge_ratio"] == 1.0
    with pytest.raises(ValueError):
        control_flow.analyze_code_region(b"", bits=32)
    with pytest.raises(ValueError):
        control_flow.analyze_code_region(b"\xc3", bits=16)
    with pytest.raises(ValueError):
        control_flow.analyze_code_region(b"\xc3", entry_offset=2)

    limited = control_flow.analyze_code_region(b"\xc3\xc3", max_input_bytes=1)
    assert limited["status"] == "input_budget_exceeded"
    with pytest.raises(ValueError):
        control_flow.analyze_code_region(b"\xc3", max_input_bytes=0)


def test_pe_structural_mode_and_parse_failures() -> None:
    """Analyze mapped PE entry code and retain conservative static context."""
    result = control_flow.analyze_pe_control_flow(minimal_pe(b"\x31\xc0\xc3"))
    assert result["status"] == "analyzed"
    assert result["entry_address"] == "0x1000"
    assert result["static_context"]["entrypoint_section"] == ".text"
    assert result["static_context"]["large_file_structural_mode"] is False
    overlay_marker = control_flow.analyze_pe_control_flow(minimal_pe(b"\xc3") + b"UPX!")
    assert overlay_marker["static_context"]["packer_markers"] == []
    assert control_flow.analyze_pe_control_flow(b"MZbad")["status"] == "parse_failed"
    unsupported = control_flow.analyze_pe_control_flow(minimal_pe(b"\xc3", machine=0x1C0))
    assert unsupported["status"] == "unsupported_architecture"
    limited = control_flow.analyze_pe_control_flow(minimal_pe(b"\xc3"), max_input_bytes=10)
    assert limited["status"] == "input_budget_exceeded"


def test_method_plan_and_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Route each suspected technique and exercise raw-code JSON output."""
    names = (
        "anti_disassembly_or_overlapping_code",
        "provable_local_opaque_predicates",
        "control_flow_flattening",
        "indirect_branch_obfuscation",
        "virtual_machine_or_protector_dispatch",
        "managed_loader_obfuscation",
    )
    analysis = {
        "static_context": {"is_dotnet": True, "packer_markers": ["Themida"]},
        "techniques": {name: {"status": "suspected"} for name in names},
    }
    methods = {item["method"] for item in control_flow.plan_static_methods(analysis)}
    assert "dispatcher_and_state_variable_recovery" in methods
    assert "static_vm_handler_table_and_semantic_clustering" in methods
    assert "managed_metadata_il_and_resource_dataflow" in methods
    source = tmp_path / "code.bin"
    output = tmp_path / "report.json"
    source.write_bytes(b"\xc3")
    args = ["--input", str(source), "--output", str(output), "--raw-bits", "32"]
    assert control_flow.build_parser().parse_args(args).raw_bits == 32
    assert control_flow.main(args) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["network_contacted"] is False
    assert "output" in capsys.readouterr().out


    original = source.read_bytes()
    with pytest.raises(ValueError, match="paths must differ"):
        control_flow.main(
            [
                "--input", str(source), "--output", str(source), "--raw-bits", "32"
            ]
        )
    assert source.read_bytes() == original

def test_large_scc_inventory_is_iterative() -> None:
    """Avoid recursion failure on a long adversarial CFG chain."""
    nodes = set(range(2000))
    adjacency = {index: {index + 1} for index in range(1999)}
    adjacency[1999] = {0}
    components = control_flow._strongly_connected_components(nodes, adjacency)
    assert len(components) == 1 and len(components[0]) == 2000


def test_clr_thunk_and_compressor_stubs_are_not_cff_attribution() -> None:
    """Keep CLR/import thunks and known compressor stubs out of CFF claims."""
    metrics = {
        "basic_blocks": 1,
        "branch_instructions": 1,
        "max_indegree": 0,
        "hub_incoming_edge_ratio": 0.0,
        "largest_scc": 1,
        "cyclomatic_complexity": 1,
        "constant_branch_evidence": [],
        "indirect_branches": 1,
        "indirect_calls": 0,
        "calls": 0,
        "unresolved_successors": 1,
        "overlapping_instruction_events": 0,
        "decode_failures": 0,
        "stop_mnemonics": {},
        "anti_analysis_mnemonics": {},
        "stack_pointer_writes": 0,
        "instructions": 1,
    }
    managed = control_flow._assess_techniques(
        metrics,
        {
            "is_dotnet": True,
            "entrypoint_high_entropy": False,
            "high_entropy_executable_sections": [],
            "imports": 1,
            "packer_markers": [],
            "virtualized_shape": False,
        },
    )
    assert managed["indirect_branch_obfuscation"]["status"] == "not_evaluable"
    assert managed["virtual_machine_or_protector_dispatch"]["status"] == "not_evaluable"

    packed_metrics = dict(metrics)
    packed_metrics.update(
        basic_blocks=20,
        branch_instructions=20,
        max_indegree=8,
        hub_incoming_edge_ratio=0.4,
        largest_scc=10,
        cyclomatic_complexity=18,
        indirect_branches=8,
        instructions=80,
    )
    packed = control_flow._assess_techniques(
        packed_metrics,
        {
            "is_dotnet": False,
            "entrypoint_high_entropy": True,
            "high_entropy_executable_sections": ["UPX1"],
            "imports": 1,
            "packer_markers": ["UPX!"],
            "virtualized_shape": False,
        },
    )
    assert packed["control_flow_flattening"]["status"] == "confounded"
    assert packed["indirect_branch_obfuscation"]["status"] == "confounded"
    assert packed["virtual_machine_or_protector_dispatch"]["status"] == "confounded"

    protected_context = {
        "is_dotnet": False,
        "entrypoint_high_entropy": True,
        "high_entropy_executable_sections": [".text"],
        "imports": 1,
        "packer_markers": ["Themida"],
        "virtualized_shape": True,
    }
    protected = control_flow._assess_techniques(packed_metrics, protected_context)
    assert protected["control_flow_flattening"]["status"] == "confounded"
    # Themida is a protector-routing hint, so independently scored VM-like
    # evidence remains suspected rather than being erased as a compressor stub.
    assert protected["virtual_machine_or_protector_dispatch"]["status"] == "suspected"

    decoy = control_flow._assess_techniques(
        packed_metrics,
        {
            "is_dotnet": False,
            "entrypoint_high_entropy": False,
            "high_entropy_executable_sections": [],
            "imports": 8,
            "packer_markers": ["Enigma"],
            "virtualized_shape": False,
            "stub_structure_corroborated": False,
        },
    )
    assert decoy["control_flow_flattening"]["status"] == "suspected"
    assert decoy["indirect_branch_obfuscation"]["status"] == "suspected"
