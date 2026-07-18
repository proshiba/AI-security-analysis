"""Tests for bounded static-only managed IL triage."""

from __future__ import annotations

import json
from pathlib import Path
import struct
from types import SimpleNamespace

import pytest

from unpackers import managed_il_triage as managed


class Table:
    """Small metadata-table stand-in."""

    def __init__(self, rows: list[object]):
        self.rows = rows
        self.num_rows = len(rows)


class StringsHeap:
    """Stand-in whose class name matches a bounded metadata stream type."""

    def __init__(self, offset: int, size: int):
        self.file_offset = offset
        self.struct = SimpleNamespace(Size=size)


def instruction(name: str, operand: object = None) -> SimpleNamespace:
    """Build a minimal dncil-like instruction."""
    return SimpleNamespace(opcode=SimpleNamespace(name=name), operand=operand)


def fake_managed_pe() -> tuple[bytes, object, object]:
    """Return inert bytes, a dnfile-like PE, and a bounded body reader."""
    data = bytearray(5_200)
    marker = b"KoiVM.Runtime\x00SmartAssembly.Attributes"
    data[8 : 8 + len(marker)] = marker

    resource = bytes(range(256)) * 16
    struct.pack_into("<I", data, 40, len(resource))
    data[44 : 44 + len(resource)] = resource

    rvas = [4_500, 4_550, 4_600, 4_650, 4_700]
    for identifier, rva in enumerate(rvas[:-1], 1):
        data[rva] = (10 << 2) | 2  # tiny header, ten declared code bytes
        data[rva + 1] = identifier
    data[rvas[-1]] = 0  # malformed method header

    method_rows = [
        SimpleNamespace(Name="Dispatch", Rva=rvas[0]),
        SimpleNamespace(Name="Proxy1", Rva=rvas[1]),
        SimpleNamespace(Name="Proxy2", Rva=rvas[2]),
        SimpleNamespace(Name="Proxy3", Rva=rvas[3]),
        SimpleNamespace(Name="Broken", Rva=rvas[4]),
    ]
    type_row = SimpleNamespace(
        TypeNamespace="KoiVM",
        TypeName="Runtime",
        MethodList=[SimpleNamespace(row_index=index) for index in range(1, 6)],
    )
    resource_row = SimpleNamespace(Name="payload.data", Offset=0, Implementation=None)
    tables = SimpleNamespace(
        TypeDef=Table([type_row]),
        TypeRef=Table([]),
        MethodDef=Table(method_rows),
        MemberRef=Table([]),
        Assembly=Table([SimpleNamespace(Name="Fixture")]),
        AssemblyRef=Table([]),
        Module=Table([]),
        ModuleRef=Table([]),
        ManifestResource=Table([resource_row]),
    )
    net = SimpleNamespace(
        mdtables=tables,
        metadata=SimpleNamespace(streams={"#Strings": StringsHeap(8, len(marker))}),
        struct=SimpleNamespace(ResourcesRva=40),
    )
    pe = SimpleNamespace(net=net, get_offset_from_rva=lambda rva: rva)

    dispatcher = SimpleNamespace(
        size=11,
        instructions=[
            instruction("switch", list(range(20))),
            instruction("call", 0x0A000001),
            instruction("calli", 0x11000001),
            instruction("ldstr", 0x70000001),
            instruction("ldc.i4.1"),
            instruction("brtrue.s", 1),
        ],
    )
    proxy = SimpleNamespace(
        size=4,
        instructions=[instruction("ldarg.0"), instruction("call", 0x0A000002), instruction("ret")],
    )

    def body_reader(body_bytes: bytes) -> object:
        return dispatcher if body_bytes[1] == 1 else proxy

    return bytes(data), pe, body_reader


def install_fakes(monkeypatch: pytest.MonkeyPatch) -> bytes:
    """Install a fake dnfile parser and dncil reader, returning fixture bytes."""
    data, pe, body_reader = fake_managed_pe()
    fake_dnfile = SimpleNamespace(__version__="test", dnPE=lambda **_kwargs: pe)
    monkeypatch.setattr(managed, "dnfile", fake_dnfile)
    monkeypatch.setattr(managed, "read_method_body_from_bytes", body_reader)
    return data


def test_analyze_managed_pe_inventory_and_conservative_techniques(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Count IL without execution and retain only hashes/entropy for resources."""
    data = install_fakes(monkeypatch)
    result = managed.analyze_managed_pe(data, max_method_bytes=64)

    assert result["status"] == "analyzed"
    assert result["executed"] is False
    assert result["emulated"] is False
    assert result["network_contacted"] is False
    assert result["clr_loaded"] is False
    assert result["raw_resources_published"] is False
    assert result["counts"]["methods_parsed"] == 4
    assert result["counts"]["malformed_method_bodies"] == 1
    assert result["counts"]["proxy_method_candidates"] == 3
    assert result["counts"]["calls"] == 4
    assert result["counts"]["calli"] == 1
    assert result["counts"]["ldstr"] == 1
    assert result["dispatcher_candidates"][0]["max_switch_targets"] == 20
    assert result["malformed_method_bodies"][0]["name"] == "Broken"
    assert result["methods"][0]["owner"] == "KoiVM.Runtime"

    resource = result["resources"][0]
    assert resource["status"] == "hashed_full_resource"
    assert len(resource["sha256"]) == 64
    assert resource["entropy"] == 8.0
    assert "data" not in resource and "content" not in resource

    assert result["techniques"]["koi_vm"]["status"] == "suspected"
    assert result["techniques"]["smartassembly"]["status"] == "suspected"
    assert result["techniques"]["managed_control_flow_flattening"]["status"] == "suspected"
    assert result["techniques"]["method_proxy_obfuscation"]["status"] == "suspected"
    assert all(
        item["interpretation"].endswith("not_protector_attribution")
        for item in result["techniques"].values()
    )


def test_parse_failures_dependencies_and_non_managed(monkeypatch: pytest.MonkeyPatch) -> None:
    """Return bounded diagnostic states instead of leaking parser messages."""
    monkeypatch.setattr(
        managed,
        "dnfile",
        SimpleNamespace(__version__="test", dnPE=lambda **_kwargs: (_ for _ in ()).throw(ValueError("secret"))),
    )
    monkeypatch.setattr(managed, "read_method_body_from_bytes", lambda _data: None)
    failed = managed.analyze_managed_pe(b"MZ")
    assert failed["status"] == "parse_failed"
    assert failed["parse_error"] == "ValueError"
    assert "secret" not in json.dumps(failed)

    monkeypatch.setattr(
        managed, "dnfile", SimpleNamespace(__version__="test", dnPE=lambda **_kwargs: SimpleNamespace(net=None))
    )
    assert managed.analyze_managed_pe(b"MZ")["status"] == "not_managed_pe"

    monkeypatch.setattr(managed, "read_method_body_from_bytes", None)
    assert managed.analyze_managed_pe(b"MZ")["status"] == "dependency_missing"


def test_all_budgets_are_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    """Stop input, metadata, method, instruction, and resource work at limits."""
    data = install_fakes(monkeypatch)
    input_limited = managed.analyze_managed_pe(data, max_input_bytes=10)
    assert input_limited["status"] == "input_budget_exceeded"
    assert input_limited["sha256"] is None

    bounded = managed.analyze_managed_pe(
        data,
        max_types=1,
        max_methods=2,
        max_instructions=2,
        max_method_bytes=64,
        max_metadata_strings=1,
        max_metadata_string_bytes=8,
        max_metadata_scan_bytes=4,
        max_resources=1,
        max_resource_bytes=10,
    )
    assert bounded["status"] == "analyzed_partial_budget"
    assert {"methods", "instructions", "metadata_names", "metadata_stream_bytes", "resource_bytes"} <= set(
        bounded["budget_exhausted"]
    )
    assert bounded["resources"][0]["sha256"] is None
    assert bounded["resources"][0]["status"] == "resource_byte_budget_exceeded"
    assert bounded["methods"][0]["parse_status"] == "parsed_partial_instruction_budget"

    with pytest.raises(TypeError):
        managed.analyze_managed_pe(bytearray(b"MZ"))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        managed.analyze_managed_pe(b"MZ", max_methods=0)


def test_exact_method_slice_and_single_signal_is_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bound dncil input exactly and reject one-switch/resource over-attribution."""
    data, pe, body_reader = fake_managed_pe()
    observed_lengths: list[int] = []

    def capturing_reader(body_bytes: bytes) -> object:
        observed_lengths.append(len(body_bytes))
        return body_reader(body_bytes)

    monkeypatch.setattr(
        managed,
        "dnfile",
        SimpleNamespace(__version__="test", dnPE=lambda **_kwargs: pe),
    )
    monkeypatch.setattr(managed, "read_method_body_from_bytes", capturing_reader)
    result = managed.analyze_managed_pe(data, max_method_bytes=64)
    assert observed_lengths == [11, 11, 11, 11]
    assert "after dncil" in result["budgets"]["instruction_budget_semantics"]

    benign = managed._assess_techniques(
        [],
        {
            "methods_parsed": 1,
            "proxy_method_candidates": 0,
            "instructions_counted": 10,
            "constant_loads": 0,
        },
        [{"high_fanout_switches": 1}],
        [
            {
                "status": "hashed_full_resource",
                "declared_size": 4096,
                "entropy": 8.0,
            }
        ],
    )
    assert benign["managed_control_flow_flattening"]["status"] == "inconclusive"
    assert benign["resource_obfuscation"]["status"] == "inconclusive"


def test_iterator_and_command_switches_are_not_cff_evidence() -> None:
    """Exclude only the two dispatch methods reviewed in the exact sample."""
    reviewed_sha256 = (
        "da590d16a8738a6c5f055fffcdcb49870e088d37e040bf1fc1880cbf9b3faa51"
    )
    candidates = [
        {
            "sample_sha256": reviewed_sha256,
            "owner": "Definitions.<GetDefinitions>d__16",
            "name": "MoveNext",
            "max_switch_targets": 65,
        },
        {
            "sample_sha256": reviewed_sha256,
            "owner": "Commands.ControlStuff",
            "name": "Input",
            "max_switch_targets": 16,
        },
    ]
    result = managed._assess_techniques(
        [{"marker": "koi_vm", "sources": ["metadata_names"]}],
        {
            "methods_parsed": 2,
            "proxy_method_candidates": 0,
            "instructions_counted": 200,
            "constant_loads": 0,
        },
        candidates,
        [],
    )
    assessment = result["managed_control_flow_flattening"]
    assert assessment["status"] == "inconclusive"
    assert "excluded 2 reviewed semantic dispatch shape" in assessment["evidence"][0]
    assert (
        managed._known_semantic_dispatch_shape(candidates[0])
        == "compiler_generated_iterator_state_machine"
    )
    assert (
        managed._known_semantic_dispatch_shape(candidates[1])
        == "application_command_dispatch"
    )


def test_attacker_named_command_handler_remains_cff_evidence() -> None:
    """Do not suppress a high-fanout switch based on owner/method names alone."""
    candidate = {
        "sample_sha256": "b" * 64,
        "owner": "Commands.Handler",
        "name": "HandleCommand",
        "max_switch_targets": 64,
    }
    assert managed._known_semantic_dispatch_shape(candidate) is None
    result = managed._assess_techniques(
        [{"marker": "koi_vm", "sources": ["metadata_names"]}],
        {
            "methods_parsed": 1,
            "proxy_method_candidates": 0,
            "instructions_counted": 100,
            "constant_loads": 0,
        },
        [candidate],
        [],
    )
    assert result["managed_control_flow_flattening"]["status"] == "suspected"

def test_plan_managed_methods_is_ordered_and_static_only() -> None:
    """Route each managed technique to a non-executing static method."""
    techniques = {
        name: {"status": "suspected"}
        for name in (
            "koi_vm",
            "confuserex",
            "dotnet_reactor",
            "smartassembly",
            "managed_control_flow_flattening",
            "method_proxy_obfuscation",
            "constant_obfuscation",
            "resource_obfuscation",
        )
    }
    plan = managed.plan_managed_methods(
        {"status": "analyzed", "techniques": techniques, "resources": [{"sha256": "0" * 64}]}
    )
    assert [item["order"] for item in plan] == list(range(1, len(plan) + 1))
    methods = {item["method"] for item in plan}
    assert "koi_vm_runtime_and_vm_data_mapping" in methods
    assert "il_dispatcher_state_variable_recovery" in methods
    assert "proxy_call_graph_collapse" in methods
    assert "constant_dataflow_and_pure_transform_reconstruction" in methods
    assert "resource_reference_and_decryption_dataflow" in methods
    assert all("do_not_CLR_load_or_execute" in item["safety_constraints"] for item in plan)
    assert all("do_not_emulate_CIL" in item["safety_constraints"] for item in plan)

    fallback = managed.plan_managed_methods({"status": "parse_failed"})
    assert [item["method"] for item in fallback] == ["metadata_integrity_and_cross_parser_validation"]


def test_build_parser_and_main(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Exercise CLI parsing and metadata-only JSON output."""
    for function in (
        managed.analyze_managed_pe,
        managed.plan_managed_methods,
        managed.build_parser,
        managed.main,
    ):
        assert function.__doc__

    source = tmp_path / "fixture.exe"
    output = tmp_path / "report.json"
    source.write_bytes(b"MZfixture")
    args = [
        "--input",
        str(source),
        "--output",
        str(output),
        "--max-methods",
        "7",
    ]
    assert managed.build_parser().parse_args(args).max_methods == 7

    seen: dict[str, object] = {}

    def fake_analyze(data: bytes, **budgets: int) -> dict[str, object]:
        seen["data"] = data
        seen["max_methods"] = budgets["max_methods"]
        return {
            "status": "analyzed",
            "counts": {"methods_enumerated": 2},
            "executed": False,
            "emulated": False,
            "network_contacted": False,
        }

    monkeypatch.setattr(managed, "analyze_managed_pe", fake_analyze)
    assert managed.main(args) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["executed"] is False and report["emulated"] is False
    assert report["network_contacted"] is False
    assert seen == {"data": b"MZfixture", "max_methods": 7}
    assert json.loads(capsys.readouterr().out)["network_contacted"] is False

    original = source.read_bytes()
    with pytest.raises(ValueError, match="same file"):
        managed.main(
            ["--input", str(source), "--output", str(source)]
        )
    assert source.read_bytes() == original
