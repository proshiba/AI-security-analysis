"""人工 source-bound PE と静的命令 fixture による有界 triage 試験。"""

from __future__ import annotations

import json
import logging
from pathlib import Path
import struct
from types import SimpleNamespace

import pytest

from unpackers.tests.resource_literal_pe_fixture import (
    resource_build_literal_pe, resource_literal_parse,
    resource_literal_managed as managed,
)


def instruction(name: str, operand: object = None) -> SimpleNamespace:
    """最小 dncil 風の静的命令 record を作る。"""
    return SimpleNamespace(opcode=SimpleNamespace(name=name), operand=operand)


def resource_literal_managed_pe() -> tuple[bytes, object, object]:
    """人工 immutable bytes、実 dnfile PE、静的命令 reader を返す。"""
    fixture = resource_build_literal_pe()
    data = fixture.data
    pe = resource_literal_parse(data)

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
        instructions=[
            instruction("ldarg.0"),
            instruction("call", 0x0A000002),
            instruction("ret"),
        ],
    )

    def body_reader(body_bytes: bytes) -> object:
        return dispatcher if body_bytes[1] == 1 else proxy

    return data, pe, body_reader


def install_resource_literal_reader(monkeypatch: pytest.MonkeyPatch) -> bytes:
    """dnfile は本物のまま、人工命令 reader だけを設置する。"""
    data, pe, body_reader = resource_literal_managed_pe()
    pe.close()
    monkeypatch.setattr(managed, "read_method_body_from_bytes", body_reader)
    return data


def test_analyze_managed_pe_inventory_and_conservative_techniques(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """命令を実行せず計数し、resource は hash／entropy だけを保持する。"""
    data = install_resource_literal_reader(monkeypatch)
    result = managed.analyze_managed_pe(data, max_method_bytes=64)

    assert result["status"] == "analyzed", (result["resource_coverage"], result["reference_metadata_coverage"])
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
    assert result["resource_coverage"]["input_binding_verified"] is True
    assert result["resource_coverage"]["status"] == "complete"
    assert result["reference_metadata_coverage"]["shared_snapshot"]["accepted"] is True

    resource = result["resources"][0]
    assert resource["status"] == "hashed_full_resource"
    assert len(resource["sha256"]) == 64
    assert resource["entropy"] == 8.0
    assert "data" not in resource and "content" not in resource

    assert result["techniques"]["koi_vm"]["status"] == "suspected"
    assert result["techniques"]["smartassembly"]["status"] == "suspected"
    assert (
        result["techniques"]["managed_control_flow_flattening"]["status"] == "suspected"
    )
    assert result["techniques"]["method_proxy_obfuscation"]["status"] == "suspected"
    assert all(
        item["interpretation"].endswith("not_protector_attribution")
        for item in result["techniques"].values()
    )


def test_method_reader_receives_bounded_window_for_extra_sections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """例外処理sectionを含む正常methodをcode末尾で切り詰めない。"""

    original_data, pe, original_reader = resource_literal_managed_pe()
    data = bytearray(original_data)
    first_method_offset = 4_500
    struct.pack_into("<H", data, first_method_offset, 0x300B)
    struct.pack_into("<H", data, first_method_offset + 2, 8)
    struct.pack_into("<I", data, first_method_offset + 4, 1)
    struct.pack_into("<I", data, first_method_offset + 8, 0)
    data[first_method_offset + 12] = 0x2A
    observed_lengths: list[int] = []

    def section_aware_reader(body_bytes: bytes) -> object:
        observed_lengths.append(len(body_bytes))
        if body_bytes[0] & 0x03 == 0x03:
            if len(body_bytes) <= 13:
                raise ValueError("extra method sectionが切り詰められています")
            return SimpleNamespace(size=20, instructions=[instruction("ret")])
        return original_reader(body_bytes)

    pe.close()
    monkeypatch.setattr(managed, "read_method_body_from_bytes", section_aware_reader)

    result = managed.analyze_managed_pe(bytes(data), max_method_bytes=64)

    assert result["counts"]["methods_parsed"] == 4
    assert result["counts"]["malformed_method_bodies"] == 1
    assert observed_lengths == [64, 11, 11, 11]
    assert [method.get("parse_window_size") for method in result["methods"][:4]] == [
        64,
        11,
        11,
        11,
    ]


def test_parser_diagnostics_suppresses_logger_created_inside_scope(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """scope中に新規生成されたparser loggerもstderrへ漏らさず、global設定を復元する。"""

    previous_disable = logging.root.manager.disable
    logger = logging.getLogger("dnfile.dynamic-parser-test")
    handler = logging.StreamHandler()
    logger.addHandler(handler)
    logger.setLevel(logging.ERROR)
    logger.propagate = False
    try:
        with managed._contained_parser_diagnostics():
            logger.error("parser-secret")
        assert "parser-secret" not in capsys.readouterr().err
        assert logging.root.manager.disable == previous_disable
    finally:
        logger.removeHandler(handler)
        handler.close()


def test_parse_failures_dependencies_and_non_managed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """parser message を漏らさず有界な固定診断状態を返す。"""
    data = resource_build_literal_pe().data
    monkeypatch.setattr(
        managed,
        "dnfile",
        SimpleNamespace(
            __version__="test",
            dnPE=lambda **_kwargs: (_ for _ in ()).throw(ValueError("secret")),
        ),
    )
    monkeypatch.setattr(managed, "read_method_body_from_bytes", lambda _data: None)
    rejected = managed.analyze_managed_pe(b"MZ")
    assert rejected["status"] == "analyzed_partial_budget"
    assert rejected["metadata_preflight"]["accepted"] is False
    assert "parse_error" not in rejected
    failed = managed.analyze_managed_pe(data)
    assert failed["status"] == "parse_failed"
    assert failed["parse_error"] == "ValueError"
    assert "secret" not in json.dumps(failed)

    monkeypatch.setattr(
        managed,
        "dnfile",
        SimpleNamespace(
            __version__="test", dnPE=lambda **_kwargs: SimpleNamespace(net=None)
        ),
    )
    assert managed.analyze_managed_pe(data)["status"] == "not_managed_pe"

    monkeypatch.setattr(managed, "read_method_body_from_bytes", None)
    assert managed.analyze_managed_pe(b"MZ")["status"] == "dependency_missing"


def test_all_budgets_are_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    """input／metadata／method／命令／resource の各作業を予算で止める。"""
    data = install_resource_literal_reader(monkeypatch)
    input_limited = managed.analyze_managed_pe(data, max_input_bytes=10)
    assert input_limited["status"] == "input_budget_exceeded"
    assert input_limited["sha256"] is None

    bounded = managed.analyze_managed_pe(
        data,
        max_types=5,
        max_methods=2,
        max_instructions=2,
        max_method_bytes=64,
        max_metadata_strings=1,
        max_metadata_string_bytes=8,
        max_metadata_scan_bytes=4,
        max_resources=1,
        max_resource_bytes=4096,
    )
    assert bounded["status"] == "analyzed_partial_budget"
    assert {
        "methods",
        "instructions",
        "metadata_names",
        "metadata_stream_bytes",
    } <= set(bounded["budget_exhausted"])
    assert bounded["methods"][0]["parse_status"] == "parsed_partial_instruction_budget"

    # 共有 row 予算を満たした上で、resource 超過は未検証 descriptor を公開しない。
    resource_limited = managed.analyze_managed_pe(data, max_resource_bytes=10,
                                                max_method_bytes=64)
    assert resource_limited["status"] == "analyzed_partial_budget"
    assert resource_limited["resources"] == []
    assert resource_limited["counts"]["resource_bytes_hashed"] == 0
    assert "resource_inventory" in resource_limited["budget_exhausted"]
    assert resource_limited["resource_coverage"]["status"] == "partial"

    row_limited = managed.analyze_managed_pe(data, max_types=1, max_methods=2,
                                           max_method_bytes=64)
    assert row_limited["status"] == "analyzed_partial_budget"
    assert row_limited["methods"] == []
    assert row_limited["reference_metadata_coverage"]["shared_snapshot"]["accepted"] is False

    with pytest.raises(TypeError):
        managed.analyze_managed_pe(bytearray(b"MZ"))  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        managed.analyze_managed_pe(b"MZ", max_methods=0)


def test_bounded_method_window_and_single_signal_is_inconclusive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """dncil入力をmethod上限内に収め、単一signalの過剰帰属を拒否する。"""
    data, pe, body_reader = resource_literal_managed_pe()
    observed_lengths: list[int] = []

    def capturing_reader(body_bytes: bytes) -> object:
        observed_lengths.append(len(body_bytes))
        return body_reader(body_bytes)

    pe.close()
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
    """既存の固定 SHA と宣言 record に一致する二つの semantic shape だけを除外する。"""
    reviewed_sha256 = "da590d16a8738a6c5f055fffcdcb49870e088d37e040bf1fc1880cbf9b3faa51"
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
    """owner／method 名だけでは高 fanout switch の evidence を抑制しない。"""
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
    """各 managed technique を非実行の静的手順へ対応づける。"""
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
        {
            "status": "analyzed",
            "techniques": techniques,
            "resources": [{"sha256": "0" * 64}],
        }
    )
    assert [item["order"] for item in plan] == list(range(1, len(plan) + 1))
    methods = {item["method"] for item in plan}
    assert "koi_vm_runtime_and_vm_data_mapping" in methods
    assert "il_dispatcher_state_variable_recovery" in methods
    assert "proxy_call_graph_collapse" in methods
    assert "constant_dataflow_and_pure_transform_reconstruction" in methods
    assert "resource_reference_and_decryption_dataflow" in methods
    assert all(
        "do_not_CLR_load_or_execute" in item["safety_constraints"] for item in plan
    )
    assert all("do_not_emulate_CIL" in item["safety_constraints"] for item in plan)

    fallback = managed.plan_managed_methods({"status": "parse_failed"})
    assert [item["method"] for item in fallback] == [
        "metadata_integrity_and_cross_parser_validation"
    ]


def test_build_parser_and_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """人工 file の CLI 引数解釈と metadata-only JSON 出力を確認する。"""
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
        managed.main(["--input", str(source), "--output", str(source)])
    assert source.read_bytes() == original


def test_lexical_references_preserve_methodspec_field_and_unknown_tokens(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """命令列のtoken関係を保持し、未知calleeを削除せず到達性は主張しない。"""
    data, pe, original_reader = resource_literal_managed_pe()
    pe.close()
    ops = [instruction("call", SimpleNamespace(value=0x2B000001)),
           instruction("ldsfld", 0x04000001), instruction("calli", 0x11000001),
           instruction("callvirt", 0x0600FFFF)]
    for offset, op in enumerate(ops, 1):
        op.offset = offset

    def reader(value: bytes) -> object:
        return SimpleNamespace(size=11, instructions=ops) if value[1] == 1 else original_reader(value)

    monkeypatch.setattr(managed, "read_method_body_from_bytes", reader)
    result = managed.analyze_managed_pe(data, max_method_bytes=64)
    refs = result["static_references"][:4]
    assert refs[0]["target"]["definition_token"] == "0x06000002"
    assert refs[0]["target"]["generic_argument_count"] == 1
    assert refs[0]["code_offset"] == 0
    assert refs[1]["edge_kind"] == "field_reference"
    assert refs[1]["target"]["status"] == "resolved"
    assert refs[2]["target"]["reason"] == "indirect_call_target_not_statically_known"
    assert refs[3]["target"]["reason"] == "rid_out_of_range"
    assert not result["reference_coverage"]["runtime_targets_complete"]
    assert not result["reference_coverage"]["body_scan_complete"]  # 人工 fixture の破損 method
    limited = managed.analyze_managed_pe(data, max_references=2, max_method_bytes=64)
    assert limited["status"] == "analyzed_partial_budget"
    # max_references*4 の共有 raw row 予約を先に満たせず、通常入口は閉じる。
    assert limited["static_references"] == []
    assert limited["reference_metadata_coverage"]["shared_snapshot"]["accepted"] is False
    assert "reference_metadata" in limited["budget_exhausted"]
    # 従来 limit2／omitted5 の命令列予算 intent は同じ source-bound resolver の直接 unit で保持。
    pe = resource_literal_parse(data)
    try:
        _, resolver, work = managed.prepare_resource_snapshot(data, pe)
        assert work["accepted"] is True
        combined = ops + [instruction("call", 0x0A000002) for _ in range(3)]
        retained, total = managed._static_references(combined, "0x06000001", resolver, 2, 1)
        assert len(retained) == 2
        assert total - len(retained) == 5
        assert retained[0]["target"]["definition_token"] == "0x06000002"
    finally:
        pe.close()
    # raw row 予約を満たす最小通常入口では参照 budget を top へ伝播する。
    reference_limited = managed.analyze_managed_pe(data, max_references=3, max_method_bytes=64)
    assert reference_limited["status"] == "analyzed_partial_budget"
    assert len(reference_limited["static_references"]) == 3
    assert reference_limited["reference_coverage"]["omitted"] == 4
    assert "static_references" in reference_limited["budget_exhausted"]


def test_literal_pe_is_artificial_and_input_bound(monkeypatch):
    """外部 binary を基にせず、人工 heap/行/section に原入力証明が成立する。"""
    fixture = resource_build_literal_pe()
    assert type(fixture.data) is bytes
    assert fixture.data == resource_build_literal_pe().data
    pe = resource_literal_parse(fixture.data)
    calls = []
    def deny_resource_loader(*_args, **_kwargs):
        calls.append("resource_loader")
        raise AssertionError("resource 本文 loader は実行しない")
    monkeypatch.setattr(type(pe.net), "_init_resources", deny_resource_loader)
    try:
        assert pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0
        assert pe.net.struct.EntryPointTokenOrRva == 0
        assert pe.sections[0].Characteristics & 0x20000000 == 0
        assert set(pe.net.mdtables.tables) == {2, 4, 6, 10, 17, 32, 40, 43}
        assert pe.net.mdtables.MethodDef.num_rows == 5
        assert set(pe.net.metadata.streams) == {b"#~", b"#Strings", b"#Blob", b"#US"}
        scan, resolver, work = managed.prepare_resource_snapshot(fixture.data, pe)
        coverage = scan.coverage()
        assert coverage["status"] == "complete"
        assert coverage["input_binding_verified"] is True
        assert coverage["parser_view_only"] is False
        assert work["accepted"] is True
        assert resolver.resolve(0x2B000001)["definition_token"] == "0x06000002"
        descriptor = scan._descriptors[0]
        assert fixture.data[descriptor.body_offset:descriptor.body_offset + descriptor.body_size] == fixture.resource_body
        assert calls == [] and pe.net._resources is None
    finally:
        pe.close()


def test_ordinary_legacy_mock_is_partial_without_source_proof(monkeypatch):
    """旧 ordinary mock を正常 parser proof へ偽装せず、通常入口は partial に閉じる。"""
    data = resource_build_literal_pe().data
    ordinary_pe = SimpleNamespace(net=SimpleNamespace(mdtables=SimpleNamespace()))
    monkeypatch.setattr(managed, "dnfile", SimpleNamespace(
        __version__="test", dnPE=lambda **_kwargs: ordinary_pe))
    monkeypatch.setattr(managed, "read_method_body_from_bytes", lambda _value: None)
    result = managed.analyze_managed_pe(data)
    assert result["status"] == "analyzed_partial_budget"
    assert result["resources"] == [] and result["methods"] == []
    assert result["resource_coverage"]["input_binding_verified"] is False
    assert result["resource_coverage"]["status"] == "partial"
    assert result["reference_metadata_coverage"]["shared_snapshot"]["accepted"] is False


def test_nonempty_typedef_loader_preserves_bound_snapshot(monkeypatch):
    """通常 dnfile MethodList/FieldList 後も同一 container と complete を保持する。"""
    fixture = resource_build_literal_pe()
    pe = resource_literal_parse(fixture.data)
    try:
        scan, resolver, work = managed.prepare_resource_snapshot(fixture.data, pe)
        before = {number: table.rows for number, table in pe.net.mdtables.tables.items()}
        assert pe.net.mdtables._loaded is False
        assert scan.coverage()["status"] == "complete"
        row = pe.net.mdtables.TypeDef.rows[0]
        assert len(row.MethodList) == 5
        assert len(row.FieldList) == 1
        after = {number: table.rows for number, table in pe.net.mdtables.tables.items()}
        assert pe.net.mdtables._loaded is True
        assert all(after[number] is source for number, source in before.items())
        assert all(type(value).__name__ == "LazyList" for value in after.values())
        fresh = managed.revalidated_resource_scan(fixture.data, scan)
        assert fresh.coverage()["status"] == "complete", fresh.coverage()["reason_counts"]
        coverage = managed._consumed_metadata_coverage(resolver, work, fresh)
        assert coverage["shared_snapshot"]["accepted"] is True
        assert coverage["complete"] is True
        print({"before_container": sorted({type(value).__name__ for value in before.values()}),
               "after_container": sorted({type(value).__name__ for value in after.values()}),
               "metadata_loaded_after": pe.net.mdtables._loaded,
               "methodlist_count": len(row.MethodList), "fieldlist_count": len(row.FieldList),
               "resource_status": fresh.coverage()["status"],
               "resource_reasons": fresh.coverage()["reason_counts"],
               "shared_accepted": coverage["shared_snapshot"]["accepted"]})
    finally:
        pe.close()
