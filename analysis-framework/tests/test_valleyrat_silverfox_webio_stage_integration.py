"""WebIO型stage取得loaderのroute-only統合境界を検証する。"""

from __future__ import annotations

import ast
import importlib.util
import json
import sys
from pathlib import Path

import pytest

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
COMMON = FRAMEWORK_ROOT / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
if str(REPOSITORY_ROOT) not in sys.path:
    sys.path.insert(0, str(REPOSITORY_ROOT))

import analysis_contract
import handler_catalog as catalog
import orchestration_outcome


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DETECT = _load_module(
    "valleyrat_silverfox_webio_stage_detector",
    FRAMEWORK_ROOT / "malware" / "valleyrat" / "detect.py",
)
HANDLER = _load_module(
    "valleyrat_silverfox_webio_stage_handler",
    FRAMEWORK_ROOT / "malware" / "valleyrat" / "campaigns" / "silverfox_webio_stage_acquisition_loader" / "analyze.py",
)


def _observation() -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": "unverified_silverfox_webio_manual_route_candidate",
        "matched": False,
        "candidate_recovered": True,
        "automatic_route_eligible": False,
        "manual_review_required": True,
        "route_validated": False,
        "static_config_recovered": False,
        "component_profile": "silverfox_webio_manual_route_candidate",
        "loader_lineage": "silverfox_style_candidate",
        "family": None,
        "family_attribution": "unresolved_manual_loader_candidate",
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "final_rat_confirmed": False,
        "command_c2_confirmed": False,
        "liveness_confirmed": False,
        "qualified": False,
        "contacted": False,
        "candidate_only": True,
        "route": {
            "method": "GET",
            "path": "/getinstall64",
            "endpoint": {
                "host": "stage.example",
                "port": 8443,
                "transport": "http",
                "role": "stage_acquisition_route_candidate",
                "evidence": "unverified_decoded_value_without_complete_cfg_dataflow_binding",
            },
            "downloaded_bundle_recovered": False,
            "downloaded_bundle_executed": False,
        },
        "decoders": {
            "source_blob_size": 4096,
            "prefix_skip": 3,
            "stage1_size": 2069,
            "key_size": 16,
            "encrypted_stage_size": 2048,
            "stage2_size": 1548,
            "marker_offset": 512,
            "encrypted_config_size": 1024,
            "config_size": 0xA88,
            "raw_key_included": False,
            "raw_stage_included": False,
            "raw_config_included": False,
        },
        "evidence_boundary": {
            "root_blob_shape_observed": True,
            "first_lznt1_output_observed": True,
            "key_payload_schema_observed": True,
            "dispatch_slot_two_shape_observed": True,
            "second_lznt1_output_observed": True,
            "unique_marker_observed": True,
            "decoded_config_size_observed": True,
            "decoded_host_port_candidate_observed": True,
            "getinstall64_literal_observed": True,
            "entrypoint_reachable_root_chain_proven": False,
            "root_cfg_and_dataflow_proven": False,
            "runtime_dispatch_slot_two_binding_proven": False,
            "hardcoded_cipher_to_runtime_dispatch_bound": False,
            "marker_to_xor_swap_key_dataflow_proven": False,
            "config_to_http_get_consumer_dataflow_proven": False,
            "end_to_end_route_lineage_proven": False,
            "root_plaintext_endpoint_candidates_used": False,
        },
        "endpoint_values_included": True,
        "raw_key_included": False,
        "raw_stage_included": False,
        "raw_config_included": False,
        "hash_or_filename_rule_used": False,
        "external_label_used": False,
        "sample_executed": False,
        "network_contacted": False,
    }


def test_detector_has_no_webio_automatic_route() -> None:
    """未証明chainをdetectorまたは専用campaignへ自動routeしない。"""

    assert not hasattr(DETECT, "probe_silverfox_webio_stage_loader")
    assert not hasattr(DETECT, "_silverfox_webio_stage_route_detection")
    source = (FRAMEWORK_ROOT / "malware" / "valleyrat" / "detect.py").read_text(encoding="utf-8")
    assert "silverfox_webio_stage_acquisition_loader" not in source
    assert "silverfox_webio_getinstall64_stage_acquisition_route" not in source


def test_automatic_catalogs_exclude_manual_webio_candidate() -> None:
    """campaign定義、strict route、coverageへmanual候補を登録しない。"""

    campaign = "silverfox_webio_stage_acquisition_loader"
    pair = ("valleyrat", campaign)
    campaigns = json.loads((FRAMEWORK_ROOT / "malware" / "valleyrat" / "campaigns.json").read_text(encoding="utf-8"))
    definition = (FRAMEWORK_ROOT / "definitions" / "malware" / "valleyrat.yaml").read_text(encoding="utf-8")
    coverage_json = json.loads(
        (REPOSITORY_ROOT / "analysis-results" / "catalog" / "automation-coverage.json").read_text(encoding="utf-8")
    )
    coverage_markdown = (REPOSITORY_ROOT / "analysis-results" / "catalog" / "AUTOMATION-COVERAGE.md").read_text(
        encoding="utf-8"
    )

    assert campaign not in json.dumps(campaigns, ensure_ascii=False)
    assert campaign not in definition
    assert campaign not in json.dumps(coverage_json, ensure_ascii=False)
    assert campaign not in coverage_markdown
    assert pair not in catalog.STRICT_EXACT_ROUTE_ONLY_CAMPAIGNS
    assert pair in catalog.MANUAL_ONLY_CAMPAIGN_HANDLERS


@pytest.mark.parametrize(
    ("path", "value"),
    [
        (("command_c2_confirmed",), True),
        (("route", "downloaded_bundle_recovered"), True),
        (("evidence_boundary", "runtime_dispatch_slot_two_binding_proven"), True),
        (("evidence_boundary", "entrypoint_reachable_root_chain_proven"), True),
        (("evidence_boundary", "root_plaintext_endpoint_candidates_used"), True),
        (("decoders", "raw_key_included"), True),
        (("decoders", "config_size"), 0xA94),
    ],
)
def test_manual_handler_rejects_overclaimed_candidate(
    monkeypatch: pytest.MonkeyPatch,
    path: tuple[str, ...],
    value: object,
) -> None:
    """lineage欠落、終端過剰主張、decoy利用、raw公開をfail-closedにする。"""

    import copy

    observation = copy.deepcopy(_observation())
    target = observation
    for key in path[:-1]:
        child = target[key]
        assert isinstance(child, dict)
        target = child
    target[path[-1]] = value
    monkeypatch.setattr(
        HANDLER,
        "probe_silverfox_webio_stage_loader",
        lambda _data: observation,
    )

    with pytest.raises(catalog.HandlerNoEvidenceError):
        HANDLER.analyze(b"MZ rejected route")


def test_handler_emits_only_unverified_manual_route_candidate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """handlerは取得先を保持するがfamily／config／command C2へ昇格しない。"""

    monkeypatch.setattr(HANDLER, "probe_silverfox_webio_stage_loader", lambda _data: _observation())
    result = HANDLER.analyze(b"MZ synthetic loader")

    assert result["family"] is None
    assert result["matched"] is False
    assert result["campaign_type"] == "silverfox_webio_manual_route_candidate"
    assert result["automatic_route_eligible"] is False
    assert result["manual_review_required"] is True
    assert result["route_validated"] is False
    assert result["stage_acquisition_loader_confirmed"] is False
    assert result["supports_family_attribution"] is False
    assert result["family_attribution_confirmed"] is False
    assert result["static_config_recovered"] is False
    assert result["c2_confirmed"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["final_rat_confirmed"] is False
    assert result["command_c2_confirmed"] is False
    assert result["c2_liveness_confirmed"] is False
    assert result["qualified"] is False
    assert result["contacted"] is False
    assert result["used_for_family_resolution"] is False
    assert result["used_for_c2_confirmation"] is False
    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["candidate_config_recovered"] is False
    assert result["config"]["endpoints"] == []
    assert result["c2_candidates"] == [
        {
            "endpoint": "stage.example:8443",
            "url": "http://stage.example:8443/getinstall64",
            "transport": "http",
            "method": "GET",
            "path": "/getinstall64",
            "role": "stage_acquisition_route_candidate",
            "confidence": "unverified_static_candidate",
            "source": "manual_webio_decode_candidate",
            "family_attribution_confirmed": False,
            "static_config_recovered": False,
            "c2_confirmed": False,
            "terminal_family_confirmed": False,
            "final_rat_confirmed": False,
            "command_c2_confirmed": False,
            "qualified": False,
            "contacted": False,
            "liveness_confirmed": False,
            "used_for_family_resolution": False,
            "used_for_c2_confirmation": False,
        }
    ]
    assert result["executed"] is False
    assert result["network_contacted"] is False


def test_handler_rejects_overclaimed_upstream_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """上流probeのbooleanを盲信せずhandlerでも境界を再検証する。"""

    observation = _observation()
    observation["terminal_family_confirmed"] = True
    monkeypatch.setattr(
        HANDLER,
        "probe_silverfox_webio_stage_loader",
        lambda _data: observation,
    )

    with pytest.raises(catalog.HandlerNoEvidenceError):
        HANDLER.analyze(b"MZ overclaimed loader")


def test_handler_is_discovered_but_manual_only_and_not_selected() -> None:
    """handlerは棚卸しできるがpreflightと自動候補選択から除外する。"""

    handler_path = (
        FRAMEWORK_ROOT
        / "malware"
        / "valleyrat"
        / "campaigns"
        / "silverfox_webio_stage_acquisition_loader"
        / "analyze.py"
    )
    audit = catalog._recursive_handler_side_effect_audit(handler_path, "analyze")
    catalog.clear_handler_caches()
    try:
        specs = catalog.discover_handlers()
        spec = next(
            item
            for item in specs
            if item.relative_path.endswith("valleyrat/campaigns/silverfox_webio_stage_acquisition_loader/analyze.py")
        )
        preflight = catalog.preflight_handler_for_assessment(
            spec,
            actual_format="pe",
            input_size=1024 * 1024,
        )
        selected, _selection, _fallback = catalog._candidate_handler_specs(
            {
                "family": "valleyrat",
                "assessment_eligible": True,
                "routing_mode": "candidate_verification",
                "sources": ["type_detector"],
                "caller_selected_string": False,
            },
            specs,
            {
                "status": "unavailable",
                "trusted_for_handler_narrowing": False,
                "campaign_types": [],
            },
        )
    finally:
        catalog.clear_handler_caches()

    assert spec.automatic is False
    assert audit["issues"] == []
    assert spec.invocation == "bytes"
    assert spec.campaign == "silverfox_webio_stage_acquisition_loader"
    assert spec.input_formats == ("pe",)
    assert spec.reason == "candidate_lineage_requires_manual_evidence_review"
    assert preflight["eligible"] is False
    assert preflight["blockers"] == ["handler_not_automatic"]
    assert preflight["sample_execution_allowed"] is False
    assert preflight["network_allowed"] is False
    assert preflight["filesystem_write_allowed"] is False
    assert spec not in selected


def test_orchestration_keeps_route_candidate_unqualified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """標準summaryでもstage取得先をqualified C2やconfigへ昇格しない。"""

    monkeypatch.setattr(HANDLER, "probe_silverfox_webio_stage_loader", lambda _data: _observation())
    payload = HANDLER.analyze(b"MZ synthetic loader")
    quality = analysis_contract.handler_result_quality(payload, minimum_score=40_000)
    records = [
        {
            "family": "valleyrat",
            "handler_id": "valleyrat:webio-stage-route:analyze",
            "source": "selected_family_analysis",
            "status": "succeeded",
            "selected_layer_sha256": "c" * 64,
            "selected_evidence": quality,
            "result": {"result": payload},
        }
    ]

    summary = orchestration_outcome.summarize_handler_outputs(records)

    assert quality["sufficient"] is False
    assert summary["config_recovered"] is False
    assert summary["config_candidate_recovered"] is False
    assert summary["qualified_network_endpoints"] == []
    assert summary["network_endpoints"] == []
    assert summary["terminal_payload"]["status"] == "unresolved"


_DISASM_SOURCE = """from capstone import CS_ARCH_X86, CS_MODE_64, Cs
MAXIMUM_FUNCTION_SIZE = 64 * 1024
MAXIMUM_INSTRUCTIONS = 32_768
def _disassemble(data: bytes, address: int, *, maximum: int = MAXIMUM_INSTRUCTIONS):
    if (
        type(maximum) is not int
        or not 1 <= maximum <= MAXIMUM_INSTRUCTIONS
        or len(data) > MAXIMUM_FUNCTION_SIZE
    ):
        return None
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    instructions = list(decoder.disasm(data, address, count=maximum + 1))
    return instructions
"""


def _disasm_shape_results(source: str) -> list[bool]:
    tree = ast.parse(source)
    scope = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_disassemble")
    calls = [
        item
        for item in ast.walk(scope)
        if isinstance(item, ast.Call) and catalog._ast_call_name(item.func) == "decoder.disasm"
    ]
    key = (
        "extractors/valleyrat/silverfox_webio_stage_loader.py",
        "reachable:_disassemble",
        "decoder.disasm",
    )
    return [
        catalog._reviewed_source_call_shape_allowed(
            call,
            key[2],
            tree,
            scope,
            catalog._import_aliases(tree),
            key=key,
        )
        for call in calls
    ]


def test_preflight_disassembly_allowance_is_source_and_shape_limited() -> None:
    """監査例外をx64、入力byte数、命令数の固定guard付き呼出しへ限定する。"""

    assert _disasm_shape_results(_DISASM_SOURCE) == [True]
    assert _disasm_shape_results(_DISASM_SOURCE.replace("CS_MODE_64", "CS_MODE_32")) == [False]
    assert _disasm_shape_results(_DISASM_SOURCE.replace("count=maximum + 1", "count=maximum + 2")) == [False]
    assert _disasm_shape_results(
        _DISASM_SOURCE.replace("MAXIMUM_FUNCTION_SIZE = 64", "MAXIMUM_FUNCTION_SIZE = 128")
    ) == [False]
    assert _disasm_shape_results(
        _DISASM_SOURCE.replace(
            "        or len(data) > MAXIMUM_FUNCTION_SIZE\n",
            "",
        )
    ) == [False]
    assert _disasm_shape_results(
        _DISASM_SOURCE.replace(
            "MAXIMUM_FUNCTION_SIZE = 64 * 1024",
            "MAXIMUM_FUNCTION_SIZE: int = 64 * 1024",
        )
    ) == [False]
    assert _disasm_shape_results(_DISASM_SOURCE + "\nMAXIMUM_INSTRUCTIONS += 1\n") == [False]
    assert _disasm_shape_results(_DISASM_SOURCE + "\ndel MAXIMUM_FUNCTION_SIZE\n") == [False]
    assert _disasm_shape_results(_DISASM_SOURCE + "\nimport math as MAXIMUM_INSTRUCTIONS\n") == [False]
    assert _disasm_shape_results(
        _DISASM_SOURCE.replace(
            "*, maximum: int = MAXIMUM_INSTRUCTIONS):",
            "*, maximum: int = MAXIMUM_INSTRUCTIONS, MAXIMUM_FUNCTION_SIZE: int = 1):",
        )
    ) == [False]
    assert _disasm_shape_results(
        _DISASM_SOURCE.replace(
            "    decoder = Cs(CS_ARCH_X86, CS_MODE_64)\n",
            "    MAXIMUM_FUNCTION_SIZE = 1\n    decoder = Cs(CS_ARCH_X86, CS_MODE_64)\n",
        )
    ) == [False]
    assert _disasm_shape_results(
        _DISASM_SOURCE.replace(
            "    instructions = list(decoder.disasm(data, address, count=maximum + 1))",
            "    decode = lambda: decoder.disasm(data, address, count=maximum + 1)\n"
            "    instructions = list(decode())",
        )
    ) == [False]
    assert _disasm_shape_results(
        _DISASM_SOURCE.replace(
            "    instructions = list(decoder.disasm(data, address, count=maximum + 1))",
            "    def decode():\n"
            "        return decoder.disasm(data, address, count=maximum + 1)\n"
            "    instructions = list(decode())",
        )
    ) == [False]


@pytest.mark.parametrize(
    "mutation",
    [
        "    decoder.disasm = _evil",
        "    decoder.disasm: object = _evil",
        "    decoder.disasm += _evil",
        "    del decoder.disasm",
        "    for decoder.disasm in [_evil]:\n        pass",
        "    [None for decoder.disasm in [_evil]]",
        "    with _context() as decoder.disasm:\n        pass",
        '    decoder.__dict__["disasm"] = _evil',
        '    setattr(decoder, "disasm", _evil)',
        "    alias = decoder",
        "    alias = chained = decoder",
        "    method = decoder.disasm",
        "    _mutate(decoder)",
        "    receivers = [decoder]",
        '    receivers = {"decoder": decoder}',
        "    _holder.value = decoder",
        "    _holder[0] = decoder",
        "    return decoder",
        "    yield decoder",
        "    global leaked\n    leaked = decoder",
        "    leaked = None\n    def _escape():\n        nonlocal leaked\n        leaked = decoder",
        "    leaked = lambda: decoder",
    ],
)
def test_preflight_disassembly_rejects_receiver_rebinding_or_escape(mutation: str) -> None:
    """decoderの差替えと未証明のalias・container・helper escapeを受理しない。"""

    source = _DISASM_SOURCE.replace(
        "    instructions = list(",
        f"{mutation}\n    instructions = list(",
    )

    assert _disasm_shape_results(source) == [False]


_REGISTER_SOURCE = """def _register_name(instruction, register: int) -> str:
    return instruction.reg_name(register).casefold()
"""


def _register_shape_results(source: str) -> list[bool]:
    tree = ast.parse(source)
    scope = next(item for item in tree.body if isinstance(item, ast.FunctionDef) and item.name == "_register_name")
    calls = [
        item
        for item in ast.walk(scope)
        if isinstance(item, ast.Call) and catalog._ast_call_name(item.func) == "instruction.reg_name"
    ]
    key = (
        "extractors/valleyrat/silverfox_webio_stage_loader.py",
        "reachable:_register_name",
        "instruction.reg_name",
    )
    return [
        catalog._reviewed_source_call_shape_allowed(
            call,
            key[2],
            tree,
            scope,
            catalog._import_aliases(tree),
            key=key,
        )
        for call in calls
    ]


@pytest.mark.parametrize(
    "mutation",
    [
        "    instruction.reg_name = _evil",
        "    instruction.reg_name: object = _evil",
        "    instruction.reg_name += _evil",
        "    del instruction.reg_name",
        "    for instruction.reg_name in [_evil]:\n        pass",
        "    [None for instruction.reg_name in [_evil]]",
        "    with _context() as instruction.reg_name:\n        pass",
        '    instruction.__dict__["reg_name"] = _evil',
        '    setattr(instruction, "reg_name", _evil)',
        "    alias = instruction",
        "    alias = chained = instruction",
        "    method = instruction.reg_name",
        "    _mutate(instruction)",
        "    receivers = [instruction]",
        '    receivers = {"instruction": instruction}',
        "    _holder.value = instruction",
        "    _holder[0] = instruction",
        "    return instruction",
        "    yield instruction",
        "    global leaked\n    leaked = instruction",
        "    leaked = None\n    def _escape():\n        nonlocal leaked\n        leaked = instruction",
        "    leaked = lambda: instruction",
    ],
)
def test_register_name_allowance_rejects_receiver_rebinding_or_escape(mutation: str) -> None:
    """instructionのmethod差替えや未証明escapeをsource-call例外へ通さない。"""

    assert _register_shape_results(
        _REGISTER_SOURCE.replace(
            "    return instruction.reg_name",
            f"{mutation}\n    return instruction.reg_name",
        )
    ) == [False]


def test_register_name_allowance_accepts_exact_parameter_call() -> None:
    """無変更のsource限定callだけは引き続き受理する。"""

    assert _register_shape_results(_REGISTER_SOURCE) == [True]
