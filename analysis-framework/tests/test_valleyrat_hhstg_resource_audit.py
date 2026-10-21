"""HHSTG resource handlerのsource限定監査境界を検証する。"""

from __future__ import annotations

import ast
import runpy
import sys
from pathlib import Path

import pytest

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
sys.path.insert(0, str(FRAMEWORK_ROOT / "common"))

import analysis_contract
import handler_catalog as catalog
import orchestration_outcome
from extractors.valleyrat.hhstg_resource import HhstgResourceRecovery, StageEndpoint

SOURCE = "extractors/valleyrat/hhstg_resource.py"


def _shape_results(source: str, key: tuple[str, str, str]) -> list[bool]:
    """合成source内の対象call全件へ同じsource限定shape監査を適用する。"""

    tree = ast.parse(source)
    function_name = key[1].removeprefix("reachable:")
    scope = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == function_name)
    calls = [
        node for node in ast.walk(scope) if isinstance(node, ast.Call) and catalog._ast_call_name(node.func) == key[2]
    ]
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


RUNTIME_SOURCE = """from capstone import CS_ARCH_X86, CS_MODE_64, Cs
MAXIMUM_RUNTIME_FUNCTION_SIZE = 0x20_000
MAXIMUM_RUNTIME_FUNCTION_BYTES = 16 * 1024 * 1024
MAXIMUM_INSTRUCTION_COUNT = 500_000
def _decode_runtime_functions(data, image):
    image_base = int(image.OPTIONAL_HEADER.ImageBase)
    entries = image.DIRECTORY_ENTRY_EXCEPTION
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    total_bytes = 0
    total_instructions = 0
    for entry in entries:
        start = int(entry.struct.BeginAddress)
        end = int(entry.struct.EndAddress)
        size = end - start
        if not 0 < size <= MAXIMUM_RUNTIME_FUNCTION_SIZE:
            return None
        offset = int(image.get_offset_from_rva(start))
        if offset + size > len(data):
            return None
        total_bytes += size
        if total_bytes > MAXIMUM_RUNTIME_FUNCTION_BYTES:
            return None
        instructions = tuple(disassembler.disasm(data[offset : offset + size], image_base + start))
        total_instructions += len(instructions)
        if total_instructions > MAXIMUM_INSTRUCTION_COUNT:
            return None
    return instructions
"""


SHELLCODE_SOURCE = """from capstone import CS_ARCH_X86, CS_MODE_64, Cs
MAXIMUM_SHELLCODE_SIZE = 4 * 1024 * 1024
MAXIMUM_SHELLCODE_INSTRUCTIONS = 100_000
def _decode_shellcode(shellcode, marker):
    if not 512 <= marker <= len(shellcode) <= MAXIMUM_SHELLCODE_SIZE:
        return None
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    decoded = tuple(disassembler.disasm(shellcode[:marker], 0))
    if (
        not decoded
        or len(decoded) > MAXIMUM_SHELLCODE_INSTRUCTIONS
        or decoded[-1].address + decoded[-1].size != marker
        or sum(item.size for item in decoded) != marker
    ):
        return None
    pending = [0]
    queued = {0}
    reachable: set[int] = set()
    cursor = 0
    while cursor < len(pending):
        if len(pending) > MAXIMUM_SHELLCODE_INSTRUCTIONS:
            return None
        address = pending[cursor]
        cursor += 1
        if address in reachable:
            continue
        reachable.add(address)
        if len(reachable) > MAXIMUM_SHELLCODE_INSTRUCTIONS:
            return None
    return decoded
"""


def test_runtime_disasm_guard_requires_x64_exact_slice_and_cumulative_limits() -> None:
    key = (SOURCE, "reachable:_decode_runtime_functions", "disassembler.disasm")

    assert key in catalog._REVIEWED_SOURCE_CALLS
    assert _shape_results(RUNTIME_SOURCE, key) == [True]
    assert _shape_results(RUNTIME_SOURCE.replace("CS_MODE_64", "CS_MODE_32"), key) == [False]
    assert _shape_results(
        RUNTIME_SOURCE.replace("data[offset : offset + size]", "data[offset:]"),
        key,
    ) == [False]
    assert _shape_results(
        RUNTIME_SOURCE.replace("MAXIMUM_RUNTIME_FUNCTION_BYTES = 16", "MAXIMUM_RUNTIME_FUNCTION_BYTES = 32"),
        key,
    ) == [False]
    assert _shape_results(
        RUNTIME_SOURCE.replace(
            "        instructions = tuple(",
            "        disassembler = other\n        instructions = tuple(",
        ),
        key,
    ) == [False]
    assert _shape_results(
        RUNTIME_SOURCE.replace(
            "        total_bytes += size",
            "        if False:\n            total_bytes += size",
        ),
        key,
    ) == [False]
    assert _shape_results(
        RUNTIME_SOURCE.replace(
            "        instructions = tuple(",
            "        disassembler.disasm = other\n        instructions = tuple(",
        ),
        key,
    ) == [False]


def test_shellcode_disasm_guard_requires_x64_marker_slice_and_exact_limits() -> None:
    key = (SOURCE, "reachable:_decode_shellcode", "disassembler.disasm")

    assert key in catalog._REVIEWED_SOURCE_CALLS
    assert _shape_results(SHELLCODE_SOURCE, key) == [True]
    assert _shape_results(SHELLCODE_SOURCE.replace("CS_MODE_64", "CS_MODE_32"), key) == [False]
    assert _shape_results(SHELLCODE_SOURCE.replace("shellcode[:marker]", "shellcode"), key) == [False]
    assert _shape_results(
        SHELLCODE_SOURCE.replace(
            "MAXIMUM_SHELLCODE_INSTRUCTIONS = 100_000", "MAXIMUM_SHELLCODE_INSTRUCTIONS = 200_000"
        ),
        key,
    ) == [False]
    assert _shape_results(
        SHELLCODE_SOURCE.replace("    disassembler = Cs", "    marker = len(shellcode)\n    disassembler = Cs"),
        key,
    ) == [False]
    assert _shape_results(
        SHELLCODE_SOURCE.replace(
            "    decoded = tuple(",
            "    disassembler.disasm = other\n    decoded = tuple(",
        ),
        key,
    ) == [False]
    assert _shape_results(
        SHELLCODE_SOURCE.replace(
            "    if not 512 <= marker <= len(shellcode) <= MAXIMUM_SHELLCODE_SIZE:\n        return None\n",
            "",
        ),
        key,
    ) == [False]
    assert _shape_results(
        SHELLCODE_SOURCE.replace(
            "        if len(pending) > MAXIMUM_SHELLCODE_INSTRUCTIONS:\n            return None\n",
            "",
        ),
        key,
    ) == [False]


@pytest.mark.parametrize(
    "mutation",
    [
        "        disassembler.disasm = _evil",
        "        disassembler.disasm: object = _evil",
        "        disassembler.disasm += _evil",
        "        del disassembler.disasm",
        "        (disassembler := _evil)",
        "        for disassembler.disasm in [_evil]:\n            pass",
        "        [None for disassembler.disasm in [_evil]]",
        "        with _context() as disassembler.disasm:\n            pass",
        "        try:\n            pass\n        except Exception as disassembler:\n            pass",
        "        import capstone as disassembler",
        "        def disassembler():\n            pass",
        "        class disassembler:\n            pass",
        "        match _value:\n            case disassembler:\n                pass",
        '        disassembler.__dict__["disasm"] = _evil',
        '        setattr(disassembler, "disasm", _evil)',
        "        alias = disassembler",
        "        alias = chained = disassembler",
        "        method = disassembler.disasm",
        "        _mutate(disassembler)",
        "        receivers = [disassembler]",
        '        receivers = {"disassembler": disassembler}',
        "        _holder.value = disassembler",
        "        _holder[0] = disassembler",
        "        return disassembler",
        "        yield disassembler",
        "        global leaked\n        leaked = disassembler",
        "        leaked = None\n        def _escape():\n            nonlocal leaked\n            leaked = disassembler",
        "        leaked = lambda: disassembler",
    ],
)
def test_runtime_disasm_guard_rejects_receiver_rebinding_or_escape(mutation: str) -> None:
    """receiverの全target系統と未証明escapeをfail-closedにする。"""

    key = (SOURCE, "reachable:_decode_runtime_functions", "disassembler.disasm")
    source = RUNTIME_SOURCE.replace(
        "        instructions = tuple(",
        f"{mutation}\n        instructions = tuple(",
    )

    assert _shape_results(source, key) == [False]


def test_runtime_disasm_guard_rejects_receiver_parameter_shadowing() -> None:
    """receiver名をparameterとして再導入するshapeも許可しない。"""

    key = (SOURCE, "reachable:_decode_runtime_functions", "disassembler.disasm")
    source = RUNTIME_SOURCE.replace(
        "def _decode_runtime_functions(data, image):",
        "def _decode_runtime_functions(data, image, disassembler=None):",
    )

    assert _shape_results(source, key) == [False]


def test_handler_recursive_audit_passes_but_automatic_preflight_is_disabled() -> None:
    handler_path = FRAMEWORK_ROOT / "malware" / "valleyrat" / "campaigns" / "single_pe_hhstg_resource" / "analyze.py"
    audit = catalog._recursive_handler_side_effect_audit(handler_path, "analyze")

    assert audit["issues"] == []
    spec = next(
        item
        for item in catalog.discover_handlers()
        if item.relative_path.endswith("malware/valleyrat/campaigns/single_pe_hhstg_resource/analyze.py")
        and item.callable_name == "analyze"
    )
    assert spec.automatic is False
    assert spec.reason == "candidate_lineage_requires_manual_evidence_review"
    catalog.clear_handler_caches()
    try:
        preflight = catalog.preflight_handler_for_assessment(
            spec,
            actual_format="pe",
            input_size=600_000,
        )
    finally:
        catalog.clear_handler_caches()

    assert preflight["eligible"] is False
    assert preflight["blockers"] == ["handler_not_automatic"]


def test_manual_handler_never_confirms_family_configuration_or_c2() -> None:
    handler_path = FRAMEWORK_ROOT / "malware" / "valleyrat" / "campaigns" / "single_pe_hhstg_resource" / "analyze.py"
    namespace = runpy.run_path(str(handler_path))
    recovery = HhstgResourceRecovery(
        endpoints=(StageEndpoint("198.51.100.10", 443, "configured_route", 0),),
        configured_route_count=1,
        embedded_fallback_count=0,
        export_binding_count=8,
        campaign_present=True,
    )
    namespace["analyze"].__globals__["recover_hhstg_resource"] = lambda _data: recovery

    result = namespace["analyze"](b"synthetic", "fixture.exe")

    assert result["family"] is None
    assert result["matched"] is False
    assert result["decoded_config_recovered"] is False
    assert result["static_config_recovered"] is False
    assert result["candidate_config_recovered"] is False
    assert result["supports_family_attribution"] is False
    assert result["family_attribution_confirmed"] is False
    assert result["c2_confirmed"] is False
    assert result["c2_liveness_confirmed"] is False
    assert result["terminal_family_confirmed"] is False
    assert result["final_rat_confirmed"] is False
    assert result["stage_acquisition_loader_confirmed"] is False
    assert result["command_c2_confirmed"] is False
    assert result["qualified"] is False
    assert result["contacted"] is False
    assert result["used_for_family_resolution"] is False
    assert result["used_for_c2_confirmation"] is False
    assert result["config"]["endpoints"] == []
    assert result["config"]["ipv4"] == []
    assert "c2" not in result
    assert result["c2_candidates"][0]["role"] == "stage_acquisition_route_candidate"
    assert result["c2_candidates"][0]["confidence"] == "unverified_static_candidate"
    assert result["c2_candidates"][0]["evidence"]["all_expected_fields_validated"] is False


def test_manual_hhstg_candidate_does_not_leak_into_standard_orchestration() -> None:
    """手動候補を標準summaryのfamily/config/C2/terminalへ昇格しない。"""

    handler_path = FRAMEWORK_ROOT / "malware" / "valleyrat" / "campaigns" / "single_pe_hhstg_resource" / "analyze.py"
    namespace = runpy.run_path(str(handler_path))
    recovery = HhstgResourceRecovery(
        endpoints=(StageEndpoint("198.51.100.10", 443, "configured_route", 0),),
        configured_route_count=1,
        embedded_fallback_count=0,
        export_binding_count=8,
        campaign_present=True,
    )
    namespace["analyze"].__globals__["recover_hhstg_resource"] = lambda _data: recovery
    payload = namespace["analyze"](b"synthetic", "fixture.exe")
    quality = analysis_contract.handler_result_quality(payload, minimum_score=40_000)
    records = [
        {
            "family": "valleyrat",
            "handler_id": "valleyrat:hhstg-manual-route:analyze",
            "source": "selected_family_analysis",
            "status": "succeeded",
            "selected_layer_sha256": "d" * 64,
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
