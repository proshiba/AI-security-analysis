from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analyze_sample as one_shot
import bounded_process
import pe_function_analysis
from static_logic import (
    build_static_logic_report,
    function_analysis_is_available,
)

SHA256 = "a" * 64


def _minimal_pe(code: bytes) -> bytes:
    """entry pointへ任意の短いx86 codeを置いた合成PEを返す。"""

    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
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


def test_direct_call_candidate_is_analyzed_and_selected() -> None:
    # 0x1000 call 0x100b; ret; padding; 0x100b ret
    sample = _minimal_pe(b"\xe8\x06\x00\x00\x00\xc3" + b"\x90" * 5 + b"\xc3")

    report = pe_function_analysis.analyze_pe(
        sample,
        program_selector="fixture:synthetic",
        relationship="root_program",
        depth=0,
    )

    assert report["status"] == "candidate_evidence_collected"
    assert report["coverage"]["discovered_function_count"] == 2
    assert report["coverage"]["attempted_function_count"] == 2
    assert report["coverage"]["all_discovered_functions_attempted"] is True
    functions = {item["function_id"]: item for item in report["representative_functions"]}
    assert set(functions) == {"pe-rva:0x1000", "pe-rva:0x100b"}
    assert functions["pe-rva:0x1000"]["callees"] == ["pe-rva:0x100b"]
    assert functions["pe-rva:0x100b"]["callers"] == ["pe-rva:0x1000"]
    assert all(item["analysis_attempt"]["method"] == "bounded_capstone_recursive_cfg" for item in functions.values())
    assert report["completion_contract"]["satisfies_reviewed_function_analysis_gate"] is False


def test_process_behavior_separates_reachable_callsite_from_import_only() -> None:
    imports = [
        {"module": "KERNEL32.dll", "api": "CreateProcessW"},
        {"module": "KERNEL32.dll", "api": "WriteProcessMemory"},
    ]
    call_sites = [
        {
            "function_id": "pe-rva:0x1000",
            "address": "0x1010",
            "transfer_kind": "call",
            "target_module": "KERNEL32.dll",
            "target_api": "WriteProcessMemory",
            "behavior_candidates": ["remote_process_access_or_injection"],
            "confidence": "confirmed_static_reachable_import_thunk_reference",
            "runtime_execution_confirmed": False,
        }
    ]

    behavior = {
        item["behavior"]: item
        for item in pe_function_analysis._process_behavior(imports, call_sites)
    }

    assert behavior["process_creation"]["assessment"] == "import_only_capability"
    assert behavior["process_creation"]["call_site_count"] == 0
    observed = behavior["remote_process_access_or_injection"]
    assert observed["assessment"] == "reachable_call_site_observed"
    assert observed["call_site_count"] == 1
    assert observed["runtime_execution_confirmed"] is False


def test_network_behavior_requires_a_matching_system_module() -> None:
    """custom DLLの一般的なconnect/send名をnetwork能力へ誤昇格しない。"""

    imports = [
        {"module": "custom.dll", "api": "connect"},
        {"module": "custom.dll", "api": "send"},
        {"module": "WS2_32.dll", "api": "connect"},
    ]

    behavior = pe_function_analysis._process_behavior(imports, [])

    network = next(item for item in behavior if item["behavior"] == "network_communication")
    assert network["apis"] == ["connect"]
    assert pe_function_analysis._behavior_categories("custom.dll", "send") == []
    assert pe_function_analysis._behavior_categories("WS2_32.dll", "send") == [
        "network_communication"
    ]


def test_automated_pe_evidence_does_not_complete_function_gate() -> None:
    secret_source_name = "private-source-name.exe"
    sample = _minimal_pe(b"\xc3")
    layer = SimpleNamespace(
        name=secret_source_name,
        data=sample,
        sha256=SHA256,
        parent_sha256=None,
        depth=0,
        transform="submission",
    )
    automated = pe_function_analysis.analyze_static_layers([layer])
    report = build_static_logic_report(
        sha256=SHA256,
        family="unknown",
        source_name=secret_source_name,
        automated_binary_analysis=automated,
    )

    assert report["status"] == "function_analysis_required"
    assert report["functions"] == []
    assert function_analysis_is_available(report) is False
    assert report["coverage"]["automated_representative_function_candidate_count"] == 1
    contract = report["automated_binary_analysis"]["completion_contract"]
    assert contract["satisfies_reviewed_function_analysis_gate"] is False
    assert secret_source_name not in json.dumps(automated, ensure_ascii=False)


def test_invalid_automated_binary_completion_contract_is_rejected() -> None:
    invalid = pe_function_analysis.analyze_static_layers([], assessment_only=True)
    invalid["completion_contract"]["satisfies_reviewed_function_analysis_gate"] = True

    with pytest.raises(ValueError, match="safety/completion contract"):
        build_static_logic_report(
            sha256=SHA256,
            family="unknown",
            source_name="fixture.exe",
            automated_binary_analysis=invalid,
        )


def test_layer_selection_keeps_root_and_prioritizes_deepest_without_names() -> None:
    layers = [
        SimpleNamespace(data=b"MZ" + bytes([index]), depth=index % 4)
        for index in range(pe_function_analysis.MAX_PROGRAMS + 3)
    ]

    selected, eligible = pe_function_analysis._selected_layer_indices(layers)

    assert eligible == len(layers)
    assert selected[0] == 0
    assert len(selected) == pe_function_analysis.MAX_PROGRAMS
    assert selected[1:] == sorted(selected[1:], key=lambda index: (-layers[index].depth, index))


def _worker_layer(sample: bytes, *, name: str = "private-source-name.exe") -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        data=sample,
        sha256=hashlib.sha256(sample).hexdigest(),
        parent_sha256=None,
        depth=0,
        transform="submission",
    )


def test_pe_function_analysis_runs_in_bounded_worker(monkeypatch) -> None:
    sample = _minimal_pe(b"\xc3")
    secret_name = "private-name-must-not-cross-worker-boundary.exe"
    captured: dict[str, object] = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        request_path = Path(command[-4])
        request_text = request_path.read_text(encoding="utf-8")
        assert secret_name not in request_text
        return_code = one_shot._pe_function_worker_main(
            str(request_path),
            str(command[-3]),
            str(command[-2]),
            str(command[-1]),
        )
        return subprocess.CompletedProcess(command, return_code)

    monkeypatch.setattr(bounded_process, "run_bounded", fake_run)
    result = one_shot._run_pe_function_analysis_isolated(
        [_worker_layer(sample, name=secret_name)],
        timeout_seconds=9,
    )

    assert result["status"] == "candidate_evidence_collected"
    assert result["worker_execution"]["status"] == "completed"
    assert result["completion_contract"]["satisfies_reviewed_function_analysis_gate"] is False
    assert secret_name not in json.dumps(result, ensure_ascii=False)
    options = captured["kwargs"]
    assert isinstance(options, dict)
    assert options["timeout"] == 9
    assert options["require_containment"] is True
    assert options["maximum_active_processes"] == one_shot.MAX_PE_FUNCTION_WORKER_ACTIVE_PROCESSES
    assert options["maximum_memory_bytes"] == one_shot.MAX_PE_FUNCTION_WORKER_MEMORY_BYTES
    assert options["input"] == b""


def test_pe_function_worker_timeout_returns_safe_partial_artifact(monkeypatch) -> None:
    sample = _minimal_pe(b"\xc3")

    def timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(bounded_process, "run_bounded", timeout)
    result = one_shot._run_pe_function_analysis_isolated(
        [_worker_layer(sample)],
        timeout_seconds=3,
    )

    assert result["status"] == "worker_timeout"
    assert result["programs"] == []
    assert result["counts"]["selected_pe_layer_count"] == 0
    assert result["worker_execution"]["requested_program_count"] == 1
    assert result["worker_execution"]["wall_clock_limit_seconds"] == 3
    assert result["completion_contract"]["satisfies_reviewed_function_analysis_gate"] is False


def test_pe_function_worker_is_not_started_without_an_eligible_pe(monkeypatch) -> None:
    """PE層がなければtemp作成も子process起動も行わない。"""

    def unexpected(*_args, **_kwargs):
        raise AssertionError("PE対象なしでworkerを起動してはいけません")

    monkeypatch.setattr(bounded_process, "run_bounded", unexpected)

    result = one_shot._run_pe_function_analysis_isolated(
        [_worker_layer(b"plain-text-static-layer")],
        timeout_seconds=3,
    )

    assert result["status"] == "not_applicable"
    assert result["worker_execution"]["status"] == "not_started_no_eligible_pe_layers"
    assert result["worker_execution"]["requested_program_count"] == 0


def test_pe_function_worker_is_not_started_in_assessment_only_mode(monkeypatch) -> None:
    """assessment-onlyではPEの有無にかかわらず子processを起動しない。"""

    def unexpected(*_args, **_kwargs):
        raise AssertionError("assessment-onlyでworkerを起動してはいけません")

    monkeypatch.setattr(bounded_process, "run_bounded", unexpected)

    result = one_shot._run_pe_function_analysis_isolated(
        [_worker_layer(_minimal_pe(b"\xc3"))],
        assessment_only=True,
        timeout_seconds=3,
    )

    assert result["status"] == "not_run_assessment_only"
    assert result["worker_execution"]["status"] == "not_started_assessment_only"
    assert result["worker_execution"]["requested_program_count"] == 0
    assert all(value is False for value in result["safety"].values())


def test_malformed_pe_function_worker_response_returns_safe_partial_artifact(
    monkeypatch,
) -> None:
    sample = _minimal_pe(b"\xc3")

    def malformed(command, **_kwargs):
        one_shot._write_private_regular_file(
            Path(command[-1]),
            b'{"ok":true,"result":[]}',
            maximum_size=one_shot.MAX_PE_FUNCTION_WORKER_RESPONSE,
        )
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(bounded_process, "run_bounded", malformed)
    result = one_shot._run_pe_function_analysis_isolated(
        [_worker_layer(sample)],
        timeout_seconds=3,
    )

    assert result["status"] == "worker_response_invalid"
    assert result["programs"] == []
    assert result["worker_execution"]["error_type"] == "WorkerResponseError"
    assert result["completion_contract"]["satisfies_reviewed_function_analysis_gate"] is False
    assert all(value is False for value in result["safety"].values())
