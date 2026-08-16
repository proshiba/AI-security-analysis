"""ValleyRAT NVML型handlerの監査・証拠契約を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import sys


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY_ROOT / "analysis-framework" / "common"
for import_root in (REPOSITORY_ROOT, COMMON):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from analysis_contract import handler_result_quality  # noqa: E402
from handler_catalog import (  # noqa: E402
    discover_handlers,
    execute_handler_bounded_for_assessment,
    preflight_handler_for_assessment,
)
from extractors.valleyrat.extractor import extract  # noqa: E402
from extractors.valleyrat.nvml_dat import recover_nvml_dat  # noqa: E402


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


FIXTURE = _load_module(
    "valleyrat_nvml_iso_fixture",
    Path(__file__).with_name("test_valleyrat_nvml_iso_routing.py"),
)
SIGNED_ANALYZER = _load_module(
    "valleyrat_signed_proxy_handler_contract",
    REPOSITORY_ROOT
    / "analysis-framework"
    / "malware"
    / "valleyrat"
    / "campaigns"
    / "signed_proxy_sideload"
    / "analyze.py",
)
REVIEWED = _load_module(
    "valleyrat_reviewed_handler_contract",
    REPOSITORY_ROOT
    / "analysis-framework"
    / "malware"
    / "valleyrat"
    / "common"
    / "reviewed_samples.py",
)


def _handlers():
    expected = {
        "analysis-framework/malware/valleyrat/campaigns/signed_proxy_sideload/analyze.py",
        "extractors/valleyrat/extractor.py",
    }
    values = [
        item
        for item in discover_handlers()
        if item.family == "valleyrat" and item.relative_path in expected
    ]
    assert {item.relative_path for item in values} == expected
    return values


def test_nvml_handlers_pass_fail_closed_preflight() -> None:
    """両handlerはsample実行・network・filesystem writeなしで監査を通る。"""

    for handler in _handlers():
        result = preflight_handler_for_assessment(
            handler,
            actual_format="data",
            input_size=1_050,
        )
        assert result["eligible"] is True
        assert result["blockers"] == []
        audit = result["dependency_audit"]
        assert audit["issues"] == []
        assert result["sample_execution_allowed"] is False
        assert result["network_allowed"] is False
        assert result["filesystem_write_allowed"] is False


def test_nvml_dat_handlers_return_validated_static_configuration() -> None:
    """DATを実行せず、2つのC2をtier 3の静的設定として返す。"""

    dat = FIXTURE._nvml_dat()
    expected = ["192.0.2.10:6666", "198.51.100.20:7777"]
    recovered = recover_nvml_dat(dat)

    generic = extract(dat, "NVML.DAT")
    signed = SIGNED_ANALYZER.analyze(dat, "NVML.DAT")

    for result in (generic, signed):
        quality = handler_result_quality(result)
        assert quality["tier"] == 3
        assert quality["sufficient"] is True
        assert result["config"]["static_config_recovered"] is True
        assert result["config"]["endpoints"] == expected
        assert result["network_contacted"] is False
        assert result["terminal_payload"] == {
            "role": "terminal_payload",
            "name": f"{recovered.stage_sha256}.bin",
            "data": recovered.stage,
        }
    assert signed["matched_patterns"] == ["nvml_dat_static_stage_codemark"]
    assert signed["config"]["nvml_dat"]["safety"] == {
        "sample_executed": False,
        "stage_executed": False,
        "network_contacted": False,
        "raw_stage_included": False,
        "raw_key_included": False,
    }


def test_nvml_worker_rehashes_and_retains_terminal_for_follow_on(
    tmp_path: Path,
) -> None:
    """worker-private stageを親で再検証し、公開結果へraw bytesを残さない。"""

    dat = FIXTURE._nvml_dat()
    recovered = recover_nvml_dat(dat)
    handler = next(
        item
        for item in _handlers()
        if item.relative_path == "extractors/valleyrat/extractor.py"
    )
    retained_directory = (tmp_path / "retained").resolve()
    retained_directory.mkdir()

    bounded = execute_handler_bounded_for_assessment(
        handler,
        dat,
        "NVML.DAT",
        actual_format="data",
        artifact_directory=retained_directory,
        artifact_path_prefix="p",
    )

    assert bounded["status"] == "completed"
    execution = bounded["execution"]
    digest = hashlib.sha256(recovered.stage).hexdigest()
    assert (retained_directory / f"{digest}.bin").read_bytes() == recovered.stage
    assert execution["verified_binary_outputs"] == [
        {
            "role": "terminal_payload",
            "kind": "binary",
            "path": f"p/{digest}.bin",
            "sha256": digest,
            "size": len(recovered.stage),
            "verification": {
                "status": "artifact_hash_verified",
                "sha256_matches": True,
                "size_matches": True,
            },
        }
    ]
    audit = execution["verified_binary_output_audit"]
    assert audit["retained_for_follow_on_analysis"] is True
    assert audit["observation_scope"] == "parent_rehashed_case_artifact"
    assert execution["result"]["terminal_payload"]["data"]["content_exported"] is False


def test_nvml_bundle_needs_correlated_loader_structure() -> None:
    """filenameだけではなく、3個以上のloader APIを要求してtier 2とする。"""

    weak = extract(b"NVML.DAT NVML.DLL RuntimeBroker.exe")
    assert weak["config"]["variant"] == "unresolved_variant"
    assert handler_result_quality(weak)["sufficient"] is False

    strong = extract(
        b"NVML.DAT NVML.DLL RuntimeBroker.exe "
        b"QueueUserAPC VirtualAlloc VirtualProtect ReadFile"
    )
    assert strong["config"]["variant"] == "nvml_compact_dat_iso_bundle"
    quality = handler_result_quality(strong)
    assert quality["tier"] == 2
    assert quality["sufficient"] is True


def test_exact_img_review_record_has_seven_ghidra_functions() -> None:
    """実検体のcomplete判定に用いる代表関数は出典とselectorを保持する。"""

    record = REVIEWED.REVIEWED_SAMPLES[
        "f0fdef3caf392f65514f439bbd5e807f9c89f5263d1b7ade0c597c9ed194dc89"
    ]
    functions = record["representative_functions"]
    assert len(functions) == 7
    required = {
        "name",
        "address",
        "role",
        "summary_ja",
        "logic_steps_ja",
        "tool",
        "program_selector",
        "confidence",
        "callees",
    }
    assert all(required <= set(function) for function in functions)
    assert all(function["tool"] == "ghidra-mcp" for function in functions)
    assert all(function["confidence"] == "confirmed_static" for function in functions)
    assert all(function["program_selector"].startswith("/Malware/ValleyRAT/") for function in functions)
    thunk = next(
        function
        for function in functions
        if function["name"] == "SetProcessDpiAwarenessThunk"
    )
    assert thunk["analysis_status"] == "limited"
    assert "opcode_hash_sha256" not in thunk
