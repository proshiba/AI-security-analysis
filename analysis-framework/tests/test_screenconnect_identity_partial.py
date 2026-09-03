"""ScreenConnect製品identityだけを確認した場合のpartial契約を検証する。"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / "common"
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import analyze_sample as one_shot  # noqa: E402
from handler_catalog import discover_handlers  # noqa: E402

REGISTRY = FRAMEWORK_ROOT / "registry" / "malware_types.json"


def _identity_only_pe() -> bytes:
    return (
        b"MZ\x00ScreenConnect.WindowsInstaller.dll\x00"
        b"ScreenConnect.ScreenConnect.ClientSetup.msi\x00"
        b"RunCommandLineProgram\x00"
    )


def _configure_static_case(
    monkeypatch: pytest.MonkeyPatch,
    data: bytes,
) -> one_shot.InputUnit:
    digest = hashlib.sha256(data).hexdigest()
    layer = one_shot.StaticLayer(
        name="fixture.exe",
        data=data,
        sha256=digest,
        parent_sha256=None,
        depth=0,
        transform="submission",
    )
    layer_report = {
        "schema_version": 1,
        "counts": {
            "layers": 1,
            "recovered_layers": 0,
            "recovered_bytes": 0,
            "limit_events": 0,
        },
        "steps": [],
        "limit_events": [],
        "layers": [layer.public()],
        "executed_sample": False,
        "network_contacted": False,
        "recovered_content_exported": False,
    }
    monkeypatch.setattr(
        one_shot,
        "recover_static_layers",
        lambda _unit, **_kwargs: ([layer], layer_report),
    )
    monkeypatch.setattr(
        one_shot,
        "_run_generic_triage",
        lambda _layers, _case_dir, **_kwargs: (
            {
                "analysis_coverage": {"status": "complete"},
                "executed_sample": False,
                "network_contacted": False,
            },
            "complete",
        ),
    )
    return one_shot.InputUnit(
        source_name="fixture.exe",
        data=data,
        input_kind="raw",
        outer_sha256=digest,
        outer_size=len(data),
    )


def test_identity_only_extractor_separates_product_from_configuration() -> None:
    detector = one_shot.classify_sample.load_detector(
        FRAMEWORK_ROOT,
        "malware/screenconnect_rmm/detect.py",
        "screenconnect_rmm",
    )
    extractor = next(spec for spec in discover_handlers() if spec.family == "screenconnect_rmm")
    data = _identity_only_pe()

    detection = detector(data, Path("fixture.exe"))
    bounded = one_shot.execute_handler_bounded_for_assessment(
        extractor,
        data,
        "fixture.exe",
        actual_format="pe",
    )

    assert detection["matched"] is True
    assert detection["observations"]["product_identity_sufficient"] is True
    assert detection["campaigns"][0]["reasons"] == [
        "screenconnect_product",
        "windows_installer_component",
        "embedded_client_setup_resource",
        "command_line_process_helper",
    ]
    assert bounded["status"] == "completed"
    execution = bounded["execution"]
    assert execution["executed_sample"] is False
    assert execution["network_contacted"] is False
    result = execution["result"]
    assert result["classification"] == "commercial_rmm_dual_use"
    assert result["malware_by_itself"] is False
    assert result["abuse_attribution"] == "not_established"
    assert result["network_contacted"] is False
    assert result["sample_executed"] is False
    assert result["product_identity"]["sufficient"] is True
    assert result["product_identity"]["capability_execution_observed"] is False
    assert result["product_identity"]["provider_label_used"] is False
    assert result["config"] == {
        "static_config_recovered": False,
        "config_endpoints": [],
        "static_evidence": {
            "all_expected_fields_validated": False,
            "source": "screenconnect_product_identity_only",
            "dual_use_endpoint": False,
            "product_identity_confirmed": True,
            "endpoint_recovery_status": "not_recovered",
        },
    }
    assert result["hunt_guidance"]["shodan_queries"] == []
    assert one_shot.handler_result_quality(result)["sufficient"] is True


@pytest.mark.parametrize(
    "data",
    [
        b"MZ\x00ScreenConnect\x00",
        b"MZ\x00ScreenConnect.WindowsInstaller.dll\x00",
        (b"MZ\x00ScreenConnect.WindowsInstaller.dll\x00ScreenConnect.ScreenConnect.ClientSetup.msi\x00"),
        (b"MZ\x00ScreenConnect.WindowsInstaller.dll\x00RunCommandLineProgram\x00"),
        (b"MZ\x00ScreenConnect.ScreenConnect.ClientSetup.msi\x00RunCommandLineProgram\x00"),
    ],
    ids=[
        "generic_product_only",
        "installer_only",
        "missing_command_helper",
        "missing_setup_resource",
        "missing_installer_component",
    ],
)
def test_weak_markers_and_provider_style_filename_do_not_select_family(
    data: bytes,
) -> None:
    detector = one_shot.classify_sample.load_detector(
        FRAMEWORK_ROOT,
        "malware/screenconnect_rmm/detect.py",
        "screenconnect_rmm",
    )

    detection = detector(data, Path("ScreenConnect.ClientSetup.exe"))

    assert detection["matched"] is False
    assert detection["campaigns"] == []
    assert "product_identity_sufficient" not in detection["observations"]


def test_identity_survives_ambiguous_endpoints_without_promoting_any_candidate() -> None:
    detector = one_shot.classify_sample.load_detector(
        FRAMEWORK_ROOT,
        "malware/screenconnect_rmm/detect.py",
        "screenconnect_rmm",
    )
    spec = next(handler for handler in discover_handlers() if handler.family == "screenconnect_rmm")
    first = "https://192.0.2.10/Bin/ScreenConnect.Client.application"
    second = "https://192.0.2.11/Bin/ScreenConnect.Client.application"
    data = _identity_only_pe() + first.encode("ascii") + b"\x00" + second.encode("ascii")

    detection = detector(data, Path("fixture.exe"))
    bounded = one_shot.execute_handler_bounded_for_assessment(
        spec,
        data,
        "fixture.exe",
        actual_format="pe",
    )

    assert detection["matched"] is True
    assert detection["observations"]["product_identity_sufficient"] is True
    assert bounded["status"] == "completed"
    result = bounded["execution"]["result"]
    assert result["product_identity"]["sufficient"] is True
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["config_endpoints"] == []
    assert result["config"]["static_evidence"]["endpoint_recovery_status"] == ("ambiguous")
    assert result["config"]["static_evidence"]["application_candidate_count"] == 2
    serialized = json.dumps(result, ensure_ascii=False)
    assert first not in serialized
    assert second not in serialized


def test_identity_only_handler_succeeds_but_config_and_network_stay_partial(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _identity_only_pe()
    unit = _configure_static_case(monkeypatch, data)
    spec = next(handler for handler in discover_handlers() if handler.family == "screenconnect_rmm")

    summary = one_shot.analyze_unit(
        unit,
        output=tmp_path / "out",
        registry=REGISTRY,
        specs=[spec],
        registered={"screenconnect_rmm"},
        forced_family=None,
        minimum_confidence="medium",
        assessment_only=False,
        analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
    )

    case_dir = tmp_path / "out" / "cases" / summary["sha256"]
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    outcome = json.loads((case_dir / "orchestration.json").read_text(encoding="utf-8"))
    execution = report["handler_executions"][0]
    assert report["classification"]["selected_families"] == ["screenconnect_rmm"]
    assert execution["status"] == "succeeded"
    assert execution["selected_evidence"]["sufficient"] is True
    assert execution["selected_evidence"]["tier_name"] == "structural_corroboration"
    assert outcome["family_resolution"]["family"] == "screenconnect_rmm"
    assert outcome["quality_gates"]["handler_evidence"]["status"] == "satisfied"
    assert outcome["quality_gates"]["config"]["status"] == "required_missing"
    assert outcome["quality_gates"]["network"]["status"] == "required_missing"
    assert outcome["outputs"]["config_recovered"] is False
    assert outcome["outputs"]["qualified_network_endpoints"] == []
    assert outcome["status"] == "partial"
    assert {"config", "network"}.issubset(outcome["blockers"])
    assert report["executed_sample"] is False
    assert report["network_contacted"] is False
