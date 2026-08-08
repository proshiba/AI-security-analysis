"""Family batchのidentity認証と成果transaction回帰テスト。"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))

import invoke_family_batch  # noqa: E402


def _case(root: Path) -> Path:
    case = root / ("a" * 64)
    case.mkdir()
    (case / f"{case.name}.zip").write_bytes(b"fixture")
    return case


def _outer_sha(case: Path) -> str:
    return hashlib.sha256((case / f"{case.name}.zip").read_bytes()).hexdigest()


def _completed_summary(case: Path) -> dict[str, object]:
    return {
        "schema_version": invoke_family_batch.SUMMARY_SCHEMA_VERSION,
        "family": "agenttesla",
        "sample_sha256": case.name,
        "outer_sha256": _outer_sha(case),
        "member_sha256": case.name,
        "member_type": "script",
        "campaign_type": "unicode_marker_powershell_png_stage",
        "completed_stages": ["triage", "classification", "script-layers"],
        "executed": False,
        "network_contacted": False,
    }


def _classification(case: Path) -> dict[str, object]:
    return {
        "malware_type": "agenttesla",
        "malware_type_confidence": "medium",
        "attribution_basis": "type_detector_structure",
        "campaign_type": "unicode_marker_powershell_png_stage",
        "observations": {
            "sha256": _outer_sha(case),
            "type_detector": {"inner_sha256": case.name},
        },
        "detector_evaluations": [
            {
                "malware_type": "agenttesla",
                "error": None,
                "automatic_route_eligible": True,
                "detection": {"observations": {"inner_sha256": case.name}},
            }
        ],
    }


def _write_results(
    case: Path,
    *,
    classification: dict[str, object] | None = None,
    triage_outer: str | None = None,
) -> None:
    output = case / "analysis-output"
    (output / "family-triage.json").write_text(
        json.dumps(
            {
                "outer_sha256": triage_outer or _outer_sha(case),
                "members": [{"name": "invoice.vbs", "type": "script", "sha256": case.name}],
            }
        ),
        encoding="utf-8",
    )
    (output / "classification.json").write_text(json.dumps(classification or _classification(case)), encoding="utf-8")


def test_custom_password_is_rejected_before_stage(short_tmp: Path) -> None:
    case = _case(short_tmp)
    with patch.object(invoke_family_batch, "run_python") as runner:  # noqa: SIM117
        with pytest.raises(invoke_family_batch.OrchestrationError, match="infected"):
            invoke_family_batch.analyze_case(
                case,
                family="agenttesla",
                password="custom",
                python="python-command",
                framework_root=short_tmp / "framework",
            )
    runner.assert_not_called()
    assert not (case / "analysis-output").exists()


@pytest.mark.parametrize("field", ["triage_outer", "classification_outer", "top_inner", "evaluation_inner"])
def test_cross_source_identity_mismatch_is_rejected(short_tmp: Path, field: str) -> None:
    case = _case(short_tmp)

    def fake_run(_python, command, **_kwargs):
        if Path(command[0]).name != "analyze_family_sample.py":
            return 0
        classification = _classification(case)
        triage_outer = None
        if field == "triage_outer":
            triage_outer = "f" * 64
        elif field == "classification_outer":
            classification["observations"]["sha256"] = "f" * 64
        elif field == "top_inner":
            classification["observations"]["type_detector"]["inner_sha256"] = "f" * 64
        else:
            classification["detector_evaluations"][0]["detection"]["observations"]["inner_sha256"] = "f" * 64
        _write_results(case, classification=classification, triage_outer=triage_outer)
        return 0

    with patch.object(invoke_family_batch, "run_python", side_effect=fake_run):  # noqa: SIM117
        with pytest.raises(invoke_family_batch.OrchestrationError, match="SHA-256"):
            invoke_family_batch.analyze_case(
                case,
                family="agenttesla",
                password="infected",
                python="python-command",
                framework_root=short_tmp / "framework",
            )


def test_stage_failure_restores_previous_isolates_failed_and_allows_retry(short_tmp: Path) -> None:
    case = _case(short_tmp)
    output = case / "analysis-output"
    output.mkdir()
    (output / "old.txt").write_text("old", encoding="utf-8")
    (output / "batch-run-summary.json").write_text(json.dumps(_completed_summary(case)), encoding="utf-8")

    def failing(_python, command, **_kwargs):
        name = Path(command[0]).name
        if name == "analyze_family_sample.py":
            _write_results(case)
        elif name == "analyze_script_layers.py":
            raise invoke_family_batch.OrchestrationError("fixture stage failure")
        return 0

    with patch.object(invoke_family_batch, "run_python", side_effect=failing):  # noqa: SIM117
        with pytest.raises(invoke_family_batch.OrchestrationError, match="fixture stage failure"):
            invoke_family_batch.analyze_case(
                case,
                family="agenttesla",
                password="infected",
                python="python-command",
                framework_root=short_tmp / "framework",
            )
    assert (output / "old.txt").read_text(encoding="utf-8") == "old"
    failed = list(case.glob(".analysis-output-failed-*"))
    assert len(failed) == 1 and (failed[0] / "classification.json").is_file()

    def successful(_python, command, **_kwargs):
        if Path(command[0]).name == "analyze_family_sample.py":
            _write_results(case)
        return 0

    with patch.object(invoke_family_batch, "run_python", side_effect=successful):
        summary = invoke_family_batch.analyze_case(
            case,
            family="agenttesla",
            password="infected",
            python="python-command",
            framework_root=short_tmp / "framework",
        )
    assert summary["outer_sha256"] == _outer_sha(case)
    assert (output / "batch-run-summary.json").is_file()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("schema_version", 1),
        ("outer_sha256", "f" * 64),
        ("member_sha256", "f" * 64),
        ("executed", True),
        ("executed", 0),
        ("network_contacted", True),
        ("network_contacted", 0),
        ("completed_stages", ["triage"]),
        ("completed_stages", ["triage", "classification", {}]),
    ],
)
def test_incomplete_previous_summary_is_rejected_before_stage(
    short_tmp: Path,
    field: str,
    value: object,
) -> None:
    """rollback候補は同じouterに対する完了済みschema 2成果だけを許可する。"""

    case = _case(short_tmp)
    output = case / "analysis-output"
    output.mkdir()
    summary = _completed_summary(case)
    summary[field] = value
    (output / "batch-run-summary.json").write_text(json.dumps(summary), encoding="utf-8")
    with patch.object(invoke_family_batch, "run_python") as runner:  # noqa: SIM117
        with pytest.raises(invoke_family_batch.OrchestrationError, match="summary|completed_stages|flag"):
            invoke_family_batch.analyze_case(
                case,
                family="agenttesla",
                password="infected",
                python="python-command",
                framework_root=short_tmp / "framework",
            )
    runner.assert_not_called()
    assert output.is_dir()
    assert not (case / invoke_family_batch.CASE_LOCK_NAME).exists()


def test_existing_case_lock_rejects_concurrent_run_before_stage(short_tmp: Path) -> None:
    """同じcaseの並行実行と未確認stale lockを自動破棄せず拒否する。"""

    case = _case(short_tmp)
    lock = case / invoke_family_batch.CASE_LOCK_NAME
    lock.mkdir()
    with patch.object(invoke_family_batch, "run_python") as runner:  # noqa: SIM117
        with pytest.raises(invoke_family_batch.OrchestrationError, match="case lock"):
            invoke_family_batch.analyze_case(
                case,
                family="agenttesla",
                password="infected",
                python="python-command",
                framework_root=short_tmp / "framework",
            )
    runner.assert_not_called()
    assert lock.is_dir()


def test_all_stages_use_immutable_snapshot_after_source_replacement(short_tmp: Path) -> None:
    """元archiveが差し替えられても全stageとsummaryは同一snapshotへ固定する。"""

    case = _case(short_tmp)
    source_archive = case / f"{case.name}.zip"
    original_sha256 = _outer_sha(case)
    observed_snapshots: list[Path] = []

    def fake_run(_python, command, **_kwargs):
        script = Path(command[0]).name
        option = "--sample" if "--sample" in command else "--outer-zip"
        snapshot = Path(command[command.index(option) + 1])
        observed_snapshots.append(snapshot)
        assert snapshot != source_archive
        assert snapshot.read_bytes() == b"fixture"
        if script == "analyze_family_sample.py":
            source_archive.write_bytes(b"replacement")
            classification = _classification(case)
            classification["observations"]["sha256"] = original_sha256
            _write_results(case, classification=classification, triage_outer=original_sha256)
        return 0

    with patch.object(invoke_family_batch, "run_python", side_effect=fake_run):
        summary = invoke_family_batch.analyze_case(
            case,
            family="agenttesla",
            password="infected",
            python="python-command",
            framework_root=short_tmp / "framework",
        )
    assert summary["outer_sha256"] == original_sha256
    assert source_archive.read_bytes() == b"replacement"
    assert observed_snapshots and len(set(observed_snapshots)) == 1
    assert not observed_snapshots[0].exists()
    assert not observed_snapshots[0].parent.exists()
    assert not (case / invoke_family_batch.CASE_LOCK_NAME).exists()


def test_snapshot_mutation_rolls_back_and_cleans_lock(short_tmp: Path) -> None:
    """子stageがsnapshotを変更した場合は成功扱いせず、成果を隔離する。"""

    case = _case(short_tmp)
    snapshot_path: Path | None = None

    def fake_run(_python, command, **_kwargs):
        nonlocal snapshot_path
        option = "--sample" if "--sample" in command else "--outer-zip"
        snapshot_path = Path(command[command.index(option) + 1])
        if Path(command[0]).name == "analyze_family_sample.py":
            _write_results(case)
        elif Path(command[0]).name == "analyze_script_layers.py":
            snapshot_path.write_bytes(b"tampered")
        return 0

    with patch.object(invoke_family_batch, "run_python", side_effect=fake_run):  # noqa: SIM117
        with pytest.raises(invoke_family_batch.OrchestrationError, match="snapshotが解析中に変更"):
            invoke_family_batch.analyze_case(
                case,
                family="agenttesla",
                password="infected",
                python="python-command",
                framework_root=short_tmp / "framework",
            )
    assert snapshot_path is not None and not snapshot_path.exists()
    assert not snapshot_path.parent.exists()
    assert not (case / invoke_family_batch.CASE_LOCK_NAME).exists()
    assert not (case / "analysis-output").exists()
    assert len(list(case.glob(".analysis-output-failed-*"))) == 1


def test_keyboard_interrupt_cleans_snapshot_output_and_lock(short_tmp: Path) -> None:
    """中断時もtemp入力とlockを残さず、partial outputだけを隔離する。"""

    case = _case(short_tmp)
    observed: list[Path] = []

    def interrupted(_python, command, **_kwargs):
        snapshot = Path(command[command.index("--outer-zip") + 1])
        observed.append(snapshot)
        raise KeyboardInterrupt

    with patch.object(invoke_family_batch, "run_python", side_effect=interrupted):  # noqa: SIM117
        with pytest.raises(KeyboardInterrupt):
            invoke_family_batch.analyze_case(
                case,
                family="agenttesla",
                password="infected",
                python="python-command",
                framework_root=short_tmp / "framework",
            )
    assert observed and not observed[0].exists() and not observed[0].parent.exists()
    assert not (case / invoke_family_batch.CASE_LOCK_NAME).exists()
    assert not (case / "analysis-output").exists()
    assert len(list(case.glob(".analysis-output-failed-*"))) == 1
