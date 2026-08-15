"""Cross-platform orchestrationの安全境界回帰テスト。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))
if str(FRAMEWORK_ROOT / "common") not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT / "common"))

import import_ghidra_project  # noqa: E402

import invoke_analysis  # noqa: E402
import invoke_family_batch  # noqa: E402


def _legacy_msi_args(root: Path, *extra: str) -> argparse.Namespace:
    return invoke_analysis.build_parser().parse_args(
        [
            "--sample",
            str(root / "sample.zip"),
            "--output-directory",
            str(root / "out"),
            "--legacy-valley-workflow",
            "--python",
            "python-command",
            *extra,
        ]
    )


def _write_legacy_classification(command: list[object]) -> None:
    if Path(command[0]).name != "classify_sample.py":
        return
    output = Path(command[command.index("--output") + 1])
    output.write_text(
        json.dumps(
            {
                "malware_type": "valleyrat",
                "campaign_type": "msi_embedded_cab_custom_actions",
                "observations": {"sha256": "a" * 64},
                "candidates": [{"msi_member": "payload/sample.msi"}],
            }
        ),
        encoding="utf-8",
    )


def _automatic_agenttesla_classification(case: Path) -> dict[str, object]:
    outer_sha256 = hashlib.sha256((case / f"{case.name}.zip").read_bytes()).hexdigest()
    return {
        "malware_type": "agenttesla",
        "malware_type_confidence": "medium",
        "attribution_basis": "type_detector_structure",
        "campaign_type": "unicode_marker_powershell_png_stage",
        "observations": {
            "sha256": outer_sha256,
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


def _create_case(root: Path, digest: str = "a" * 64) -> Path:
    case = root / digest
    case.mkdir(parents=True)
    (case / f"{digest}.zip").write_bytes(b"fixture")
    return case


def _outer_sha(case: Path) -> str:
    return hashlib.sha256((case / f"{case.name}.zip").read_bytes()).hexdigest()


def _completed_family_summary(case: Path) -> dict[str, object]:
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


def _write_family_results(
    case: Path,
    *,
    members: list[dict[str, object]],
    classification: dict[str, object] | None = None,
) -> None:
    output = case / "analysis-output"
    (output / "family-triage.json").write_text(
        json.dumps(
            {
                "outer_sha256": hashlib.sha256((case / f"{case.name}.zip").read_bytes()).hexdigest(),
                "members": members,
            }
        ),
        encoding="utf-8",
    )
    (output / "classification.json").write_text(
        json.dumps(classification or _automatic_agenttesla_classification(case)),
        encoding="utf-8",
    )


def test_ambient_vt_key_does_not_trigger_external_stage(short_tmp: Path) -> None:
    """環境にkeyがあるだけではVT stageを起動しない。"""

    with patch.dict(os.environ, {"VT_API_KEY": "ambient-secret"}, clear=False):
        args = _legacy_msi_args(short_tmp)
        args.output_directory.mkdir()
        observed: list[str] = []

        def fake_run(_python, command, **_kwargs):
            observed.append(Path(command[0]).name)
            _write_legacy_classification(command)
            return 0

        with patch.object(invoke_analysis, "run_python", side_effect=fake_run):
            invoke_analysis.run_legacy(args, "python-command", short_tmp / "framework")
    assert "vt_sandbox.py" not in observed
    summary = json.loads((args.output_directory / "run-summary.json").read_text(encoding="utf-8"))
    assert summary["network_contacted"] is False


def test_fetch_vt_uses_environment_overlay_not_argv(short_tmp: Path) -> None:
    """明示flag時だけ環境からkeyを読み、対象子processのoverlayだけへ渡す。"""

    secret = "unique-explicit-vt-secret"
    args = _legacy_msi_args(short_tmp, "--fetch-virus-total-evidence")
    with patch.dict(os.environ, {"VT_API_KEY": secret}, clear=False):
        assert invoke_analysis._virus_total_api_key(args) == secret
    with patch.object(invoke_analysis, "run_python") as runner:
        invoke_analysis.fetch_vt_evidence(
            {"observations": {"sha256": "a" * 64}},
            secret,
            short_tmp,
            "python-command",
            short_tmp / "framework",
        )
    command = runner.call_args.args[1]
    assert secret not in [str(value) for value in command]
    assert "--api-key" not in command
    assert runner.call_args.kwargs["environment_overlay"] == {"VT_API_KEY": secret}


def test_raw_vt_key_option_is_not_available(short_tmp: Path) -> None:
    """API keyを親processのargvへ置く旧optionを公開しない。"""

    with pytest.raises(SystemExit) as caught:
        invoke_analysis.build_parser().parse_args(
            [
                "--sample",
                str(short_tmp / "sample.zip"),
                "--output-directory",
                str(short_tmp / "out"),
                "--virus-total-api-key",
                "secret",
            ]
        )
    assert caught.value.code == 2


@pytest.mark.parametrize("value", [" leading", "trailing ", "   "])
def test_vt_environment_key_rejects_surrounding_whitespace(short_tmp: Path, value: str) -> None:
    """誤ったVT keyを暗黙trimして使用しない。"""

    args = _legacy_msi_args(short_tmp, "--fetch-virus-total-evidence")
    with patch.dict(os.environ, {"VT_API_KEY": value}, clear=False):  # noqa: SIM117
        with pytest.raises(invoke_analysis.OrchestrationError, match="VT_API_KEY"):
            invoke_analysis._virus_total_api_key(args)


def test_run_python_strips_ambient_secrets_and_allows_explicit_overlay() -> None:
    """通常stageから8種類のambient secretを除外し、明示overlayだけを再追加する。"""

    secret_names = (
        "VT_API_KEY",
        "TRIAGE_API_KEY",
        "MAXMIND_LICENSE_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    )
    ambient = {name: f"ambient-{index}" for index, name in enumerate(secret_names)}
    completed = subprocess.CompletedProcess(args=[], returncode=0)
    with patch.dict(os.environ, ambient, clear=False):
        with patch.object(invoke_analysis, "run_bounded", return_value=completed) as runner:
            invoke_analysis.run_python("python", ["stage.py"], stage="fixture")
        child_environment = runner.call_args.kwargs["env"]
        assert all(name not in child_environment for name in secret_names)
        assert runner.call_args.kwargs["timeout"] == invoke_analysis.DEFAULT_STAGE_TIMEOUT_SECONDS
        assert runner.call_args.kwargs["require_containment"] is True
        assert (
            runner.call_args.kwargs["maximum_active_processes"]
            == invoke_analysis.MAX_STAGE_ACTIVE_PROCESSES
        )
        assert (
            runner.call_args.kwargs["maximum_memory_bytes"]
            == invoke_analysis.MAX_STAGE_MEMORY_BYTES
        )

        with patch.object(invoke_analysis, "run_bounded", return_value=completed) as runner:
            invoke_analysis.run_python(
                "python",
                ["stage.py"],
                stage="fixture",
                environment_overlay={"TRIAGE_API_KEY": "explicit-triage"},
            )
        child_environment = runner.call_args.kwargs["env"]
        assert child_environment["TRIAGE_API_KEY"] == "explicit-triage"
        assert all(name not in child_environment for name in secret_names if name != "TRIAGE_API_KEY")


def test_run_python_converts_timeout() -> None:
    """子stageのhangを日本語のorchestration errorへ変換する。"""

    with (
        patch.object(
            invoke_analysis,
            "run_bounded",
            side_effect=subprocess.TimeoutExpired(cmd=["python"], timeout=17),
        ),
        pytest.raises(invoke_analysis.OrchestrationError, match="17秒でtimeout"),
    ):
        invoke_analysis.run_python("python", ["stage.py"], stage="fixture", timeout_seconds=17)


def test_python_command_script_is_rejected() -> None:
    """Windows command scriptをPython interpreterとして起動しない。"""

    with pytest.raises(invoke_analysis.OrchestrationError, match=r"\.bat/\.cmd"):
        invoke_analysis.resolve_python("runner.cmd")


def test_collect_jarm_is_rejected_by_nmap_only_policy(short_tmp: Path) -> None:
    """外部JARM helperをNmap-onlyのactive観測へ混在させない。"""

    args = invoke_analysis.build_parser().parse_args(
        [
            "--sample",
            str(short_tmp / "sample.zip"),
            "--output-directory",
            str(short_tmp / "out"),
            "--collect-jarm",
        ]
    )
    with pytest.raises(invoke_analysis.OrchestrationError, match="Nmap NSE-only"):
        invoke_analysis.orchestrate(args, framework_root=short_tmp / "framework")
    assert not args.output_directory.exists()


@pytest.mark.parametrize(
    "text",
    [
        '{"schema_version":1,"schema_version":2}',
        '{"value":NaN}',
        '{"value":Infinity}',
    ],
)
def test_strict_json_rejects_duplicate_and_nonfinite(short_tmp: Path, text: str) -> None:
    """曖昧なsecurity JSONを後勝ちで受理しない。"""

    path = short_tmp / "unsafe.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(invoke_analysis.OrchestrationError):
        invoke_analysis.load_json_object(path, label="fixture")


def test_strict_json_converts_recursion_error(short_tmp: Path) -> None:
    """JSON decoderのRecursionErrorを契約違反として拒否する。"""

    path = short_tmp / "deep.json"
    path.write_text("{}", encoding="utf-8")
    with (
        patch.object(invoke_analysis.json, "loads", side_effect=RecursionError("deep JSON")),
        pytest.raises(invoke_analysis.OrchestrationError, match="厳格なUTF-8 JSON"),
    ):
        invoke_analysis.load_json_object(path, label="fixture")


def test_legacy_rejects_nonempty_output_before_stage(short_tmp: Path) -> None:
    """旧フローは古い固定JSONを含む出力先を再利用しない。"""

    args = _legacy_msi_args(short_tmp)
    args.output_directory.mkdir()
    (args.output_directory / "classification.json").write_text("{}", encoding="utf-8")
    with patch.object(invoke_analysis, "run_python") as runner:  # noqa: SIM117
        with pytest.raises(invoke_analysis.OrchestrationError, match="空"):
            invoke_analysis.orchestrate(args, framework_root=short_tmp / "framework")
    runner.assert_not_called()


def test_legacy_rejects_symlink_in_output_path_chain(short_tmp: Path) -> None:
    """旧フロー出力の親componentにあるsymlinkを追跡しない。"""

    real = short_tmp / "real"
    real.mkdir()
    link = short_tmp / "linked"
    try:
        link.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("この環境ではdirectory symlinkを作成できません")
    args = _legacy_msi_args(short_tmp)
    args.output_directory = link / "out"
    with patch.object(invoke_analysis, "run_python") as runner:  # noqa: SIM117
        with pytest.raises(invoke_analysis.OrchestrationError, match="symlink|reparse"):
            invoke_analysis.orchestrate(args, framework_root=short_tmp / "framework")
    runner.assert_not_called()


@pytest.mark.parametrize("name", ["ABC", "a" * 63, "a" * 65, "G" * 64])
def test_batch_rejects_noncanonical_case_identity(short_tmp: Path, name: str) -> None:
    """case directory名をlowercase 64hexへ限定する。"""

    _create_case(short_tmp, name)
    args = argparse.Namespace(
        sample_root=short_tmp,
        family="agenttesla",
        password="infected",
        python="python-command",
    )
    with pytest.raises(invoke_family_batch.OrchestrationError, match="lowercase SHA-256"):
        invoke_family_batch.run_batch(args, framework_root=short_tmp / "framework")


def test_batch_rejects_zero_cases(short_tmp: Path) -> None:
    """空rootを成功として報告しない。"""

    args = argparse.Namespace(
        sample_root=short_tmp,
        family="agenttesla",
        password="infected",
        python="python-command",
    )
    with pytest.raises(invoke_family_batch.OrchestrationError, match="0件"):
        invoke_family_batch.run_batch(args, framework_root=short_tmp / "framework")


def test_batch_rejects_symlink_case(short_tmp: Path) -> None:
    """sample root直下のcase symlink/junctionを追跡しない。"""

    outside = short_tmp / "outside"
    outside.mkdir()
    target = _create_case(outside)
    link = short_tmp / target.name
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("この環境ではdirectory symlinkを作成できません")
    args = argparse.Namespace(
        sample_root=short_tmp,
        family="agenttesla",
        password="infected",
        python="python-command",
    )
    with pytest.raises(invoke_family_batch.OrchestrationError, match="symlink|junction"):
        invoke_family_batch.run_batch(args, framework_root=short_tmp / "framework")


def test_family_mismatch_blocks_specific_handler(short_tmp: Path) -> None:
    """分類family不一致時はAgentTesla固有handlerへ進まない。"""

    case = _create_case(short_tmp)
    observed: list[str] = []

    def fake_run(_python, command, **_kwargs):
        script = Path(command[0]).name
        observed.append(script)
        if script == "analyze_family_sample.py":
            _write_family_results(
                case,
                members=[{"name": "invoice.vbs", "type": "script", "sha256": case.name}],
                classification={"malware_type": "remcosrat", "campaign_type": "fixture_campaign"},
            )
        return 0

    with patch.object(invoke_family_batch, "run_python", side_effect=fake_run):  # noqa: SIM117
        with pytest.raises(invoke_family_batch.OrchestrationError, match="一致しません"):
            invoke_family_batch.analyze_case(
                case,
                family="agenttesla",
                password="infected",
                python="python-command",
                framework_root=short_tmp / "framework",
            )
    assert "agenttesla_recover.py" not in observed


def test_family_rejects_explicit_unmatched_and_uses_independent_classifier(short_tmp: Path) -> None:
    """指定label由来の低confidence分類を認証として使わない。"""

    case = _create_case(short_tmp)
    classifier_command: list[object] | None = None
    observed: list[str] = []

    def fake_run(_python, command, **_kwargs):
        nonlocal classifier_command
        script = Path(command[0]).name
        observed.append(script)
        if script == "analyze_family_sample.py":
            _write_family_results(
                case,
                members=[{"name": "invoice.vbs", "type": "script", "sha256": case.name}],
                classification={
                    "malware_type": "agenttesla",
                    "malware_type_confidence": "low",
                    "attribution_basis": "explicit_user_type_unmatched",
                    "campaign_type": "fixture_campaign",
                    "detector_evaluations": [
                        {
                            "malware_type": "agenttesla",
                            "error": None,
                            "automatic_route_eligible": False,
                        }
                    ],
                },
            )
        elif script == "classify_sample.py":
            classifier_command = command
        return 0

    with patch.object(invoke_family_batch, "run_python", side_effect=fake_run):  # noqa: SIM117
        with pytest.raises(invoke_family_batch.OrchestrationError, match="分類根拠"):
            invoke_family_batch.analyze_case(
                case,
                family="agenttesla",
                password="infected",
                python="python-command",
                framework_root=short_tmp / "framework",
            )
    assert classifier_command is not None
    assert "--malware-type" not in classifier_command
    assert "agenttesla_recover.py" not in observed


def test_family_rejects_multiple_members(short_tmp: Path) -> None:
    """outer archive全体を処理するhandlerへ複数memberを渡さない。"""

    case = _create_case(short_tmp)

    def fake_run(_python, command, **_kwargs):
        if Path(command[0]).name == "analyze_family_sample.py":
            _write_family_results(
                case,
                members=[
                    {"name": "decoy.txt", "type": "text", "sha256": "b" * 64},
                    {"name": "invoice.vbs", "type": "script", "sha256": case.name},
                ],
            )
        return 0

    with patch.object(invoke_family_batch, "run_python", side_effect=fake_run):  # noqa: SIM117
        with pytest.raises(invoke_family_batch.OrchestrationError, match="正確に1件"):
            invoke_family_batch.analyze_case(
                case,
                family="agenttesla",
                password="infected",
                python="python-command",
                framework_root=short_tmp / "framework",
            )


def test_family_existing_output_rejects_symlink(short_tmp: Path) -> None:
    """既存output tree内の固定JSON symlinkを退避前に拒否する。"""

    case = _create_case(short_tmp)
    output = case / "analysis-output"
    output.mkdir()
    outside = case / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    try:
        (output / "classification.json").symlink_to(outside)
    except OSError:
        pytest.skip("この環境ではfile symlinkを作成できません")
    with pytest.raises(invoke_family_batch.OrchestrationError, match="symlink|reparse"):
        invoke_family_batch.prepare_output_directory(case, family="agenttesla", outer_sha256=_outer_sha(case))


def test_family_existing_output_rejects_hardlink(short_tmp: Path) -> None:
    """既存output tree内のhardlinkを退避前に拒否する。"""

    case = _create_case(short_tmp)
    output = case / "analysis-output"
    output.mkdir()
    outside = case / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    try:
        os.link(outside, output / "classification.json")
    except OSError:
        pytest.skip("この環境ではhardlinkを作成できません")
    with pytest.raises(invoke_family_batch.OrchestrationError, match="hardlink"):
        invoke_family_batch.prepare_output_directory(case, family="agenttesla", outer_sha256=_outer_sha(case))


def test_family_authenticated_output_is_backed_up_before_fresh_run(short_tmp: Path) -> None:
    """認証済み旧成果をcase内へ退避し、fresh outputを作成する。"""

    case = _create_case(short_tmp)
    output = case / "analysis-output"
    output.mkdir()
    (output / "batch-run-summary.json").write_text(
        json.dumps(_completed_family_summary(case)),
        encoding="utf-8",
    )
    fresh, previous = invoke_family_batch.prepare_output_directory(
        case, family="agenttesla", outer_sha256=_outer_sha(case)
    )
    assert fresh == output.resolve()
    assert previous is not None
    assert previous.parent == case.resolve()
    assert previous.name.startswith(".analysis-output-previous-")
    assert (previous / "batch-run-summary.json").is_file()
    assert list(fresh.iterdir()) == []


@pytest.mark.parametrize(
    "project_name",
    [".", "..", r"folder\project", "folder/project", "project&whoami", "CON", "name."],
)
def test_ghidra_rejects_unsafe_project_name(project_name: str) -> None:
    """両OSのpath区切り、traversal、cmd metacharacter、予約名を拒否する。"""

    with pytest.raises(import_ghidra_project.GhidraImportError):
        import_ghidra_project.validate_project_name(project_name)


def test_windows_batch_shell_boundary_is_narrow() -> None:
    """Windows batch/cmdだけでPython側shell escapingを有効にする。"""

    assert import_ghidra_project.uses_windows_batch_shell(r"C:\Tools & Data\analyzeHeadless.bat", os_name="nt")
    assert not import_ghidra_project.uses_windows_batch_shell(r"C:\Tools\analyzeHeadless.exe", os_name="nt")
    assert not import_ghidra_project.uses_windows_batch_shell("/opt/ghidra/support/analyzeHeadless", os_name="posix")


def _ghidra_args(short_tmp: Path, *, target: str, project_directory: Path) -> argparse.Namespace:
    payload = short_tmp / "payload"
    payload.mkdir(exist_ok=True)
    (payload / target).write_bytes(b"MZ")
    return argparse.Namespace(
        payload_directory=payload,
        project_directory=project_directory,
        project_name="sample-project",
        target=[target],
        analyze_headless="analyzeHeadless.bat",
        analysis_timeout_per_file=600,
    )


def test_ghidra_batch_subprocess_uses_safe_argument_list(short_tmp: Path) -> None:
    """batch境界で安全な空白入り引数listを保ち、shell=Trueを明示する。"""

    args = _ghidra_args(
        short_tmp,
        target="module data.bin",
        project_directory=short_tmp / "project data",
    )
    completed = subprocess.CompletedProcess(args=[], returncode=0)

    def fake_run(*_args, **_kwargs):
        (args.project_directory / "sample-project.gpr").write_bytes(b"fixture-project")
        return completed

    with patch.object(import_ghidra_project, "uses_windows_batch_shell", return_value=True):  # noqa: SIM117
        with patch.object(import_ghidra_project, "run_bounded", side_effect=fake_run) as runner:
            import_ghidra_project.import_project(args)
    assert isinstance(runner.call_args.args[0], list)
    assert runner.call_args.kwargs["shell"] is True
    assert runner.call_args.kwargs["require_containment"] is True
    assert (
        runner.call_args.kwargs["maximum_active_processes"]
        == import_ghidra_project.MAX_GHIDRA_ACTIVE_PROCESSES
    )
    assert (
        runner.call_args.kwargs["maximum_memory_bytes"]
        == import_ghidra_project.MAX_GHIDRA_MEMORY_BYTES
    )
    environment = runner.call_args.kwargs["env"]
    for secret_name in (
        "VT_API_KEY",
        "TRIAGE_API_KEY",
        "MAXMIND_LICENSE_KEY",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
    ):
        assert secret_name not in environment


def test_ghidra_batch_rejects_target_cmd_metacharacter(short_tmp: Path) -> None:
    """batch境界ではtarget pathのcmd命令境界文字を拒否する。"""

    args = _ghidra_args(short_tmp, target="module&whoami.bin", project_directory=short_tmp / "project")
    with patch.object(import_ghidra_project, "uses_windows_batch_shell", return_value=True):  # noqa: SIM117
        with patch.object(import_ghidra_project, "run_bounded") as runner:
            with pytest.raises(import_ghidra_project.GhidraImportError, match="cmd metacharacter"):
                import_ghidra_project.import_project(args)
    runner.assert_not_called()


def test_ghidra_batch_rejects_project_path_cmd_metacharacter(short_tmp: Path) -> None:
    """batch境界ではproject directoryのcmd命令境界文字を拒否する。"""

    args = _ghidra_args(short_tmp, target="module.bin", project_directory=short_tmp / "p&whoami")
    with patch.object(import_ghidra_project, "uses_windows_batch_shell", return_value=True):  # noqa: SIM117
        with patch.object(import_ghidra_project, "run_bounded") as runner:
            with pytest.raises(import_ghidra_project.GhidraImportError, match="cmd metacharacter"):
                import_ghidra_project.import_project(args)
    runner.assert_not_called()


@pytest.mark.parametrize("existing_name", ["sample-project.gpr", "sample-project.rep"])
def test_ghidra_rejects_preexisting_project_artifact(short_tmp: Path, existing_name: str) -> None:
    """古いproject成果を新しい成功判定へ再利用しない。"""

    args = _ghidra_args(short_tmp, target="module.bin", project_directory=short_tmp / "project")
    args.project_directory.mkdir()
    (args.project_directory / existing_name).write_text("fixture", encoding="utf-8")
    with patch.object(import_ghidra_project, "run_bounded") as runner:  # noqa: SIM117
        with pytest.raises(import_ghidra_project.GhidraImportError, match="既存Ghidra project"):
            import_ghidra_project.import_project(args)
    runner.assert_not_called()


def test_one_shot_rejects_symlink_output_before_child_or_external_write(short_tmp: Path) -> None:
    """標準one-shotも外部directoryへのsymlinkをfollowせず、子stageを起動しない。"""

    outside = short_tmp / "outside"
    outside.mkdir()
    output_link = short_tmp / "output-link"
    try:
        output_link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("この環境ではdirectory symlinkを作成できません")
    args = invoke_analysis.build_parser().parse_args(
        [
            "--sample",
            str(short_tmp / "sample.zip"),
            "--output-directory",
            str(output_link),
        ]
    )
    with patch.object(invoke_analysis, "run_python") as runner:  # noqa: SIM117
        with pytest.raises(invoke_analysis.OrchestrationError, match="symlink|reparse"):
            invoke_analysis.orchestrate(args, framework_root=short_tmp / "framework")
    runner.assert_not_called()
    assert list(outside.iterdir()) == []


def test_one_shot_allows_existing_real_output_directory(short_tmp: Path) -> None:
    """通常directoryの既存成果は保持し、標準解析stageへ正規化pathを渡す。"""

    output = short_tmp / "output"
    output.mkdir()
    (output / "existing.txt").write_text("fixture", encoding="utf-8")
    args = invoke_analysis.build_parser().parse_args(
        [
            "--sample",
            str(short_tmp / "sample.zip"),
            "--output-directory",
            str(output),
        ]
    )
    with patch.object(invoke_analysis, "run_python", return_value=0) as runner:
        invoke_analysis.orchestrate(args, framework_root=short_tmp / "framework")
    runner.assert_called_once()
    assert args.output_directory == output.resolve()
    assert (output / "existing.txt").read_text(encoding="utf-8") == "fixture"


def test_collect_jarm_is_rejected_even_with_live_permission(short_tmp: Path) -> None:
    """live permissionがあっても外部JARM helperを起動しない。"""

    args = invoke_analysis.build_parser().parse_args(
        [
            "--sample",
            str(short_tmp / "sample.zip"),
            "--output-directory",
            str(short_tmp / "out"),
            "--allow-live-c2-check",
            "--collect-jarm",
        ]
    )
    with patch.object(invoke_analysis, "run_python") as runner:  # noqa: SIM117
        with pytest.raises(invoke_analysis.OrchestrationError, match="Nmap NSE-only"):
            invoke_analysis.orchestrate(args, framework_root=short_tmp / "framework")
    runner.assert_not_called()
    assert not args.output_directory.exists()


def test_jarm_script_symlink_is_rejected_before_stage(short_tmp: Path) -> None:
    """JARM helperのsymlink/reparse経路をPython childへ渡さない。"""

    target = short_tmp / "real-jarm.py"
    target.write_text("# fixture\n", encoding="utf-8")
    link = short_tmp / "jarm-link.py"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("この環境ではfile symlinkを作成できません")
    with pytest.raises(invoke_analysis.OrchestrationError, match="symlink|reparse"):
        invoke_analysis.validate_jarm_script(link)


@pytest.mark.parametrize("link_kind", ["symlink", "hardlink"])
def test_one_shot_rejects_linked_existing_write_target(
    short_tmp: Path,
    link_kind: str,
) -> None:
    """既存summary write targetからoutput外fileを上書きできない。"""

    output = short_tmp / "output"
    output.mkdir()
    outside = short_tmp / "outside.json"
    outside.write_text("preserve", encoding="utf-8")
    target = output / "summary.json"
    try:
        if link_kind == "symlink":
            target.symlink_to(outside)
        else:
            os.link(outside, target)
    except OSError:
        pytest.skip(f"この環境では{link_kind}を作成できません")
    args = invoke_analysis.build_parser().parse_args(
        [
            "--sample",
            str(short_tmp / "sample.zip"),
            "--output-directory",
            str(output),
        ]
    )
    with patch.object(invoke_analysis, "run_python") as runner:  # noqa: SIM117
        with pytest.raises(invoke_analysis.OrchestrationError, match="symlink|reparse|hardlink"):
            invoke_analysis.orchestrate(args, framework_root=short_tmp / "framework")
    runner.assert_not_called()
    assert outside.read_text(encoding="utf-8") == "preserve"
