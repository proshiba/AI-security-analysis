"""Cross-platform Python orchestrationの単体テスト。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
if str(FRAMEWORK_ROOT) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT))
if str(FRAMEWORK_ROOT / "common") not in sys.path:
    sys.path.insert(0, str(FRAMEWORK_ROOT / "common"))

import import_ghidra_project  # noqa: E402
import invoke_analysis  # noqa: E402
import invoke_family_batch  # noqa: E402


def test_resolve_python_uses_each_os_venv_then_falls_back(short_tmp: Path) -> None:
    """Windows/Linuxそれぞれのvenv配置とfallbackを選択する。"""

    windows_python = short_tmp / ".venv" / "Scripts" / "python.exe"
    windows_python.parent.mkdir(parents=True)
    windows_python.touch()
    assert invoke_analysis.resolve_python(None, short_tmp, os_name="nt") == str(windows_python)

    windows_python.unlink()
    linux_python = short_tmp / ".venv" / "bin" / "python"
    linux_python.parent.mkdir(parents=True)
    linux_python.touch()
    assert invoke_analysis.resolve_python(None, short_tmp, os_name="posix") == str(linux_python)

    linux_python.unlink()
    assert invoke_analysis.resolve_python(None, short_tmp, os_name="posix") == sys.executable
    assert invoke_analysis.resolve_python("custom-python", short_tmp) == "custom-python"


def test_one_shot_builds_an_argument_list(short_tmp: Path) -> None:
    """標準フローがshell文字列ではなく既存CLI向けargument listを組み立てる。"""

    args = invoke_analysis.build_parser().parse_args(
        [
            "--sample",
            str(short_tmp / "sample with spaces.zip"),
            "--output-directory",
            str(short_tmp / "output with spaces"),
            "--archive-mode",
            "raw",
            "--malware-type",
            "valleyrat",
            "--assessment-only",
        ]
    )
    with patch.object(invoke_analysis, "run_python") as runner:
        invoke_analysis.run_one_shot(args, "python-command", short_tmp / "framework")

    positional = runner.call_args.args
    assert positional[0] == "python-command"
    command = positional[1]
    assert isinstance(command, list)
    assert command == [
        short_tmp / "framework" / "common" / "analyze_sample.py",
        "--input",
        short_tmp / "sample with spaces.zip",
        "--output",
        short_tmp / "output with spaces",
        "--archive-mode",
        "raw",
        "--family",
        "valleyrat",
        "--assessment-only",
    ]


def test_legacy_msi_flow_writes_compatible_summary(short_tmp: Path) -> None:
    """旧MSIフローが分類、2解析stage、run-summaryを生成する。"""

    output = short_tmp / "out"
    args = invoke_analysis.build_parser().parse_args(
        [
            "--sample",
            str(short_tmp / "sample.zip"),
            "--output-directory",
            str(output),
            "--legacy-valley-workflow",
            "--python",
            "python-command",
        ]
    )
    output.mkdir()
    observed: list[list[object]] = []

    def fake_run(_python, command, **_kwargs):
        observed.append(command)
        if Path(command[0]).name == "classify_sample.py":
            classification = {
                "malware_type": "valleyrat",
                "campaign_type": "msi_embedded_cab_custom_actions",
                "observations": {"sha256": "a" * 64},
                "candidates": [{"msi_member": "payload/sample.msi"}],
            }
            Path(command[command.index("--output") + 1]).write_text(
                json.dumps(classification), encoding="utf-8"
            )
        return 0

    with patch.object(invoke_analysis, "run_python", side_effect=fake_run):
        invoke_analysis.run_legacy(args, "python-command", short_tmp / "framework")

    assert [Path(command[0]).name for command in observed] == [
        "classify_sample.py",
        "analyze_msi.py",
        "analyze_chain_c2.py",
    ]
    summary = json.loads((output / "run-summary.json").read_text(encoding="utf-8"))
    assert summary["malware_type"] == "valleyrat"
    assert summary["campaign_type"] == "msi_embedded_cab_custom_actions"
    assert summary["executed"] is False
    assert summary["network_contacted"] is False
    assert summary["live_c2_results"] == []


def test_live_probe_accepts_documented_exit_one_and_sanitizes_filename(short_tmp: Path) -> None:
    """到達不能を表す終了code 1を保持し、IPv6も安全なfile名にする。"""

    profile = {
        "live_c2_targets": [
            {"host": "2001:db8::1", "port": 443, "protocol": "https", "sni": "example.test"}
        ]
    }

    def fake_run(_python, command, **kwargs):
        assert kwargs["allowed_exit_codes"] == frozenset({0, 1})
        output = Path(command[command.index("--output") + 1])
        output.write_text(json.dumps({"status": "unreachable"}), encoding="utf-8")
        return 1

    with patch.object(invoke_analysis, "run_python", side_effect=fake_run):
        result = invoke_analysis.run_live_checks(
            profile,
            True,
            short_tmp,
            "python-command",
            short_tmp / "framework",
        )

    assert result == [{"status": "unreachable"}]
    assert (short_tmp / "c2-live" / "01-2001_db8_1-443.json").is_file()


def test_family_batch_routes_script_stages_without_execution(short_tmp: Path) -> None:
    """従来family batchのscript分岐と安全summaryを再現する。"""

    case = short_tmp / ("a" * 64)
    case.mkdir()
    (case / f"{case.name}.zip").touch()

    def fake_run(_python, command, **_kwargs):
        output_directory = case / "analysis-output"
        script = Path(command[0]).name
        if script == "analyze_family_sample.py":
            (output_directory / "family-triage.json").write_text(
                json.dumps(
                    {"members": [{"name": "invoice.vbs", "type": "script", "sha256": "b" * 64}]}
                ),
                encoding="utf-8",
            )
        elif script == "classify_sample.py":
            (output_directory / "classification.json").write_text(
                json.dumps(
                    {
                        "malware_type": "agenttesla",
                        "campaign_type": "unicode_marker_powershell_png_stage",
                    }
                ),
                encoding="utf-8",
            )
        return 0

    with patch.object(invoke_family_batch, "run_python", side_effect=fake_run):
        summary = invoke_family_batch.analyze_case(
            case,
            family="agenttesla",
            password="infected",
            python="python-command",
            framework_root=short_tmp / "framework",
        )

    assert summary is not None
    assert summary["completed_stages"] == [
        "triage",
        "classification",
        "script-layers",
        "script-logic",
        "encoded-text",
        "vbs-variable-trace",
        "unicode-marker",
        "agenttesla-static-recovery",
    ]
    assert summary["executed"] is False
    assert summary["network_contacted"] is False


def test_ghidra_import_uses_argument_list_and_rejects_escape(short_tmp: Path) -> None:
    """Ghidra import対象をroot内へ限定し、shellを使わないargument listで起動する。"""

    payload = short_tmp / "payload"
    payload.mkdir()
    (payload / "module.bin").write_bytes(b"MZ")
    args = argparse.Namespace(
        payload_directory=payload,
        project_directory=short_tmp / "project",
        project_name="sample-project",
        target=["module.bin"],
        analyze_headless="analyzeHeadless",
        analysis_timeout_per_file=600,
    )
    completed = subprocess.CompletedProcess(args=[], returncode=0)
    with patch.object(import_ghidra_project.subprocess, "run", return_value=completed) as runner:
        result = import_ghidra_project.import_project(args)

    command = runner.call_args.args[0]
    assert isinstance(command, list)
    assert command[0] == "analyzeHeadless"
    assert "-import" in command
    assert result["executed_sample"] is False

    outside = short_tmp / "outside.bin"
    outside.touch()
    try:
        import_ghidra_project.contained_target(payload, "../outside.bin")
    except import_ghidra_project.GhidraImportError:
        pass
    else:
        raise AssertionError("payload directory外のtargetが拒否されませんでした")
