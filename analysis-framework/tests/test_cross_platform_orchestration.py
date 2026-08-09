"""Cross-platform Python orchestrationの既存6回帰テスト。"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(FRAMEWORK_ROOT), str(FRAMEWORK_ROOT / "common")]

import import_ghidra_project

import invoke_analysis
import invoke_family_batch


def test_resolve_python_uses_each_os_venv_then_falls_back(short_tmp: Path) -> None:
    windows_python = short_tmp / ".venv" / "Scripts" / "python.exe"
    windows_python.parent.mkdir(parents=True)
    windows_python.touch()
    assert invoke_analysis.resolve_python(None, short_tmp, os_name="nt") == str(windows_python)
    windows_python.unlink()
    linux_python = short_tmp / ".venv" / "bin" / "python"
    linux_python.parent.mkdir(parents=True)
    linux_python.touch()
    linux_python.chmod(0o700)
    assert invoke_analysis.resolve_python(None, short_tmp, os_name="posix") == str(linux_python)
    linux_python.unlink()
    assert invoke_analysis.resolve_python(None, short_tmp, os_name="posix") == sys.executable
    assert invoke_analysis.resolve_python("custom-python", short_tmp) == "custom-python"


def test_one_shot_builds_an_argument_list(short_tmp: Path) -> None:
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
    assert runner.call_args.args[1] == [
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


def test_legacy_msi_flow_writes_compatible_summary(
    short_tmp: Path,
    monkeypatch,
) -> None:
    """旧MSIフローが分類、2解析stage、run-summaryを生成する。"""

    monkeypatch.delenv("VT_API_KEY", raising=False)
    output = short_tmp / "out"
    output.mkdir()
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
    observed: list[list[object]] = []

    def fake_run(_python, command, **_kwargs):
        observed.append(command)
        if Path(command[0]).name == "classify_sample.py":
            Path(command[command.index("--output") + 1]).write_text(
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
        return 0

    with patch.object(invoke_analysis, "run_python", side_effect=fake_run):
        invoke_analysis.run_legacy(args, "python-command", short_tmp / "framework")
    assert [Path(command[0]).name for command in observed] == [
        "classify_sample.py",
        "analyze_msi.py",
        "analyze_chain_c2.py",
    ]
    summary = json.loads((output / "run-summary.json").read_text(encoding="utf-8"))
    assert summary["executed"] is False and summary["network_contacted"] is False


def test_live_probe_accepts_documented_exit_one_and_sanitizes_filename(short_tmp: Path) -> None:
    profile = {"live_c2_targets": [{"host": "2001:db8::1", "port": 443, "protocol": "https", "sni": "example.test"}]}

    def fake_run(_python, command, **kwargs):
        assert kwargs["allowed_exit_codes"] == frozenset({0, 1})
        assert command[command.index("--jarm-script") + 1] == jarm_script
        Path(command[command.index("--output") + 1]).write_text(json.dumps({"status": "unreachable"}), encoding="utf-8")
        return 1

    jarm_script = short_tmp / "jarm.py"
    jarm_script.write_text("# fixture\n", encoding="utf-8")
    with patch.object(invoke_analysis, "run_python", side_effect=fake_run):
        result = invoke_analysis.run_live_checks(
            profile,
            True,
            short_tmp,
            "python-command",
            short_tmp / "framework",
            jarm_script=jarm_script,
        )
    assert result == [{"status": "unreachable"}]
    assert (short_tmp / "c2-live" / "01-2001_db8_1-443.json").is_file()


def test_family_batch_routes_script_stages_without_execution(short_tmp: Path) -> None:
    case = short_tmp / ("a" * 64)
    case.mkdir()
    archive = case / f"{case.name}.zip"
    archive.touch()
    outer = hashlib.sha256(b"").hexdigest()

    def fake_run(_python, command, **_kwargs):
        output = case / "analysis-output"
        name = Path(command[0]).name
        if name == "analyze_family_sample.py":
            (output / "family-triage.json").write_text(
                json.dumps(
                    {
                        "outer_sha256": outer,
                        "members": [{"name": "invoice.vbs", "type": "script", "sha256": case.name}],
                    }
                ),
                encoding="utf-8",
            )
        elif name == "classify_sample.py":
            (output / "classification.json").write_text(
                json.dumps(
                    {
                        "malware_type": "agenttesla",
                        "malware_type_confidence": "medium",
                        "attribution_basis": "type_detector_structure",
                        "campaign_type": "unicode_marker_powershell_png_stage",
                        "observations": {
                            "sha256": outer,
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
    assert summary["outer_sha256"] == outer
    assert summary["executed"] is False and summary["network_contacted"] is False


def test_ghidra_import_uses_argument_list_and_rejects_escape(short_tmp: Path) -> None:
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

    def fake_run(*_args, **_kwargs):
        (args.project_directory / "sample-project.gpr").write_bytes(b"fixture")
        return subprocess.CompletedProcess(args=[], returncode=0)

    with patch.object(import_ghidra_project, "run_bounded", side_effect=fake_run) as runner:
        result = import_ghidra_project.import_project(args)
    assert isinstance(runner.call_args.args[0], list)
    assert result["executed_sample"] is False
    (short_tmp / "outside.bin").touch()
    with pytest.raises(import_ghidra_project.GhidraImportError):
        import_ghidra_project.contained_target(payload, "../outside.bin")
