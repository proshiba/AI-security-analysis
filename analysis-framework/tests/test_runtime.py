"""Unit tests for every offline discovery and runner function."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path

import pytest

from asa import discovery, runner, runtime_cli

DEFINITIONS = Path(__file__).parents[1] / "definitions"


def test_discovery_functions(tmp_path: Path) -> None:
    assert discovery.safe_member_name("a/b.bin") == "a/b.bin"
    for bad in ("../x", "/x", "C:/x"):
        with pytest.raises(ValueError, match="unsafe"):
            discovery.safe_member_name(bad)
    raw = tmp_path / "raw.bin"
    raw.write_bytes(b"mx-go/internal/mail mx-go/internal/control mx-go/internal/remote /api/v1/heartbeat_direct")
    data, name, metadata = discovery.read_submission(raw)
    assert data == raw.read_bytes() and name == "raw.bin" and "outer_sha256" in metadata
    archive = tmp_path / "one.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("inner.bin", b"Remcos Agent")
    assert discovery.read_submission(archive)[1] == "inner.bin"
    assert discovery.infer_family(["remcos agent"]) == "remcosrat"
    assert discovery.infer_family(["lummac2"]) == "lummastealer"
    assert discovery.infer_family(["rpsgwra{l", "[iljvvrsrel", "tvdqhg''''"]) == "spyglace"
    assert discovery.infer_family(
        ["index.php", "/plugins/", "os=", "computername"]
    ) == "amadey"
    assert discovery.infer_family(
        ["counter=%d&type=%d&guid=", "/files/", "urls|"]
    ) == "latrodectus"
    assert discovery.infer_family(["none"]) is None
    assert (
        discovery.infer_campaign("mx-go", ["/api/v1/heartbeat_direct"], []) == "remotely_controlled_bulk_email_spam_bot"
    )
    assert discovery.infer_campaign("amosstealer", [], ["sample.macho"]) == "direct_macho"
    assert discovery.infer_campaign("spyglace", [], ["payload.bin"]) == "direct_spyglace_pe"
    assert discovery.infer_campaign("amadey", [], ["sample.exe"]) == "direct_pe_or_container"
    assert discovery.infer_campaign("latrodectus", [], ["sample.docm"]) == "office_delivery"
    assert discovery.infer_campaign("latrodectus", [], ["sample.dll"]) == "direct_dll_or_loader"
    assert discovery.infer_campaign(None, [], []) is None
    _, facts = discovery.discover(raw)
    assert facts["classification"]["family_hint"] == "mx-go"


def make_context(data: bytes = b"text c2.example:443 http://x.example/a") -> dict:
    """Build a minimal in-memory runner context."""
    return {
        "data": data,
        "facts": {"submission": {"name": "x.bin"}},
        "plan": {"family": "remcosrat", "campaign": "unknown"},
        "results": {},
    }


def test_runner_step_functions(monkeypatch: pytest.MonkeyPatch) -> None:
    context = make_context()
    assert runner.step_intake(context)["size"] == len(context["data"])
    assert runner.step_inventory(context)["type"] == "data"
    assert runner.step_strings(context)["count"] > 0
    assert runner.step_iocs(context)["endpoints"] == ["c2.example:443"]
    with pytest.raises(ValueError, match="not a PE"):
        runner.step_pe(context)
    context["results"]["pe"] = {"is_dotnet": True}
    assert runner.step_dotnet(context)["is_dotnet"]
    assert runner.step_go(make_context(b"go1.26.1 mx-go/internal/mail.Send"))["version"] == "go1.26.1"
    assert runner.step_unpack(make_context(b"var x = 1"))["format"] == "script"
    assert runner.step_scripts(make_context(b"PowerShell WScript.Shell"))["powershell"]
    assert not runner.step_iso(make_context())["iso9660"]
    monkeypatch.setattr(runner.shutil, "which", lambda name: "C:/tool" if name == "floss.exe" else None)
    assert runner.step_tool(context, "floss")["available"]
    assert runner.step_config(make_context(b"Remcos Agent c2.example:2404"), "remcosrat")["family"] == "remcosrat"
    context["results"]["config"] = {"findings": [{"value": "x"}]}
    assert runner.step_report(context)["config_findings"]


def test_execute_write_and_run(tmp_path: Path) -> None:
    context = make_context(b"Remcos Agent c2.example:2404")
    assert runner.execute_step("intake.submission@^1", context)["name"] == "x.bin"
    with pytest.raises(ValueError, match="no offline implementation"):
        runner.execute_step("unknown.step@^1", context)
    output = tmp_path / "value.json"
    runner.write_json(output, {"ok": True})
    assert json.loads(output.read_text())["ok"]
    sample = tmp_path / "vvas.bin"
    sample.write_bytes(b"odaktomk |8888:2o|72.8.59.202:2p|6666:1o|72.8.59.202:1p|")
    summary = runner.run_analysis(
        sample, DEFINITIONS, tmp_path / "run", family_hint="valleyrat", campaign_hint="dll_sideload_vvas_bundle"
    )
    assert summary["family"] == "valleyrat" and summary["network_contacted"] is False
    assert (tmp_path / "run" / "steps" / "config" / "result.json").exists()


def test_runtime_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    sample = tmp_path / "vvas.bin"
    sample.write_bytes(b"odaktomk")
    args = [
        "--sample",
        str(sample),
        "--definitions",
        str(DEFINITIONS),
        "--output",
        str(tmp_path / "out"),
        "--family-hint",
        "valleyrat",
    ]
    assert runtime_cli.build_parser().parse_args(args).family_hint == "valleyrat"
    assert runtime_cli.main(args) == 0
    assert '"family": "valleyrat"' in capsys.readouterr().out
