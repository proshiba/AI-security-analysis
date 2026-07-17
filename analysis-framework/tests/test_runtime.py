"""Unit tests for every offline discovery and runner function."""

from __future__ import annotations

import hashlib
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
    assert discovery.infer_family(["remcos agent", "rmc-"]) == "remcosrat"
    assert discovery.infer_family(["lummac2", "build_id"]) == "lummastealer"
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


@pytest.mark.parametrize(
    "literal",
    [
        "remcos agent",
        "lummac2",
        "remusstealer",
        "formbook",
        "agenttesla",
        "otnmpxnddvnptbn",
        "vvas.bin",
        "n520",
        "quasar.client",
        "asyncrat server",
        "security dump-keychain",
    ],
)
def test_discovery_rejects_single_family_literal(literal: str) -> None:
    """Do not promote one family, runtime, or delivery literal to a family hint."""
    assert discovery.infer_family([literal]) is None


@pytest.mark.parametrize(
    ("strings", "family"),
    [
        (["remusstealer", "login data"], "remusstealer"),
        (["formbook", "ntsetcontextthread"], "formbook"),
        (["agenttesla", "appdomain"], "agenttesla"),
        (["vvas.bin", "loggercollector.dll"], "valleyrat"),
        (["n520", "config.enc"], "valleyrat"),
        (["quasar.client", "xclient.core", "reconnectdelay"], "venomrat"),
        (["asyncrat server", "hwid"], "asyncrat"),
        (["security dump-keychain", "osascript"], "amosstealer"),
    ],
)
def test_discovery_requires_correlated_family_evidence(strings: list[str], family: str) -> None:
    """Accept reviewed N-of-M or cross-category family evidence."""
    assert discovery.infer_family(strings) == family


def test_discovery_rejects_ambiguous_profile_evidence() -> None:
    """Do not turn the first matching profile into a compiler-bypassing hint."""
    assert discovery.infer_family(
        ["asyncrat server", "hwid", "dcrat.server", "darkcrystal"]
    ) is None


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
    assert runner.step_tool(context, "floss") == {
        "tool": "floss",
        "available": True,
        "path": "C:/tool",
        "invoked": False,
        "status": "preflight_only",
    }
    assert runner.step_config(make_context(b"Remcos Agent c2.example:2404"), "remcosrat")["family"] == "remcosrat"
    context["results"]["config"] = {"findings": [{"value": "x"}]}
    assert runner.step_report(context)["config_findings"]


def test_unpack_retains_private_child_and_config_selects_stronger_layer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep recovered bytes private while routing config to the evidenced child."""
    root = b"MZ-root"
    child = b"MZ-child-config"
    context = make_context(root)

    monkeypatch.setattr(
        runner,
        "unpack_bytes",
        lambda data, name: (
            {"format": "pe", "recovered": [{"kind": "decoded-pe", "sha256": hashlib.sha256(child).hexdigest()}]},
            [("decoded-pe", child)],
        ),
    )
    report = runner.step_unpack(context)
    assert report["retained_layers"][0]["parent_sha256"] == hashlib.sha256(root).hexdigest()
    assert "data" not in json.dumps(report)
    assert context["_layer_bytes"][hashlib.sha256(child).hexdigest()] == child

    def fake_extractor(data: bytes, name: str) -> dict:
        return {
            "family": "test",
            "sample_sha256": hashlib.sha256(data).hexdigest(),
            "config": {},
            "findings": [{"value": "child"}] if data == child else [],
        }

    monkeypatch.setattr(runner, "get_extractor", lambda family: fake_extractor)
    result = runner.step_config(context, "test")
    assert result["input_layer"]["sha256"] == hashlib.sha256(child).hexdigest()
    assert context["selected_layer_sha256"] == result["input_layer"]["sha256"]
    assert result["layer_selection"]["candidate_count"] == 2


def test_config_preserves_root_on_evidence_tie(monkeypatch: pytest.MonkeyPatch) -> None:
    """Avoid silently preferring an arbitrary recovered child without evidence."""
    context = make_context(b"root")
    monkeypatch.setattr(runner, "unpack_bytes", lambda data, name: ({"format": "data"}, [("blob", b"child")]))
    runner.step_unpack(context)
    monkeypatch.setattr(
        runner,
        "get_extractor",
        lambda family: lambda data, name: {"family": family, "config": {}, "findings": []},
    )
    result = runner.step_config(context, "test")
    assert result["input_layer"]["sha256"] == hashlib.sha256(b"root").hexdigest()


def test_config_prefers_confirmed_child_over_many_outer_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Quality of decoded evidence must outrank the outer literal count."""
    root = b"root"
    child = b"child"
    context = make_context(root)
    monkeypatch.setattr(runner, "unpack_bytes", lambda data, name: ({"format": "data"}, [("decoded", child)]))
    runner.step_unpack(context)

    def extract(data: bytes, name: str) -> dict:
        if data == root:
            findings = [
                {
                    "value": f"https://delivery.example/{index}",
                    "role": "delivery",
                    "confidence": "candidate",
                    "source": "embedded_literal",
                }
                for index in range(8)
            ]
            return {"family": "test", "config": {"static_config_recovered": False}, "findings": findings}
        return {
            "family": "test",
            "config": {"static_config_recovered": True},
            "findings": [
                {
                    "value": "c2.example:443",
                    "role": "configured_c2",
                    "confidence": "confirmed",
                    "source": "decoded_static_config",
                }
            ],
        }

    monkeypatch.setattr(runner, "get_extractor", lambda family: extract)
    result = runner.step_config(context, "test")
    assert result["input_layer"]["sha256"] == hashlib.sha256(child).hexdigest()
    assert result["layer_selection"]["attempts"][1]["evidence_score"] > result["layer_selection"]["attempts"][0][
        "evidence_score"
    ]


def test_donut_layers_retain_child_for_terminal_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Route a terminal-family step to a child recovered by the layer step."""
    root = b"donut-root"
    child = b"terminal-child"
    context = make_context(root)
    monkeypatch.setattr(
        runner,
        "unpack_bytes",
        lambda data, name: ({"format": "data"}, [("donut-terminal-payload", child)]),
    )

    def extractor_for(family: str):
        def extract(data: bytes, name: str) -> dict:
            finding = (
                family == "donutloader" and data == root
            ) or (
                family == "purehvnc" and data == child
            )
            return {"family": family, "config": {}, "findings": [{"value": family}] if finding else []}

        return extract

    monkeypatch.setattr(runner, "get_extractor", extractor_for)
    layer_result = runner.execute_step("family.donutloader.layers@^1", context)
    assert layer_result["unpack"]["retained_layers"][0]["sha256"] == hashlib.sha256(child).hexdigest()
    terminal = runner.execute_step("family.purehvnc.config@^1", context)
    assert terminal["input_layer"]["sha256"] == hashlib.sha256(child).hexdigest()
    context["results"]["terminal"] = terminal
    assert runner.step_report(context)["config_findings"] == [{"value": "purehvnc"}]


def test_config_rejects_tampered_retained_layer(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail closed if in-memory layer bytes no longer match recorded provenance."""
    context = make_context(b"root")
    runner._ensure_root_layer(context)
    context["_layer_bytes"][hashlib.sha256(b"root").hexdigest()] = b"tampered"
    monkeypatch.setattr(runner, "get_extractor", lambda family: lambda data, name: {})
    with pytest.raises(ValueError, match="hash mismatch"):
        runner.step_config(context, "test")


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
    tool_states = {item["id"]: item["status"] for item in summary["steps"]}
    assert tool_states["floss"] == "not_invoked" and tool_states["ghidra"] == "not_invoked"


def test_unknown_family_executes_bounded_static_fallback(tmp_path: Path) -> None:
    """Unknown attribution must still reach the offline fallback workflow."""
    sample = tmp_path / "unknown.bin"
    sample.write_bytes(b"plain unknown bytes http://unknown.example/path")
    summary = runner.run_analysis(sample, DEFINITIONS, tmp_path / "unknown-run")
    assert summary["family"] == "unknown" and summary["plan_status"] == "needs_review"
    assert [item["id"] for item in summary["steps"]] == ["intake", "inventory", "strings", "iocs", "report"]
    assert all(item["status"] == "succeeded" for item in summary["steps"])
    assert (tmp_path / "unknown-run" / "steps" / "report" / "result.json").exists()


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
