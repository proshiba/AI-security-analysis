"""Onyx Qt loader handlerのfail-closed判定とone-shot接続を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK_ROOT = REPOSITORY_ROOT / "analysis-framework"
COMMON = FRAMEWORK_ROOT / "common"
for import_root in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from analysis_contract import handler_result_quality  # noqa: E402
from handler_catalog import (  # noqa: E402
    discover_handlers,
    preflight_handler_for_assessment,
)
from static_logic import build_static_logic_report  # noqa: E402


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


FIXTURES = _load(
    "onyx_qt_loader_handler_fixtures",
    REPOSITORY_ROOT / "unpackers" / "tests" / "test_onyx_qt_loader.py",
)
ANALYZER = _load(
    "onyx_qt_loader_handler",
    FRAMEWORK_ROOT / "malware" / "valleyrat" / "campaigns" / "onyx_qt_loader" / "analyze.py",
)
STATIC_REVIEW = _load(
    "onyx_qt_loader_static_review",
    FRAMEWORK_ROOT / "malware" / "valleyrat" / "campaigns" / "onyx_qt_loader" / "static_review.py",
)
REVIEWED = _load(
    "onyx_qt_loader_reviewed_samples",
    FRAMEWORK_ROOT / "malware" / "valleyrat" / "common" / "reviewed_samples.py",
)


def _source_with_terminal_config() -> bytes:
    shellcode, _ = FIXTURES._terminal_config_fixture()
    return FIXTURES._fixture(shellcode)


def _handler_spec():
    return next(
        item
        for item in discover_handlers()
        if item.family == "valleyrat"
        and item.campaign == "onyx_qt_loader"
        and item.relative_path.endswith("onyx_qt_loader/analyze.py")
    )


def test_handler_confirms_full_chain_and_static_config() -> None:
    """外層から4反復slotまで一致した場合だけtier 3の静的設定を返す。"""

    shellcode, _config = FIXTURES._terminal_config_fixture()
    result = ANALYZER.analyze(FIXTURES._fixture(shellcode), "offline-fixture.exe")

    assert result["matched"] is True
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["terminal"]["repeated_slot_count"] == 4
    assert result["protocol_fingerprint"]["request"]["body_size"] == 0xACA
    assert result["protocol_fingerprint"]["response"]["header_size"] == 0x36
    assert result["attribution"]["terminal_component"]["status"] == "confirmed_static"
    assert result["attribution"]["valleyrat"]["status"] == "not_attributed_terminal"
    assert result["attribution"]["silverfox"]["status"] == "delivery_ecosystem_label_only"
    assert result["attribution"]["independent_onyx_family"]["status"] == "unresolved"
    assert result["executed"] is False
    assert result["network_contacted"] is False
    assert result["terminal_payload"] == {
        "role": "terminal_payload",
        "name": f"{hashlib.sha256(shellcode).hexdigest()}.bin",
        "data": shellcode,
    }
    assert handler_result_quality(result)["tier"] == 3


def test_handler_fails_closed_before_and_after_outer_recovery() -> None:
    """identity欠落と終端設定欠落はいずれもevidence tier 0で拒否する。"""

    source = _source_with_terminal_config()
    identity_mismatch = ANALYZER.analyze(
        source.replace(b"D3DCompile", b"NoGpuMarker"),
        "identity-mismatch.exe",
    )
    terminal_missing = ANALYZER.analyze(
        FIXTURES._fixture(b"\x90" * 128),
        "terminal-missing.exe",
    )

    for result in (identity_mismatch, terminal_missing):
        assert result["matched"] is False
        assert result["config"]["static_config_recovered"] is False
        assert result["config"]["endpoints"] == []
        assert result["representative_functions"] == []
        assert "terminal_payload" not in result
        assert handler_result_quality(result)["sufficient"] is False


def test_reviewed_exact_route_returns_eight_ghidra_functions(monkeypatch) -> None:
    """既知routeでは8関数と明示selector付きprogram証拠をone-shotへ返す。"""

    source = _source_with_terminal_config()
    digest = hashlib.sha256(source).hexdigest()
    monkeypatch.setitem(
        ANALYZER.REVIEWED,
        digest,
        {"variant": "offline_reviewed_fixture", "final_rat_confirmed": False},
    )
    monkeypatch.setattr(ANALYZER, "ROOT_SHA256", digest)

    result = ANALYZER.analyze(source, "reviewed-fixture.exe")
    functions = result["representative_functions"]
    programs = result["program_evidence"]

    assert len(functions) == 8
    assert {item["name"] for item in functions} == {
        "ResolveApiByRor13Hash",
        "GetCallerReturnAddress",
        "InitializeXorSwapStreamState",
        "TransformWithXorSwapStream",
        "EncryptOnyxConfigBuffer",
        "FindEmbeddedConfigMarker",
        "PostOnyxHttpRequest",
        "RunOnyxTerminalStage",
    }
    assert all(item["tool"] == "ghidra-mcp" for item in functions)
    assert all(item["program_selector"].startswith("/") for item in functions)
    assert len(programs) == 1
    assert programs[0]["function_count"] == 8
    assert programs[0]["mcp_responses_valid"] is True
    assert len(programs[0]["function_hashes"]) == 8


def test_exact_sample_registry_and_handler_catalog_are_connected() -> None:
    """4972 root hashは専用campaignへroutingされ、handlerは自動実行可能である。"""

    record = REVIEWED.REVIEWED_SAMPLES[STATIC_REVIEW.ROOT_SHA256]
    assert record["campaign"] == "onyx_qt_loader"
    assert record["final_rat_confirmed"] is False
    assert record["terminal_family_attribution"] == "component_confirmed_family_unresolved"

    handler = _handler_spec()
    assert handler.automatic is True
    assert handler.input_formats == ("pe",)
    assert handler.minimum_evidence_score == 30_000
    preflight = preflight_handler_for_assessment(
        handler,
        actual_format="pe",
        input_size=3_593_216,
    )
    assert preflight["eligible"] is True
    assert preflight["blockers"] == []
    assert preflight["sample_execution_allowed"] is False
    assert preflight["network_allowed"] is False
    assert preflight["filesystem_write_allowed"] is False


def test_static_logic_keeps_api_calls_separate_from_fingerprint_tokens() -> None:
    """構造fingerprint用tokenをAPI call一覧へ混入させない。"""

    report = build_static_logic_report(
        sha256=STATIC_REVIEW.ROOT_SHA256,
        family="valleyrat",
        source_name="onyx-terminal-shellcode.bin",
        records=STATIC_REVIEW.REPRESENTATIVE_FUNCTIONS,
        program_evidence=STATIC_REVIEW.PROGRAM_EVIDENCE,
    )
    functions = {item["name"]: item for item in report["functions"]}

    assert functions["ResolveApiByRor13Hash"]["api_calls"] == []
    assert functions["PostOnyxHttpRequest"]["api_calls"] == [
        "LoadLibraryA",
        "InternetOpenW",
        "InternetConnectW",
        "HttpOpenRequestW",
        "HttpSendRequestW",
        "InternetReadFile",
        "InternetCloseHandle",
        "Sleep",
        "memcpy",
    ]
    assert report["coverage"]["function_count"] == 8
    assert report["coverage"]["call_edge_count"] == 10
