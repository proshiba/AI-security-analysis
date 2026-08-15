"""日本語マルスパム経由VIPKeylogger caseの公開契約を検証する。"""

from __future__ import annotations

import importlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest


REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
SNAKE = REPOSITORY / "analysis-framework" / "malware" / "snakekeylogger"
DIGEST = "dfc8e7b7e48faab9a410111ea31001c729ab9b1c83525499f028b5344869be9e"
TERMINAL = "0acab73175c36331fb8a46f78d0eb6c02f76e79cf1f52bdd0ef27d61ca8c10df"
CASE = (
    REPOSITORY
    / "analysis-results"
    / "malware"
    / "snakekeylogger"
    / "versions"
    / "unknown"
    / "cases"
    / DIGEST
)


def _module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))
analysis_contract = importlib.import_module("analysis_contract")
c2_contract = importlib.import_module("c2_analysis_contract")
static_logic = _module("snakekeylogger_static_logic", SNAKE / "static_logic.py")


def _json(name: str) -> dict[str, object]:
    value = json.loads((CASE / name).read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_static_logic_contract_and_roles() -> None:
    report = _json("static-logic.json")
    assert report["sha256"] == TERMINAL
    assert report["status"] == "reviewed_function_logic"
    assert report["managed_method_count"] == 647
    assert report["managed_cil_body_count"] == 591
    assert report["managed_declaration_count"] == 56
    assert len(report["managed_method_inventory"]) == 647
    assert {item["role"] for item in report["functions"]} == {
        "config_initializer",
        "config_decryptor",
        "screenshot_collector",
        "multi_backend_exfiltration",
        "telegram_sender",
        "keyboard_hook_initializer",
        "clipboard_collector",
    }


def test_static_logic_helpers_are_fail_closed() -> None:
    assert static_logic._strict_token(True) is None
    assert static_logic._strict_token(0) is None
    assert static_logic._strict_token(0x06000020) == 0x06000020
    assert static_logic._api_category("SetWindowsHookExA") == "keyboard_hook"
    assert static_logic._api_category("OpenClipboard") == "clipboard_access"
    assert static_logic._api_category("unrelated") is None
    with pytest.raises(static_logic.SnakeStaticLogicError, match="SHA-256"):
        static_logic.analyze(b"not-the-terminal")
    with pytest.raises(static_logic.SnakeStaticLogicError, match="32 MiB"):
        static_logic.analyze(b"x" * (static_logic.MAXIMUM_INPUT_SIZE + 1))


def test_exact_static_chain_and_public_config() -> None:
    layers = _json("static-layers.json")
    records = layers["layers"]
    assert [item["sha256"] for item in records] == [
        DIGEST,
        "36ea8b1a990ceb83adf53f626078d631580b7d973e410e916a4818fab0014d3d",
        "52f0c0230b580e2fdf53a378b5c6d0db9829af900dae43e0df8f18635cd9f0c1",
        "223c68d8250224d43d2faed546ffa2b2fbc3e0e5e60261f7e758a915495424e0",
        TERMINAL,
    ]
    assert layers["counts"] == {
        "total_layers": 5,
        "recovered_layers": 4,
        "terminal_layers": 1,
        "failed_steps": 0,
    }
    config = _json("config.json")
    assert config["builder_version"] == "4.4"
    assert config["endpoints"] == [
        {
            "host": "mail.elpasohonroso.com",
            "port": 587,
            "protocol": "smtp",
            "role": "credential_exfiltration",
            "confidence": "confirmed_static_config",
        }
    ]
    assert config["smtp"]["credential_values_published"] is False
    assert config["telegram"]["token_configured"] is False
    assert config["telegram"]["chat_id_configured"] is False


def test_c2_contract_is_daily_ready_without_overpromotion() -> None:
    result = c2_contract.validate_case(CASE, DIGEST, repository=REPOSITORY)
    assert result["complete"] is False
    assert result["daily_ready"] is True
    assert result["deferred"] is True
    assert result["daily_blocking_finding_count"] == 0
    c2 = _json("c2-analysis.json")
    assert c2["terminal_payload"]["status"] == "recovered"
    assert c2["c2"]["outcome"] == "unresolved"
    assert c2["c2"]["protocol"]["status"] == "static_confirmed_live_unverified"
    assert c2["c2"]["live_check"]["payload_sent"] is False
    assert c2["safety"]["credentials_published"] is False


def test_case_integrity_and_partial_liveness_blocker() -> None:
    report = _json("report.json")
    assert report["case_state"] == {
        "blockers": ["live_protocol_confirmation_pending"],
        "complete": False,
        "detector_error_families": [],
        "incomplete_selected_layer_attempts": [],
        "resumable": False,
        "static_layer_issues": [],
        "status": "partial",
    }
    assert (
        analysis_contract.case_integrity_errors(
            CASE,
            report,
            expected_digest=DIGEST,
            require_resumable=False,
        )
        == []
    )


def test_triage_and_iocs_exclude_secrets() -> None:
    triage = _json("triage-evidence.json")
    match = triage["public_matches"][0]
    assert match["sample_id"] == "260812-j8tk9acr6t"
    assert match["families"] == ["donutloader", "vipkeylogger"]
    assert match["smtp_connection_observed"] is False
    iocs = _json("iocs.json")
    assert iocs["network"] == [
        {
            "host": "mail.elpasohonroso.com",
            "port": 587,
            "protocol": "smtp",
            "role": "credential_exfiltration",
            "confidence": "confirmed_static_configuration",
            "source": "config.json",
            "evidence": {
                "kind": "des_decrypted_static_config",
                "source_file": "config.json",
                "terminal_sha256": TERMINAL,
            },
        }
    ]
    rendered = "\n".join(
        (CASE / name).read_text(encoding="utf-8")
        for name in ("config.json", "c2-analysis.json", "triage-evidence.json")
    )
    for forbidden in ('"smtp_password":', '"telegram_token":', "chat_id=", "SYNTHETIC"):
        assert forbidden not in rendered
