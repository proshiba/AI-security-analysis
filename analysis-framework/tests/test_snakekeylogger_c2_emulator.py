"""Snake KeyloggerのC2評価と秘密値非保持エミュレーターを検証する。"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1] / "malware" / "snakekeylogger"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


c2_detector = _load("c2_detector")
emulator = _load("emulator")


def _config() -> dict[str, object]:
    return {
        "family": "snakekeylogger",
        "variant": "vipkeylogger",
        "recovery_status": "confirmed_static_config",
        "config_endpoints": [
            {
                "protocol": "smtp",
                "host": "mail.example.test",
                "port": 587,
                "role": "credential_exfiltration",
                "confidence": "confirmed_static_config",
            }
        ],
        "smtp_identity_present": True,
        "smtp_recipient_present": True,
        "smtp_password_present": True,
        "credential_values_published": False,
        "telegram": {
            "api_host": "api.telegram.org",
            "path_template": "/bot{token}/sendMessage",
            "token_configured": False,
            "chat_id_configured": False,
            "credential_values_published": False,
        },
    }


def _observation() -> dict[str, object]:
    return {
        "source": "triage_dynamic_report",
        "host": "api.telegram.org",
        "protocol": "https",
        "request_observed": True,
        "process_attributed": True,
        "path_family": "bot_sendMessage",
    }


def test_build_report_separates_static_smtp_and_passive_telegram() -> None:
    report = c2_detector.build_report(_config(), [_observation()])
    assert report["static_config"] == {
        "status": "confirmed",
        "protocol": "smtp",
        "host": "mail.example.test",
        "port": 587,
        "role": "credential_exfiltration",
        "credentials_present": True,
        "credentials_published": False,
        "liveness_confirmed": False,
    }
    assert report["telegram"]["passive_runtime_observation"] is True
    assert report["telegram"]["configured_operator_endpoint"] is False
    assert report["assessment"]["c2_config_confirmed"] is True
    assert report["assessment"]["c2_liveness_confirmed"] is False
    rendered = repr(report)
    assert "chat_id=" not in rendered
    assert "bot-" not in rendered


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.update(family="agenttesla"),
        lambda value: value.update(recovery_status="candidate"),
        lambda value: value["config_endpoints"][0].update(port=0),
        lambda value: value["config_endpoints"][0].update(confidence="candidate"),
        lambda value: value.update(credential_values_published=True),
        lambda value: value["telegram"].update(token_configured=True),
    ],
)
def test_build_report_rejects_semantic_mutations(mutator) -> None:
    value = _config()
    mutator(value)
    with pytest.raises(c2_detector.SnakeC2DetectionError):
        c2_detector.build_report(value)


def test_observation_is_exact_and_bounded() -> None:
    extra = _observation()
    extra["raw_request"] = "secret"
    with pytest.raises(c2_detector.SnakeC2DetectionError):
        c2_detector.build_report(_config(), [extra])
    with pytest.raises(c2_detector.SnakeC2DetectionError, match="最大1件"):
        c2_detector.build_report(_config(), [_observation(), _observation()])


def test_smtp_sink_refuses_authentication_and_retains_no_secret() -> None:
    session = emulator.SmtpSinkSession()
    assert session.feed(b"EHLO workstation\r\n").startswith(b"250-")
    assert session.feed(b"AUTH LOGIN synthetic-secret\r\n").startswith(b"535 ")
    result = session.public_result()
    assert result["authentication_attempted"] is True
    assert result["authentication_accepted"] is False
    assert result["credentials_published"] is False
    assert "synthetic-secret" not in repr(result)


def test_telegram_sink_returns_fixed_failure_without_publishing_query() -> None:
    request = (
        b"GET /botSYNTHETIC/sendMessage?chat_id=123&text=secret HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n\r\n"
    )
    response, result = emulator.handle_telegram_request(request)
    assert response.startswith(b"HTTP/1.1 400 Bad Request")
    assert result["valid_telegram_response_generated"] is False
    assert result["query_published"] is False
    assert "secret" not in repr(result)
    with pytest.raises(emulator.SnakeEmulatorError):
        emulator.handle_telegram_request(b"POST / HTTP/1.1\r\n\r\n")


def test_emulator_rejects_external_bind_before_socket_creation() -> None:
    calls = 0

    def forbidden_socket(*_args, **_kwargs):
        nonlocal calls
        calls += 1
        raise AssertionError("socketを作成してはならない")

    with pytest.raises(emulator.SnakeEmulatorError, match="loopback外"):
        emulator.run_telegram_loopback(
            "8.8.8.8", 8080, socket_factory=forbidden_socket
        )
    assert calls == 0
    plan = emulator.build_plan("telegram")
    assert plan["network_scope"] == "offline_or_numeric_loopback_only"
    assert plan["external_network_contacted"] is False
