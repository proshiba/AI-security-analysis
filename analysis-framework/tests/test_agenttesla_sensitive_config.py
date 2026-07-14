from __future__ import annotations

import importlib.util
from pathlib import Path


MODULE = (
    Path(__file__).parents[1]
    / "malware"
    / "agenttesla"
    / "agenttesla_sensitive_config.py"
)
SPEC = importlib.util.spec_from_file_location("agenttesla_sensitive_config", MODULE)
assert SPEC and SPEC.loader
MODULE_OBJECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE_OBJECT)


def test_ftp_secrets_are_available_only_in_sensitive_result() -> None:
    strings = [
        "Mozilla/5.0",
        "ftp://collector.example/upload",
        "operator@example",
        "secret-value",
    ]
    result = MODULE_OBJECT.extract_sensitive_from_strings(strings)
    assert result["classification"] == "sensitive_local_only"
    assert result["records"] == [
        {
            "protocol": "FTP",
            "endpoint": "collector.example:21",
            "username": "operator@example",
            "password": "secret-value",
            "source": "dotnet_user_string",
        }
    ]


def test_sensitive_writer_does_not_echo_secret(tmp_path: Path) -> None:
    output = tmp_path / "private.json"
    MODULE_OBJECT.write_sensitive_json(output, {"password": "secret-value"})
    assert "secret-value" in output.read_text(encoding="utf-8")
