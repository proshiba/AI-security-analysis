"""ZIPサイドロード終端handlerの結果契約を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).parents[2]
HANDLER = (
    ROOT
    / "analysis-framework"
    / "malware"
    / "valleyrat"
    / "campaigns"
    / "zip_sideload_shellcode_vvas_terminal"
    / "analyze.py"
)


def _load_handler():
    spec = importlib.util.spec_from_file_location("test_zip_sideload_vvas_handler", HANDLER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _recovery(data: bytes) -> SimpleNamespace:
    payload = b"synthetic-vvas-terminal"
    terminal = SimpleNamespace(
        data=payload,
        sha256=hashlib.sha256(payload).hexdigest(),
        endpoints=("198.51.100.27:443",),
        endpoint_slots=(
            {
                "slot": 1,
                "transport": "tcp",
                "state": "configured_external",
                "endpoint": "198.51.100.27:443",
            },
            {"slot": 2, "transport": "tcp", "state": "incomplete_backup_without_port"},
            {"slot": 3, "transport": "tcp", "state": "placeholder"},
        ),
        shellcode_evidence={"required_groups": {"bounded_cfg_complete": True}},
        config_evidence={"candidate_count": 1},
    )
    reachability = SimpleNamespace(completed=True, instruction_count=128)
    return SimpleNamespace(
        source_size=len(data),
        member_count=4,
        pe_member_count=3,
        import_binding_count=4,
        proxy_reachability=reachability,
        launcher_reachability=reachability,
        delimiter_size=8,
        carrier_offset=64,
        shellcode=terminal,
    )


def test_handler_confirms_only_complete_lineage(monkeypatch: pytest.MonkeyPatch) -> None:
    handler = _load_handler()
    data = b"PK\x03\x04synthetic-archive"
    monkeypatch.setattr(handler, "recover_zip_sideload_shellcode", lambda _data: _recovery(data))

    result = handler.analyze(data, r"private\submission.zip")

    assert result["family"] == "valleyrat"
    assert result["config"]["terminal_family_confirmed"] is True
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["endpoints"] == ["198.51.100.27:443"]
    assert result["config"]["configuration_identity_included"] is False
    assert "configuration_identity_sha256" not in result["config"]
    assert result["c2"][0]["role"] == "configured_external_c2"
    assert result["c2"][0]["confidence"] == "confirmed_static_configuration"
    assert result["terminal_payload"]["data"] == b"synthetic-vvas-terminal"
    summary = result["config"]["zip_sideload_shellcode"]
    assert summary["raw_network_values_included"] is False
    assert summary["source_integrity_hash_included"] is False
    assert summary["component_hashes_included"] is False
    assert "source_sha256" not in summary
    launcher = summary["lineage"]["launcher_to_carrier"]
    assert launcher["delimiter_identity_hash_included"] is False
    assert "delimiter_sha256" not in launcher
    terminal = summary["lineage"]["terminal_shellcode"]
    assert terminal["shellcode_integrity_hash_included"] is False
    assert terminal["configuration_identity_included"] is False
    assert "shellcode_sha256" not in terminal
    assert "configuration_identity_sha256" not in terminal
    assert result["terminal_payload"]["name"] == "recovered-terminal.bin"
    assert result["terminal_payload"]["name"] != f"{hashlib.sha256(result['terminal_payload']['data']).hexdigest()}.bin"
    assert "198.51.100.27" not in repr(summary)


def test_handler_raises_no_evidence_for_incomplete_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    handler = _load_handler()
    monkeypatch.setattr(handler, "recover_zip_sideload_shellcode", lambda _data: None)

    with pytest.raises(handler.HandlerNoEvidenceError):
        handler.analyze(b"PK\x03\x04incomplete")
