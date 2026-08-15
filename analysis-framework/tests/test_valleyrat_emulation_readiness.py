"""ValleyRATエミュレーション準備監査をofflineで検証する。"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = (
    ROOT
    / "analysis-framework"
    / "malware"
    / "valleyrat"
    / "audit_emulation_readiness.py"
)


def _load():
    spec = importlib.util.spec_from_file_location("valleyrat_emulation_readiness", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


AUDIT = _load()
SAMPLE = "1" * 64


def test_repository_reports_expected_offline_component_states() -> None:
    result = AUDIT.audit_repository(ROOT)

    assert result["components"]["n520"]["status"] == "ready"
    assert result["components"]["winos"]["status"] in {
        "adapter_ready_common_runner_pending",
        "ready",
    }
    assert result["components"]["vvas"]["status"] == "probe_only_ready"
    assert result["safety"]["live_network_used"] is False
    assert result["safety"]["sample_executed"] is False
    assert result["safety"]["adapter_modules_imported"] is False

    host_registry = json.loads(
        (ROOT / AUDIT.HOST_REGISTRY).read_text(encoding="utf-8")
    )
    expected_protocol_sha256 = host_registry["protocol_profile_registry"]["sha256"]
    assert result["status"] == "complete"
    assert result["check_passed"] is True
    assert result["registry_binding"]["protocol_registry_pin_matches"] is True
    assert result["registry_binding"]["protocol_registry_sha256"] == expected_protocol_sha256
    assert result["registry_binding"]["host_registry_sha256"] == (
        "e0bee32089355702a37b6a4f4c014e35df1d409873d0afc97ef71376a482a43d"
    )


def test_safe_common_winos_profile_transitions_to_ready(tmp_path: Path) -> None:
    evidence = tmp_path / "winos-evidence.json"
    evidence.write_text("{}\n", encoding="utf-8")
    protocol_profile = {
        "profile_id": "valleyrat-winos-test",
        "family": "valleyrat",
        "sample_sha256s": [SAMPLE],
        "host": "198.51.100.10",
        "port": 8868,
        "protocol": "winos",
        "method": "winos_heartbeat",
        "handler": "valleyrat_winos_reviewed",
        "channel_role": "control",
        "maximum_response_bytes": 64,
    }
    host_profile = {
        "profile_id": "valleyrat-winos-host-test",
        "protocol_profile_id": protocol_profile["profile_id"],
        "protocol_profile_object_sha256": AUDIT._canonical_object_sha256(protocol_profile),
        "family": "valleyrat",
        "adapter_id": "valleyrat_winos_v1",
        "host": protocol_profile["host"],
        "port": protocol_profile["port"],
        "pinned_ips": ["198.51.100.10"],
        "sample_sha256s": [SAMPLE],
        "evidence_source": evidence.name,
        "evidence_sha256": AUDIT._canonical_lf_json_sha256(
            evidence.read_bytes(),
            label="test Winos evidence",
        ),
        "registration_mode": "fixed_c9_heartbeat",
        "station_id_sent": False,
        "unknown_task_action": "no_response",
        "file_transfer_action": "reject_and_close",
        "fake_result_scope": "loopback_or_offline_only",
        "allow_live_fake_results": False,
        "limits": {
            "maximum_connections": 1,
            "maximum_outbound_frames": 1,
            "maximum_inbound_frames": 1,
            "maximum_commands": 1,
            "maximum_inbound_bytes": 64,
            "maximum_frame_bytes": 64,
        },
    }

    result = AUDIT._audit_winos(
        tmp_path,
        {protocol_profile["profile_id"]: protocol_profile},
        {host_profile["profile_id"]: host_profile},
        {"safe": True},
        {"allowlisted": True, "runner_mapped": True},
    )

    assert result["status"] == "ready"
    assert result["host_profiles"][0]["safe"] is True


def test_check_returns_nonzero_for_partial(
    tmp_path: Path,
    monkeypatch,
) -> None:
    output = tmp_path / "result.json"
    monkeypatch.setattr(AUDIT, "audit_repository", lambda _repository: {"status": "partial"})

    assert AUDIT.main(["--repository", str(tmp_path), "--output", str(output), "--check"]) == 1
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "partial"
