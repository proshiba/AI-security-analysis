"""外部通信data requirement catalogの全registry被覆を検証する。"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

FRAMEWORK = Path(__file__).resolve().parents[1]
ROOT = FRAMEWORK.parent
MODULE = FRAMEWORK / "common" / "audit_external_communication_requirements.py"
CATALOG = FRAMEWORK / "common" / "external_communication_requirements.json"


def _load():
    spec = importlib.util.spec_from_file_location("audit_external_communication_requirements", MODULE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


AUDIT = _load()


def test_catalog_covers_every_registered_handler_and_host_adapter() -> None:
    result = AUDIT.build_audit(repository=ROOT)
    assert result["status"] == "complete"
    assert result["network_used"] is False
    assert result["sample_executed"] is False
    assert result["coverage"]["requirement_contract_count"] == 17
    assert result["coverage"]["protocol_handler_count"] == 13
    assert result["coverage"]["host_adapter_count"] == 4
    assert result["coverage"]["unmapped_registry_handlers"] == []
    assert result["coverage"]["unmapped_host_adapters"] == []
    assert result["coverage"]["emulator_source_count"] >= 60
    assert sum(result["coverage"]["source_mode_counts"].values()) == result["coverage"]["emulator_source_count"]
    assert (
        result["coverage"]["mapped_emulator_source_count"]
        + result["coverage"]["unmapped_emulator_source_count"]
        == result["coverage"]["emulator_source_count"]
    )


def test_winos_and_purerat_gaps_are_explicit_not_promoted_to_live() -> None:
    result = AUDIT.build_audit(repository=ROOT)
    contracts = {item["contract_id"]: item for item in result["requirements"]}
    winos = contracts["valleyrat-winos-control"]
    assert winos["synthetic_support"] == "offline_reference_layout_only"
    assert winos["external_status"] == "fixed_probe_only"
    assert "sample_specific_login_token" in winos["unresolved"]
    assert "current_sample_logininfo_serializer" in winos["unresolved"]
    purerat = contracts["purerat-441-direct-tls"]
    assert purerat["synthetic_support"] == "exact_empty_gclass4_only"
    assert purerat["external_status"] == "offline_or_loopback_only"
    assert "required_populated_member_subset" in purerat["unresolved"]


def test_identity_bearing_contracts_name_real_and_synthetic_requirements() -> None:
    document = json.loads(CATALOG.read_text(encoding="utf-8"))
    contracts = {item["contract_id"]: item for item in document["requirements"]}
    assert "HWID" in contracts["asyncrat-058-clientinfo"]["registration_fields"]
    assert "DesktopName" in contracts["venomrat-603-clientinfo"]["registration_fields"]
    assert contracts["stealc-v2-registration-task"]["synthetic_support"] == "stable_uuidv5_hwid"
    assert contracts["lumma-v6-registration-task"]["registration_fields"] == ["uid", "cid", "hwid"]
    assert contracts["remus-registration-task"]["registration_fields"] == [
        "tag",
        "exp",
        "hwid",
        "access_token",
        "step",
    ]


def test_every_emulator_source_is_inventoried_without_granting_live_support() -> None:
    result = AUDIT.build_audit(repository=ROOT)
    inventory = result["emulator_source_inventory"]
    paths = {item["path"] for item in inventory}
    assert "analysis-framework/malware/valleyrat/winos_host_emulator.py" in paths
    assert "analysis-framework/malware/purehvnc/purerat_host_emulator.py" in paths
    assert "analysis-framework/malware/acrstealer/emulator.py" in paths
    assert all(item["docstring_present"] is True for item in inventory)
    assert result["safety"]["unregistered_emulator_implies_live_support"] is False


def test_cli_check_is_offline_and_successful(capsys) -> None:
    assert AUDIT.main(["--repository", str(ROOT), "--check"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "complete"
    assert result["safety"]["external_connection_attempted"] is False
    assert result["safety"]["malware_application_data_sent"] is False
