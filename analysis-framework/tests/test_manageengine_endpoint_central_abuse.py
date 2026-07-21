"""ManageEngine Endpoint Central無断登録解析機能の回帰テスト。"""

from __future__ import annotations

from io import BytesIO
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import zipfile

import pytest


ROOT = Path(__file__).resolve().parents[2]
FAMILY = ROOT / "analysis-framework" / "malware" / "manageengine_endpoint_central_abuse"
COMMON = ROOT / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


EXTRACTOR = _load("manageengine_abuse_extractor", FAMILY / "extract_config.py")
DETECTOR = _load("manageengine_abuse_detector", FAMILY / "detect.py")
NETWORK = _load("manageengine_abuse_network", FAMILY / "network_detector.py")
EMULATOR = _load("manageengine_abuse_emulator", FAMILY / "emulator.py")


def _numeric_vbs(payload: str, *, remove_delimiter: bool = False) -> bytes:
    tokens = [str(ord(character) ^ 42) for character in payload]
    encoded = ",".join(tokens)
    if remove_delimiter:
        encoded = encoded.replace("2,27", "227", 1)
    return (
        "Function Decode(blob, key)\n"
        "  Dim items, value, i\n"
        "  items = Split(blob, \",\")\n"
        "  value = \"\"\n"
        "  For i = 0 To UBound(items)\n"
        "    value = value & Chr(CInt(items(i)) Xor key)\n"
        "  Next\n"
        "  Decode = value\n"
        "End Function\n"
        f"encoded = \"{encoded}\"\n"
        "decoded = Decode(encoded, 31 + 11)\n"
        "ExecuteGlobal decoded\n"
    ).encode("ascii")


def _server_config() -> tuple[bytes, str, str]:
    auth = "synthetic-auth-value"
    ds_value = "synthetic-distribution-secret"
    document = {
        "RemoteOfficeProps": {
            "SERVERPROTOCOL": "https",
            "REMOTEOFFICENAME": "試験グループ",
            "CUSTOMERID": "1",
            "REMOTEOFFICEID": "301",
            "REMOTEOFFICEAUTHKEY": auth,
        },
        "DSAuthProps": {"VALUE1": ds_value, "VALUE2": auth},
        "ServerInfoProps": {
            "SERVERSECIPADDRESS": "203.0.113.10",
            "SERVERSECUREPORT": "8383",
            "SERVERNAME": "TEST-SERVER",
            "SERVERFLATNAME": "TEST-SERVER",
            "productcode": "DCEE",
        },
        "AgentProps": {
            "AGENTVERSION": "11.3.test",
            "ProductVersion": "11.3.test",
            "AGENTPOLLINGINTERVAL": "2",
            "ENABLEREMOTEOFFICEMGMT": "yes",
        },
    }
    return json.dumps(document, ensure_ascii=False).encode("utf-8"), auth, ds_value


def _setup_script() -> bytes:
    return (
        'CreateObject("Shell.Application").ShellExecute "wscript.exe", "", "", "runas", 0\n'
        'cmd = "powercfg /hibernate off"\n'
        'cmd = "msiexec /i UEMSAgent.msi TRANSFORMS=UEMSAgent.mst ENABLESILENT=yes '
        'SERVER_ROOT_CRT=DMRootCA-Server.crt DS_ROOT_CRT=DMRootCA.crt /qn"\n'
    ).encode("ascii")


def _bundle_zip() -> bytes:
    config, _, _ = _server_config()
    stream = BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("UEMSAgent.msi", b"synthetic signed product placeholder")
        archive.writestr("UEMSAgent.mst", b"synthetic transform")
        archive.writestr("DCAgentServerInfo.json", config)
        archive.writestr("DMRootCA.crt", b"synthetic ca")
        archive.writestr("DMRootCA-Server.crt", b"synthetic server ca")
        archive.writestr("setup1.vbs", _setup_script())
    return stream.getvalue()


def test_numeric_xor_vbs_is_decoded_without_execution() -> None:
    payload = 'Set x = CreateObject("WScript.Shell")\nurl = "https://example.invalid/payload.zip"\nEnd If\n'
    result = EXTRACTOR.extract_config(_numeric_vbs(payload))
    analysis = result["analysis"]
    assert analysis["xor_key"] == 42
    assert analysis["delivered_execution_state"] == "decoded_vbscript_structurally_valid"
    assert analysis["urls"] == ["https://example.invalid/payload.zip"]
    assert result["safety"] == {
        "sample_executed": False,
        "network_contacted": False,
        "secrets_exported": False,
    }


def test_malformed_numeric_token_is_not_silently_treated_as_valid() -> None:
    payload = "CreateObject(1)\nEnd Function\n"
    result = EXTRACTOR.extract_config(_numeric_vbs(payload, remove_delimiter=True))
    analysis = result["analysis"]
    assert analysis["delivered_execution_state"] == "syntactically_invalid_decoded_vbscript"
    assert analysis["raw_decoded"]["malformed_tokens"]
    if analysis["analysis_repair"]["performed"]:
        assert analysis["analysis_repair"]["sample_bytes_modified"] is False


def test_chr_xor_chains_are_folded_without_execution() -> None:
    expected = "https://example.invalid/payload.zip"
    chain = "&".join(f"Chr({ord(character) ^ 73} Xor 73)" for character in expected)
    resolved, metadata = EXTRACTOR._resolve_chr_xor_layer(f"url = {chain}")
    assert expected in resolved
    assert metadata == {
        "expression_count": len(expected),
        "chain_count": 1,
        "unresolved_count": 0,
    }


def test_server_config_extracts_endpoint_and_redacts_secrets() -> None:
    config, auth, ds_value = _server_config()
    result = EXTRACTOR.extract_config(config)
    analysis = result["analysis"]
    assert analysis["server"]["host"] == "203.0.113.10"
    assert analysis["server"]["port"] == 8383
    assert analysis["agent"]["version"] == "11.3.test"
    assert analysis["agent"]["polling_interval"] == "2"
    assert analysis["remote_office"]["authentication"]["sha256"] == hashlib.sha256(auth.encode()).hexdigest()
    rendered = json.dumps(result, ensure_ascii=False)
    assert auth not in rendered
    assert ds_value not in rendered
    assert analysis["secrets_exported"] is False


def test_bundle_zip_is_parsed_in_memory_and_detected() -> None:
    bundle = _bundle_zip()
    extracted = EXTRACTOR.extract_config(bundle)["analysis"]
    detected = DETECTOR.detect(bundle, Path("bundle.zip"))
    assert extracted["deployment_bundle"] is True
    assert extracted["member_count"] == 6
    assert any(item["configuration_type"] == "manageengine_endpoint_central_agent_server" for item in extracted["artifacts"])
    assert detected["matched"] is True
    assert detected["observations"]["deployment_bundle"] is True


def test_standalone_msi_like_data_is_not_declared_malicious() -> None:
    data = b"MZ synthetic ManageEngine UEMSAgent.msi product data"
    result = DETECTOR.detect(data, Path("UEMSAgent.msi"))
    assert result["matched"] is False
    assert result["observations"]["standalone_msi_is_not_detected"] is True


def test_network_detector_requires_campaign_or_unauthorized_context() -> None:
    base = {
        "host": "202.61.160.189",
        "port": 8383,
        "tls_subject": "CN=ManageEngine, O=Zoho Corporation",
        "tls_issuer": "CN=ManageEngineCA, O=Zoho Corporation",
        "product": "ManageEngine Endpoint Central",
    }
    observed = NETWORK.detect_flow(base)
    assert observed["matched"] is True
    assert observed["malicious"] is False
    correlated = NETWORK.detect_flow({**base, "campaign_config_correlation": True})
    assert correlated["malicious"] is True
    assert correlated["classification"] == "suspected_unauthorized_rmm_enrollment"


def test_emulator_has_no_external_side_effects() -> None:
    result = EMULATOR.emulate(download_success_attempt=2, extraction_success_method=1)
    assert result["network_contacted"] is False
    assert result["sample_executed"] is False
    assert result["files_written"] is False
    assert result["processes_started"] is False
    assert result["stage1"]["would_start"].startswith("wscript.exe")


def test_automatic_handler_and_registry_are_present() -> None:
    from handler_catalog import discover_handlers

    handlers = [item for item in discover_handlers() if item.family == "manageengine_endpoint_central_abuse"]
    assert len(handlers) == 1
    assert handlers[0].automatic is True
    assert handlers[0].callable_name == "extract_config"
    registry = json.loads((ROOT / "analysis-framework" / "registry" / "malware_types.json").read_text(encoding="utf-8"))
    entry = registry["malware_types"]["manageengine_endpoint_central_abuse"]
    assert entry["classification"] == "legitimate_rmm_unauthorized_enrollment_abuse"


def test_rules_compile_when_yara_is_available() -> None:
    yara = pytest.importorskip("yara")
    yara.compile(filepath=str(FAMILY / "rules" / "manageengine_endpoint_central_abuse.yar"))


def test_sigma_rule_is_valid_yaml() -> None:
    yaml = pytest.importorskip("yaml")
    document = yaml.safe_load((FAMILY / "rules" / "manageengine_endpoint_central_abuse.yml").read_text(encoding="utf-8"))
    assert document["detection"]["condition"] == "selection_image and selection_command"
    assert document["level"] == "high"


def test_new_documents_are_japanese_and_machine_files_are_valid() -> None:
    result_root = ROOT / "analysis-results" / "malware" / "manageengine-endpoint-central-abuse"
    for path in [FAMILY / "README.md", *result_root.rglob("*.md")]:
        text = path.read_text(encoding="utf-8")
        assert any("ぁ" <= character <= "ん" or "一" <= character <= "龯" for character in text), path
        assert "譁" not in text and "縺" not in text, path
    for path in [*FAMILY.glob("*.json"), *result_root.rglob("*.json")]:
        json.loads(path.read_text(encoding="utf-8"))
