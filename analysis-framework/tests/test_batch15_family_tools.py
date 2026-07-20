from __future__ import annotations

import base64
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_prometei_embedded_config_redacts_encrypted_key() -> None:
    module = load("analysis-framework/malware/prometei/extract_config.py", "b15_prometei")
    data = b"\x7fELFUPX!" + json.dumps({
        "config": 1,
        "id": "bot",
        "enckey": "秘密値",
        "ParentId": "parent",
        "ip": "192.0.2.10",
        "ParentIp": "192.0.2.20",
        "ParentHostname": "host",
    }).encode()
    report = module.extract_config(data)
    assert report["classification_confidence"] == "candidate_embedded_config"
    assert report["config"]["encrypted_key_present"] is True
    assert report["config"]["encrypted_key_published"] is False
    assert "秘密値" not in json.dumps(report, ensure_ascii=False)
    assert report["c2"] == [{
        "host": "192.0.2.10", "port": None, "role": "controller",
        "confidence": "confirmed_config_host_only",
    }]


def test_prometei_detector_uses_common_classifier_schema() -> None:
    module = load("analysis-framework/malware/prometei/detect.py", "b15_prometei_detect")
    synthetic = (
        b"\x7fELFUPX! prometei "
        b'{"config":1,"ParentId":"p","ParentHostname":"h"}'
    )
    report = module.detect(synthetic)
    assert report["matched"] is True
    assert report["observations"]["sample_executed"] is False
    assert report["campaigns"] == [{
        "campaign_type": "prometei_linux_nrv_202607",
        "confidence": "medium",
        "reasons": ["elf", "json_config", "prometei_string", "upx_marker"],
    }]


def test_remcos_rc4_settings_round_trip_without_credentials() -> None:
    module = load(
        "analysis-framework/malware/remcosrat/remcos_config_extractor.py",
        "b15_remcos_config",
    )
    key = b"reviewed-test-key"
    clear = b"host.example:62050\x7c\x1e\x1e\x1f\x7cfield"
    resource = bytes([len(key)]) + key + module.rc4_crypt(clear, key)
    recovered, recovered_key, key_size = module.decode_settings_blob(resource)
    assert recovered == clear
    assert recovered_key == key
    assert key_size == len(key)


def test_agenttesla_hunt_report_and_emulator_are_offline() -> None:
    detector = load(
        "analysis-framework/malware/agenttesla/c2_detector.py",
        "b15_agenttesla_detector",
    )
    emulator_module = load(
        "analysis-framework/malware/agenttesla/emulator.py",
        "b15_agenttesla_emulator",
    )
    report = detector.build_report({
        "config_endpoints": [{"host": "ftp.example.test", "port": 21, "protocol": "ftp"}],
        "password": "公開してはいけない値",
    })
    assert report["network_contacted"] is False
    assert report["credentials_published"] is False
    assert report["endpoints"][0]["shodan_queries"] == ["hostname:ftp.example.test port:21"]
    assert "公開してはいけない値" not in json.dumps(report, ensure_ascii=False)
    emulator = emulator_module.ExfiltrationEmulator("ftp")
    assert emulator.collect() == "collected"
    assert emulator.serialize() == "serialized"
    assert emulator.prepare_transport() == "ftp_prepared"
    assert emulator.stop_before_network() == "blocked_before_network"


def test_family_emulators_never_generate_packets() -> None:
    prometei = load("analysis-framework/malware/prometei/emulator.py", "b15_prometei_emulator")
    remcos = load("analysis-framework/malware/remcosrat/emulator.py", "b15_remcos_emulator")
    p_report = prometei.emulate({"config": {"controller_ip": "192.0.2.1"}})
    r_report = remcos.emulate({"c2": [{"endpoint": "example.test:1"}]})
    assert p_report["network_contacted"] is False
    assert p_report["packets_generated"] == 0
    assert r_report["network_contacted"] is False
    assert r_report["packets_generated"] == 0


def test_fa7d_helpers_decode_only_data() -> None:
    module = load(
        "analysis-framework/malware/windows_script_stager/fa7d_xor_stager.py",
        "b15_fa7d",
    )
    assert module.decode_js_string('"A\\x42\\u0043"') == "ABC"
    clear = b"Write-Output reviewed"
    encrypted = bytes(value ^ module.KEY[index % len(module.KEY)] for index, value in enumerate(clear))
    script = "Unspi86 '" + base64.b64encode(encrypted).decode() + "' 0"
    decoded = module.decode_unspi86(script)
    assert decoded[0]["text"] == clear.decode()
    assert decoded[0]["execute_flag"] is False


def test_b499_transform_matches_its_inverse_on_synthetic_data() -> None:
    module = load("unpackers/b499_resource_transform.py", "b15_b499")
    plain = bytes(range(256)) * 2
    state_a = 17937
    state_b = 50497
    encoded = bytearray()
    for index, value in enumerate(plain):
        state_b = module._int32((state_b ^ index) * 31)
        state_a = module._int32((state_a + state_b) ^ 13)
        temporary = ((value ^ 45) + state_b) & 0xFF
        encoded.append(temporary ^ (state_a & 0xFF))
        state_b = module._int32(state_b + value)
    assert module.transform(bytes(encoded)) == plain


def test_javascript_two_array_profile_fails_closed_on_unknown_hash() -> None:
    module = load("unpackers/javascript_two_array.py", "b15_two_array")
    with pytest.raises(ValueError, match="SHA-256"):
        module.deobfuscate(b"not reviewed")


def test_bd20_base64_xor_decoder_is_data_only() -> None:
    module = load(
        "analysis-framework/malware/windows_script_stager/bd20_base64_stager.py",
        "b15_bd20_stager",
    )
    clear = b"User-Agent"
    encrypted = bytes(
        value ^ module.XOR_KEY[index % len(module.XOR_KEY)]
        for index, value in enumerate(clear)
    )
    assert module.decode_literal(base64.b64encode(encrypted).decode()) == "User-Agent"
    with pytest.raises(ValueError, match="SHA-256"):
        module.extract_config(b"not reviewed")


def test_e629_mist_transform_and_wannacry_models_are_offline() -> None:
    e629 = load("unpackers/e629_managed_image_layers.py", "b15_e629_layers")
    with pytest.raises(ValueError, match="SHA-256"):
        e629.mist_transform(b"not reviewed")
    assert e629.mist_transform(b"\xf4", enforce_reviewed_hash=False) == b"p"

    emulator = load("analysis-framework/malware/wannacry/emulator.py", "b15_wannacry_emulator")
    detector = load(
        "analysis-framework/malware/wannacry/network_detector.py",
        "b15_wannacry_network_detector",
    )
    plan = emulator.build_plan({
        "kill_switch": [{"url": "http://example.invalid"}],
        "tor_endpoints": [{"host": "57g7spgrzlojinas.onion"}],
    })
    assert plan["safety"]["network_contacted"] is False
    assert plan["safety"]["packets_generated"] == 0
    report = detector.detect_events([
        {
            "host": "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwff.com",
            "port": 80,
            "wannacry_process_or_hash_correlation": True,
        },
        {
            "host": "57g7spgrzlojinas.onion",
            "port": 80,
            "wannacry_process_or_hash_correlation": True,
        },
    ])
    assert report["observations"][0]["role"] == "kill_switch_not_c2"
    assert report["c2_candidates"][0]["role"] == "tor_c2_candidate"
    assert report["c2_confirmed"] is False
    assert report["network_contacted"] is False


def test_efimer_and_prometei_network_detectors_are_offline() -> None:
    efimer = load("analysis-framework/malware/efimer/network_detector.py", "b15_efimer_network")
    prometei = load("analysis-framework/malware/prometei/c2_detector.py", "b15_prometei_c2")
    e_report = efimer.detect_events([{
        "url": "http://gfoqsewps57xcyxoedle2gd53o6jne6y5nq5eh25muksqwzutzq7b3ad.onion/route.php",
        "proxy_type": "socks5h",
        "efimer_process_or_hash_correlation": True,
    }])
    assert e_report["matched"] is True
    assert e_report["c2_confirmed"] is False
    assert e_report["network_contacted"] is False
    p_report = prometei.detect_events(
        [{
            "host": "192.0.2.10",
            "port": 12345,
            "prometei_process_or_hash_correlation": True,
        }],
        {"config": {"controller_ip": "192.0.2.10"}},
    )
    assert p_report["matched"] is True
    assert p_report["shodan_query_generated"] is False
    assert p_report["c2_confirmed"] is False
    assert p_report["network_contacted"] is False


def test_batch15_framework_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    rules = [
        "analysis-framework/malware/agenttesla/rules/agenttesla.yar",
        "analysis-framework/malware/prometei/rules/prometei.yar",
        "analysis-framework/malware/remcosrat/rules/remcosrat.yar",
        "analysis-framework/malware/windows_script_stager/rules/bd20_base64_substring_stager.yar",
        "analysis-framework/malware/unclassified/rules/e629_managed_image_loader.yar",
    ]
    for relative in rules:
        yara.compile(filepath=str(ROOT / relative))


def test_batch15_layout_and_c2_safety() -> None:
    batch = ROOT / "analysis-results/research/malwarebazaar/batches/batch-0015"
    classification = json.loads((batch / "classification.json").read_text(encoding="utf-8"))
    assert len(classification["samples"]) == 10
    for item in classification["samples"]:
        case = (
            ROOT / "analysis-results/malware" / item["family"] / "versions"
            / item["version"] / "cases" / item["sha256"]
        )
        assert {"README.md", "metadata.json", "config.json", "iocs.json", "IOC-LIST.md"} <= {
            path.name for path in case.iterdir()
        }
        text = (case / "README.md").read_text(encoding="utf-8")
        assert "静的解析ロジック" in text
        assert "開発者・利用アクター・コモディティ性・過去の悪用" in text
    validation = json.loads((batch / "c2-validation.json").read_text(encoding="utf-8"))
    assert len(validation["results"]) == 2
    assert all(item["application_data_sent"] is False for item in validation["results"])
    assert all(item["server_data_read"] is False for item in validation["results"])
    assert all(item["c2_confirmed"] is False for item in validation["results"])
