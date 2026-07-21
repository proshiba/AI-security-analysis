"""第13バッチの解析資材、デュアルユース判定、安全境界、公開成果物を回帰検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

import pytest


FRAMEWORK = Path(__file__).parents[1]
REPOSITORY = FRAMEWORK.parent
BATCH13 = REPOSITORY / "analysis-results/research/malwarebazaar/batches/batch-0013"
SCREENCONNECT_SHA256 = "16d76fb73e844e7ae13081b614f4b7449d4f020246189bfd6d77585d33a55a71"
JACK_ARM_SHA256 = "02e960e5278a686f38a356e5e7842def5797e07ec0b06b8fe5f34d0b28fde0b2"
JACK_AARCH64_SHA256 = "875257991745c0557dd2fb00cd40934de6281ded379289c26d900bca2628f25f"
SIGNED_ARMV7_SHA256 = "fd5a48693a99cbb7c49f5f4245f3090ffeec58ce3f9d9bcf7f6c7eade62769f1"
GEND_MIPS_SHA256 = "e7889354c0d2cce6cc0c6a34ec13afd79bf361388e76ed2b3b987e0613d9c6a6"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def family_module(family: str, filename: str = "extract_config.py"):
    return load_module(FRAMEWORK / "malware" / family / filename, f"batch13_{family}_{filename}")


def test_jackskid_arm_and_aarch64_exact_profiles_cover_same_generation() -> None:
    extractor = family_module("jackskid")
    arm = extractor.HASH_PROFILES[JACK_ARM_SHA256]
    aarch64 = extractor.HASH_PROFILES[JACK_AARCH64_SHA256]
    assert arm["architecture"] == "armv5"
    assert aarch64["architecture"] == "aarch64"
    assert arm["key_address"] == 0x24804
    assert aarch64["key_bytes"] == extractor.KEY_BYTES
    assert arm["ghidra_main"] == "0x0000f544"
    assert aarch64["ghidra_main"] == "0x00100d8c"
    assert len(arm["entries"]) == len(aarch64["entries"]) == 53
    assert arm["controller_ports"] == aarch64["controller_ports"]
    assert len(arm["controller_ports"]) == 101
    assert arm["controller_ports"][0] == 64409
    assert arm["observed_controller_ips"] == ["172.233.124.230", "45.154.98.115"]


def test_jackskid_new_port_requires_protocol_correlation() -> None:
    detector = family_module("jackskid", "network_detector.py")
    endpoint_only = detector.detect_flow({"host": "172.233.124.230", "port": 64409, "events": []})
    assert endpoint_only["matched"] is False
    flow = {
        "host": "172.233.124.230",
        "port": 64409,
        "events": [
            {"direction": "out", "size": 32},
            {"direction": "in", "size": 32},
            {"direction": "out", "size": 16},
            {"direction": "out", "size": 64},
        ],
    }
    assert detector.detect_flow(flow)["matched"] is True
    flow["host"] = "ethereum.publicnode.com"
    assert detector.detect_flow(flow)["matched"] is False


def test_signed_dht_armv7_repair_profile_is_fixed_and_nonexecuting() -> None:
    extractor = family_module("signed_dht_bot")
    profile = extractor.PROFILES[SIGNED_ARMV7_SHA256]
    assert profile["architecture"] == "armv7"
    assert profile["packaging"] == "tampered_upx"
    assert profile["inserted_trailer_bytes"] == 10
    assert profile["repaired_packed_sha256"] == "0ca62676007dbfdbc1a68719dda27bd7e52507b294032282a98c8faf5f32cac5"
    assert profile["recovered_sha256"] == "3f09fcfdcc84cf8e478def482cbf8d5b953b13de3fb096fb3c5ebd1577039e2e"
    assert profile["ghidra_main"] == "0x00008db8"
    assert profile["table_cipher_key"] == "0x25e27a77"
    assert profile["attack_handler_count"] == 19


def test_genddos_batch13_mips_profile_is_exact() -> None:
    extractor = family_module("genddos_bot")
    profile = extractor.HASH_PROFILES[GEND_MIPS_SHA256]
    assert profile["architecture"] == "mips"
    assert profile["key_address"] == 0x0046188C
    assert profile["domain_address"] == 0x0041F030
    assert profile["port_address"] == 0x0041F03C
    assert profile["ghidra"]["main_address"] == "0x0040da78"


def test_screenconnect_extractor_redacts_synthetic_tenant_key() -> None:
    extractor = family_module("screenconnect_rmm")
    key = "synthetic-test-key-0123456789-abcdefghijklmnop"
    query = f"?h=tenant-lab-relay.screenconnect.com&p=443&k={key}"
    data = b"MZ" + b"ScreenConnect.WindowsInstaller\x00ClientSetup\x00" + query.encode() + b"\x00"
    result = extractor.extract_config(data)
    assert result["classification"] == "commercial_rmm_dual_use"
    assert result["classification_confidence"] == "structural_only"
    assert result["malware_by_itself"] is False
    assert result["version"] is None
    assert result["relay"]["tenant_key_sha256"] == hashlib.sha256(key.encode()).hexdigest()
    assert result["relay"]["tenant_key_length"] == len(key)
    assert key not in json.dumps(result, ensure_ascii=False)
    assert result["relay"]["redacted_query"].endswith("&k=<redacted>")


def test_screenconnect_detector_requires_product_and_authorization_context() -> None:
    detector = family_module("screenconnect_rmm", "network_detector.py")
    hostname_only = detector.detect_flow({
        "host": "tenant-lab-relay.screenconnect.com", "port": 443,
    })
    assert hostname_only["matched"] is False
    authorized_or_unknown = detector.detect_flow({
        "host": "tenant-lab-relay.screenconnect.com", "port": 443,
        "product": "ScreenConnect Client", "signer": "ConnectWise, LLC",
    })
    assert authorized_or_unknown["matched"] is True
    assert authorized_or_unknown["classification"] == "authorized_or_unknown_dual_use_rmm"
    assert authorized_or_unknown["malicious"] is False
    suspected = detector.detect_flow({
        "host": "tenant-lab-relay.screenconnect.com", "port": 443,
        "product": "ScreenConnect Client", "signer": "ConnectWise, LLC",
        "unauthorized_installation": True,
    })
    assert suspected["classification"] == "suspected_rmm_abuse"
    assert suspected["malicious"] is False
    assert suspected["requires_incident_context"] is True


def test_screenconnect_emulator_is_offline_and_redacts() -> None:
    emulator = family_module("screenconnect_rmm", "emulator.py")
    key = "synthetic-screenconnect-tenant-key"
    result = emulator.inspect_query(
        f"?h=tenant-lab-relay.screenconnect.com&p=443&k={key}"
    )
    assert result["network_contacted"] is False
    assert result["malware_protocol_compatible"] is False
    assert key not in json.dumps(result, ensure_ascii=False)
    assert "ネットワーク接続" in result["not_implemented"]


def test_batch13_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in (
        "screenconnect_rmm", "jackskid", "signed_dht_bot", "genddos_bot",
        "efimer", "freepbx_k_php", "condi",
    ):
        for rule in (FRAMEWORK / "malware" / family / "rules").glob("*.yar"):
            yara.compile(filepath=str(rule))


def test_batch13_publication_has_ten_unique_fixed_depth_cases() -> None:
    classification = json.loads((BATCH13 / "classification.json").read_text(encoding="utf-8"))
    samples = classification["samples"]
    assert len(samples) == 10
    assert len({sample["sha256"] for sample in samples}) == 10
    for sample in samples:
        version = sample["version"] or "unknown"
        case = REPOSITORY / "analysis-results/malware" / sample["family"] / "versions" / version / "cases" / sample["sha256"]
        metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["sha256"] == sample["sha256"]
        assert metadata["malware_version"]["normalized_key"] == version
        assert "refresh" not in case.parts
        for filename in ("README.md", "metadata.json", "config.json", "iocs.json", "IOC-LIST.md"):
            assert (case / filename).is_file()


def test_batch13_connection_validation_preserves_safety_boundaries() -> None:
    validation = json.loads((BATCH13 / "c2-validation.json").read_text(encoding="utf-8"))
    assert validation["sample_count"] == 10
    assert validation["unique_probe_count"] == 12
    assert validation["policy"]["timeout_seconds"] == 3.0
    assert validation["policy"]["port_scanning"] is False
    assert validation["policy"]["tor_started"] is False
    candidates = [item for sample in validation["samples"] for item in sample["candidate_results"]]
    assert all(item["application_data_sent"] is False for item in candidates)
    assert all(item["banner_read"] is False for item in candidates)
    assert all(item["c2_confirmed"] is False for item in candidates)
    screen = next(item for item in validation["samples"] if item["family"] == "screenconnect-rmm")
    assert screen["candidate_results"][0]["role"] == "remote_management_relay_not_c2"
    jack = next(item for item in validation["samples"] if item["family"] == "jackskid")
    assert {item["port"] for item in jack["candidate_results"]} == {64409, 9018}


def test_batch13_shodan_results_are_passive_and_nonattributing() -> None:
    shodan = json.loads((BATCH13 / "shodan-hunt.json").read_text(encoding="utf-8"))
    assert len(shodan["queries"]) == 9
    assert len(shodan["internetdb_results"]) == 9
    statuses = [item["status"] for item in shodan["internetdb_results"]]
    assert statuses.count("ok") == 8
    assert statuses.count("http_404_not_found") == 1
    assert all(item["vulnerability_list_omitted"] is True for item in shodan["internetdb_results"])
    assert "悪性" in shodan["policy_note"]


def test_screenconnect_public_config_contains_only_redacted_key_evidence() -> None:
    path = (
        REPOSITORY / "analysis-results/malware/screenconnect-rmm/versions/v26.4.3.9662/cases"
        / SCREENCONNECT_SHA256 / "config.json"
    )
    config = json.loads(path.read_text(encoding="utf-8"))
    relay = config["relay"]
    assert config["malware_by_itself"] is False
    assert relay["tenant_key_length"] == 448
    assert relay["tenant_key_sha256"] == "8de7b8af2393dd81fbbdeb78790555bd417b01036f1130833ff19715a5490589"
    assert set(relay) == {
        "host", "port", "transport", "role", "c2_classification",
        "tenant_key_sha256", "tenant_key_length", "redacted_query",
    }


def test_registry_contains_all_new_reviewed_hashes() -> None:
    registry = json.loads((FRAMEWORK / "registry/malware_types.json").read_text(encoding="utf-8"))["malware_types"]
    assert registry["screenconnect_rmm"]["known_sample_sha256"] == [SCREENCONNECT_SHA256]
    assert registry["screenconnect_rmm"]["classification"] == "commercial_rmm_dual_use"
    assert JACK_ARM_SHA256 in registry["jackskid"]["known_sample_sha256"]
    assert JACK_AARCH64_SHA256 in registry["jackskid"]["known_sample_sha256"]
    assert SIGNED_ARMV7_SHA256 in registry["signed_dht_bot"]["known_sample_sha256"]


def test_screenconnect_osint_knowledge_is_registered_as_commercial_dual_use() -> None:
    knowledge = json.loads(
        (FRAMEWORK / "knowledge/malware_families/n_z.json").read_text(encoding="utf-8")
    )["families"]
    screen = next(item for item in knowledge if item["id"] == "screenconnect-rmm")
    assert screen["developer"]["assessment_ja"].startswith("製品の開発・提供主体はConnectWise")
    assert screen["commodity"]["classification"] == "commercial_service"
    assert screen["versioning"]["local_confirmed_case_count"] == 1
    actors = {item["name"] for item in screen["actors"]}
    assert {"MuddyWater", "ALPHV／BlackCat関係者", "Interlockランサムウェア運用者"} <= actors
