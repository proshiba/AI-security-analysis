"""第11バッチの解析資材、公開成果物、接続検証を回帰検証する。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


FRAMEWORK = Path(__file__).parents[1]
REPOSITORY = FRAMEWORK.parent
BATCH11 = (
    REPOSITORY
    / "analysis-results"
    / "research"
    / "malwarebazaar"
    / "batches"
    / "batch-0011"
)


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def family_module(family: str, filename: str = "extract_config.py"):
    return load_module(
        FRAMEWORK / "malware" / family / filename,
        f"batch11_{family}_{filename}",
    )


def test_recurring_family_profiles_cover_batch11_architectures() -> None:
    gend = family_module("genddos_bot")
    expected = {
        "338b19ba5a4d15cca22d48c02c298064164d9db9654e7473880d12211f3cd185": ("sparc", 0x3B4FC, 0x293B8),
        "3bc7efeed4bbebc6a515be55736e6726dd3873553b00e70af513f8ab05761422": ("arm", 0x2B098, 0x20B6C),
        "5c299c0278faf2fb51febdde019a7f24ea147e6c968b688cb05f7cef4d4f76a0": ("armv6", 0x2C100, 0x222C4),
        "5f85a860b374bb803aff4cc9e1d928b5ad3d678c0e252b45e7b88d3bed88b152": ("mipsel", 0x4625AC, 0x41FCAC),
    }
    for digest, (architecture, key_address, port_address) in expected.items():
        profile = gend.HASH_PROFILES[digest]
        assert profile["architecture"] == architecture
        assert profile["key_address"] == key_address
        assert profile["port_address"] == port_address
        assert profile["fallback_host"] == "65.222.202.53"
        assert profile["fallback_port"] == 80

    jack = family_module("jackskid")
    profile = jack.HASH_PROFILES[
        "c3ba74fb10475f9e9db534ad484bbcfaa7ee1fd571639b35f57906e1fca1d716"
    ]
    assert profile["architecture"] == "mipsel"
    assert profile["key_address"] == 0x426E30
    assert profile["entries"][0x00] == (0x426914, 0x0B)
    assert profile["entries"][0x33] == (0x426BFC, 0x2C)

    signed = family_module("signed_dht_bot")
    signed_profile = signed.PROFILES[
        "b3512d6dd71746655648180b30a3812939c7adbcbb2958b3abf6ae004f691156"
    ]
    assert signed_profile["architecture"] == "mips64be"
    assert signed_profile["ghidra_main"] == "0x00102e48"
    assert signed_profile["table_cipher_key"] == "0x42ae9aea"

    putita = family_module("putita_v3")
    putita_profile = putita.HASH_PROFILES[
        "49d9e5fda3eb3064f04e6d2ac0e4876b509392cc65ad2445f0806339c6a1a356"
    ]
    assert putita_profile["architecture"] == "x86_64"
    assert putita_profile["controller"] == ("127.0.0.2", 23)
    assert putita_profile["controller_role"] == "loopback_controller"


def test_putita_loopback_case_does_not_publish_external_c2_crypto() -> None:
    config = json.loads(
        (
            REPOSITORY
            / "analysis-results/malware/putita-v3/versions/v3/cases"
            / "49d9e5fda3eb3064f04e6d2ac0e4876b509392cc65ad2445f0806339c6a1a356/config.json"
        ).read_text(encoding="utf-8")
    )
    assert config["c2"] == []
    assert config["local_controller"][0]["host"] == "127.0.0.2"
    assert config["external_c2_recovery_status"] == "not_present_static_loopback_only"
    assert config["configuration_crypto"]["applicable"] is False
    assert config["configuration_crypto"]["algorithm"] == "not_applicable"
    assert config["configuration_crypto"]["derived_key_sha256"] is None
    assert config["configuration_crypto"]["embedded_controller_encrypted"] is False


def test_linux_downloader_emulator_is_noncommunicating_and_nonexecuting() -> None:
    emulator = family_module("linux_downloader", "emulator.py")
    case = (
        REPOSITORY
        / "analysis-results/malware/unclassified/versions/unknown/cases"
        / "45ce79bbac91e3ca67d3cc7dd150ada9109cf6a52b09d3e6eaad8adb4df30777/config.json"
    )
    config = json.loads(case.read_text(encoding="utf-8"))
    result = emulator.build_plan(config)
    assert result["endpoint_count"] == 6
    assert len(result["events"]) == 18
    assert all(event["mode"] == "simulated" for event in result["events"])
    assert all(value is False for value in result["safety"].values())
    assert all(
        event.get("started") is False
        for event in result["events"]
        if event["step"] == "payload_start"
    )

    profile = json.loads(
        (FRAMEWORK / "malware/linux_downloader/c2_profile.json").read_text(
            encoding="utf-8"
        )
    )
    current = [item for item in profile["endpoints"] if item["host"] == "45.150.195.235"]
    assert {item["path"] for item in current} == {
        "/tarm", "/tarm5", "/tarm6", "/tarm7", "/tmips", "/tmpsl"
    }
    assert all(item["role"] == "payload_distribution" for item in current)


def test_batch11_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in (
        "genddos_bot", "jackskid", "signed_dht_bot", "putita_v3",
        "efimer", "freepbx_k_php", "linux_downloader",
    ):
        for rule in (FRAMEWORK / "malware" / family / "rules").glob("*.yar"):
            yara.compile(filepath=str(rule))


def test_batch11_publication_has_ten_unique_canonical_cases() -> None:
    classification = json.loads(
        (BATCH11 / "classification.json").read_text(encoding="utf-8")
    )
    samples = classification["samples"]
    assert len(samples) == 10
    assert len({sample["sha256"] for sample in samples}) == 10
    catalog = json.loads(
        (REPOSITORY / "analysis-results/catalog/cases.json").read_text(encoding="utf-8")
    )["cases"]
    for sample in samples:
        version = sample["version"] or "unknown"
        case = (
            REPOSITORY / "analysis-results/malware" / sample["family"]
            / "versions" / version / "cases" / sample["sha256"]
        )
        metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["sha256"] == sample["sha256"]
        assert metadata["malware_version"]["normalized_key"] == version
        assert catalog[sample["sha256"]]["canonical_path"] == case.relative_to(REPOSITORY).as_posix()
        for filename in ("README.md", "metadata.json", "config.json", "iocs.json", "IOC-LIST.md"):
            assert (case / filename).is_file()


def test_batch11_connection_validation_records_policy_boundaries() -> None:
    validation = json.loads((BATCH11 / "c2-validation.json").read_text(encoding="utf-8"))
    assert validation["sample_count"] == 10
    assert validation["unique_probe_count"] == 9
    assert validation["validation_status_counts"] == {
        "performed": 7,
        "not_performed_proxy_unavailable": 1,
        "not_performed_no_exact_target": 1,
        "not_applicable": 1,
    }
    candidates = [
        item
        for sample in validation["samples"]
        for item in sample["candidate_results"]
    ]
    assert all(item["application_data_sent"] is False for item in candidates)
    assert all(item["c2_confirmed"] is False for item in candidates)
    assert all("prefix_base64" not in item.get("banner", {}) for item in candidates)
    assert any(
        item["host"] == "genddos.st" and item.get("target_connection_established") is True
        for item in candidates
    )
    assert any(
        item["host"] == "nvms9000.online" and item.get("status") == "banner_received"
        for item in candidates
    )

    efimer = next(item for item in validation["samples"] if item["family"] == "efimer")
    assert efimer["connection_validation_status"] == "not_performed_proxy_unavailable"
    assert all(item["proxy_connection_established"] is False for item in efimer["candidate_results"])
    assert all(item["target_contact_attempted"] is False for item in efimer["candidate_results"])
    assert all(item["network_contacted"] is True for item in efimer["candidate_results"])

    signed = next(item for item in validation["samples"] if item["family"] == "signed-dht-bot")
    assert signed["connection_validation_status"] == "not_performed_no_exact_target"
    putita = next(item for item in validation["samples"] if item["family"] == "putita-v3")
    assert putita["connection_validation_status"] == "not_applicable"


def test_batch11_shodan_output_separates_shared_and_dynamic_services() -> None:
    shodan = json.loads((BATCH11 / "shodan-hunt.json").read_text(encoding="utf-8"))
    assert {item["ip"] for item in shodan["observations"]} == {
        "160.119.69.4", "45.95.147.178", "162.249.125.140",
        "166.0.192.57", "65.222.202.53", "45.150.195.235",
    }
    assert {item["family"] for item in shodan["dynamic_endpoint_exclusions"]} == {
        "signed-dht-bot", "jackskid", "putita-v3", "efimer",
    }
    assert "公開Ethereum RPC" in shodan["excluded_shared_services"]
    jack = next(item for item in shodan["observations"] if item["ip"] == "162.249.125.140")
    assert jack["live_banner_hash"]["value"] == -2008115501
    assert "banner" not in jack
