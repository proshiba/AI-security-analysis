"""第12バッチの解析資材、C2相関、安全境界、公開成果物を回帰検証する。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


FRAMEWORK = Path(__file__).parents[1]
REPOSITORY = FRAMEWORK.parent
BATCH12 = REPOSITORY / "analysis-results/research/malwarebazaar/batches/batch-0012"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def family_module(family: str, filename: str = "extract_config.py"):
    return load_module(FRAMEWORK / "malware" / family / filename, f"batch12_{family}_{filename}")


def test_recurring_profiles_cover_all_batch12_architectures() -> None:
    gend = family_module("genddos_bot")
    assert gend.HASH_PROFILES["c0685aa4c68bbecb0bc5a61c3ee46eb9056ae33ded414784761d8ccac48e5bbd"]["architecture"] == "ppc"
    assert gend.HASH_PROFILES["850847440cf308046af0139b1c74e7059d19e82f591705f772d4568d854c1079"]["architecture"] == "armv5"
    putita = family_module("putita_v3")
    packed = putita.HASH_PROFILES["aee705055f820ed7147ce7ecd39f293ee56e71a2118d5bd0ca21584bfb89124f"]
    assert packed["packed"] is True
    assert packed["logical_payload"] == "49d9e5fda3eb3064f04e6d2ac0e4876b509392cc65ad2445f0806339c6a1a356"
    signed = family_module("signed_dht_bot")
    sh4 = signed.PROFILES["6327eb7f0e774b2be50bcc9665bfcb4a35f120c101368d4800de7e0b94827b0d"]
    assert sh4["architecture"] == "sh4"
    assert sh4["table_cipher_key"] == "0x82ed3d64"
    condi = family_module("condi")
    assert "garden" in condi.PUBLIC_TLDS


def test_maskgram_dead_drop_decoder_and_detector_require_correlation() -> None:
    extractor = family_module("maskgram_stealer")
    assert extractor.decode_dead_drop_value("0URjDQpoX0JUrwNs5rT/w51V6OPSHPve1WKoVd2S") == "geschmeidig6307-kotyatanet.sbs"
    detector = family_module("maskgram_stealer", "network_detector.py")
    dead_drop_only = detector.detect_events([{"host": "t.me", "method": "GET", "port": 443}])
    assert dead_drop_only["matched"] is False
    assert dead_drop_only["dead_drop_only"] is True
    correlated = detector.detect_events([
        {"host": "t.me", "method": "GET", "port": 443},
        {"host": "geschmeidig6307-kotyatanet.sbs", "method": "POST", "port": 443,
         "resolved_from_dead_drop": True},
    ])
    assert correlated["matched"] is True


def test_maskgram_emulator_is_offline_and_does_not_exfiltrate() -> None:
    emulator = family_module("maskgram_stealer", "emulator.py")
    decoded = emulator.decode_synthetic_dead_drop(
        "0URjDQpoX0JUrwNs5rT/w51V6OPSHPve1WKoVd2S",
        "kmVMgDX05VonDmpxioLnTe7xTjtLIdvf!!q",
    )
    assert decoded["decoded"] == "geschmeidig6307-kotyatanet.sbs"
    assert decoded["network_contacted"] is False
    assert decoded["exfiltration_performed"] is False
    config = json.loads((REPOSITORY / "analysis-results/malware/maskgram-stealer/versions/unknown/cases/e8c73ce5eb660ea6570b5bf5f560eaf994394da02148f7df10aefac1fda8a756/config.json").read_text(encoding="utf-8"))
    plan = emulator.build_plan(config)
    assert len(plan["events"]) == 8
    assert all(value is False for value in plan["safety"].values())


def test_jackskid_mipsbe_port_table_and_handshake_correlation() -> None:
    extractor = family_module("jackskid")
    profile = extractor.HASH_PROFILES["6afda92c73f89ddce818f752d2d3fb7f39cef34c53478ecd993cd42936a12efc"]
    assert profile["architecture"] == "mipsbe"
    assert profile["word_endian"] == ">"
    assert profile["controller_port_table_address"] == 0x425A54
    assert len(profile["controller_ports"]) == 101
    detector = family_module("jackskid", "network_detector.py")
    flow = {"host": "172.233.124.230", "port": 39419, "events": [
        {"direction": "out", "size": 32}, {"direction": "in", "size": 32},
        {"direction": "out", "size": 16}, {"direction": "out", "size": 64},
    ]}
    assert detector.detect_flow(flow)["matched"] is True
    flow["host"] = "sdk-proxy.sns.id"
    assert detector.detect_flow(flow)["matched"] is False
    emulator = family_module("jackskid", "emulator.py")
    parsed = emulator.parse_synthetic_handshake([
        {"direction": "out", "size": 32}, {"direction": "in", "size": 32},
        {"direction": "out", "size": 16}, {"direction": "out", "size": 64},
    ])
    assert parsed["shape_matches"] is True
    assert parsed["network_contacted"] is False
    assert parsed["payload_retained"] is False


def test_batch12_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in ("maskgram_stealer", "jackskid", "genddos_bot", "signed_dht_bot", "putita_v3", "condi", "efimer", "linux_downloader"):
        for rule in (FRAMEWORK / "malware" / family / "rules").glob("*.yar"):
            yara.compile(filepath=str(rule))


def test_batch12_publication_has_ten_unique_canonical_cases() -> None:
    classification = json.loads((BATCH12 / "classification.json").read_text(encoding="utf-8"))
    samples = classification["samples"]
    assert len(samples) == 10
    assert len({sample["sha256"] for sample in samples}) == 10
    for sample in samples:
        version = sample["version"] or "unknown"
        case = REPOSITORY / "analysis-results/malware" / sample["family"] / "versions" / version / "cases" / sample["sha256"]
        metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["sha256"] == sample["sha256"]
        assert metadata["malware_version"]["normalized_key"] == version
        for filename in ("README.md", "metadata.json", "config.json", "iocs.json", "IOC-LIST.md"):
            assert (case / filename).is_file()


def test_batch12_connection_validation_preserves_safety_boundaries() -> None:
    validation = json.loads((BATCH12 / "c2-validation.json").read_text(encoding="utf-8"))
    assert validation["sample_count"] == 10
    assert validation["unique_probe_count"] == 9
    candidates = [item for sample in validation["samples"] for item in sample["candidate_results"]]
    assert candidates
    assert all(item["application_data_sent"] is False for item in candidates)
    assert all(item["banner_read"] is False for item in candidates)
    assert all(item["c2_confirmed"] is False for item in candidates)
    assert validation["policy"]["port_scanning"] is False
    jack = next(item for item in validation["samples"] if item["family"] == "jackskid")
    assert {item["port"] for item in jack["candidate_results"]} == {39419}


def test_shodan_failure_and_shared_service_exclusions_are_explicit() -> None:
    shodan = json.loads((BATCH12 / "shodan-hunt.json").read_text(encoding="utf-8"))
    assert len(shodan["internetdb_results"]) == 10
    assert all(item["status"] == "http_403" for item in shodan["internetdb_results"])
    targets = json.loads((BATCH12 / "c2-targets.json").read_text(encoding="utf-8"))
    assert "Telegram" in targets["shared_service_exclusions"]
    assert "公開Ethereum RPC" in targets["shared_service_exclusions"]


def test_registry_contains_new_and_extended_reviewed_families() -> None:
    registry = json.loads((FRAMEWORK / "registry/malware_types.json").read_text(encoding="utf-8"))["malware_types"]
    assert registry["maskgram_stealer"]["known_sample_sha256"] == ["e8c73ce5eb660ea6570b5bf5f560eaf994394da02148f7df10aefac1fda8a756"]
    assert "6afda92c73f89ddce818f752d2d3fb7f39cef34c53478ecd993cd42936a12efc" in registry["jackskid"]["known_sample_sha256"]
    assert "6327eb7f0e774b2be50bcc9665bfcb4a35f120c101368d4800de7e0b94827b0d" in registry["signed_dht_bot"]["known_sample_sha256"]
