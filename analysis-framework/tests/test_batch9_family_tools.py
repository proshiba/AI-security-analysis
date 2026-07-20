"""第9バッチのファミリー解析資材と公開成果物を検証する。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


FRAMEWORK = Path(__file__).parents[1]
REPOSITORY = FRAMEWORK.parent
BATCH9 = REPOSITORY / "analysis-results" / "research" / "malwarebazaar" / "batches" / "batch-0009"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def family_module(family: str, filename: str = "extract_config.py"):
    return load_module(FRAMEWORK / "malware" / family / filename, f"batch9_{family}_{filename}")


def test_recurring_family_profiles_cover_batch9_samples() -> None:
    putita = family_module("putita_v3")
    unpacked = putita.HASH_PROFILES["70005bbb6db8afaf30661df0311395fb3cf7bf1ece51d511841d4f4def908a29"]
    packed = putita.HASH_PROFILES["f0ea2d0017a88323d730042c2b571a4d06cd8dbe169c3cef2e457bd0c5d676ff"]
    assert unpacked["architecture"] == packed["architecture"] == "armv6"
    assert packed["logical_payload"] == "70005bbb6db8afaf30661df0311395fb3cf7bf1ece51d511841d4f4def908a29"
    assert unpacked["config_blobs"] == {"host": (0x1AA61, 13), "port": (0x1AA81, 3)}

    eclipse = family_module("eclipse_ddos_bot")
    for digest, registration in {
        "4280445841f4898c26f409239f1a623304b637363087bd88a6ee9506e0256463": "armv6l",
        "a832528ba9cac310fd4e5bcb7f8523865a6a19b2c95891515f323009910f610e": "armv7l",
    }.items():
        assert eclipse.HASH_PROFILES[digest]["registration"] == registration
        assert eclipse.HASH_PROFILES[digest]["port"] == 7000
    assert b"armv6l" in eclipse.REGISTRATION_VALUES

    gend = family_module("genddos_bot")
    profile = gend.HASH_PROFILES["c7e7d77602c121ebe2785d8e4068b7d459abe975ad9e3e8471ba28e9783b8dca"]
    assert profile["architecture"] == "x86"
    assert profile["key_address"] == 0x080610A4
    assert profile["domain_address"] == 0x0805EBC1


def test_new_family_emulators_are_noncommunicating_and_nonexecuting() -> None:
    phorpiex = family_module("phorpiex_downloader", "emulator.py")
    decision = phorpiex.evaluate_synthetic_metadata(6000, 5000)
    assert decision["download_would_be_selected"] is True
    assert decision["network_contacted"] is False
    assert decision["process_started"] is False

    tbot = family_module("tbot_iot_bot", "emulator.py")
    frame = tbot.parse_server_frame(b"\x00\x06test")
    assert frame["body_length"] == 4
    assert frame["body_retained"] is False
    assert frame["command_executed"] is False
    with pytest.raises(ValueError):
        tbot.parse_server_frame(b"\x00\x07test")

    blaze = family_module("blazetrack", "emulator.py")
    parsed = blaze.parse_synthetic_json(b'{"command":"do-not-run","id":1}')
    assert parsed["command_present"] is True
    assert parsed["values_retained"] is False
    assert parsed["command_executed"] is False
    assert "do-not-run" not in json.dumps(parsed)


def test_new_passive_profiles_separate_c2_and_non_c2_roles() -> None:
    detector = load_module(FRAMEWORK / "common" / "passive_c2_detector.py", "batch9_passive")
    phorpiex = json.loads((FRAMEWORK / "malware" / "phorpiex_downloader" / "c2_profile.json").read_text(encoding="utf-8"))
    result = detector.detect(phorpiex, [{
        "destination_host": "178.16.54.109", "destination_port": 80,
        "http": {"path": "/grabit.exe"},
    }])
    assert result["matches"][0]["verdict"] == "non_c2_role"
    assert result["matches"][0]["c2_confirmed"] is False

    tbot = json.loads((FRAMEWORK / "malware" / "tbot_iot_bot" / "c2_profile.json").read_text(encoding="utf-8"))
    result = detector.detect(tbot, [{
        "destination_host": "193.46.218.20", "destination_port": 34661,
        "payload": {"framing": "uint16-be-total-length"},
    }])
    assert result["matches"][0]["verdict"] == "possible_c2"
    result = detector.detect(tbot, [{
        "destination_host": "193.46.218.20", "destination_port": 34661,
        "payload": {"framing": "uint16-be-total-length", "marker": "TBOT"},
    }])
    assert result["matches"][0]["c2_confirmed"] is True

    blaze = json.loads((FRAMEWORK / "malware" / "blazetrack" / "c2_profile.json").read_text(encoding="utf-8"))
    result = detector.detect(blaze, [{
        "destination_host": "dry-band-ae8f.zavrayah.workers.dev", "destination_port": 443,
        "http": {"content_type": "application/json", "json_keys": ["command", "id"]},
    }])
    assert result["matches"][0]["c2_confirmed"] is True
    result = detector.detect(blaze, [{
        "destination_host": "gist.github.com", "destination_port": 443,
        "http": {"content_type": "application/json", "json_keys": ["command"]},
    }])
    assert result["matches"][0]["verdict"] == "non_c2_role"


def test_new_detectors_are_registered_and_structurally_bounded() -> None:
    classifier = load_module(FRAMEWORK / "classifiers" / "classify_sample.py", "batch9_classifier")
    registry = json.loads((FRAMEWORK / "registry" / "malware_types.json").read_text(encoding="utf-8"))["malware_types"]
    for family in ("phorpiex_downloader", "tbot_iot_bot", "blazetrack"):
        detector = classifier.load_detector(FRAMEWORK, registry[family]["detector"], family)
        assert callable(detector)

    phorpiex = family_module("phorpiex_downloader", "detect.py")
    synthetic = b"MZ" + b"\0" * 32 + b"".join(value.encode("utf-16le") for value in (
        "http://178.16.54.109/grabit.exe", "eheheheehh.jpg",
        "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\",
    )) + b"URLDownloadToFileW\0InternetOpenW"
    assert phorpiex.detect(synthetic, Path("sample"))["matched"] is True

    blaze = family_module("blazetrack", "detect.py")
    synthetic = b"MZMSCF AutoIt3.exe Greece.a3x " + "Win32 Cabinet Self-Extractor".encode("utf-16le")
    assert blaze.detect(synthetic, Path("sample"))["matched"] is True


def test_batch9_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in (
        "putita_v3", "eclipse_ddos_bot", "freepbx_k_php", "genddos_bot",
        "phorpiex_downloader", "tbot_iot_bot", "blazetrack",
    ):
        rule = next((FRAMEWORK / "malware" / family / "rules").glob("*.yar"))
        yara.compile(filepath=str(rule))


def test_batch9_publication_has_ten_unique_canonical_cases() -> None:
    classification = json.loads((BATCH9 / "classification.json").read_text(encoding="utf-8"))
    samples = classification["samples"]
    assert len(samples) == 10
    assert len({sample["sha256"] for sample in samples}) == 10
    for sample in samples:
        version = sample["version"] or "unknown"
        case = REPOSITORY / "analysis-results" / "malware" / sample["family"] / "versions" / version / "cases" / sample["sha256"]
        metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["sha256"] == sample["sha256"]
        assert metadata["malware_version"]["normalized_key"] == version
        assert (case / "README.md").is_file()
        assert (case / "IOC-LIST.md").is_file()


def test_batch9_connection_validation_is_exact_and_payload_free() -> None:
    validation = json.loads((BATCH9 / "c2-validation.json").read_text(encoding="utf-8"))
    assert validation["sample_count"] == 10
    assert validation["unique_probe_count"] == 23
    assert validation["validation_status_counts"] == {"performed": 10}
    candidates = [item for sample in validation["samples"] for item in sample["candidate_results"]]
    assert candidates
    assert all(item["application_data_sent"] is False for item in candidates)
    assert all(item["c2_confirmed"] is False for item in candidates)
    assert any(item["host"] == "genddos.st" and item["tcp_status"] == "open" for item in candidates)
    assert any(item["host"] == "178.16.54.109" and item["target_role"] == "distribution" for item in candidates)
    tbot = next(sample for sample in validation["samples"] if sample["family"] == "infectedslurs-tbot")
    assert len(tbot["candidate_results"]) == 8
    assert all(item["tcp_status"] == "closed" for item in tbot["candidate_results"])
