"""第8バッチの多アーキテクチャ抽出・検知に対する回帰試験。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest


FRAMEWORK = Path(__file__).parents[1]
REPOSITORY = FRAMEWORK.parent
BATCH8 = REPOSITORY / "analysis-results" / "research" / "malwarebazaar" / "batches" / "batch-0008"


def load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def family_module(family: str):
    return load_module(FRAMEWORK / "malware" / family / "extract_config.py", f"batch8_{family}")


def test_eclipse_batch8_profiles_cover_three_architectures() -> None:
    module = family_module("eclipse_ddos_bot")
    expected = {
        "23a3e7fc7099fd75f7bfb7c0ca426278f1d8b26af8e90fd9c861409b99e5b39e": ("x86", "i686"),
        "30b37af8712dec58014f16686fd105d736883646d1ecaa55f256698230712502": ("armv7", "armv7l"),
        "ac4b0373be4ff4de4e778f1363a4d0675a672d16fd11e8aa5b202701e2a6b747": ("x86_64", "x86_64"),
    }
    for digest, (architecture, registration) in expected.items():
        profile = module.HASH_PROFILES[digest]
        assert profile["architecture"] == architecture
        assert profile["registration"] == registration
        assert profile["port"] == 7000
        assert profile["reconnect"] == "固定5秒"
        assert profile["ghidra"]["main_address"].startswith("0x")
    assert b"TCP_FLOOD" in module.COMMANDS


def test_genddos_batch8_endian_profiles_and_static_decryption() -> None:
    module = family_module("genddos_bot")
    arc = module.HASH_PROFILES["1e55ecd233043bea9f7b1850cb560acf58d10d0fea04c097b54ef0488aaefe4c"]
    mips = module.HASH_PROFILES["956f66bf9a0d796c9913a9b9cd255e8d1c49ab1b3de29d5418fd01b485032430"]
    assert arc["key_bytes"] == "efbeadde"
    assert "fallback_host" not in arc
    assert mips["key_bytes"] == "deadbeef"
    assert mips["fallback_host"] == "65.222.202.53"
    for profile in (arc, mips):
        key = bytes.fromhex(profile["key_bytes"])
        assert key[0] ^ key[1] ^ key[2] ^ key[3] == 0x22


def test_putita_mips_profiles_distinguish_config_and_session_keys() -> None:
    module = family_module("putita_v3")
    unpacked = module.HASH_PROFILES["11ce110d1a9b0b3aeb13e1827fb66fce905504a8ec4239c32dfabd66cf34bdb4"]
    packed = module.HASH_PROFILES["195fe7c703d6fef572f1a6d7441898488c5483db820a7feb0c2d622d1c4e4b2c"]
    assert unpacked["architecture"] == packed["architecture"] == "mipsel"
    assert packed["logical_payload"] == "11ce110d1a9b0b3aeb13e1827fb66fce905504a8ec4239c32dfabd66cf34bdb4"
    assert unpacked["session_key_seed"] == (0x34BEEF56, 0xC0FFEE12)
    assert module.derive_static_key(*unpacked["session_key_seed"]) != module.derive_static_key()


def test_ens_sns_batch8_arm_profile_is_exact_table_relocation() -> None:
    profile = load_module(
        FRAMEWORK / "malware" / "linux_ens_sns_bot" / "profile.py", "batch8_ens_profile"
    )
    item = profile.PROFILE_BY_SHA256["aa91037d96973b8a145864fe4784cf74e3869ca4afdd51aea0dddc0a587c1aa3"]
    assert item["architecture"] == "armv4l"
    assert item["key_address"] == 0x225AC
    assert item["port_address"] == 0x21BA6
    assert len(item["descriptors"]) == len(profile.ARM_STRING_DESCRIPTORS)


def test_jackskid_absorbs_the_previous_provisional_ens_sns_profiles() -> None:
    module = family_module("jackskid")
    digest = "aa91037d96973b8a145864fe4784cf74e3869ca4afdd51aea0dddc0a587c1aa3"
    assert digest in module.HASH_PROFILES
    assert module.HASH_PROFILES[digest]["architecture"] == "armv4l"
    assert "再帰属" in module.HASH_PROFILES[digest]["profile_relation"]
    assert len(module.HASH_PROFILES) >= 5

def test_layout_accepts_a_dated_inferred_configuration_generation() -> None:
    module = load_module(FRAMEWORK / "common" / "result_layout.py", "batch8_result_layout")
    path = module.canonical_malware_case_path(
        Path("analysis-results"),
        "jackskid",
        "a" * 64,
        "2026-07-ens-sns",
    )
    assert "versions/2026-07-ens-sns/cases" in path.as_posix()

def test_batch8_publication_has_ten_unique_canonical_cases() -> None:
    classification = json.loads((BATCH8 / "classification.json").read_text(encoding="utf-8"))
    samples = classification["samples"]
    assert len(samples) == 10
    assert len({sample["sha256"] for sample in samples}) == 10
    for sample in samples:
        version = sample["version"] or "unknown"
        case = (
            REPOSITORY / "analysis-results" / "malware" / sample["family"]
            / "versions" / version / "cases" / sample["sha256"]
        )
        metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["sha256"] == sample["sha256"]
        assert metadata["malware_version"]["normalized_key"] == version
        assert (case / "README.md").is_file()
        assert (case / "IOC-LIST.md").is_file()


def test_batch8_connection_validation_is_exact_and_payload_free() -> None:
    validation = json.loads((BATCH8 / "c2-validation.json").read_text(encoding="utf-8"))
    assert validation["sample_count"] == 10
    assert validation["unique_probe_count"] == 7
    assert validation["validation_status_counts"] == {"performed": 10}
    candidates = [item for sample in validation["samples"] for item in sample["candidate_results"]]
    assert candidates
    assert all(item["application_data_sent"] is False for item in candidates)
    assert all(item["c2_confirmed"] is False for item in candidates)
    assert any(item["host"] == "45.66.228.114" and item["tcp_status"] == "open" for item in candidates)
    assert any(item["host"] == "genddos.st" and item["tcp_status"] == "open" for item in candidates)
    freepbx = [sample for sample in validation["samples"] if sample["family"] == "freepbx-k-php"]
    assert len(freepbx) == 2
    assert all(sample["c2_connection_validation_status"] == "not_applicable" for sample in freepbx)
    assert all(sample["non_c2_connection_validation_status"] == "performed" for sample in freepbx)
def test_batch8_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in ("eclipse_ddos_bot", "genddos_bot", "putita_v3", "freepbx_k_php", "jackskid", "linux_ens_sns_bot"):
        path = next((FRAMEWORK / "malware" / family / "rules").glob("*.yar"))
        yara.compile(filepath=str(path))


def test_classifier_loads_legacy_extractor_imports_without_errors() -> None:
    classifier = load_module(FRAMEWORK / "classifiers" / "classify_sample.py", "batch8_classifier")
    registry = json.loads((FRAMEWORK / "registry" / "malware_types.json").read_text(encoding="utf-8"))["malware_types"]
    for family in ("amadey", "latrodectus", "shadowpad", "stealc"):
        detector = classifier.load_detector(FRAMEWORK, registry[family]["detector"], family)
        assert callable(detector)
