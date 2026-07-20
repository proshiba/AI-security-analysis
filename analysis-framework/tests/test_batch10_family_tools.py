"""第10バッチの解析資材、公開成果物、接続検証を回帰検証する。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import struct
from types import SimpleNamespace

import pytest


FRAMEWORK = Path(__file__).parents[1]
REPOSITORY = FRAMEWORK.parent
BATCH10 = (
    REPOSITORY
    / "analysis-results"
    / "research"
    / "malwarebazaar"
    / "batches"
    / "batch-0010"
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
        f"batch10_{family}_{filename}",
    )


def test_genddos_profiles_and_elf64_mapping_cover_batch10() -> None:
    gend = family_module("genddos_bot")
    expected = {
        "517164c29c0e178b1bb4613d3d5ceb552329c9596791624d8277f2dc5ba37c50": "armv7",
        "ee44fb0df1cf9740c5779bc5a811e4d1c984365fd5e0482434f58fc1cc54d638": "x86_64",
        "13f6c8dcecb6677e77680f2b75d82b17fcee135cc00b474bcff5d9c64a06e9bb": "m68k",
        "f9191fbfcd25b4d0274e7831ae190d888c42be4e3794c4bb3dea7517b704fdee": "sh4",
    }
    for digest, architecture in expected.items():
        profile = gend.HASH_PROFILES[digest]
        assert profile["architecture"] == architecture
        assert profile["fallback_host"] == "65.222.202.53"
        assert profile["fallback_port"] == 80

    data = bytearray(0x240)
    data[:6] = b"\x7fELF\x02\x01"
    struct.pack_into("<Q", data, 32, 0x40)
    struct.pack_into("<HH", data, 54, 56, 1)
    struct.pack_into(
        "<IIQQQQQQ", data, 0x40, 1, 5, 0x200, 0x400000, 0, 0x40, 0x40, 0x1000
    )
    assert gend._vaddr_to_offset(bytes(data), 0x400010) == 0x210


def test_jackskid_batch10_profile_keeps_secondary_role_separate() -> None:
    jack = family_module("jackskid")
    profile = jack.HASH_PROFILES[
        "d1e7bb3d3a56b3fa0810838df4885c5c3c794519502f3bc7ae335c9720099215"
    ]
    assert profile["architecture"] == "arm"
    assert profile["key_address"] == 0x255DC
    assert profile["secondary_host"] == "nvms9000.online"
    assert profile["entries"][0x33] == (0x253B4, 0x2C)


def test_dotnet_resource_extractor_supports_nested_byte_entries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    extractor = load_module(
        FRAMEWORK / "common" / "extract_dotnet_resources.py", "batch10_resources"
    )
    nested = SimpleNamespace(
        entries=[
            SimpleNamespace(name="resources/bartia.m4a", value=b"cipher", type_name="System.Stream"),
            SimpleNamespace(name="ignored", value="text", type_name="System.String"),
        ]
    )
    resources = [
        SimpleNamespace(name="plain.bin", data=b"plain"),
        SimpleNamespace(name="container.resources", data=nested),
    ]
    fake_pe = SimpleNamespace(net=SimpleNamespace(resources=resources))
    monkeypatch.setattr(extractor.dnfile, "dnPE", lambda **_kwargs: fake_pe)

    blobs, warnings = extractor.resource_blobs(b"synthetic")
    assert warnings == []
    assert [item["data"] for item in blobs] == [b"plain", b"cipher"]
    assert blobs[1]["container_name"] == "container.resources"
    assert blobs[1]["resource_type"] == "System.Stream"
    assert blobs[1]["output_name"] == "bartia.m4a"


def test_new_emulators_and_network_detector_are_nonexecuting() -> None:
    signed = family_module("signed_dht_bot")
    assert len(signed.PROFILES) >= 3
    assert signed.C2_PORTS == [23, 80, 123, 8080, 25565]
    assert len(signed.COMMAND_IDS) == 9

    emulator = family_module("signed_dht_bot", "emulator.py")
    body = (0x58137722).to_bytes(4, "little") + b"synthetic"
    parsed = emulator.parse_synthetic_frame(emulator.encode_synthetic_frame(body))
    assert parsed["known_command_id"] is True
    assert parsed["body_retained"] is False
    assert parsed["network_contacted"] is False
    assert parsed["command_executed"] is False
    with pytest.raises(ValueError):
        emulator.parse_synthetic_frame(b"\x04\x01x")

    detector = family_module("signed_dht_bot", "network_detector.py")
    bootstrap_only = detector.detect([{"host": "router.bittorrent.com", "transport": "udp"}])
    assert bootstrap_only["matched"] is False
    correlated = detector.detect([
        {"transport": "udp", "bep44_mutable": True, "ed25519_signature_valid": True},
        {
            "transport": "tcp",
            "port": 8080,
            "framing": "uint16-be-body-length",
            "destination_from_signed_record": True,
            "protocol_response_valid": False,
        },
    ])
    assert correlated["matched"] is True
    assert correlated["c2_confirmed"] is False
    assert correlated["verdict"] == "possible_c2"

    formbook = family_module("formbook_loader", "emulator.py")
    envelope = (5).to_bytes(4, "little") + b"child"
    result = formbook.parse_synthetic_stream(envelope)
    assert result["payload_retained"] is False
    assert result["assembly_loaded"] is False
    assert result["network_contacted"] is False
    assert result["process_started"] is False


def test_new_detectors_and_registry_entries_are_bounded() -> None:
    registry = json.loads(
        (FRAMEWORK / "registry" / "malware_types.json").read_text(encoding="utf-8")
    )["malware_types"]
    for family in ("signed_dht_bot", "formbook_loader"):
        assert registry[family]["detector"].endswith("detect.py")
        assert registry[family]["known_sample_sha256"]

    formbook = family_module("formbook_loader", "detect.py")
    synthetic = b"MZ BSJB Rfc2898DeriveBytes Aes AppDomain Load"
    result = formbook.detect(synthetic, Path("synthetic.exe"))
    assert result["matched"] is True
    assert result["observations"]["reviewed_hash"] is False


def test_batch10_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in (
        "signed_dht_bot",
        "formbook_loader",
        "genddos_bot",
        "jackskid",
        "freepbx_k_php",
    ):
        for rule in (FRAMEWORK / "malware" / family / "rules").glob("*.yar"):
            yara.compile(filepath=str(rule))


def test_batch10_publication_has_ten_unique_canonical_cases() -> None:
    classification = json.loads(
        (BATCH10 / "classification.json").read_text(encoding="utf-8")
    )
    samples = classification["samples"]
    assert len(samples) == 10
    assert len({sample["sha256"] for sample in samples}) == 10
    catalog = json.loads(
        (REPOSITORY / "analysis-results" / "catalog" / "cases.json").read_text(
            encoding="utf-8"
        )
    )["cases"]
    for sample in samples:
        version = sample["version"] or "unknown"
        case = (
            REPOSITORY
            / "analysis-results"
            / "malware"
            / sample["family"]
            / "versions"
            / version
            / "cases"
            / sample["sha256"]
        )
        metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["sha256"] == sample["sha256"]
        assert metadata["malware_version"]["normalized_key"] == version
        assert catalog[sample["sha256"]]["canonical_path"] == case.relative_to(REPOSITORY).as_posix()
        assert (case / "README.md").is_file()
        assert (case / "IOC-LIST.md").is_file()


def test_batch10_connectivity_and_shodan_outputs_are_safe() -> None:
    validation = json.loads((BATCH10 / "c2-validation.json").read_text(encoding="utf-8"))
    assert validation["sample_count"] == 10
    assert validation["unique_probe_count"] == 5
    assert validation["validation_status_counts"] == {
        "not_performed_no_exact_target": 4,
        "performed": 6,
    }
    candidates = [
        item
        for sample in validation["samples"]
        for item in sample["candidate_results"]
    ]
    assert all(item["application_data_sent"] is False for item in candidates)
    assert all(item["c2_confirmed"] is False for item in candidates)
    assert all("prefix_base64" not in item for item in candidates)
    assert any(
        item["host"] == "genddos.st" and item.get("tcp_status") == "open"
        for item in candidates
    )
    assert any(
        item["host"] == "nvms9000.online" and item.get("tcp_status") == "open"
        for item in candidates
    )
    unresolved = {
        sample["family"]
        for sample in validation["samples"]
        if sample["connection_validation_status"] == "not_performed_no_exact_target"
    }
    assert unresolved == {"signed-dht-bot", "formbook"}

    shodan = json.loads((BATCH10 / "shodan-hunt.json").read_text(encoding="utf-8"))
    assert set(shodan["excluded_shared_services"]) == {
        "dht.transmissionbt.com",
        "router.bittorrent.com",
        "router.utorrent.com",
        "dht.libtorrent.org",
    }
    assert {item["family"] for item in shodan["dynamic_endpoint_exclusions"]} == {
        "signed-dht-bot",
        "formbook",
    }
    jack = next(item for item in shodan["observations"] if item["ip"] == "162.249.125.140")
    assert jack["live_banner_hash"]["value"] == -2008115501
    assert "banner" not in jack
