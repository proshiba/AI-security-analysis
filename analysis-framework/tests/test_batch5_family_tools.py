"""第5バッチで追加・拡張した静的解析資材の回帰試験。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest


FRAMEWORK = Path(__file__).parents[1]
REPOSITORY = FRAMEWORK.parent
BATCH5 = REPOSITORY / "analysis-results" / "research" / "malwarebazaar" / "batches" / "batch-0005"

COMMON = FRAMEWORK / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import extract_dotnet_resources  # noqa: E402
import passive_c2_detector  # noqa: E402


def load_file(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def family_module(family: str, filename: str = "extract_config.py"):
    return load_file(FRAMEWORK / "malware" / family / filename, f"batch5_{family}_{filename}")


def test_dotnet_resource_filename_is_flat_and_stable() -> None:
    assert extract_dotnet_resources.safe_name(r"..\payloads\PoP go.exe", 1) == "PoP_go.exe"
    assert extract_dotnet_resources.safe_name("...", 7) == "resource-0007.bin"


def test_dotnet_resource_hash_mismatch_fails_before_parse(tmp_path: Path) -> None:
    sample = tmp_path / "fixture.bin"
    sample.write_bytes(b"not a PE")
    with pytest.raises(ValueError, match="SHA-256"):
        extract_dotnet_resources.extract(sample, tmp_path / "out", "0" * 64)


def test_protected_dotnet_analyzer_returns_partial_result_for_unreadable_input() -> None:
    module = load_file(
        FRAMEWORK / "malware" / "valleyrat" / "campaigns" / "single_pe" / "analyze_dotnet_il.py",
        "batch5_protected_dotnet_analyzer",
    )
    data = b"not a PE"
    result = module.analyze(data, hashlib.sha256(data).hexdigest())
    assert result["analysis_status"] == "partial"
    assert result["metadata_status"] == "unreadable"
    assert result["executed"] is False
    assert result["network_contacted"] is False
    assert result["warnings"]


def test_ens_arm_profile_has_same_logical_table_shape() -> None:
    profile = load_file(FRAMEWORK / "malware" / "linux_ens_sns_bot" / "profile.py", "batch5_ens_profile")
    arm = profile.PROFILE_BY_SHA256["b6b9753bf156d5eb5dcbad43de9ab651146a819da27fe9d2c031097ca10619d3"]
    assert arm["architecture"] == "arm"
    assert len(arm["descriptors"]) == len(profile.STRING_DESCRIPTORS) == 53
    assert arm["port_count"] == 101


def test_jiproxy_cipher_decrypts_reviewed_fragment() -> None:
    module = family_module("jiproxy_relay")
    ciphertext = bytes.fromhex("f56029471447b51be7f057c6fbd558d9d8db5069d49fbd28d5")
    assert module.decrypt_entry(ciphertext, module.build_state(module.KEY_BYTES)) == (b"n1.persistfromchicago.com")


def test_softbot_emulator_validates_frames() -> None:
    module = family_module("softbot", "emulator.py")
    assert module.parse_registration(b"ABCD\x03bot") == {"marker_hex": "41424344", "bot_id": "bot"}
    assert module.encode_command(b"PING") == b"\x00\x04PING"
    with pytest.raises(ValueError):
        module.parse_registration(b"ABCD\x05bot")


def test_jiproxy_emulator_parses_status_datagram() -> None:
    module = family_module("jiproxy_relay", "emulator.py")
    packet = (
        b'POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{"status":"ONLINE","connections":3,"bandwidth":0.0}'
    )
    assert module.parse_status_datagram(packet)["connections"] == 3


def test_proxy_launcher_emulator_parses_reviewed_client_key() -> None:
    module = family_module("proxyrack_pop_deployer", "emulator.py")
    result = module.parse_launcher_arguments(
        "--homeIp point-of-presence.sock.sh --homePort 443 --clientKey proxyrack-pop-client --clientType PoP"
    )
    assert result["homeIp"] == "point-of-presence.sock.sh"
    assert result["homePort"] == "443"


def test_traffmonetizer_settings_are_redacted(tmp_path: Path) -> None:
    module = family_module("traffmonetizer_deployer")
    settings = tmp_path / "settings.json"
    settings.write_text(
        json.dumps({"Token": "secret-token", "StartWithWindows": False, "Accepting": True}),
        encoding="utf-8",
    )
    result = module.settings_summary(settings)
    assert result == {
        "token_present": True,
        "token_length": 12,
        "token_value": "<redacted>",
        "start_with_windows": False,
        "accepting": True,
    }
    assert "secret-token" not in json.dumps(result)


def test_dual_use_profiles_do_not_confirm_c2_or_emit_shodan_queries() -> None:
    for family, host in (
        ("proxyrack_pop_deployer", "point-of-presence.sock.sh"),
        ("traffmonetizer_deployer", "blnc.traffmonetizer.com"),
    ):
        profile = json.loads((FRAMEWORK / "malware" / family / "c2_profile.json").read_text(encoding="utf-8"))
        port = profile["endpoints"][0]["port"]
        result = passive_c2_detector.detect(profile, [{"destination_host": host, "destination_port": port}])
        assert result["matches"][0]["verdict"] == "non_c2_role"
        assert result["shodan"]["queries"] == []


def test_batch5_publication_has_ten_unique_canonical_cases() -> None:
    classification = json.loads((BATCH5 / "classification.json").read_text(encoding="utf-8"))
    samples = classification["samples"]
    assert len(samples) == 10
    assert len({sample["sha256"] for sample in samples}) == 10
    for sample in samples:
        case = (
            REPOSITORY
            / "analysis-results"
            / "malware"
            / sample["family"]
            / "versions"
            / "unknown"
            / "cases"
            / sample["sha256"]
        )
        metadata = json.loads((case / "metadata.json").read_text(encoding="utf-8"))
        assert metadata["sha256"] == sample["sha256"]
        assert metadata["malware_version"]["status"] == "unknown"
        assert metadata["canonical_path"].endswith(f"/cases/{sample['sha256']}")
        assert (case / "README.md").is_file()
        assert (case / "IOC-LIST.md").is_file()


def test_batch5_live_validation_preserves_udp_and_c2_safety_invariants() -> None:
    validation = json.loads((BATCH5 / "c2-validation.json").read_text(encoding="utf-8"))
    assert validation["sample_count"] == 10
    assert validation["unique_probe_count"] == 8
    assert validation["validation_status_counts"] == {
        "not_performed_no_exact_target": 1,
        "performed": 9,
    }
    candidates = [candidate for sample in validation["samples"] for candidate in sample["candidate_results"]]
    assert candidates
    assert all(candidate["c2_confirmed"] is False for candidate in candidates)
    udp_candidates = [candidate for candidate in candidates if candidate["protocol"] == "udp"]
    assert udp_candidates
    assert all(candidate["empty_datagram_sent"] is True for candidate in udp_candidates)
    assert all(candidate["datagram_payload_length"] == 0 for candidate in udp_candidates)
    assert all(candidate["application_data_sent"] is False for candidate in udp_candidates)
    protected = next(sample for sample in validation["samples"] if sample["family"] == "protection-agent-loader")
    assert protected["connection_validation_status"] == "not_performed_no_exact_target"


def test_public_traffmonetizer_token_is_redacted() -> None:
    case = (
        REPOSITORY
        / "analysis-results"
        / "malware"
        / "traffmonetizer-deployer"
        / "versions"
        / "unknown"
        / "cases"
        / "06e3950cfa439625ead51e1c47c4ebe9e1762910c91ee77687f85dbe02d3f437"
    )
    config = json.loads((case / "config.json").read_text(encoding="utf-8"))
    serialized = json.dumps(config, ensure_ascii=False)
    assert config["settings"]["token_value"] == "<redacted>"
    assert "secret-token" not in serialized


def test_protection_agent_emulator_marks_protocol_unavailable() -> None:
    module = family_module("protection_agent_loader", "emulator.py")
    assert module.status()["available"] is False
    assert module.status()["malware_protocol_compatible"] is False


def test_batch5_yara_rules_compile() -> None:
    yara = pytest.importorskip("yara")
    for family in (
        "jiproxy_relay",
        "softbot",
        "protection_agent_loader",
        "proxyrack_pop_deployer",
        "traffmonetizer_deployer",
    ):
        rule = next((FRAMEWORK / "malware" / family / "rules").glob("*.yar"))
        yara.compile(filepath=str(rule))
