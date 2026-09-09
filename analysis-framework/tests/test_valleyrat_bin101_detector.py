"""codemark stageとBIN/101外層の構造detector回帰を検証する。"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"
)
SPEC = importlib.util.spec_from_file_location("valleyrat_bin101_detect", MODULE_PATH)
assert SPEC and SPEC.loader
DETECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECT)


def _codemark_stage() -> bytes:
    first_host = b"198.51.100.24\0"
    second_host = b"example.test\0"
    header = bytearray(0x38)
    header[:8] = b"codemark"
    header[0x20:0x24] = len(first_host).to_bytes(4, "little")
    header[0x24:0x28] = (449).to_bytes(4, "little")
    header[0x28:0x2C] = (1).to_bytes(4, "little")
    header[0x2C:0x30] = len(second_host).to_bytes(4, "little")
    header[0x30:0x34] = (8856).to_bytes(4, "little")
    header[0x34:0x38] = (1).to_bytes(4, "little")
    code = b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00"
    code += b"\xe8\x00\x00\x00\x00" * 4
    code += b"\x90" * (0x400 - len(code))
    return code + bytes(header) + first_host + second_host


def _minimal_x86_pe(encoded_tail: bytes) -> bytes:
    data = bytearray(0x100)
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    return bytes(data) + encoded_tail


def test_direct_codemark_stage_is_route_only_without_outer_provenance() -> None:
    result = DETECT.detect(_codemark_stage(), Path("recovered-stage.bin"))

    assert result["matched"] is True
    assert result["campaigns"] == [
        {
            "campaign_type": "winos_codemark_recovered_stage",
            "confidence": "medium",
            "reasons": [
                "raw x64命令形状とcodemark C2 slotの境界検証",
                "外層の静的復元provenanceは単体stageから独立確認できない",
            ],
            "attribution_scope": "component_handler_route",
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
        }
    ]
    assert result["supports_family_attribution"] is False
    observation = result["observations"]["codemark_stage"]
    assert observation["config"] == {
        "endpoint_count": 2,
        "raw_config_included": False,
        "raw_network_values_included": False,
    }
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)
    assert "198.51.100.24" not in serialized
    assert "example.test" not in serialized
    assert observation["raw_stage_included"] is False
    assert observation["executed"] is False
    assert observation["network_contacted"] is False


def test_direct_codemark_rejects_arbitrary_blob_and_container_wrappers() -> None:
    """設定bytesだけをMZ/container/任意blobのfamily証拠へ昇格しない。"""

    config_only = _codemark_stage()[0x400:]
    samples = (
        b"\0" * 0x400 + config_only,
        b"MZ" + _codemark_stage(),
        b"PK\x03\x04" + _codemark_stage(),
        bytes.fromhex("d0cf11e0a1b11ae1") + _codemark_stage(),
    )

    for index, sample in enumerate(samples):
        result = DETECT._terminal_configuration_detection(
            sample,
            DETECT.hashlib.sha256(sample).hexdigest(),
            f"sample-{index}",
        )
        assert result is None


def test_bin101_outer_requires_recovered_codemark_correlation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recovery = SimpleNamespace(
        payload=_codemark_stage(),
        metadata=lambda: {
            "status": "shellcode_recovered",
            "raw_payload_included": False,
        },
    )
    monkeypatch.setattr(DETECT, "recover_bin101_payload", lambda _data: recovery)

    result = DETECT.detect(b"MZ synthetic outer", Path("sample.exe"))

    assert result["matched"] is True
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "bin101_nibble_rc4_loader"
    assert campaign["confidence"] == "high"
    assert campaign["attribution_scope"] == "validated_terminal_component_structure"
    assert campaign["terminal_family_confirmed"] is True
    observation = result["observations"]["recovered_codemark_stage"]
    assert observation["config"] == {
        "endpoint_count": 2,
        "raw_config_included": False,
        "raw_network_values_included": False,
    }
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)
    assert "198.51.100.24" not in serialized
    assert "example.test" not in serialized


def test_bin101_outer_without_valid_terminal_config_is_not_promoted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recovery = SimpleNamespace(
        payload=b"ordinary shellcode-shaped bytes",
        metadata=lambda: {"status": "shellcode_recovered"},
    )
    monkeypatch.setattr(DETECT, "recover_bin101_payload", lambda _data: recovery)

    result = DETECT.detect(b"MZ synthetic outer", Path("sample.exe"))

    assert result["matched"] is False
    assert result["campaigns"] == []


def _terminal_probe(variant: str) -> dict[str, object]:
    return {
        "matched": True,
        "family": "valleyrat",
        "variant": variant,
        "supports_family_attribution": True,
        "attribution_scope": "validated_terminal_component_structure",
        "static_config_recovered": True,
        "evidence": {"validated_structure": True},
        "config": {
            "public_network_value_count": 1,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def test_n520_probe_selects_family_before_other_pe_probes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        DETECT,
        "probe_n520_config",
        lambda _data: _terminal_probe("single_pe_n520_managed"),
    )
    monkeypatch.setattr(
        DETECT,
        "probe_vvas_config",
        lambda *_args, **_kwargs: pytest.fail("N520一致後にvvaS probeを呼んではならない"),
    )

    result = DETECT.detect(b"MZ managed fixture", Path("n520.exe"))

    assert result["matched"] is True
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "single_pe_n520_managed"
    assert campaign["terminal_family_confirmed"] is True
    probe = result["observations"]["terminal_config_probe"]
    assert probe["static_config_recovered"] is True
    assert probe["config"]["raw_network_values_included"] is False


def test_vvas_pe_probe_selects_terminal_family(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(DETECT, "probe_n520_config", lambda _data: {"matched": False})
    monkeypatch.setattr(
        DETECT,
        "probe_vvas_config",
        lambda _data, *, input_format: (
            _terminal_probe("vvas_reversed_config_terminal")
            if input_format == "pe"
            else {"matched": False}
        ),
    )

    result = DETECT.detect(b"MZ vvaS fixture", Path("vvas.exe"))

    assert result["matched"] is True
    assert result["campaigns"][0]["campaign_type"] == "vvas_reversed_config_terminal"
    assert result["campaigns"][0]["terminal_family_confirmed"] is True


def test_vvas_rcdata_probe_routes_unreviewed_terminal_variant(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Winsock非依存のRCDATA/788 variantも構造probeから自動選択する。"""

    monkeypatch.setattr(DETECT, "probe_n520_config", lambda _data: {"matched": False})
    monkeypatch.setattr(
        DETECT,
        "probe_vvas_config",
        lambda *_args, **_kwargs: {"matched": False},
    )
    monkeypatch.setattr(
        DETECT,
        "probe_vvas_resource_config",
        lambda _data: _terminal_probe("single_pe_vvas_resource"),
    )
    monkeypatch.setattr(
        DETECT,
        "recover_bin101_payload",
        lambda _data: pytest.fail("RCDATA一致後にBIN101を探索してはならない"),
    )

    result = DETECT.detect(b"MZ resource fixture", Path("unreviewed.exe"))

    assert result["matched"] is True
    assert result["campaigns"][0]["campaign_type"] == "single_pe_vvas_resource"
    assert result["campaigns"][0]["terminal_family_confirmed"] is True
    assert result["observations"]["terminal_config_probe"][
        "static_config_recovered"
    ] is True


def test_raw_vvas_probe_is_route_only_and_publish_safe() -> None:
    sample = b"odaktomk |944:1o|42.001.15.891:1p|"

    result = DETECT.detect(sample, Path("vvas.bin"))
    serialized = json.dumps(result, ensure_ascii=False, sort_keys=True)

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == "vvas_reversed_config_candidate"
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["supports_family_attribution"] is False
    assert campaign["terminal_family_confirmed"] is False
    probe = result["observations"]["static_config_candidate_probe"]
    assert probe["static_config_recovered"] is False
    assert probe["candidate_config_recovered"] is True
    assert "198.51.100.24" not in serialized
    assert ":449" not in serialized


def test_single_byte_xor_vvas_routes_unknown_hash_without_family_attribution() -> None:
    """raw XOR設定は後続解析へrouteするが終端familyへ昇格しない。"""

    plaintext = (
        b"payload odaktomk "
        b"|0:2t|8448:2o|elpmaxe.pukcab:2p|1:1t|944:1o|42.001.15.891:1p|"
    )
    encrypted = bytes(value ^ 0x14 for value in plaintext)

    result = DETECT.detect(encrypted, Path("unknown.bin"))
    serialized = json.dumps(result, sort_keys=True)

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    assert result["campaigns"][0]["campaign_type"] == (
        "single_byte_xor_vvas_candidate"
    )
    assert result["campaigns"][0]["supports_family_attribution"] is False
    assert result["campaigns"][0]["terminal_family_confirmed"] is False
    probe = result["observations"]["static_config_candidate_probe"]
    assert probe["static_config_recovered"] is False
    assert probe["candidate_config_recovered"] is True
    assert "198.51.100.24" not in serialized
    assert "backup.example" not in serialized
    assert "0x14" not in serialized


def test_single_byte_xor_loader_is_route_only_stage_locator() -> None:
    """未知hashの単一byte XOR downloaderはrouteするが終端familyにしない。"""

    decoded = (
        b"wininet.dll GetProcAddress GetModuleHandleA InternetOpenA "
        b"InternetOpenUrlA InternetReadFile AddVectoredExceptionHandler VirtualAlloc "
        b"https://stage.example/payload.bin"
    )
    encrypted = bytes(value ^ 0xB1 for value in decoded)

    result = DETECT.detect(_minimal_x86_pe(encrypted), Path("unknown.exe"))
    serialized = json.dumps(result, sort_keys=True)

    assert result["matched"] is True
    assert result["supports_family_attribution"] is False
    campaign = result["campaigns"][0]
    assert campaign["campaign_type"] == (
        "x86_single_byte_xor_wininet_next_stage_loader"
    )
    assert campaign["attribution_scope"] == "component_handler_route"
    assert campaign["supports_family_attribution"] is False
    assert campaign["terminal_family_confirmed"] is False
    probe = result["observations"]["static_stage_locator_probe"]
    assert probe["static_config_recovered"] is False
    assert probe["static_stage_locator_recovered"] is True
    assert "stage.example" not in serialized
    assert "fixed_key" not in serialized
    assert "0xB1" not in serialized
    assert "x86_xor_b1" not in serialized


def test_xor_b1_loader_requires_full_wininet_veh_structure() -> None:
    """API解決名とURLだけの一般x86 PEをValleyRAT routeへ入れない。"""

    weak = (
        b"wininet.dll GetProcAddress GetModuleHandleA InternetOpenA "
        b"InternetOpenUrlA InternetReadFile https://stage.example/payload.bin"
    )
    encrypted = bytes(value ^ 0xB1 for value in weak)

    result = DETECT.detect(_minimal_x86_pe(encrypted), Path("generic.exe"))

    assert result["matched"] is False
    assert result["campaigns"] == []


def test_reviewed_route_can_only_be_upgraded_by_terminal_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = b"MZ reviewed route with terminal config"
    digest = DETECT.hashlib.sha256(data).hexdigest()
    monkeypatch.setitem(DETECT.KNOWN_CAMPAIGNS, digest, "signed_proxy_sideload")
    monkeypatch.setitem(
        DETECT.REVIEWED_SAMPLES,
        digest,
        {"campaign": "signed_proxy_sideload", "final_rat_confirmed": False},
    )
    monkeypatch.setattr(
        DETECT,
        "probe_n520_config",
        lambda _data: _terminal_probe("single_pe_n520_managed"),
    )

    result = DETECT.detect(data, Path("reviewed.exe"))

    assert result["matched"] is True
    assert result["campaigns"][0]["campaign_type"] == "single_pe_n520_managed"
    assert result["campaigns"][0]["terminal_family_confirmed"] is True
    assert result.get("supports_family_attribution") is not False
