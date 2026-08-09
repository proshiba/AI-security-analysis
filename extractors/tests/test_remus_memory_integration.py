"""Remus memory configと既存extractorの統合境界を検証する。"""

from __future__ import annotations

import json
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from extractors.remusstealer import extractor as remus_extractor

IMAGE_SIZE = 0x3000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
KEY_RVA = 0x2000
CIPHER_RVA = 0x2030
TAG_RVA = 0x2160
TOKEN_RVA = 0x21D0
STATE_RVA = 0x2200
RUNTIME_ENDPOINT_RVA = 0x2280
SELECTOR_RVA = 0x23F0
CODE_RVA = 0x1100
KEY = bytes(range(1, 33))
NONCE = bytes.fromhex("1020304050607080")
TAG = "844bd1dce6c8ac2a8b8a026e61811dac"
ENDPOINTS = (
    "http://none",
    "http://onesdto.shop:2535",
    "http://slyfogx.shop:5776",
)


def _chacha(value: bytes, counter: int) -> bytes:
    transform = Cipher(
        algorithms.ChaCha20(KEY, counter.to_bytes(8, "little") + NONCE),
        mode=None,
    ).encryptor()
    return transform.update(value) + transform.finalize()


def _write_pe_headers(data: bytearray) -> None:
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 2, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, CODE_RVA)
    struct.pack_into("<I", data, optional + 20, TEXT_RVA)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, IMAGE_SIZE)
    struct.pack_into("<I", data, optional + 60, 0x400)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + 108, 16)

    section = optional + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x400, TEXT_RVA, 0x400, 0x400)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    section += 40
    data[section : section + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x1000, DATA_RVA, 0x1000, 0x800)
    struct.pack_into("<I", data, section + 36, 0xC0000040)


def _mapped_remus_fixture() -> bytes:
    data = bytearray(IMAGE_SIZE)
    _write_pe_headers(data)
    data[KEY_RVA : KEY_RVA + 32] = KEY
    data[KEY_RVA + 32 : KEY_RVA + 40] = NONCE
    data[KEY_RVA + 40 : KEY_RVA + 48] = b"\0" * 8
    for index, uri in enumerate((*ENDPOINTS, "not-a-url")):
        plain = (uri.encode("ascii") + b"\0").ljust(64, b"\0")
        offset = CIPHER_RVA + index * 64
        data[offset : offset + 64] = _chacha(plain, index)

    data[TAG_RVA : TAG_RVA + len(TAG)] = TAG.encode("ascii")
    token = b"11111111-2222-4333-8444-555555555555"
    data[TOKEN_RVA : TOKEN_RVA + len(token)] = token
    data[STATE_RVA : STATE_RVA + 16] = b"expand 32-byte k"
    data[STATE_RVA + 16 : STATE_RVA + 48] = KEY
    struct.pack_into("<Q", data, STATE_RVA + 48, 2)
    data[STATE_RVA + 56 : STATE_RVA + 64] = NONCE
    wide_endpoint = ENDPOINTS[1].encode("utf-16le") + b"\0\0"
    data[
        RUNTIME_ENDPOINT_RVA : RUNTIME_ENDPOINT_RVA + len(wide_endpoint)
    ] = wide_endpoint
    data[SELECTOR_RVA] = 1 ^ 0x16

    code = bytearray()
    code += b"\x0f\xb6\x05" + struct.pack("<i", SELECTOR_RVA - (CODE_RVA + 7))
    code += b"\x83\xf0\x16\xc1\xe0\x06"
    code += b"\x48\x8d\x15" + struct.pack("<i", CIPHER_RVA - (CODE_RVA + 20))
    code += b"\x48\x01\xc2"
    code += b"\x48\x8d\x0d" + struct.pack("<i", STATE_RVA - (CODE_RVA + 30))
    data[CODE_RVA : CODE_RVA + len(code)] = code
    return bytes(data)


def test_exact_memory_config_is_promoted_with_blocked_active_profile() -> None:
    result = remus_extractor.extract(_mapped_remus_fixture(), "terminal-memory.bin")
    config = result["config"]
    assert config["static_config_recovered"] is True
    assert config["endpoints"] == [
        "onesdto.shop:2535",
        "slyfogx.shop:5776",
    ]
    assert config["urls"] == list(ENDPOINTS[1:])
    assert config["c2_liveness_confirmed"] is False

    findings = {item["value"]: item for item in result["findings"]}
    assert findings["onesdto.shop:2535"]["role"] == "selected_c2"
    assert findings["slyfogx.shop:5776"]["role"] == "fallback_c2"
    assert all(
        findings[value]["confidence"] == "confirmed_static_config"
        for value in config["endpoints"]
    )

    protocol = config["protocol_analysis"]
    assert protocol["terminal_protocol_recovered"] is True
    assert protocol["confirmed_c2"] == []
    assert protocol["static_confirmed_c2"] == config["endpoints"]
    assert [phase["phase"] for phase in protocol["protocol_sequence"]] == [
        "registration",
        "registration_response",
        "task_poll",
        "task_response",
    ]
    assert protocol["protocol_sequence"][0]["form_fields"] == [
        "tag",
        "exp",
        "hwid",
    ]
    assert protocol["protocol_sequence"][2]["form_fields"] == [
        "access_token",
        "step",
    ]
    assert protocol["protocol_sequence"][2]["required_values"] == {"step": "1"}
    envelope = protocol["response_envelope"]
    assert envelope["key_length_bytes"] == 32
    assert envelope["nonce_length_bytes"] == 8
    assert envelope["ciphertext_offset_bytes"] == 40
    assert envelope["cipher"] == "ChaCha20"

    generation = protocol["active_profile_generation"]
    assert generation["status"] == "blocked"
    assert generation["profile"] is None
    assert {reason["code"] for reason in generation["blocked_reasons"]} == {
        "tag_unreviewed",
        "exp_missing",
        "reviewed_http_host_missing",
        "selected_endpoint_pinned_ip_missing",
        "dump_sha256_missing",
        "evidence_manifest_missing",
    }
    assert protocol["active_probe_blocked_reasons"] == generation[
        "blocked_reasons"
    ]
    assert protocol["profile_generation_safety"]["other_sample_defaults_used"] is False
    rendered = json.dumps(result, ensure_ascii=False)
    assert "ba0044e8231f34a997f1591a11b2758b" not in rendered
    assert result["executed"] is False
    assert result["network_contacted"] is False


def test_static_config_survives_protocol_profile_generation_failure(
    monkeypatch,
) -> None:
    monkeypatch.setattr(
        remus_extractor,
        "_build_protocol_profile",
        lambda _result, _report: None,
    )

    result = remus_extractor.extract(_mapped_remus_fixture(), "terminal-memory.bin")

    config = result["config"]
    assert config["static_config_recovered"] is True
    assert config["c2_liveness_confirmed"] is False
    assert config["endpoints"] == [
        "onesdto.shop:2535",
        "slyfogx.shop:5776",
    ]
    protocol = config["protocol_analysis"]
    assert protocol["confirmed_c2"] == []
    assert protocol["static_confirmed_c2"] == config["endpoints"]
    assert protocol["terminal_protocol_recovered"] is False
    generation = protocol["active_profile_generation"]
    assert generation["status"] == "blocked"
    assert generation["profile"] is None
    assert generation["blocked_reasons"][0]["code"] == "protocol_profile_generation_failed"


def test_non_matching_input_keeps_conservative_fallback() -> None:
    result = remus_extractor.extract(
        b"RemusStealer https://unknown.example/api/upload",
        "unmatched.bin",
    )
    config = result["config"]
    assert config["static_config_recovered"] is False
    assert "memory_config_analysis" not in config
    assert config["protocol_analysis"]["terminal_protocol_recovered"] is False
    assert config["protocol_analysis"]["confirmed_c2"] == []
    assert config["protocol_analysis"]["candidate_infrastructure"] == [
        "https://unknown.example/api/upload"
    ]
    assert all(
        finding["confidence"] != "confirmed_static_config"
        for finding in result["findings"]
    )
