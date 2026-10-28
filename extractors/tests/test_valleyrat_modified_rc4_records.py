from __future__ import annotations

import json
import struct

import pytest

from extractors.valleyrat import extractor
from extractors.valleyrat import modified_rc4_records as target


def _xor_swap(data: bytes, key: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray(data)
    i = j = 0
    for offset, value in enumerate(output):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[offset] = value ^ state[i] ^ state[j]
    return bytes(output)


def _stock_rc4(data: bytes, key: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray(data)
    i = j = 0
    for offset, value in enumerate(output):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[offset] = value ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def _core_record(
    *,
    stock_rc4: bool = False,
    zeroed_signature: bool = True,
    raw_pointer: int = 0x400,
) -> bytes:
    total_size = 0x800
    assembled = bytearray(total_size)
    assembled[0] = target.CORE_KEY_LENGTH
    assembled[1 : target.CORE_PREFIX_SIZE] = bytes(
        ((index * 37) + 11) & 0xFF for index in range(target.CORE_KEY_LENGTH)
    )
    e_lfanew = 0x138
    struct.pack_into("<I", assembled, 0x3C, e_lfanew)
    if zeroed_signature:
        assembled[e_lfanew : e_lfanew + 4] = b"\0\0\0\0"
    else:
        assembled[e_lfanew : e_lfanew + 4] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        assembled,
        e_lfanew + 4,
        0x8664,
        1,
        0,
        0,
        0,
        0xF0,
        0x2022,
    )
    optional = e_lfanew + 24
    struct.pack_into("<H", assembled, optional, 0x20B)
    struct.pack_into("<I", assembled, optional + 0x10, 0x1000)
    struct.pack_into("<Q", assembled, optional + 0x18, 0x180000000)
    struct.pack_into("<I", assembled, optional + 0x20, 0x1000)
    struct.pack_into("<I", assembled, optional + 0x24, 0x200)
    struct.pack_into("<I", assembled, optional + 0x38, 0x2000)
    struct.pack_into("<I", assembled, optional + 0x3C, 0x400)
    struct.pack_into("<I", assembled, optional + 0x6C, 16)
    section = optional + 0xF0
    assembled[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", assembled, section + 8, 0x180, 0x1000, 0x200, raw_pointer)
    struct.pack_into("<I", assembled, section + 36, 0x60000020)
    if raw_pointer + 0x200 <= len(assembled):
        assembled[raw_pointer : raw_pointer + 0x200] = b"\x90" * 0x1FF + b"\xc3"
    key = bytes(assembled[1 : target.CORE_PREFIX_SIZE])
    plaintext = bytes(assembled[target.CORE_PREFIX_SIZE :])
    cipher = _stock_rc4(plaintext, key) if stock_rc4 else _xor_swap(plaintext, key)
    return bytes(assembled[: target.CORE_PREFIX_SIZE]) + cipher


def _config_record(
    *,
    endpoint: str = "node.c2-fixture.example.org:443",
    include_path: bool = True,
) -> bytes:
    config = bytearray(target.CONFIG_SIZE)
    values = ["444.exe", "teamspeak_control.dll", endpoint]
    if include_path:
        values.insert(0, r"C:\Program Files\Common Files")
    cursor = 0x20
    for value in values:
        encoded = value.encode("ascii") + b"\0"
        config[cursor : cursor + len(encoded)] = encoded
        cursor += len(encoded) + 3
    return _xor_swap(bytes(config), target.CONFIG_KEY)


def _frame(*records: bytes) -> bytes:
    return (
        b"".join(struct.pack("<I", len(item)) + item for item in records) + b"\0\0\0\0"
    )


def _fixture(
    *,
    core: bytes | None = None,
    config: bytes | None = None,
) -> bytes:
    loader = bytes((index * 17 + 3) & 0xFF for index in range(0x100))
    return _frame(loader, core or _core_record(), config or _config_record())


def test_modified_rc4_known_vector() -> None:
    assert _xor_swap(bytes(range(16)), b"Key").hex() == (
        "7d438bea74c50e7d077fe96fce2db2d3"
    )
    assert target._modified_rc4(bytes(range(16)), b"Key") == _xor_swap(
        bytes(range(16)), b"Key"
    )


def test_recovers_strict_three_record_candidate_without_raw_material() -> None:
    data = _fixture()
    recovery = target.recover_modified_rc4_records(data)
    summary = recovery.public_summary()

    assert recovery.core.reconstructed_pe.startswith(b"MZ")
    assert len(recovery.core.reconstructed_pe) == recovery.core.assembled_size
    assert summary["status"] == "validated_modified_rc4_record_container_candidate"
    assert summary["candidate_config_recovered"] is True
    assert summary["static_config_recovered"] is False
    assert summary["supports_family_attribution"] is False
    assert summary["input"]["record_count"] == 3
    assert summary["input"]["record_sizes"] == [0x100, 0x800, target.CONFIG_SIZE]
    assert summary["core"]["machine"] == "0x8664"
    assert summary["core"]["section_count"] == 1
    assert summary["core"]["e_lfanew"] == 0x138
    assert summary["core"]["mz_reconstructed"] is True
    assert summary["core"]["pe_signature_reconstructed"] is True
    assert summary["config"]["endpoint_candidates"] == [
        "node.c2-fixture.example.org:443"
    ]
    assert summary["config"]["endpoint_role"] == "command_c2_candidate"
    assert summary["config"]["path_or_filename_marker_count"] >= 2
    assert summary["safety"] == {
        "sample_executed": False,
        "core_executed": False,
        "network_contacted": False,
        "raw_key_included": False,
        "raw_core_included": False,
        "raw_config_included": False,
    }
    serialized = json.dumps(summary, sort_keys=True)
    assert '"reconstructed_pe":' not in serialized
    assert '"raw_config":' not in serialized
    assert target.CONFIG_KEY.hex() not in serialized


def test_probe_rejects_non_bytes_and_malformed_inputs() -> None:
    assert target.probe_modified_rc4_records(bytearray(_fixture())) is None
    assert target.probe_modified_rc4_records(b"") is None
    assert (
        target.probe_modified_rc4_records(
            struct.pack("<I", target.MAXIMUM_RECORD_SIZE + 1)
        )
        is None
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data + b"trailing",
        lambda data: data[:-1],
        lambda data: data + _fixture(),
        lambda data: data[:-4],
        lambda data: _frame(b"short", _core_record(), _config_record()),
        lambda data: _frame(b"L" * 0x100, _core_record()),
        lambda data: _frame(b"L" * 0x100, _core_record(), _config_record(), b"fourth"),
    ],
)
def test_rejects_trailing_truncated_ambiguous_and_wrong_record_count(mutation) -> None:
    assert target.probe_modified_rc4_records(mutation(_fixture())) is None


def test_rejects_wrong_core_key_length() -> None:
    core = bytearray(_core_record())
    core[0] = 0x72
    assert target.probe_modified_rc4_records(_fixture(core=bytes(core))) is None


def test_rejects_stock_rc4_core() -> None:
    assert (
        target.probe_modified_rc4_records(_fixture(core=_core_record(stock_rc4=True)))
        is None
    )


def test_rejects_non_zero_pe_signature_instead_of_reconstruction_shape() -> None:
    assert (
        target.probe_modified_rc4_records(
            _fixture(core=_core_record(zeroed_signature=False))
        )
        is None
    )


def test_rejects_section_raw_range_outside_core() -> None:
    assert (
        target.probe_modified_rc4_records(
            _fixture(core=_core_record(raw_pointer=0x1000))
        )
        is None
    )


def test_rejects_config_without_validated_string_structure() -> None:
    config = _xor_swap(b"\0" * target.CONFIG_SIZE, target.CONFIG_KEY)
    assert target.probe_modified_rc4_records(_fixture(config=config)) is None


def test_config_without_endpoint_remains_non_c2_candidate() -> None:
    summary = target.probe_modified_rc4_records(
        _fixture(config=_config_record(endpoint="not-an-endpoint"))
    )

    assert summary is not None
    assert summary["decrypted_config_recovered"] is True
    assert summary["candidate_config_recovered"] is False
    assert summary["config"]["endpoint_candidates"] == []


def test_rejects_config_encrypted_with_stock_rc4() -> None:
    plaintext = _xor_swap(_config_record(), target.CONFIG_KEY)
    stock_encrypted = _stock_rc4(plaintext, target.CONFIG_KEY)
    assert target.probe_modified_rc4_records(_fixture(config=stock_encrypted)) is None


@pytest.mark.parametrize(
    "endpoint",
    [
        "127.0.0.1:443",
        "10.0.0.1:443",
        "169.254.1.2:80",
        "fixture.invalid:443",
        "localhost:443",
    ],
)
def test_placeholder_endpoint_is_not_published(endpoint: str) -> None:
    summary = target.probe_modified_rc4_records(
        _fixture(config=_config_record(endpoint=endpoint))
    )

    assert summary is not None
    assert summary["candidate_config_recovered"] is False
    assert summary["config"]["endpoint_candidates"] == []


def test_shared_extractor_returns_reconstructed_core_for_static_follow_on() -> None:
    result = extractor.extract(_fixture(), "teamspeak_control.bin")

    config = result["config"]
    assert config["variant"] == "modified_rc4_three_record_container_candidate"
    assert config["candidate_config_recovered"] is True
    assert config["terminal_family_confirmed"] is False
    assert config["endpoints"] == ["node.c2-fixture.example.org:443"]
    recovered = result["recovered_payload"]
    assert recovered["role"] == "recovered_payload"
    assert recovered["analysis_priority"] == 3
    assert recovered["source_name"] == recovered["name"]
    assert recovered["data"].startswith(b"MZ")
