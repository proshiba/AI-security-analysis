import hashlib
import json

import pytest

from extractors.valleyrat.extractor import extract
from extractors.valleyrat.nvml_dat import (
    NvmlDatError,
    analyze_nvml_dat,
    parse_trailer,
    recover_nvml_dat,
    resolve_companion_dat,
)

FIXTURE_STAGE_SHA256 = "58d48206457c79dd63cae9b78e5dec8a3f1e6fdfdfe486162dcce45ed95725a2"
FIXTURE_DAT_SHA256 = "84a8b85a2f8f20c976e4b5c7156d2ac93e510571fb732cc6022c22790905d2dc"


def _rc4(data: bytes, key: bytes) -> bytes:
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray(data)
    i = j = 0
    for offset in range(len(output)):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[offset] ^= state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def _permutation(length: int, seed: int) -> list[int]:
    table = list(range(length // 4))
    state = seed ^ 0x5A5A5A5A
    for index in range(len(table) - 1, 0, -1):
        state = (state * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        swap_index = state % (index + 1)
        table[index], table[swap_index] = table[swap_index], table[index]
    return table


def _fixture(*, execution_size: int | None = None) -> tuple[bytes, bytes, bytes]:
    stage = bytearray(b"\x90" * 1_024)
    marker_offset = 0x200
    host1 = b"192.0.2.10\0"
    host2 = b"198.51.100.20\0"
    header = bytearray(0x38)
    header[0:8] = b"codemark"
    header[0x20:0x24] = len(host1).to_bytes(4, "little")
    header[0x24:0x28] = (6_666).to_bytes(4, "little")
    header[0x28:0x2C] = (1).to_bytes(4, "little")
    header[0x2C:0x30] = len(host2).to_bytes(4, "little")
    header[0x30:0x34] = (7_777).to_bytes(4, "little")
    header[0x34:0x38] = (1).to_bytes(4, "little")
    config = bytes(header) + host1 + host2 + b"synthetic-config"
    stage[marker_offset : marker_offset + len(config)] = config

    key = bytes(range(16))
    xor_a, xor_b = 0x36, 0x79
    seed = len(stage) if execution_size is None else execution_size
    executable_stage = bytes(stage[:seed])
    scattered = _rc4(executable_stage, key) + bytes(len(stage) - seed)
    table = _permutation(len(stage), seed)
    transformed = bytearray(len(stage))
    for source, destination in enumerate(table):
        transformed[source * 4 : source * 4 + 4] = scattered[
            destination * 4 : destination * 4 + 4
        ]
    encrypted = bytes(
        ((~(value ^ xor_a)) & 0xFF) ^ xor_b for value in transformed
    )
    trailer = (
        len(stage).to_bytes(4, "little")
        + bytes((xor_a, xor_b))
        + seed.to_bytes(4, "little")
        + key
    )
    return encrypted + trailer, executable_stage, key


def test_known_fixture_recovers_verified_stage_and_c2() -> None:
    dat, stage, key = _fixture()
    assert hashlib.sha256(stage).hexdigest() == FIXTURE_STAGE_SHA256
    assert hashlib.sha256(dat).hexdigest() == FIXTURE_DAT_SHA256

    recovery = recover_nvml_dat(dat, expected_stage_sha256=FIXTURE_STAGE_SHA256)
    assert recovery.stage == stage
    assert recovery.codemark_config["endpoints"] == [
        "192.0.2.10:6666",
        "198.51.100.20:7777",
    ]
    summary = recovery.public_summary(dat)
    assert summary["trailer"]["permutation_applied"] is True
    assert summary["stage_sha256"] == FIXTURE_STAGE_SHA256
    serialized = json.dumps(summary, sort_keys=True)
    assert key.hex() not in serialized
    assert summary["safety"]["raw_key_included"] is False
    assert summary["safety"]["raw_stage_included"] is False


def test_rejects_trailer_length_mismatch() -> None:
    dat, _, _ = _fixture()
    broken = bytearray(dat)
    broken[-26:-22] = (len(dat)).to_bytes(4, "little")
    with pytest.raises(NvmlDatError, match="payload size"):
        parse_trailer(bytes(broken))


def test_rejects_wrong_key_by_verified_stage_sha() -> None:
    dat, _, _ = _fixture()
    broken = bytearray(dat)
    broken[-1] ^= 0xFF
    with pytest.raises(NvmlDatError, match="SHA-256"):
        recover_nvml_dat(
            bytes(broken), expected_stage_sha256=FIXTURE_STAGE_SHA256
        )


def test_permutation_seed_limits_executable_stage_length() -> None:
    dat, stage, _ = _fixture(execution_size=1_000)
    recovery = recover_nvml_dat(dat)
    assert len(stage) == 1_000
    assert recovery.stage == stage


def test_single_dat_integrates_with_family_extractor() -> None:
    dat, _, _ = _fixture()
    result = extract(dat, "NVML.DAT")
    assert result["config"]["variant"] == "nvml_compact_dat_winos_stage"
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["endpoints"] == [
        "192.0.2.10:6666",
        "198.51.100.20:7777",
    ]
    assert result["config"]["nvml_dat"]["stage_sha256"] == FIXTURE_STAGE_SHA256
    assert {
        finding["value"]
        for finding in result["findings"]
        if finding["kind"] == "network.endpoint"
    } == {"192.0.2.10:6666", "198.51.100.20:7777"}


def test_companion_resolver_accepts_case_insensitive_dat(tmp_path) -> None:
    dll = tmp_path / "nvml.dll"
    dat = tmp_path / "NVML.DAT"
    dll.write_bytes(b"MZ")
    dat.write_bytes(b"fixture")
    assert resolve_companion_dat(dll) == dat.resolve()
    assert resolve_companion_dat(tmp_path) == dat.resolve()


def test_companion_resolver_rejects_missing_input(tmp_path) -> None:
    with pytest.raises(NvmlDatError, match="存在"):
        resolve_companion_dat(tmp_path / "missing.dll")


def test_public_analyzer_rejects_invalid_expected_hash() -> None:
    dat, _, _ = _fixture()
    with pytest.raises(NvmlDatError, match="形式"):
        analyze_nvml_dat(dat, expected_stage_sha256="not-a-sha256")
