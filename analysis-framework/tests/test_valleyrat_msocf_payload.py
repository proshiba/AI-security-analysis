"""ValleyRAT MSOCFプロキシの静的復元回帰テスト。"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "malware/valleyrat/campaigns/signed_proxy_sideload/msocf_payload.py"
SPEC = importlib.util.spec_from_file_location("valleyrat_msocf_payload", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def _index_setup(index: int) -> bytes:
    prefix = b"\x33\xc0\x40"
    if index == 1:
        return prefix + b"\xc1\xe0\x00"
    if index > 0 and index & (index - 1) == 0:
        return prefix + b"\xc1\xe0" + (index.bit_length() - 1).to_bytes(1, "little")
    if index <= 0x7F:
        return prefix + b"\x6b\xc0" + index.to_bytes(1, "little")
    return prefix + b"\x69\xc0" + index.to_bytes(4, "little")


def _key_builder(key: bytes) -> bytes:
    result = bytearray(b"\x55\x8b\xec")
    for index, value in enumerate(key + b"\x00"):
        result.extend(_index_setup(index))
        result.extend(b"\x8b\x4d\x08\xc6\x04\x01")
        result.append(value)
    return bytes(result)


def test_sequential_key_builder_and_payload_are_recovered_without_execution() -> None:
    key = (b"Ab9" * 80)[:200]
    payload = bytearray(b"\x55\x8b\xec" + b"\x90" * 1_197)
    payload[128:136] = b"codemark"
    payload[256:270] = b"203.0.113.77\0"
    before_rc4 = bytes(value ^ 0xFF for value in payload)
    encrypted = MODULE.rc4(before_rc4, key)
    sample = _key_builder(key) + b"\x00not-hex\x00" + encrypted.hex().encode() + b"\x00"

    recovery = MODULE.recover_msocf_payload(sample)
    summary = recovery.public_summary()

    assert recovery.key == key
    assert recovery.payload == bytes(payload)
    assert summary["algorithm"] == ["ascii_hex_decode", "rc4", "xor_each_byte_0xff"]
    assert summary["endpoints"] == ["203.0.113.77"]
    assert summary["markers"] == ["codemark"]
    assert summary["executed"] is False
    assert "payload" not in summary
    assert "key" not in summary


def test_invalid_hex_or_key_fails_closed() -> None:
    for sample in (b"ordinary file", b"a" * 4096, _key_builder(b"A" * 200)):
        try:
            MODULE.recover_msocf_payload(sample)
        except MODULE.MsocfPayloadError:
            continue
        raise AssertionError("invalid sample must not recover")


def test_truncated_key_instruction_fails_closed() -> None:
    assert MODULE.find_built_keys(b"prefix\x33\xc0\x40\x6b\xc0") == []


def test_payload_output_must_be_outside_repository() -> None:
    with pytest.raises(ValueError, match="repository外"):
        MODULE.outside_repository(MODULE.REPOSITORY_ROOT / "analysis-results")
