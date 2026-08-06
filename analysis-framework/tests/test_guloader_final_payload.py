"""GuLoader暗号化後段の反復XOR検証テスト。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest


GULOADER = Path(__file__).parents[1] / "malware" / "guloader"
if str(GULOADER) not in sys.path:
    sys.path.insert(0, str(GULOADER))

import final_payload  # noqa: E402


def synthetic_pe(size: int = 4096) -> bytes:
    data = bytearray((index * 29 + 17) & 0xFF for index in range(size))
    data[:2] = b"MZ"
    data[0x3C:0x40] = (0x80).to_bytes(4, "little")
    data[0x80:0x84] = b"PE\0\0"
    data[0x84:0x86] = (0x14C).to_bytes(2, "little")
    data[0x86:0x88] = (1).to_bytes(2, "little")
    data[0x94:0x96] = (0xE0).to_bytes(2, "little")
    data[0x98:0x9A] = (0x10B).to_bytes(2, "little")
    return bytes(data)


def encrypt(plaintext: bytes, key: bytes, prefix: bytes) -> bytes:
    return prefix + bytes(value ^ key[index % len(key)] for index, value in enumerate(plaintext))


def test_exact_repeating_xor_recovery_with_partial_final_period() -> None:
    plaintext = synthetic_pe(4097)
    key = bytes((index * 13 + 7) & 0xFF for index in range(37))
    encrypted = encrypt(plaintext, key, bytes(range(64)))
    recovery = final_payload.derive_recovery(encrypted, plaintext)
    assert recovery.plaintext == plaintext
    assert recovery.key == key
    report = final_payload.build_report(encrypted, plaintext, recovery)
    assert report["status"] == "exact_match"
    assert report["xor"]["key_length"] == len(key)
    assert report["xor"]["key_sha256"] == hashlib.sha256(key).hexdigest()
    assert "key" not in report["xor"]
    assert report["recovered_payload"]["architecture"] == "x86"


def test_recovery_rejects_size_mismatch() -> None:
    plaintext = synthetic_pe()
    encrypted = encrypt(plaintext, b"sample-key", b"X" * 64)
    with pytest.raises(final_payload.FinalPayloadError, match="長さが一致"):
        final_payload.derive_recovery(encrypted[:-1], plaintext)


def test_recovery_rejects_non_pe_plaintext() -> None:
    plaintext = b"A" * 4096
    encrypted = encrypt(plaintext, b"sample-key", b"X" * 64)
    with pytest.raises(final_payload.FinalPayloadError, match="MZ"):
        final_payload.derive_recovery(encrypted, plaintext)


def test_cli_writes_exact_payload_and_report(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    plaintext = synthetic_pe(8193)
    key = bytes((index * 7 + 3) & 0xFF for index in range(53))
    encrypted = encrypt(plaintext, key, b"P" * 64)
    encrypted_path = tmp_path / "encrypted.bin"
    plaintext_path = tmp_path / "known.exe"
    output_path = tmp_path / "recovered.exe"
    report_path = tmp_path / "report.json"
    encrypted_path.write_bytes(encrypted)
    plaintext_path.write_bytes(plaintext)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "final_payload.py",
            "--encrypted",
            str(encrypted_path),
            "--known-plaintext",
            str(plaintext_path),
            "--output",
            str(output_path),
            "--report",
            str(report_path),
        ],
    )
    assert final_payload.main() == 0
    assert output_path.read_bytes() == plaintext
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["recovered_payload"]["sha256"] == hashlib.sha256(plaintext).hexdigest()
    assert report["safety"]["sample_executed"] is False
