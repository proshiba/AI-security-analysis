"""PowerShell回転XOR復元器の安全境界を検証する。"""

from __future__ import annotations

import base64
import hashlib

import pytest

from unpackers import powershell_rotational_xor as rotational_xor
from unpackers.powershell_rotational_xor import (
    MAX_INPUT_SIZE,
    recover_powershell_rotational_xor,
)


def _encrypt(clear: bytes, key: bytes) -> bytes:
    output = bytearray(len(clear))
    rotation = 0
    for position, value in enumerate(clear):
        key_position = (position + rotation) % len(key)
        output[position] = value ^ key[key_position]
        rotation = (rotation + key[key_position]) % 7
    return bytes(output)


def _fixture(clear: bytes, key: bytes, *, modulus: int = 7) -> bytes:
    encrypted = base64.b64encode(_encrypt(clear, key)).decode()
    encoded_key = base64.b64encode(key).decode()
    return f"""
$securemessage = @'
{encrypted}
'@
$cryptorotation = @'
{encoded_key}
'@
$keyPosition = ($bytePosition + $rotationCounter) % $cryptoKey.Length
$resultBuffer[$bytePosition] = $encryptedData[$bytePosition] -bxor $cryptoKey[$keyPosition]
$rotationCounter = ($rotationCounter + $cryptoKey[$keyPosition]) % {modulus}
""".encode()


def test_recovers_reviewed_mod7_script_without_publishing_key() -> None:
    clear = b"# fixture\n$answer = 42\nWrite-Output $answer\n" * 12
    key = bytes(range(32))
    recovery = recover_powershell_rotational_xor(_fixture(clear, key))
    assert recovery.script == clear
    assert recovery.report["status"] == "script_recovered"
    assert recovery.report["key_sha256"] == hashlib.sha256(key).hexdigest()
    assert recovery.report["raw_key_published"] is False
    assert key.hex() not in str(recovery.report)
    assert recovery.report["family_attribution_allowed"] is False
    assert recovery.report["terminal_promotion_eligible"] is False


def test_rejects_unreviewed_modulus_and_non_script_output() -> None:
    key = b"K" * 32
    assert (
        recover_powershell_rotational_xor(
            _fixture(b"# valid shape\n" * 32, key, modulus=9)
        ).script
        is None
    )
    binary = b"\x00\x01\x02\x03" * 128
    assert recover_powershell_rotational_xor(_fixture(binary, key)).script is None


def test_rejects_ambiguous_pairs_and_oversized_input() -> None:
    clear = b"# fixture\n$x = 1\n" * 32
    key = b"A" * 32
    first = _fixture(clear, key)
    duplicate = first.replace(
        b"$cryptorotation = @'",
        b"$secondkey = @'\n" + base64.b64encode(key) + b"\n'@\n$cryptorotation = @'",
        1,
    )
    assert recover_powershell_rotational_xor(duplicate).script is None
    rejected = recover_powershell_rotational_xor(b"A" * (MAX_INPUT_SIZE + 1))
    assert rejected.report["status"] == "input_size_rejected"


def test_rejects_key_cross_product_above_total_work_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """候補件数が少なくてもkey×ciphertextの総復号量をhard limitで止める。"""

    clear = b"# fixture\n$x = 1\n" * 32
    key = b"A" * 32
    monkeypatch.setattr(rotational_xor, "MAX_DECRYPT_WORK_BYTES", len(clear) - 1)

    recovery = rotational_xor.recover_powershell_rotational_xor(_fixture(clear, key))

    assert recovery.script is None
    assert recovery.report["status"] == "decrypt_work_limit_exceeded"
    assert recovery.report["candidate_count"] == 0


def test_rejects_excess_unterminated_here_string_openers_before_body_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """未終端openerを大量に置いた入力を全suffix探索する前に拒否する。"""

    monkeypatch.setattr(rotational_xor, "MAX_HERE_STRINGS", 2)
    data = b"""
$one = @'
$two = @'
$three = @'
$keyPosition = ($bytePosition + $rotationCounter) % $cryptoKey.Length
$resultBuffer[$bytePosition] = $encryptedData[$bytePosition] -bxor $cryptoKey[$keyPosition]
$rotationCounter = ($rotationCounter + $cryptoKey[$keyPosition]) % 7
"""

    recovery = rotational_xor.recover_powershell_rotational_xor(data)

    assert recovery.script is None
    assert recovery.report["status"] == "here_string_count_rejected"
