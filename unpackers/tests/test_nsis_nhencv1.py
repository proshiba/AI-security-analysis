from __future__ import annotations

import hashlib
import hmac
import struct

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

from unpackers.nsis_nhencv1 import recover_nsis_nhencv1
from unpackers.nsis_static import NsisMember


def _member(blob: bytes, occurrence: int = 0) -> NsisMember:
    output = "$PLUGINSDIR/$R6" if occurrence == 0 else f"$PLUGINSDIR/$R6_{occurrence}"
    return NsisMember(
        archive_name="$PLUGINSDIR\\$R6",
        normalized_name="$PLUGINSDIR/$R6",
        output_name=output,
        size=len(blob),
        packed_size=None,
        crc32=None,
        encrypted=False,
        attributes="A",
    )


def _encrypted_blob(plaintext: bytes, aes_key: bytes, hmac_key: bytes) -> bytes:
    iv = bytes(range(16))
    reserved = bytes(range(16, 32))
    ciphertext = AES.new(aes_key, AES.MODE_CBC, iv=iv).encrypt(pad(plaintext, 16))
    header = (
        b"NHENCV1\0"
        + struct.pack("<HHBBHQQ", 1, 96, 1, 1, 0, len(plaintext), len(ciphertext))
        + iv
        + reserved
    )
    authentication = hmac.new(
        hmac_key, header + ciphertext, hashlib.sha256
    ).digest()
    return header + authentication + ciphertext


def _script(aes_key: bytes, hmac_key: bytes, *, complete: bool = True) -> bytes:
    def key_lines(pointer: str, key: bytes, seed: int) -> list[str]:
        lines: list[str] = []
        words = struct.unpack("<8I", key)
        masks = [seed + index for index in range(8)]
        for index, mask in enumerate(masks):
            lines.append(f"  StrCpy ${index} 0x{mask:08X}")
        for index, (word, mask) in enumerate(zip(words, masks, strict=True)):
            lines.extend(
                (
                    f"  IntOp $R0 0x{word ^ mask:08X} ^ ${index}",
                    f"  IntOp $R1 {pointer} + {index * 4}",
                    '  System::Call "*$R1(i R0)"',
                )
            )
        return lines

    markers = [
        "Function decrypt_payload",
        (
            '  System::Call "bcrypt::BCryptOpenAlgorithmProvider('
            '*p .R0, w SHA256, p 0, i 8)"'
        ),
        (
            '  System::Call "bcrypt::BCryptCreateHash('
            'p R0, *p .R2, p R1, i R6, p r4, i 32, i 0)"'
        ),
        '  System::Call "bcrypt::BCryptHashData(p R2, p r5, i 64, i 0)"',
        '  System::Call "bcrypt::BCryptFinishHash(p R2, p r7, i 32, i 0)"',
        "  IntCmp $R6 0x4E45484E ok bad bad",
        "  IntCmp $R7 0x00315643 ok bad bad",
        '  System::Call "*$5(&v16, l .R6)"',
        '  System::Call "*$5(&v24, l .R6)"',
        '  System::Call "*$5(&v32, i .R6)"',
        '  System::Call "bcrypt::BCryptOpenAlgorithmProvider(*p .R0, w AES, p 0, i 0)"',
        (
            '  System::Call "bcrypt::BCryptSetProperty('
            'p R0, w ChainingMode, w ChainingModeCBC, i 32, i 0)"'
        ),
        (
            '  System::Call "bcrypt::BCryptGenerateSymmetricKey('
            'p R0, *p .R2, p R1, i R6, p r3, i 32, i 0)"'
        ),
        (
            '  System::Call "bcrypt::BCryptDecrypt('
            'p R2, p r6, i R8, p 0, p R3, i 16, p r7, i 1048576, '
            '*i .R7, i R9)"'
        ),
        "FunctionEnd",
        "Section MainSection",
        "  StrCpy $R6 $PLUGINSDIR\\object.nhc",
        "  File $R6",
    ]
    lines = markers + key_lines("$R8", aes_key, 0x11110000)
    lines.extend(key_lines("$R9", hmac_key, 0x22220000))
    if not complete:
        lines = [line for line in lines if "$R9 + 28" not in line]
    lines.extend(
        (
            "  Push $R6",
            "  Push $APPDATA\\fixture\\payload.exe",
            "  Push $R7",
            "  Push $R8",
            "  Push $R9",
            "  Call decrypt_payload",
            "SectionEnd",
        )
    )
    return ("; NSIS script NSIS-3 Unicode\n" + "\n".join(lines)).encode()


def test_recover_nsis_nhencv1_requires_complete_lineage_and_authentication() -> None:
    aes_key = bytes(range(32))
    hmac_key = bytes(range(32, 64))
    plaintext = b"MZ" + b"P" * 100
    blob = _encrypted_blob(plaintext, aes_key, hmac_key)

    report, artifacts = recover_nsis_nhencv1(
        _script(aes_key, hmac_key),
        [(_member(blob), blob)],
        max_output_size=1024,
        max_total_size=2048,
    )

    assert report["status"] == "recovered"
    assert report["recipe_count"] == 1
    assert report["source_member_count"] == 1
    assert report["recovered_count"] == 1
    assert report["secret_material_in_report"] is False
    assert report["terminal_promotion_eligible"] is False
    assert report["entries"][0]["hmac_verified"] is True
    assert artifacts == [("nsis-nhencv1-000-pe", plaintext)]


def test_recover_nsis_nhencv1_fails_closed_on_authentication_mismatch() -> None:
    aes_key = bytes(range(32))
    hmac_key = bytes(range(32, 64))
    blob = bytearray(_encrypted_blob(b"MZfixture", aes_key, hmac_key))
    blob[-1] ^= 1

    report, artifacts = recover_nsis_nhencv1(
        _script(aes_key, hmac_key),
        [(_member(bytes(blob)), bytes(blob))],
        max_output_size=1024,
        max_total_size=2048,
    )

    assert report["status"] == "authenticated_decryption_failed"
    assert artifacts == []


def test_recover_nsis_nhencv1_rejects_incomplete_key_recipe() -> None:
    aes_key = bytes(range(32))
    hmac_key = bytes(range(32, 64))
    blob = _encrypted_blob(b"MZfixture", aes_key, hmac_key)

    report, artifacts = recover_nsis_nhencv1(
        _script(aes_key, hmac_key, complete=False),
        [(_member(blob), blob)],
        max_output_size=1024,
        max_total_size=2048,
    )

    assert report["status"] == "recipe_validation_failed"
    assert report["rejected_recipe_count"] == 1
    assert artifacts == []


def test_recover_nsis_nhencv1_rejects_duplicate_member_count_mismatch() -> None:
    aes_key = bytes(range(32))
    hmac_key = bytes(range(32, 64))
    blob = _encrypted_blob(b"MZfixture", aes_key, hmac_key)

    report, artifacts = recover_nsis_nhencv1(
        _script(aes_key, hmac_key),
        [(_member(blob), blob), (_member(blob, 1), blob)],
        max_output_size=1024,
        max_total_size=2048,
    )

    assert report["status"] == "source_member_mapping_failed"
    assert artifacts == []


def test_recover_nsis_nhencv1_is_not_applicable_without_full_transform() -> None:
    report, artifacts = recover_nsis_nhencv1(
        b"; NSIS script NSIS-3\nSection MainSection\nSectionEnd",
        [],
        max_output_size=1024,
        max_total_size=2048,
    )

    assert report["status"] == "not_applicable"
    assert report["transform_function_count"] == 0
    assert artifacts == []


def test_recover_nsis_nhencv1_enforces_plaintext_size_limit() -> None:
    aes_key = bytes(range(32))
    hmac_key = bytes(range(32, 64))
    blob = _encrypted_blob(b"MZ" + b"P" * 100, aes_key, hmac_key)

    report, artifacts = recover_nsis_nhencv1(
        _script(aes_key, hmac_key),
        [(_member(blob), blob)],
        max_output_size=64,
        max_total_size=2048,
    )

    assert report["status"] == "authenticated_decryption_failed"
    assert artifacts == []
