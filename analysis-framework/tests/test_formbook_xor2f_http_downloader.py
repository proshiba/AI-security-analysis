"""x64 XOR-0x2f HTTP downloader routeのfail-closed動作を検証する。"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

import pytest

FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
for trusted in (FRAMEWORK, COMMON):
    if str(trusted) not in sys.path:
        sys.path.insert(0, str(trusted))

from unpackers.static_unpacker import unpack_bytes

from malware.formbook_loader import extract_config as facade
from malware.formbook_loader.xor2f_http_downloader import (
    AES_INVERSE_SBOX_PREFIX,
    AES_SBOX_PREFIX,
    PNG_SIGNATURE,
    Xor2fDownloaderError,
    Xor2fDownloaderNoEvidence,
    recover_xor2f_http_downloader,
    recover_xor2f_png_payload,
)

SECTION_RVA = 0x1000
SECTION_RAW_OFFSET = 0x200
SECTION_SIZE = 0x2000


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) & ~(alignment - 1)


def _wide_xor2f(value: str) -> bytes:
    return b"".join(bytes((byte ^ 0x2F, 0)) for byte in value.encode("ascii")) + b"\x2f\x00"


def _minimal_x64_pe(
    *,
    url: str = "https://updates.example.test/payload.png?token=private#anchor",
    key: bytes = b"H1OX2WsqMLPKvGkQ",
    target: str = r"C:\Program Files\Image Viewer\viewer.exe",
    extra_url: str | None = None,
    extra_key: bytes | None = None,
    duplicate_iv: bool = False,
    include_xor_marker: bool = True,
    include_cbc_marker: bool = True,
    include_url_references: bool = True,
    machine: int = 0x8664,
) -> bytes:
    section = bytearray(SECTION_SIZE)
    blobs: list[tuple[str, int, bytes]] = []
    cursor = 0x800

    def place(role: str, value: bytes) -> int:
        nonlocal cursor
        cursor = _align(cursor, 16)
        offset = cursor
        section[offset : offset + len(value)] = value
        blobs.append((role, offset, value))
        cursor += len(value) + 16
        return offset

    place("url", _wide_xor2f(url))
    place("key", bytes(value ^ 0x2F for value in key) + b"\x2f")
    place("iv", key)
    place("target", target.encode("utf-16le") + b"\x00\x00")
    if extra_url is not None:
        place("url", _wide_xor2f(extra_url))
    if extra_key is not None:
        place("key", bytes(value ^ 0x2F for value in extra_key) + b"\x2f")
    if duplicate_iv:
        place("iv", key)

    code = bytearray()
    if include_xor_marker:
        code += b"\x83\xf0\x2f"
    if include_cbc_marker:
        code += bytes.fromhex(
            "0f1006"
            "0f1107"
            "e800000000"
            "488d91b0000000"
            "e800000000"
            "0f1007"
            "0f1181b0000000"
            "4883c610"
        )
    code += AES_SBOX_PREFIX
    code += AES_INVERSE_SBOX_PREFIX
    code += bytes.fromhex("0fb7003d0b020000")
    code += bytes.fromhex(
        "c744243800000000"
        "c74424300c040808"
        "48c744242000000000"
    )

    def add_reference(target_rva: int, width: int) -> None:
        source_rva = SECTION_RVA + len(code)
        if width == 16:
            prefix = b"\x0f\x10\x05"
            length = 7
        elif width == 1:
            prefix = b"\x8a\x05"
            length = 6
        else:
            raise AssertionError("unsupported synthetic RIP read width")
        code.extend(prefix)
        code.extend(struct.pack("<i", target_rva - (source_rva + length)))

    for role, offset, value in blobs:
        if role == "url" and not include_url_references:
            continue
        if role == "key":
            add_reference(SECTION_RVA + offset, 16)
            add_reference(SECTION_RVA + offset + 16, 1)
            continue
        for chunk in range(0, len(value), 16):
            add_reference(SECTION_RVA + offset + chunk, 16)
    section[: len(code)] = code

    headers = bytearray(SECTION_RAW_OFFSET)
    headers[:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", headers, 0x84, machine, 1, 0, 0, 0, 0xF0, 0x2022)
    optional = 0x98
    struct.pack_into("<H", headers, optional, 0x20B)
    struct.pack_into("<I", headers, optional + 4, SECTION_SIZE)
    struct.pack_into("<I", headers, optional + 16, SECTION_RVA)
    struct.pack_into("<I", headers, optional + 20, SECTION_RVA)
    struct.pack_into("<Q", headers, optional + 24, 0x140000000)
    struct.pack_into("<II", headers, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", headers, optional + 56, 0x4000, SECTION_RAW_OFFSET)
    struct.pack_into("<H", headers, optional + 68, 3)
    struct.pack_into("<I", headers, optional + 108, 16)
    section_header = optional + 0xF0
    headers[section_header : section_header + 8] = b".text\x00\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        headers,
        section_header + 8,
        SECTION_SIZE,
        SECTION_RVA,
        SECTION_SIZE,
        SECTION_RAW_OFFSET,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    return bytes(headers + section)


def _minimal_payload_pe() -> bytes:
    """entrypointが実行section内にある非実行用の最小PE32を作る。"""

    headers = bytearray(0x200)
    section = bytearray(0x200)
    section[0] = 0xC3
    headers[:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x80)
    headers[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", headers, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", headers, optional, 0x10B)
    struct.pack_into("<I", headers, optional + 4, 0x200)
    struct.pack_into("<I", headers, optional + 16, 0x1000)
    struct.pack_into("<II", headers, optional + 20, 0x1000, 0x2000)
    struct.pack_into("<I", headers, optional + 28, 0x400000)
    struct.pack_into("<II", headers, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", headers, optional + 56, 0x2000, 0x200)
    struct.pack_into("<H", headers, optional + 68, 3)
    struct.pack_into("<I", headers, optional + 92, 16)
    section_header = optional + 0xE0
    headers[section_header : section_header + 8] = b".text\x00\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        headers,
        section_header + 8,
        1,
        0x1000,
        0x200,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    return bytes(headers + section)


def _aes_cbc_encrypt(data: bytes, key: bytes) -> bytes:
    """合成fixtureだけを既存cryptographyでAES-CBC暗号化する。"""

    ciphers = pytest.importorskip("cryptography.hazmat.primitives.ciphers")
    encryptor = ciphers.Cipher(
        ciphers.algorithms.AES(key), ciphers.modes.CBC(key)
    ).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _rtf_package(payload: bytes) -> bytes:
    def ole_string(value: bytes) -> bytes:
        raw = value + b"\x00" if value else b""
        return struct.pack("<I", len(raw)) + raw

    temp_path = b"C:\\Temp\\invoice.pdf\x00"
    native = (
        struct.pack("<H", 2)
        + b"invoice.pdf\x00"
        + b"C:\\fake\\invoice.pdf\x00"
        + b"\x00" * 4
        + struct.pack("<I", len(temp_path))
        + temp_path
        + struct.pack("<I", len(payload))
        + payload
    )
    ole = (
        struct.pack("<II", 0x501, 2)
        + ole_string(b"Package")
        + ole_string(b"")
        + ole_string(b"")
        + struct.pack("<I", len(native))
        + native
    )
    return b"{\\rtf1{\\object{\\*\\objdata " + ole.hex().encode("ascii") + b"}}}"


def test_recovers_sanitized_stage_and_route_only_facade_result() -> None:
    key = b"H1OX2WsqMLPKvGkQ"
    data = _minimal_x64_pe(key=key)

    recovered = recover_xor2f_http_downloader(data)
    result = facade.extract_config(data)
    rendered = json.dumps(result, ensure_ascii=False)

    assert recovered["status"] == "matched"
    assert recovered["urls"] == [
        {
            "url": "https://updates.example.test/payload.png",
            "role": "encrypted_payload_stage",
            "query_present": True,
            "fragment_removed": True,
        }
    ]
    assert recovered["crypto"]["candidate_key_sha256"] == hashlib.sha256(key).hexdigest()
    assert recovered["crypto"]["key_material_exported"] is False
    assert recovered["crypto"]["mode"] == "CBC"
    assert recovered["crypto"]["iv_source"] == "loader_constant_equal_to_decoded_key"
    assert key.decode("ascii") not in rendered
    assert "private" not in rendered
    assert result["variant"] == "x64_xor2f_aes_png_downloader"
    assert result["supports_family_attribution"] is False
    assert result["terminal_payload_recovered"] is False
    assert result["c2"] == []
    assert result["process_hollowing"]["status"] == "statically_indicated"


def test_recovers_hash_independent_aes_cbc_pe_payload() -> None:
    """異なるkeyとURLでもoffset 0のAES-CBC ciphertextからPEを復元する。"""

    key = b"Q7mN2xR4vB8kL5pZ"
    loader = _minimal_x64_pe(
        url="https://cdn.example.test/new/path/stage.png", key=key
    )
    payload = _minimal_payload_pe()
    encrypted = _aes_cbc_encrypt(payload, key)

    report, artifacts = recover_xor2f_png_payload(loader, encrypted)
    rendered = json.dumps(report, ensure_ascii=False)

    assert report["status"] == "payload_recovered"
    assert report["crypto"]["algorithm"] == "AES-128"
    assert report["crypto"]["mode"] == "CBC"
    assert report["encrypted_stage"]["ciphertext_offset"] == 0
    assert report["encrypted_stage"]["png_signature_present"] is False
    assert report["payload"]["architecture"] == "x86"
    assert report["payload"]["sha256"] == hashlib.sha256(payload).hexdigest()
    assert key.decode("ascii") not in rendered
    assert artifacts == [("xor2f-aes-cbc-decrypted-pe", payload)]


def test_corrupted_ciphertext_is_rejected_without_artifact() -> None:
    """AES block境界でも復号後PEが不正ならartifactを返さない。"""

    key = b"Q7mN2xR4vB8kL5pZ"
    encrypted = bytearray(_aes_cbc_encrypt(_minimal_payload_pe(), key))
    encrypted[0] ^= 0x80

    with pytest.raises(Xor2fDownloaderNoEvidence, match="復号結果"):
        recover_xor2f_png_payload(_minimal_x64_pe(key=key), bytes(encrypted))


def test_real_png_envelope_conflicts_with_offset_zero_dataflow() -> None:
    """実PNG signatureを持つ入力をtrailer推測で復号しない。"""

    stage = PNG_SIGNATURE + bytes(0x200 - len(PNG_SIGNATURE))
    with pytest.raises(Xor2fDownloaderError, match="offset 0"):
        recover_xor2f_png_payload(_minimal_x64_pe(), stage)


def test_payload_recovery_fails_on_ambiguous_key_material() -> None:
    """参照済みkey候補が複数なら復号成功を推測しない。"""

    key = b"Q7mN2xR4vB8kL5pZ"
    stage = _aes_cbc_encrypt(_minimal_payload_pe(), key)
    loader = _minimal_x64_pe(key=key, extra_key=b"R4Nd0mKeyValue9Q")
    with pytest.raises(Xor2fDownloaderError, match="16-byte素材が一意ではありません"):
        recover_xor2f_png_payload(loader, stage)


def test_payload_recovery_fails_on_ambiguous_iv_reference() -> None:
    """同じIV素材への独立参照が複数ある場合も推測しない。"""

    key = b"Q7mN2xR4vB8kL5pZ"
    stage = _aes_cbc_encrypt(_minimal_payload_pe(), key)
    loader = _minimal_x64_pe(key=key, duplicate_iv=True)
    with pytest.raises(Xor2fDownloaderError, match="IV参照が一意ではありません"):
        recover_xor2f_png_payload(loader, stage)


def test_missing_xor_marker_is_no_evidence() -> None:
    with pytest.raises(Xor2fDownloaderNoEvidence):
        recover_xor2f_http_downloader(_minimal_x64_pe(include_xor_marker=False))


def test_missing_cbc_structure_is_no_evidence() -> None:
    """AES tableとkeyがあってもCBC chaining構造なしでは採用しない。"""

    with pytest.raises(Xor2fDownloaderNoEvidence, match="CBC decrypt loop"):
        recover_xor2f_http_downloader(_minimal_x64_pe(include_cbc_marker=False))


def test_two_referenced_urls_fail_closed() -> None:
    data = _minimal_x64_pe(extra_url="https://cdn.example.test/second.png")
    with pytest.raises(Xor2fDownloaderError, match="URLが一意ではありません"):
        recover_xor2f_http_downloader(data)


def test_two_referenced_key_materials_fail_closed() -> None:
    data = _minimal_x64_pe(extra_key=b"R4Nd0mKeyValue9Q")
    with pytest.raises(Xor2fDownloaderError, match="16-byte素材が一意ではありません"):
        recover_xor2f_http_downloader(data)


def test_userinfo_url_is_rejected() -> None:
    data = _minimal_x64_pe(url="https://name:secret@updates.example.test/payload.png")
    with pytest.raises(Xor2fDownloaderNoEvidence):
        recover_xor2f_http_downloader(data)


def test_unreferenced_url_is_not_guessed() -> None:
    data = _minimal_x64_pe(include_url_references=False)
    with pytest.raises(Xor2fDownloaderNoEvidence):
        recover_xor2f_http_downloader(data)


def test_non_x64_pe_is_not_routed() -> None:
    data = _minimal_x64_pe(machine=0x14C)
    with pytest.raises(Xor2fDownloaderNoEvidence):
        recover_xor2f_http_downloader(data)


def test_standard_unpacker_hands_rtf_embedded_dll_to_facade() -> None:
    child = _minimal_x64_pe()
    report, artifacts = unpack_bytes(_rtf_package(child), "invoice.rtf")

    assert report["format"] == "rtf"
    assert report["rtf_objdata"]["status"] == "artifacts_recovered"
    recovered = next(
        blob for kind, blob in artifacts if kind == "rtf-ole1-package-payload"
    )
    assert hashlib.sha256(recovered).digest() == hashlib.sha256(child).digest()
    result = facade.extract_config(recovered)
    assert result["variant"] == "x64_xor2f_aes_png_downloader"
    assert result["terminal_payload_recovered"] is False
