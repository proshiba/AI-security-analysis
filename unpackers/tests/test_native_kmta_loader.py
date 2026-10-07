from __future__ import annotations

import struct

from Cryptodome.Cipher import AES

from unpackers.native_kmta_loader import recover_native_kmta_payload

_IMAGE_BASE = 0x140000000
_KEY = bytes(range(32))
_IV = bytes(range(32, 48))


def _put_section(
    image: bytearray,
    offset: int,
    name: bytes,
    *,
    virtual_size: int,
    virtual_address: int,
    raw_size: int,
    raw_offset: int,
    characteristics: int,
) -> None:
    struct.pack_into(
        "<8sIIIIIIHHI",
        image,
        offset,
        name.ljust(8, b"\0"),
        virtual_size,
        virtual_address,
        raw_size,
        raw_offset,
        0,
        0,
        0,
        0,
        characteristics,
    )


def _pe64_headers(
    *,
    section_count: int,
    size_of_code: int,
    size_of_initialized_data: int,
    size_of_image: int,
    export_rva: int = 0,
    export_size: int = 0,
    machine: int = 0x8664,
) -> bytearray:
    image = bytearray(0x200)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into(
        "<HHIIIHH",
        image,
        0x84,
        machine,
        section_count,
        0,
        0,
        0,
        0xF0,
        0x2022,
    )
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x20B)
    struct.pack_into("<I", image, optional + 4, size_of_code)
    struct.pack_into("<I", image, optional + 8, size_of_initialized_data)
    struct.pack_into("<I", image, optional + 16, 0x1000)
    struct.pack_into("<I", image, optional + 20, 0x1000)
    struct.pack_into("<Q", image, optional + 24, _IMAGE_BASE)
    struct.pack_into("<II", image, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", image, optional + 56, size_of_image)
    struct.pack_into("<I", image, optional + 60, 0x200)
    struct.pack_into("<H", image, optional + 68, 3)
    struct.pack_into("<H", image, optional + 70, 0x8160)
    struct.pack_into("<Q", image, optional + 72, 0x100000)
    struct.pack_into("<Q", image, optional + 80, 0x1000)
    struct.pack_into("<Q", image, optional + 88, 0x100000)
    struct.pack_into("<Q", image, optional + 96, 0x1000)
    struct.pack_into("<I", image, optional + 108, 16)
    struct.pack_into("<II", image, optional + 112, export_rva, export_size)
    return image


def _child_pe(*, machine: int = 0x8664, trailing: bytes = b"") -> bytes:
    image = _pe64_headers(
        section_count=1,
        size_of_code=0x200,
        size_of_initialized_data=0,
        size_of_image=0x2000,
        machine=machine,
    )
    _put_section(
        image,
        0x188,
        b".text",
        virtual_size=1,
        virtual_address=0x1000,
        raw_size=0x200,
        raw_offset=0x200,
        characteristics=0x60000020,
    )
    image.extend(b"\xC3" + b"\0" * 0x1FF)
    return bytes(image) + trailing


def _loader(*, omit_reference: int | None = None) -> bytes:
    image = _pe64_headers(
        section_count=2,
        size_of_code=0x600,
        size_of_initialized_data=0x600,
        size_of_image=0x3000,
        export_rva=0x2000,
        export_size=0x100,
    )
    _put_section(
        image,
        0x188,
        b".text",
        virtual_size=0x600,
        virtual_address=0x1000,
        raw_size=0x600,
        raw_offset=0x200,
        characteristics=0x60000020,
    )
    _put_section(
        image,
        0x1B0,
        b".rdata",
        virtual_size=0x600,
        virtual_address=0x2000,
        raw_size=0x600,
        raw_offset=0x800,
        characteristics=0x40000040,
    )
    image.extend(b"\0" * 0xC00)

    code = bytearray()
    for index in range(48):
        instruction_rva = 0x1000 + len(code)
        if index == omit_reference:
            code.extend(b"\x90" * 6)
            continue
        displacement = 0x2100 + index - (instruction_rva + 6)
        code.extend(b"\x8A\x05" + struct.pack("<i", displacement))
    code.extend(b"\x81\x3F\x4B\x4D\x54\x41\xC3")
    image[0x200 : 0x200 + len(code)] = code

    rdata = 0x800
    struct.pack_into(
        "<IIHHIIIIIII",
        image,
        rdata,
        0,
        0,
        0,
        0,
        0x2050,
        1,
        1,
        1,
        0x2060,
        0x2064,
        0x2068,
    )
    image[rdata + 0x50 : rdata + 0x5B] = b"loader.dll\0"
    struct.pack_into("<I", image, rdata + 0x60, 0x1000)
    struct.pack_into("<I", image, rdata + 0x64, 0x2070)
    struct.pack_into("<H", image, rdata + 0x68, 0)
    image[rdata + 0x70 : rdata + 0x77] = b"Decode\0"
    image[rdata + 0x100 : rdata + 0x130] = _KEY + _IV
    return bytes(image)


def _ciphertext(
    *,
    child: bytes | None = None,
    ansi_path: bytes = b"C:\\stage.exe\0",
    wide_text: str = "C:\\stage.exe",
) -> bytes:
    payload = _child_pe() if child is None else child
    wide_path = (wide_text + "\0").encode("utf-16le")
    header_size = 0x28 + len(ansi_path) + len(wide_path)
    plaintext = (
        struct.pack(
            "<4sIQQQII",
            b"KMTA",
            header_size,
            _IMAGE_BASE,
            0x2000,
            0,
            len(ansi_path),
            len(wide_path),
        )
        + ansi_path
        + wide_path
        + payload
    )
    padding = 16 - len(plaintext) % 16
    return AES.new(_KEY, AES.MODE_CBC, _IV).encrypt(
        plaintext + bytes([padding]) * padding
    )


def test_recovers_exact_x64_pe_from_referenced_key_material() -> None:
    child = _child_pe()

    report, recovered = recover_native_kmta_payload(_loader(), _ciphertext(child=child))

    assert report["status"] == "pe_recovered"
    assert report["referenced_key_iv_candidates"] == 1
    assert report["candidate_recipe_matches"] == 1
    assert report["kmta"]["decoded_size"] == len(child)
    assert report["executed"] is False
    assert report["emulated"] is False
    assert report["network_contacted"] is False
    assert recovered == child


def test_rejects_material_without_one_contiguous_48_byte_reference_run() -> None:
    report, recovered = recover_native_kmta_payload(
        _loader(omit_reference=23), _ciphertext()
    )

    assert report["status"] == "loader_profile_not_found"
    assert recovered is None


def test_rejects_tampered_pkcs7_ciphertext() -> None:
    ciphertext = bytearray(_ciphertext())
    ciphertext[-1] ^= 0x80

    report, recovered = recover_native_kmta_payload(_loader(), bytes(ciphertext))

    assert report["status"] == "payload_validation_failed"
    assert recovered is None


def test_rejects_child_with_unvalidated_trailing_data() -> None:
    report, recovered = recover_native_kmta_payload(
        _loader(), _ciphertext(child=_child_pe(trailing=b"unvalidated"))
    )

    assert report["status"] == "payload_validation_failed"
    assert recovered is None


def test_rejects_non_x64_child_even_with_matching_kmta_sizes() -> None:
    report, recovered = recover_native_kmta_payload(
        _loader(), _ciphertext(child=_child_pe(machine=0x14C))
    )

    assert report["status"] == "payload_validation_failed"
    assert recovered is None


def test_rejects_disagreeing_ansi_and_utf16_paths() -> None:
    report, recovered = recover_native_kmta_payload(
        _loader(), _ciphertext(wide_text="C:\\different.exe")
    )

    assert report["status"] == "payload_validation_failed"
    assert recovered is None
