"""Unit tests for every public static-unpacker function."""

from __future__ import annotations

import io
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import zipfile

import pefile
import pytest

from unpackers import static_unpacker as unpacker


def minimal_macho() -> bytes:
    """Build a minimal little-endian Mach-O 64 header."""
    return b"\xcf\xfa\xed\xfe" + struct.pack("<IIIIIII", 0x01000007, 3, 2, 0, 0, 0, 0)


def test_hash_entropy_format_and_names() -> None:
    """Cover common primitives and traversal rejection."""
    assert len(unpacker.sha256_bytes(b"x")) == 64
    assert unpacker.entropy(b"\0" * 100) == 0
    assert unpacker.detect_format(minimal_macho(), "x") == "macho"
    assert unpacker.detect_format(b"7z\xbc\xaf'\x1c", "x") == "7z"
    assert unpacker.detect_format(b"Rar!\x1a\x07\x01\x00", "x") == "rar"
    assert unpacker.detect_format(b"var x = 1", "x.js") == "script"
    assert unpacker.detect_format("// loader".encode("utf-16"), "x") == "script"
    assert unpacker.safe_member_name("a/b") == "a/b"
    with pytest.raises(ValueError):
        unpacker.safe_member_name("../x")


def test_macho_and_encoded_blob() -> None:
    """Parse Mach-O metadata and recover only meaningful script base64."""
    assert unpacker.macho_summary(minimal_macho())["kind"] == "macho64"
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("payload.js", b"var x = 1")
    encoded = __import__("base64").b64encode(stream.getvalue())
    blobs = unpacker.recover_encoded_blobs(b"x='" + encoded + b"'")
    assert blobs == [("base64-zip", stream.getvalue())]
    noise = __import__("base64").b64encode(b"MZ" + b"A" * 256)
    assert unpacker.recover_encoded_blobs(b"x='" + noise + b"'") == []


def test_chunked_echo_base64_reassembly() -> None:
    """Reassemble a CMD payload emitted in Base64 chunks to one target."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("payload.js", b"var payload = true")
    encoded = __import__("base64").b64encode(stream.getvalue()).decode()
    split = max(128, len(encoded) // 2)
    split -= split % 4
    first, second = encoded[:split], encoded[split:]
    script = (
        f"echo {first} > %TEMPBASE64%\r\n"
        f"echo {second} >> %TEMPBASE64%\r\n"
        "certutil -decode %TEMPBASE64% %TEMPEXE%\r\n"
    ).encode()
    assert unpacker.recover_encoded_blobs(script) == [
        ("base64-echo-reassembled-zip", stream.getvalue())
    ]


def test_zip_recovery_and_write(tmp_path: Path) -> None:
    """Recover recognized ZIP members and encrypt output artifacts."""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("payload.js", b"var x = 1")
    inventory, artifacts = unpacker.recover_zip(stream.getvalue())
    assert inventory[0]["format"] == "script" and artifacts
    blocked = io.BytesIO()
    with zipfile.ZipFile(blocked, "w") as archive:
        for index in range(513):
            archive.writestr(f"{index}.txt", b"x")
    report, recovered = unpacker.unpack_bytes(blocked.getvalue(), "large.zip")
    assert report["zip"][0]["status"] == "member_limit_applied" and recovered == []
    destination = tmp_path / "artifacts.zip"
    unpacker.write_artifacts(destination, artifacts)
    assert zipfile.is_zipfile(destination)


def test_valid_pe_carving_and_cab_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Validate bounded PE carving and CAB recognition without a real sample."""
    fake = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(NumberOfSections=1),
        OPTIONAL_HEADER=SimpleNamespace(
            SizeOfHeaders=0x200,
            DATA_DIRECTORY=[
                SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(16)
            ],
        ),
        sections=[SimpleNamespace(PointerToRawData=0x200, SizeOfRawData=0x200)],
    )
    monkeypatch.setattr(unpacker.pefile, "PE", lambda **_: fake)
    payload = b"X" * 32 + b"MZ" + b"A" * 0x3FE
    assert unpacker.valid_pe_extent(payload, 32) == 0x400
    carved = unpacker.carve_embedded_pes(payload)
    assert len(carved) == 1 and len(carved[0][1]) == 0x400
    assert unpacker.detect_format(b"MSCF" + b"X" * 32, "x") == "cab"
    assert unpacker.detect_format(b"opaque", "payload.a3x") == "autoit-a3x"
    autoit, scripts = unpacker.recover_autoit_script(b"invalid a3x")
    assert autoit["status"] in {"decompile_failed", "invalid_or_oversized_output"}
    assert scripts == []


def test_split_reassembly_and_external_extract_preflight(tmp_path: Path) -> None:
    """Reassemble validated split payloads and reject a missing 7-Zip binary."""
    manifest = {
        "file_name": "payload.exe",
        "file_size": 6,
        "parts": [
            {"original_name": "a.part", "size": 2, "start": 0, "end": 1},
            {"original_name": "b.part", "size": 4, "start": 2, "end": 5},
        ],
    }
    reports, artifacts = unpacker.reassemble_split_parts(
        {
            "data/file_info.json": json.dumps(manifest).encode(),
            "data/a.part": b"MZ",
            "data/b.part": b"1234",
        }
    )
    assert reports[0]["status"] == "reassembled"
    assert artifacts[0][1] == b"MZ1234"
    report, recovered = unpacker.sevenzip_extract(b"7z", tmp_path / "missing.exe")
    assert report["status"] == "unavailable" and recovered == []


def test_autoit_xor_and_rc4_lznt1_recovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Recover a synthetic PE-shaped AutoIt RC4 then LZNT1 payload."""
    from Cryptodome.Cipher import ARC4
    from refinery.units.compression.lznt1 import lznt1

    assert unpacker.decode_autoit_xor_literals(b'F("0x292E", "A")') == ["ho"]
    payload = b"MZ" + b"P" * 1022
    compressed = bytes(lznt1().reverse(payload))
    key = b"fixture-key"
    ciphertext = ARC4.new(key).encrypt(compressed)
    wrapping_key = b"Z"
    encoded_key = bytes(value ^ wrapping_key[0] for value in key)
    script = (
        f'$PAYLOAD = "0x{ciphertext.hex()}"\n'
        f'OUTER(INNER(Binary($PAYLOAD), Binary(DECODE("0x{encoded_key.hex()}", "Z"))))'
    ).encode()
    monkeypatch.setattr(unpacker, "valid_pe_extent", lambda *_: len(payload))
    reports, artifacts = unpacker.recover_autoit_rc4_lznt1(script)
    assert reports[0]["status"] == "pe_recovered"
    assert artifacts[0][1] == payload


def test_dotnet_bitmap_payload_recovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Mirror column-major Bitmap.GetPixel extraction from a ResourceSet entry."""
    pixel = bytes((0x41, 0x5A, 0x4D, 0xFF))  # BGRA becomes RGB ``MZA``.
    header = bytearray(54)
    header[:2] = b"BM"
    struct.pack_into("<I", header, 2, 58)
    struct.pack_into("<I", header, 10, 54)
    struct.pack_into("<I", header, 14, 40)
    struct.pack_into("<ii", header, 18, 1, 1)
    struct.pack_into("<HH", header, 26, 1, 32)
    entry = SimpleNamespace(
        name="payload",
        type_name="System.Drawing.Bitmap",
        struct=SimpleNamespace(DataOffset=0),
    )
    resource_set = SimpleNamespace(
        entries=[entry],
        struct=SimpleNamespace(DataSectionOffset=0),
        _data=b"\x40" + bytes(header) + pixel,
    )
    monkeypatch.setattr(unpacker, "valid_pe_extent", lambda *_: 3)
    report, artifacts = unpacker.recover_dotnet_bitmap_payloads(resource_set)
    assert report["status"] == "pe_recovered"
    assert artifacts == [("dotnet-bitmap-rgb-pe", b"MZA")]


def test_pe_summary_and_external_preflight(tmp_path: Path) -> None:
    """Reject non-PE bytes and report unavailable external tools."""
    with pytest.raises(pefile.PEFormatError):
        unpacker.pe_summary(b"MZbad")
    malformed, malformed_artifacts = unpacker.unpack_bytes(b"MZbad", "bad.exe")
    assert malformed["unpack_status"] == "corrupt_or_truncated"
    assert malformed_artifacts == []
    dotnet, recovered = unpacker.recover_dotnet_resources(b"MZbad")
    assert dotnet["status"] == "parse_failed" and recovered == []
    assert (
        unpacker.run_upx(b"MZbad", tmp_path / "missing.exe")[0]["status"]
        == "unavailable"
    )
    assert (
        unpacker.run_die(b"MZbad", tmp_path / "missing.exe")["status"] == "unavailable"
    )
    assert (
        unpacker.sevenzip_inventory(b"7z", tmp_path / "missing.exe")["status"]
        == "unavailable"
    )


def test_unpack_and_cli(tmp_path: Path) -> None:
    """Exercise orchestration, parser, and CLI output."""
    source = tmp_path / "sample.osascript"
    source.write_bytes(b'tell application "Finder"')
    report, artifacts = unpacker.unpack_bytes(source.read_bytes(), source.name)
    assert report["format"] == "script" and artifacts == []
    output = tmp_path / "report.json"
    args = ["--input", str(source), "--output", str(output)]
    assert unpacker.build_parser().parse_args(args).input == source
    assert unpacker.main(args) == 0
    assert json.loads(output.read_text())["executed"] is False
