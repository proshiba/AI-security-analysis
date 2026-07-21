"""静的展開器の全公開関数に対する単体試験。"""

from __future__ import annotations

import io
import json
from pathlib import Path
import struct
from types import SimpleNamespace
import zipfile
import zlib

import pefile
import pytest

from unpackers import static_unpacker as unpacker


def minimal_macho() -> bytes:
    """最小のリトルエンディアンMach-O 64ヘッダーを構築する。"""
    return b"\xcf\xfa\xed\xfe" + struct.pack("<IIIIIII", 0x01000007, 3, 2, 0, 0, 0, 0)


def test_hash_entropy_format_and_names() -> None:
    """共通プリミティブとパストラバーサル拒否を試験する。"""
    assert len(unpacker.sha256_bytes(b"x")) == 64
    assert unpacker.entropy(b"\0" * 100) == 0
    assert unpacker.detect_format(minimal_macho(), "x") == "macho"
    java_class = b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 32
    assert unpacker.detect_format(java_class, "Fixture.class") == "java-class"
    assert unpacker.detect_format(b"7z\xbc\xaf'\x1c", "x") == "7z"
    assert unpacker.detect_format(b"\x7fELF" + b"\0" * 64, "x") == "elf"
    assert unpacker.detect_format(b"\x89PNG\r\n\x1a\n" + b"\0" * 16, "x.H") == "png"
    assert unpacker.detect_format(b"ER\x02\x00" + b"\0" * 28, "x") == "apple-disk-image"
    assert unpacker.detect_format(b"Rar!\x1a\x07\x01\x00", "x") == "rar"
    assert unpacker.detect_format(b"var x = 1", "x.js") == "script"
    assert unpacker.detect_format("// loader".encode("utf-16"), "x") == "script"
    assert unpacker.safe_member_name("a/b") == "a/b"
    with pytest.raises(ValueError):
        unpacker.safe_member_name("../x")


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def test_png_idat_zlib_unused_data_is_recovered_as_bounded_layer() -> None:
    """正常画像stream後のIDAT内データを公開本文ではなく復元層へ渡す。"""

    hidden = bytes(range(256)) * 32
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr)
    png += _png_chunk(b"IDAT", zlib.compress(b"\0\0\0\0") + hidden)
    png += _png_chunk(b"IEND", b"")

    report, artifacts = unpacker.unpack_bytes(png, "Nmg5t7d.H")

    assert report["format"] == "png"
    assert report["png"]["status"] == "concealed_data_recovered"
    assert report["png"]["concealed_size"] == len(hidden)
    assert report["png"]["concealed_content_in_report"] is False
    assert artifacts == [("png-idat-zlib-unused-data", hidden)]


def test_plain_png_resource_is_inspected_without_becoming_a_layer() -> None:
    """通常のPNGリソースは検査するが、次の解析層として複製しない。"""

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    png = b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", ihdr)
    png += _png_chunk(b"IDAT", zlib.compress(b"\0\0\0\0"))
    png += _png_chunk(b"IEND", b"")

    kind, children, report = unpacker.pe_resource_children(png)

    assert kind == "png"
    assert children == []
    assert report is not None
    assert report["status"] == "valid_png_no_concealed_data"


def test_repetitive_padding_detection() -> None:
    """反復PEオーバーレイと埋め込みペイロードを区別する。"""
    report = unpacker.repetitive_padding(b"pqrs" * 4096)
    assert report == {
        "period": 4,
        "pattern_hex": "70717273",
        "repetitions": 4096,
        "trailing_bytes": 0,
    }
    assert unpacker.repetitive_padding(bytes(range(256)) * 16) is None


def test_macho_and_encoded_blob() -> None:
    """Mach-Oメタデータを解析し、有意なスクリプトBase64だけを復元する。"""
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
    """1つの出力先へBase64断片として出力されたCMDペイロードを再構築する。"""
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
    """認識済みZIPメンバーを復元し、出力アーティファクトを暗号化する。"""
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
    assert report["unpack_status"] == "bounded_limit"
    destination = tmp_path / "artifacts.zip"
    unpacker.write_artifacts(destination, artifacts)
    assert zipfile.is_zipfile(destination)


def test_zip_aggregate_and_ratio_quotas_fail_closed() -> None:
    """部分アーティファクトを保持する前にアーカイブ全体を拒否する。"""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("one.js", b"12345678")
        archive.writestr("two.js", b"abcdefgh")
    data = stream.getvalue()

    inventory, artifacts = unpacker.recover_zip(data, max_members=1)
    assert inventory[0]["status"] == "member_limit_applied"
    assert artifacts == []

    inventory, artifacts = unpacker.recover_zip(data, max_total_size=15)
    assert inventory[0]["status"] == "total_size_blocked"
    assert artifacts == []

    dense = io.BytesIO()
    with zipfile.ZipFile(dense, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("dense.js", b"A" * 4096)
    inventory, artifacts = unpacker.recover_zip(
        dense.getvalue(), max_compression_ratio=2
    )
    assert inventory[0]["status"] == "ratio_blocked"
    assert artifacts == []


def test_zip_malformed_and_streaming_size_mismatch_fail_closed() -> None:
    """宣言サイズを1バイトだけ超える不正メタデータも拒否する。"""
    with pytest.raises(zipfile.BadZipFile):
        unpacker.recover_zip(b"not a zip archive")

    class TrackingStream(io.BytesIO):
        bytes_read = 0

        def read(self, size=-1):
            chunk = super().read(size)
            self.bytes_read += len(chunk)
            return chunk

    stream = TrackingStream(b"ABCDE" + b"unread" * 100)

    class FakeArchive:
        def open(self, *_args, **_kwargs):
            return stream

    with pytest.raises(unpacker._ZipQuotaExceeded, match="output exceeded"):
        unpacker._read_standard_zip_member_capped(
            FakeArchive(),
            SimpleNamespace(file_size=4, compress_size=4),
            name="forged.bin",
            max_member_size=100,
            remaining_total=100,
            max_compression_ratio=200,
            chunk_size=2,
        )
    assert stream.bytes_read == 5


def test_valid_pe_carving_and_cab_detection(monkeypatch: pytest.MonkeyPatch) -> None:
    """実検体を使わず、上限付きPE切り出しとCAB認識を検証する。"""
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
    """検証済み分割ペイロードを再構築し、7-Zip不在を拒否する。"""
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
    """合成PE形式のAutoIt RC4・LZNT1ペイロードを復元する。"""
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
    """ResourceSetエントリからBitmap.GetPixelの列優先抽出を再現する。"""
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
    """PE以外のバイト列を拒否し、利用不能な外部ツールを報告する。"""
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


def test_reviewed_container_hint_forces_bounded_archive_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """汎用レイアウト分岐が偽でも、レビュー済みNSIS類似PEを検査する。"""
    monkeypatch.setattr(unpacker, "detect_format", lambda *_args: "pe")
    monkeypatch.setattr(
        unpacker, "recover_inflated_pe", lambda _data: ({"status": "none"}, None)
    )
    monkeypatch.setattr(
        unpacker,
        "pe_summary",
        lambda _data: (
            {
                "containerized": False,
                "is_dotnet": False,
                "sections": [],
                "packer_markers": [],
            },
            [],
        ),
    )
    monkeypatch.setattr(
        unpacker, "recover_xor32_donut_wrapper", lambda _data: ({}, [])
    )
    monkeypatch.setattr(
        unpacker, "recover_donut_payloads", lambda _data: ({}, [])
    )
    monkeypatch.setattr(unpacker, "carve_embedded_pes", lambda _data: [])
    observed: list[bytes] = []

    def fake_extract(data: bytes, *_args):
        observed.append(data)
        return {"status": "extracted"}, [("nsis-stage", b"child")]

    monkeypatch.setattr(unpacker, "sevenzip_extract", fake_extract)
    report, artifacts = unpacker.unpack_bytes(
        b"MZfixture",
        "fixture.exe",
        sevenzip=tmp_path / "7z.exe",
        force_container_probe=True,
    )
    assert observed == [b"MZfixture"]
    assert report["sevenzip"]["forced_by_reviewed_hint"] is True
    assert artifacts == [("nsis-stage", b"child")]


def test_nsis_probe_does_not_hide_decompiled_script_with_archive_password(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """無関係なアーカイブパスワードをNSIS PEへ渡さない。"""
    inventory_passwords: list[str] = []
    commands: list[list[str]] = []

    def fake_inventory(_data: bytes, _executable: Path, password: str = ""):
        inventory_passwords.append(password)
        return {
            "status": "listed",
            "archive_types": ["Nsis", "PE"],
            "members": ["[NSIS].nsi"],
            "total_members": 0,
            "declared_total_size": 0,
            "archive_unlock_attempted": bool(password),
        }

    def fake_run(command, **_kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(unpacker, "sevenzip_inventory", fake_inventory)
    monkeypatch.setattr(unpacker.subprocess, "run", fake_run)
    report, artifacts = unpacker.sevenzip_extract(
        b"MZfixture", tmp_path / "7z.exe", password="infected"
    )
    assert inventory_passwords == [""]
    assert all(not argument.startswith("-p") for argument in commands[0])
    assert report["archive_unlock_attempted"] is False
    assert report["status"] == "extracted"
    assert artifacts == []


def test_unpack_and_cli(tmp_path: Path) -> None:
    """オーケストレーション、パーサー、CLI出力を試験する。"""
    source = tmp_path / "sample.osascript"
    source.write_bytes(b'tell application "Finder"')
    report, artifacts = unpacker.unpack_bytes(source.read_bytes(), source.name)
    assert report["format"] == "script" and artifacts == []
    output = tmp_path / "report.json"
    args = ["--input", str(source), "--output", str(output)]
    assert unpacker.build_parser().parse_args(args).input == source
    assert unpacker.main(args) == 0
    assert json.loads(output.read_text())["executed"] is False
    original = source.read_bytes()
    with pytest.raises(ValueError, match="paths must differ"):
        unpacker.main(["--input", str(source), "--output", str(source)])
    assert source.read_bytes() == original
