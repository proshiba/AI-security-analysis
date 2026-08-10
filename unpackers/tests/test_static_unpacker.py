"""静的展開器の全公開関数に対する単体試験。"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import zipfile
import zlib

import pefile
import pyzipper
import pytest

from unpackers import static_unpacker as unpacker


def test_static_tool_process_drops_host_secret_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """外部toolへAPI key等のhost環境変数を継承しない。"""

    monkeypatch.setenv("VT_API_KEY", "must-not-leak")
    completed = unpacker._run_static_tool_process(
        [
            str(Path(sys.executable).resolve()),
            "-I",
            "-B",
            "-c",
            "import os; print(os.environ.get('VT_API_KEY', 'missing'))",
        ],
        cwd=tmp_path.resolve(),
        timeout=10,
        max_temp_entries=8,
        max_temp_bytes=1024 * 1024,
    )
    assert completed.returncode == 0
    assert completed.stdout.strip() == "missing"


def test_static_tool_process_rejects_bounded_stdout_overflow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """tool stdoutを保持上限超過時に成功扱いしない。"""

    monkeypatch.setattr(unpacker, "MAX_STATIC_TOOL_STDOUT_BYTES", 64)
    with pytest.raises(unpacker.StaticToolExecutionError, match="output_limit"):
        unpacker._run_static_tool_process(
            [
                str(Path(sys.executable).resolve()),
                "-I",
                "-B",
                "-c",
                "print('X' * 4096)",
            ],
            cwd=tmp_path.resolve(),
            timeout=10,
            max_temp_entries=8,
            max_temp_bytes=1024 * 1024,
        )


def test_static_tool_process_rejects_temporary_byte_overflow(tmp_path: Path) -> None:
    """toolが一時directory quotaを超えた場合は成果物を採用しない。"""

    with pytest.raises(unpacker.StaticToolExecutionError, match="temporary_byte_limit"):
        unpacker._run_static_tool_process(
            [
                str(Path(sys.executable).resolve()),
                "-I",
                "-B",
                "-c",
                "open('overflow.bin', 'wb').write(b'X' * 4096)",
            ],
            cwd=tmp_path.resolve(),
            timeout=10,
            max_temp_entries=8,
            max_temp_bytes=128,
        )


def test_static_tool_temp_tree_rejects_entry_overflow(tmp_path: Path) -> None:
    """directory全体をlist化せず、entry上限到達時点で走査を止める。"""

    (tmp_path / "one.bin").write_bytes(b"1")
    (tmp_path / "two.bin").write_bytes(b"2")
    with pytest.raises(
        unpacker.StaticToolExecutionError, match="temporary_entry_limit"
    ):
        unpacker._validate_static_tool_temp_tree(
            tmp_path,
            expected_root=tmp_path.lstat(),
            max_entries=1,
            max_bytes=1024,
        )


def test_static_tool_temp_tree_rejects_hardlink(tmp_path: Path) -> None:
    """tool一時tree内の複数link fileを成果物として扱わない。"""

    source = tmp_path / "source.bin"
    alias = tmp_path / "alias.bin"
    source.write_bytes(b"fixture")
    try:
        os.link(source, alias)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"このfilesystemではhardlinkを作成できません: {exc}")
    with pytest.raises(
        unpacker.StaticToolExecutionError,
        match="temporary_special_file_forbidden",
    ):
        unpacker._validate_static_tool_temp_tree(
            tmp_path,
            expected_root=tmp_path.lstat(),
            max_entries=8,
            max_bytes=1024,
        )


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


def test_detached_idat_stream_is_recovered_without_png_header() -> None:
    recovered = b"MZ" + b"P" * 64
    compressed = zlib.compress(recovered)
    midpoint = len(compressed) // 2
    carrier = b"prefix-random-data" + _png_chunk(b"IDAT", compressed[:midpoint])
    carrier += _png_chunk(b"IDAT", compressed[midpoint:]) + _png_chunk(b"IEND", b"")

    report, artifacts = unpacker.recover_detached_idat_stream(carrier)

    assert report["status"] == "detached_idat_zlib_recovered"
    assert report["chunk_count"] == 2
    assert report["prefix_size"] == len(b"prefix-random-data")
    assert artifacts == [("detached-idat-zlib", recovered)]


def test_detached_idat_stream_reports_non_zlib_without_emitting_payload() -> None:
    carrier = b"X" * 19 + _png_chunk(b"IDAT", b"encrypted-one")
    carrier += _png_chunk(b"IDAT", b"encrypted-two") + _png_chunk(b"IEND", b"")

    report, artifacts = unpacker.recover_detached_idat_stream(carrier)

    assert report["status"] == "encrypted_or_non_zlib_detached_idat"
    assert report["chunk_count"] == 2
    assert report["executed"] is False
    assert report["network_contacted"] is False
    assert artifacts == []


def test_detached_idat_false_marker_fails_closed() -> None:
    report, artifacts = unpacker.recover_detached_idat_stream(
        b"noise" + (4).to_bytes(4, "big") + b"IDATbad!" + b"not-a-valid-crc"
    )

    assert report["status"] == "not_found"
    assert artifacts == []


def test_recovery_candidate_priority_prefers_loader_and_detached_idat() -> None:
    compressed = zlib.compress(b"payload")
    midpoint = len(compressed) // 2
    carrier = _png_chunk(b"IDAT", compressed[:midpoint])
    carrier += _png_chunk(b"IDAT", compressed[midpoint:]) + _png_chunk(b"IEND", b"")

    assert unpacker.recovery_candidate_priority(b"MZloader4.cfg", "pe", "DG.dll") == 0
    assert unpacker.recovery_candidate_priority(carrier, "data", "blob.cfg") == 0
    assert unpacker.recovery_candidate_priority(b"MZordinary", "pe", "clean.dll") == 1
    assert unpacker.recovery_candidate_priority(b"ordinary", "data", "blob.bin") == 2


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
        archive.writestr(
            "payload.bin", b"asyncrat HWID Hosts http://malicious-example.xyz/gate"
        )
    inventory, artifacts = unpacker.recover_zip(stream.getvalue())
    assert inventory[0]["format"] == "script"
    assert {kind for kind, _blob in artifacts} == {
        "zip-script-payload.js",
        "zip-data-payload.bin",
    }
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


def test_aes_zip_password_and_member_name_are_propagated() -> None:
    """AES ZIPを指定passwordとone-shot相当quota内で復元し、拡張子を保持する。"""

    stream = io.BytesIO()
    with pyzipper.AESZipFile(
        stream,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as archive:
        archive.setpassword(b"infected")
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        archive.writestr("nested/stage.ps1", b"Write-Output 'fixture'")

    report, artifacts = unpacker.unpack_bytes(
        stream.getvalue(),
        "protected.zip",
        archive_password="infected",
        max_archive_members=4,
        max_archive_member_size=1024,
        max_archive_total_size=2048,
        max_archive_compression_ratio=100,
    )
    assert report["unpack_status"] == "artifacts_recovered"
    assert artifacts == [("zip-script-stage.ps1", b"Write-Output 'fixture'")]


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


def test_zip_oversized_member_does_not_hide_safe_siblings() -> None:
    """先頭の大容量hostを除外しても、上限内の隣接DLLとsidecarを保持する。"""

    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("large-signed-host.exe", b"MZ" + b"A" * 1024)
        archive.writestr("AppVIsvSubsystems64.dll", b"MZ" + b"B" * 30)
        archive.writestr("riched32.dat", b"sidecar")
    inventory, artifacts = unpacker.recover_zip(
        stream.getvalue(),
        max_member_size=128,
        max_total_size=1024,
        max_compression_ratio=1_000,
    )
    assert inventory[0]["name"] == "large-signed-host.exe"
    assert inventory[0]["status"] == "size_blocked"
    assert {kind for kind, _blob in artifacts} == {
        "zip-pe-AppVIsvSubsystems64.dll",
        "zip-data-riched32.dat",
    }


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
    assert unpacker.detect_format(b"Func Main()\nEndFunc", "decoded.au3") == "script"
    assert (
        unpacker.detect_format(
            b"Func Main()\nEndFunc",
            "sample.exe::7z-autoit-a3x::autoit-decompiled-script.au3",
        )
        == "script"
    )
    assert ".au3" in unpacker.SCRIPT_SUFFIXES
    assert unpacker.detect_format(b"opaque", "payload.a3x") == "autoit-a3x"
    autoit, scripts = unpacker.recover_autoit_script(b"invalid a3x")
    assert autoit["status"] in {"decompile_failed", "invalid_or_oversized_output"}
    assert scripts == []


def test_valid_pe_extent_rejects_header_only_image(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """宣言section数と実在section数が異なるヘッダー断片を子PEへ昇格しない。"""

    fake = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(NumberOfSections=3),
        OPTIONAL_HEADER=SimpleNamespace(
            SizeOfHeaders=0x200,
            DATA_DIRECTORY=[
                SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(16)
            ],
        ),
        sections=[],
    )
    monkeypatch.setattr(unpacker.pefile, "PE", lambda **_: fake)
    assert unpacker.valid_pe_extent(b"MZ" + bytes(0x1FE)) is None
    assert unpacker.carve_embedded_pes(b"X" + b"MZ" + bytes(0x1FE)) == []


def test_autoit_source_skips_javascript_specific_transforms() -> None:
    """逆コンパイル済みAutoItにはJavaScript専用変換を適用しない。"""

    report, artifacts = unpacker.unpack_bytes(
        b"Func Main()\nLocal $value = 1\nEndFunc", "decoded.au3"
    )
    assert report["format"] == "script"
    for field in (
        "javascript_dropper",
        "javascript_string_array",
        "javascript_plain_string_array",
    ):
        assert report[field]["status"] == "not_applicable_autoit_source"
    assert artifacts == []


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


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("sample.exe", ".exe"),
        ("sample.exe::pe-inflated-gap-removed", ".bin"),
        ("sample.dll::stage:2", ".bin"),
        ("sample.", ".bin"),
        ("sample.abcdefghijklmnop", ".abcdefghijklmnop"),
        ("sample.abcdefghijklmnopq", ".bin"),
    ],
)
def test_safe_temporary_suffix_rejects_recovered_layer_delimiters(
    name: str,
    expected: str,
) -> None:
    """復元レイヤーの表示名をWindowsの一時ファイル名へ伝播させない。"""

    assert unpacker.safe_temporary_suffix(name) == expected


def test_sevenzip_inventory_forces_utf8_and_replaces_invalid_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """7-Zipの非UTF-8出力がreader threadを停止させない設定を固定する。"""

    executable = tmp_path / "7z.exe"
    executable.write_bytes(b"fixture")
    observed: dict[str, object] = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return SimpleNamespace(
            returncode=0,
            stdout="Path = member-�.bin\nType = 7z\nSize = 4\n",
            stderr="",
        )

    monkeypatch.setattr(unpacker, "_run_static_tool_process", fake_run)
    report = unpacker.sevenzip_inventory(b"fixture", executable)
    assert "-sccUTF-8" in observed["command"]
    assert observed["kwargs"]["encoding"] == "utf-8"
    assert Path(observed["kwargs"]["cwd"]).is_absolute()
    assert Path(observed["kwargs"]["cwd"]).name.startswith("asa-7z-list-")
    assert report["members"] == ["member-�.bin"]


def test_select_high_value_archive_members_prioritizes_application_code() -> None:
    """大規模Electronアーカイブでは依存ライブラリよりアプリ本体を優先する。"""

    records = [
        {"name": "resources/app/node_modules/a/index.js", "size": 10},
        {"name": "resources/app/main.js", "size": 20},
        {"name": "resources/app/app.jsc", "size": 30},
        {"name": "resources/app/package.json", "size": 40},
        {"name": "resources/app/node_modules/dpapi.node", "size": 50},
        {"name": "LICENSES.chromium.html", "size": 60},
        {"name": "oversized.exe", "size": 5000},
        {"name": "../escape.js", "size": 1},
    ]

    selected = unpacker.select_high_value_archive_members(
        records,
        max_members=4,
        max_member_size=100,
        max_total_size=140,
    )

    assert [item["name"] for item in selected] == [
        "resources/app/app.jsc",
        "resources/app/main.js",
        "resources/app/package.json",
        "resources/app/node_modules/dpapi.node",
    ]
    assert sum(int(item["size"]) for item in selected) == 140


def test_sevenzip_over_member_limit_uses_bounded_selective_extraction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """全展開を拒否する件数でも高価値ファイルだけを明示選択して回収する。"""

    records = [
        {"name": "resources/app/main.js", "size": 18, "attributes": "A"},
        {"name": "resources/app/package.json", "size": 2, "attributes": "A"},
        {
            "name": "resources/app/node_modules/a/index.js",
            "size": 10,
            "attributes": "A",
        },
    ]

    def fake_inventory(_data: bytes, _executable: Path, _password: str = ""):
        return {
            "status": "listed",
            "archive_types": ["7z"],
            "members": [item["name"] for item in records],
            "total_members": 1823,
            "declared_total_size": 9999,
            "archive_unlock_attempted": False,
            "_member_records": records,
        }

    commands: list[list[str]] = []

    def fake_run(command, **_kwargs):
        commands.append(command)
        output_arg = next(item for item in command if item.startswith("-o"))
        output = Path(output_arg[2:]) / "resources" / "app"
        output.mkdir(parents=True)
        (output / "main.js").write_bytes(b"require-app-jsc")
        (output / "package.json").write_bytes(b"{}")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(unpacker, "sevenzip_inventory", fake_inventory)
    monkeypatch.setattr(unpacker, "_run_static_tool_process", fake_run)

    report, artifacts = unpacker.sevenzip_extract(
        b"7zfixture",
        tmp_path / "7z.exe",
        max_members=2,
        max_member_size=1024,
        max_total_size=1024,
    )

    assert report["status"] == "selectively_extracted"
    assert report["selective_extraction"]["full_inventory_count"] == 1823
    assert report["selective_extraction"]["selected_total_size"] == 20
    assert "resources/app/main.js" in commands[0]
    assert "resources/app/package.json" in commands[0]
    assert all("node_modules" not in item for item in commands[0])
    assert {kind for kind, _blob in artifacts} == {"7z-script", "7z-data"}


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
    monkeypatch.setattr(unpacker, "recover_xor32_donut_wrapper", lambda _data: ({}, []))
    monkeypatch.setattr(unpacker, "recover_donut_payloads", lambda _data: ({}, []))
    monkeypatch.setattr(unpacker, "carve_embedded_pes", lambda _data: [])
    observed: list[tuple[bytes, dict[str, object]]] = []

    def fake_extract(data: bytes, *_args, **kwargs):
        observed.append((data, kwargs))
        return {"status": "extracted"}, [("nsis-stage", b"child")]

    monkeypatch.setattr(unpacker, "sevenzip_extract", fake_extract)
    report, artifacts = unpacker.unpack_bytes(
        b"MZfixture",
        "fixture.exe",
        sevenzip=tmp_path / "7z.exe",
        force_container_probe=True,
        max_archive_members=3,
        max_archive_member_size=1024,
        max_archive_total_size=2048,
    )
    assert observed == [
        (
            b"MZfixture",
            {"max_members": 3, "max_member_size": 1024, "max_total_size": 2048},
        )
    ]
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
    monkeypatch.setattr(unpacker, "_run_static_tool_process", fake_run)
    report, artifacts = unpacker.sevenzip_extract(
        b"MZfixture", tmp_path / "7z.exe", password="infected"
    )
    assert inventory_passwords == [""]
    assert all(not argument.startswith("-p") for argument in commands[0])
    assert report["archive_unlock_attempted"] is False
    assert report["status"] == "extracted"
    assert artifacts == []


def test_sevenzip_empty_member_is_inventory_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """空memberを再帰解析artifactへ渡さず、inventoryへ事実だけを残す。"""

    def fake_inventory(_data: bytes, _executable: Path, _password: str = ""):
        return {
            "status": "listed",
            "archive_types": ["zip", "PE"],
            "members": ["package.dat"],
            "total_members": 1,
            "declared_total_size": 0,
            "archive_unlock_attempted": False,
        }

    def fake_run(command, **_kwargs):
        output_arg = next(item for item in command if item.startswith("-o"))
        output = Path(output_arg[2:])
        output.mkdir(parents=True)
        (output / "package.dat").write_bytes(b"")
        return SimpleNamespace(returncode=2, stdout="", stderr="data error")

    monkeypatch.setattr(unpacker, "sevenzip_inventory", fake_inventory)
    monkeypatch.setattr(unpacker, "_run_static_tool_process", fake_run)
    report, artifacts = unpacker.sevenzip_extract(
        b"MZfixture",
        tmp_path / "7z.exe",
        name="installer.exe",
    )
    assert report["status"] == "partially_extracted"
    assert report["inventory"] == [
        {
            "name": "package.dat",
            "size": 0,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "format": "data",
            "status": "empty_file",
        }
    ]
    assert artifacts == []


def test_sevenzip_rar_retries_known_wannacry_password_without_reporting_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """RARは既知候補を再試行し、reportにはpassword値を残さない。"""

    commands: list[list[str]] = []

    def fake_inventory(_data: bytes, _executable: Path, password: str = ""):
        return {
            "status": "listed",
            "archive_types": ["Rar5"],
            "members": ["eee.exe"],
            "total_members": 1,
            "declared_total_size": 9,
            "archive_unlock_attempted": bool(password),
        }

    def fake_run(command, **_kwargs):
        commands.append(command)
        output_arg = next(item for item in command if item.startswith("-o"))
        output = Path(output_arg[2:])
        output.mkdir(parents=True)
        if "-pWNcry@2ol7" in command:
            (output / "eee.exe").write_bytes(b"MZpayload")
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        (output / "eee.exe").write_bytes(b"")
        return SimpleNamespace(returncode=2, stdout="", stderr="data error")

    monkeypatch.setattr(unpacker, "sevenzip_inventory", fake_inventory)
    monkeypatch.setattr(unpacker, "_run_static_tool_process", fake_run)

    report, artifacts = unpacker.sevenzip_extract(
        b"Rar!fixture", tmp_path / "7z.exe", password="infected"
    )

    assert len(commands) == 2
    assert report["status"] == "extracted"
    assert report["archive_unlock_attempt_count"] == 2
    assert report["archive_unlock_candidate_index"] == 1
    assert "WNcry@2ol7" not in repr(report)
    assert artifacts == [("7z-pe", b"MZpayload")]


def test_sevenzip_temp_source_rejects_unsafe_layer_suffix(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """復元layer名のWindows禁則文字を7-Zip一時pathへ持ち込まない。"""

    commands: list[list[str]] = []

    def fake_inventory(_data: bytes, _executable: Path, _password: str = ""):
        return {
            "status": "listed",
            "archive_types": ["Cab"],
            "members": [],
            "total_members": 0,
            "declared_total_size": 0,
            "archive_unlock_attempted": False,
        }

    def fake_run(command, **_kwargs):
        commands.append(command)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(unpacker, "sevenzip_inventory", fake_inventory)
    monkeypatch.setattr(unpacker, "_run_static_tool_process", fake_run)
    report, artifacts = unpacker.sevenzip_extract(
        b"MSCFfixture",
        tmp_path / "7z.exe",
        name="sample.exe::pe-resource-cab",
    )
    source = Path(commands[0][-1])
    assert source.name == "input.bin"
    assert report["status"] == "extracted"
    assert artifacts == []


def test_sevenzip_preflight_uses_caller_member_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """外部7-Zip経路でも呼び出し元の件数上限を展開前に適用する。"""

    def fake_inventory(_data: bytes, _executable: Path, _password: str = ""):
        return {
            "status": "listed",
            "archive_types": ["7z"],
            "members": ["one.bin", "two.bin"],
            "total_members": 2,
            "declared_total_size": 32,
            "archive_unlock_attempted": False,
        }

    monkeypatch.setattr(unpacker, "sevenzip_inventory", fake_inventory)
    report, artifacts = unpacker.sevenzip_extract(
        b"7zfixture",
        tmp_path / "7z.exe",
        max_members=1,
        max_member_size=64,
        max_total_size=64,
    )
    assert report["status"] == "member_limit_blocked"
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


def test_recover_ole_streams_routes_cab_and_pe_without_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """MSI/OLE内のCAB・PEだけを次の静的解析層へ渡す。"""

    streams = {
        ("cab",): b"MSCF" + b"C" * 32,
        ("payload",): b"MZ" + b"P" * 62,
        ("table",): b"ordinary metadata",
    }

    class FakeOle:
        def listdir(self, **_kwargs):
            return [list(name) for name in streams]

        def get_size(self, parts):
            return len(streams[tuple(parts)])

        def openstream(self, parts):
            return io.BytesIO(streams[tuple(parts)])

        def close(self):
            return None

    monkeypatch.setattr(unpacker.olefile, "OleFileIO", lambda _source: FakeOle())
    report, artifacts = unpacker.recover_ole_streams(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1fixture"
    )

    assert report["status"] == "artifacts_recovered"
    assert report["stream_count"] == 3
    assert [(kind, data[:4]) for kind, data in artifacts] == [
        ("ole-cab-stream", b"MSCF"),
        ("ole-pe-stream", b"MZPP"),
    ]
    assert report["executed"] is False and report["network_contacted"] is False


def test_recover_ole_streams_fails_closed_on_member_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OLE stream件数が上限を超えた場合は部分復元せず停止する。"""

    class FakeOle:
        def listdir(self, **_kwargs):
            return [["one"], ["two"]]

        def close(self):
            return None

    monkeypatch.setattr(unpacker.olefile, "OleFileIO", lambda _source: FakeOle())
    report, artifacts = unpacker.recover_ole_streams(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1fixture",
        max_members=1,
    )
    assert report["status"] == "member_limit_blocked"
    assert artifacts == []


def test_recover_cab_members_filters_paths_and_respects_size(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CAB memberのpath・sizeを検証し、許可した静的層だけを返す。"""

    fake_archive = {
        "payload.exe": SimpleNamespace(buf=b"MZ" + b"P" * 62),
        "../escape.dll": SimpleNamespace(buf=b"MZ" + b"E" * 62),
        "large.bin": SimpleNamespace(buf=b"L" * 129),
        "note.txt": SimpleNamespace(buf=b"analysis note"),
    }
    monkeypatch.setattr(
        unpacker.cabarchive,
        "CabArchive",
        lambda _data: fake_archive,
    )
    report, artifacts = unpacker.recover_cab_members(
        b"MSCFfixture",
        max_member_size=128,
        max_total_size=512,
    )

    assert report["member_count"] == 4
    assert ("cab-pe", b"MZ" + b"P" * 62) in artifacts
    assert all(blob != b"MZ" + b"E" * 62 for _kind, blob in artifacts)
    statuses = {item["name"]: item["status"] for item in report["inventory"]}
    assert statuses["../escape.dll"] == "path_blocked"
    assert statuses["large.bin"] == "size_blocked"
    assert report["executed"] is False and report["network_contacted"] is False


def test_whole_file_base64_unknown_carrier_recovery() -> None:
    """既知形式でないシェルコードとスクリプトのBase64キャリアを全体一致で復号する。"""
    carrier = b"\x90" * 256 + b"function Stage { return 1 }"
    encoded = __import__("base64").b64encode(carrier)
    expected = [("whole-file-base64-data", carrier)]
    assert unpacker.recover_whole_file_base64(encoded) == expected
    report, artifacts = unpacker.unpack_bytes(encoded, "carrier.xtp")
    assert report["executed"] is False
    assert expected[0] in artifacts
    assert unpacker.recover_whole_file_base64(b"prefix" + encoded) == []
    assert unpacker.recover_whole_file_base64(encoded[:-1]) == []
