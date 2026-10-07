"""Equation Editor OLE downloaderの静的LCG復元を合成fixtureで検証する。"""

from __future__ import annotations

import hashlib

import pytest

from unpackers import equation_ole


def _wide(value: str) -> bytes:
    return value.encode("utf-16le") + b"\0\0"


def _decoded_stage(url: str, destination: str) -> bytes:
    """API集合、配布URL、保存先を持つ非実行用の合成stageを作る。"""

    apis = b"\0".join(
        value.encode("ascii")
        for value in (
            "LoadLibraryW",
            "GetProcAddress",
            "ExpandEnvironmentStringsW",
            "URLDownloadToFileW",
            "ShellExecuteExW",
            "ExitProcess",
        )
    ) + b"\0"
    return (
        b"\x81\xec\x68\x02\x00\x00"
        + apis
        + b"\xff"
        + _wide("kernel32")
        + _wide("UrlMon")
        + _wide("shell32")
        + _wide(url)
        + _wide(destination)
        + b"synthetic-static-fixture"
    )


def _lcg_xor(data: bytes, multiplier: int, increment: int) -> bytes:
    key = increment
    output = bytearray()
    for offset in range(0, len(data), 4):
        chunk = data[offset : offset + 4]
        padded = chunk + bytes(4 - len(chunk))
        output.extend(
            (int.from_bytes(padded, "little") ^ key).to_bytes(4, "little")[: len(chunk)]
        )
        key = (key * multiplier + increment) & 0xFFFFFFFF
    return bytes(output)


def _native_fixture(
    stage: bytes,
    *,
    multiplier: int = 0x13579BDF,
    increment: int = 0x2468ACE1,
) -> bytes:
    """call/pop、CFG loop、LCG dword XORを持つ合成native streamを作る。"""

    stage_offset = 0x120
    entry = equation_ole.NATIVE_ENTRY_OFFSET
    decoder_entry = 0x80
    bootstrap = 0x90
    native = bytearray(stage_offset + len(stage))
    native[entry : entry + 5] = b"\xe9" + struct_pack_i32(decoder_entry - (entry + 5))
    native[decoder_entry : decoder_entry + 5] = b"\xe8" + struct_pack_i32(
        bootstrap - (decoder_entry + 5)
    )
    native[decoder_entry + 5 : decoder_entry + 10] = b"\xe9" + struct_pack_i32(
        bootstrap - (decoder_entry + 10)
    )

    return_address = decoder_entry + 5
    code = bytearray()
    code += b"\x5d"  # pop ebp
    code += b"\x81\xc5" + (stage_offset - return_address).to_bytes(4, "little")
    code += b"\x8d\x9d" + len(stage).to_bytes(4, "little")  # lea ebx,[ebp+size]
    code += b"\x6b\xc0\x00"  # imul eax,eax,0
    multiplier_address = bootstrap + len(code)
    code += b"\x69\xc0" + multiplier.to_bytes(4, "little")
    code += b"\x05" + increment.to_bytes(4, "little")
    code += b"\x31\x45\x00"  # xor dword ptr [ebp],eax
    code += b"\x83\xc5\x04"  # add ebp,4
    code += b"\x39\xdd"  # cmp ebp,ebx
    branch_address = bootstrap + len(code)
    displacement = multiplier_address - (branch_address + 2)
    assert -128 <= displacement <= 127
    code += b"\x72" + bytes([displacement & 0xFF])  # jb LCG update
    code += b"\xff\xe5"  # jmp ebp
    assert bootstrap + len(code) < stage_offset
    native[bootstrap : bootstrap + len(code)] = code
    native[stage_offset:] = _lcg_xor(stage, multiplier, increment)
    return bytes(native)


def struct_pack_i32(value: int) -> bytes:
    return int(value).to_bytes(4, "little", signed=True)


@pytest.mark.parametrize(
    ("url", "destination", "multiplier", "increment"),
    [
        (
            "http://192.0.2.10/a/payload.exe",
            r"%PUBLIC%\fixture-a.exe",
            0x13579BDF,
            0x2468ACE1,
        ),
        (
            "https://example.invalid/stage/b.exe",
            r"%TEMP%\fixture-b.exe",
            0x4342BC0F,
            0x5AC60825,
        ),
    ],
)
def test_hash_independent_lcg_stage_recovery(
    url: str,
    destination: str,
    multiplier: int,
    increment: int,
) -> None:
    """hash、URL、file名、LCG定数が異なる2変種を構造だけで復元する。"""

    pytest.importorskip("capstone")
    stage = _decoded_stage(url, destination)
    native = _native_fixture(stage, multiplier=multiplier, increment=increment)
    report, artifacts = equation_ole.recover_equation_native_stream(native)

    assert report["status"] == "equation_ole_stage_recovered"
    assert report["native_stream_sha256"] == hashlib.sha256(native).hexdigest()
    assert report["decoder"]["multiplier"] == f"0x{multiplier:08x}"
    assert report["decoder"]["increment"] == f"0x{increment:08x}"
    assert report["decoded_stage"]["stage_url"] == url
    assert report["decoded_stage"]["destination_path"] == destination
    assert report["decoded_stage"]["download_payload_transform"] == "identity"
    assert report["decoded_stage"]["download_payload_recovered"] is False
    assert report["sample_executed"] is False
    assert report["cpu_emulated"] is False
    assert report["network_contacted"] is False
    assert artifacts == [("equation-ole-decoded-stage", stage)]


def test_missing_required_api_fails_closed() -> None:
    """decoderが成立してもstage意味論が不足する場合はbyte列を返さない。"""

    pytest.importorskip("capstone")
    stage = _decoded_stage(
        "http://192.0.2.20/stage.exe", r"%PUBLIC%\fixture.exe"
    ).replace(b"ExitProcess\0", b"ExitProcesx\0")
    report, artifacts = equation_ole.recover_equation_native_stream(
        _native_fixture(stage)
    )

    assert report["status"] == "structure_rejected"
    assert "ExitProcess" in report["reason"]
    assert artifacts == []


def test_ambiguous_stage_url_fails_closed() -> None:
    """複数URLを検出しても先頭候補へ推測で収束しない。"""

    pytest.importorskip("capstone")
    stage = _decoded_stage(
        "http://192.0.2.30/a.exe", r"%TEMP%\fixture.exe"
    ) + _wide("http://192.0.2.31/b.exe")
    report, artifacts = equation_ole.recover_equation_native_stream(
        _native_fixture(stage)
    )

    assert report["status"] == "structure_rejected"
    assert "URL候補が一意ではありません" in report["reason"]
    assert artifacts == []


def test_decoder_back_edge_is_required() -> None:
    """LCG定数が見えてもloop back-edgeを壊した入力は拒否する。"""

    pytest.importorskip("capstone")
    stage = _decoded_stage(
        "http://192.0.2.40/a.exe", r"%TEMP%\fixture.exe"
    )
    native = bytearray(_native_fixture(stage))
    branch = native.find(b"\x72", 0x90, 0x120)
    assert branch >= 0
    native[branch] = 0x73  # jaeへ変更し、LCG更新edgeを無効化する
    report, artifacts = equation_ole.recover_equation_native_stream(bytes(native))

    assert report["status"] == "structure_rejected"
    assert artifacts == []


def test_xlsx_routing_preserves_embedding_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """OOXML routeのCLSID、member、hidden sheet文脈をreportへ保持する。"""

    pytest.importorskip("capstone")
    stage = _decoded_stage(
        "http://192.0.2.50/a.exe", r"%PUBLIC%\fixture.exe"
    )
    native = _native_fixture(stage)
    context = {
        "name": "Sheet1",
        "state": "hidden",
        "auto_load": True,
        "prog_id": "synthetic",
    }
    monkeypatch.setattr(
        equation_ole,
        "_extract_xlsx_equation_object",
        lambda _data: (
            native,
            equation_ole.EQUATION_EDITOR_CLSID,
            "xl/embeddings/oleObject1.bin",
            context,
        ),
    )
    report, artifacts = equation_ole.recover_equation_ole(b"PK\x03\x04fixture")

    assert report["status"] == "equation_ole_stage_recovered"
    assert report["source_kind"] == "xlsx_equation_embedding"
    assert report["embedding_member"] == "xl/embeddings/oleObject1.bin"
    assert report["clsid"] == equation_ole.EQUATION_EDITOR_CLSID
    assert report["worksheet"] == context
    assert len(artifacts) == 1


def test_malformed_ole_fails_closed() -> None:
    """magicだけを持つ破損OLEを例外で漏らさず、artifactなしで拒否する。"""

    pytest.importorskip("olefile")
    report, artifacts = equation_ole.recover_equation_ole(
        equation_ole.OLE_MAGIC + b"synthetic-malformed-ole"
    )

    assert report["status"] == "structure_rejected"
    assert "OLE compound fileを検証できません" in report["reason"]
    assert artifacts == []
