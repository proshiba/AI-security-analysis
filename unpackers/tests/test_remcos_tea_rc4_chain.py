"""Remcos TEA/RC4配送層の安全境界を合成fixtureで検証する。"""

from __future__ import annotations

import base64
import gzip
import struct

import pytest

from unpackers import remcos_tea_rc4_chain as chain


def _minimal_pe(marker: int = 0x42) -> bytes:
    image = bytearray(0x400)
    image[:2] = b"MZ"
    struct.pack_into("<I", image, 0x3C, 0x80)
    image[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", image, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x210E)
    optional = 0x98
    struct.pack_into("<H", image, optional, 0x10B)
    struct.pack_into("<I", image, optional + 0x10, 0x1000)
    struct.pack_into("<I", image, optional + 0x14, 0x1000)
    struct.pack_into("<I", image, optional + 0x1C, 0x400000)
    struct.pack_into("<I", image, optional + 0x20, 0x1000)
    struct.pack_into("<I", image, optional + 0x24, 0x200)
    struct.pack_into("<I", image, optional + 0x38, 0x2000)
    struct.pack_into("<I", image, optional + 0x3C, 0x200)
    struct.pack_into("<H", image, optional + 0x44, 3)
    struct.pack_into("<I", image, optional + 0x5C, 16)
    section = optional + 0xE0
    image[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", image, section + 8, 0x20, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", image, section + 36, 0x60000020)
    image[0x200:0x210] = bytes([marker]) * 16
    return bytes(image)


def _tea_encrypt(data: bytes, key: bytes) -> bytes:
    output = bytearray(data)
    words = [
        int.from_bytes(key[offset : offset + 4], "big") for offset in range(0, 16, 4)
    ]
    for offset in range(0, len(output), 8):
        left = int.from_bytes(output[offset : offset + 4], "big")
        right = int.from_bytes(output[offset + 4 : offset + 8], "big")
        total = 0
        for _round in range(16):
            total = chain._u32(total + 0x9E3779B9)
            left = chain._u32(
                left
                + (
                    chain._u32((right << 4) + words[0])
                    ^ chain._u32(right + total)
                    ^ chain._u32((right >> 5) + words[1])
                )
            )
            right = chain._u32(
                right
                + (
                    chain._u32((left << 4) + words[2])
                    ^ chain._u32(left + total)
                    ^ chain._u32((left >> 5) + words[3])
                )
            )
        output[offset : offset + 4] = left.to_bytes(4, "big")
        output[offset + 4 : offset + 8] = right.to_bytes(4, "big")
    return bytes(output)


def _javascript_fixture(clear: bytes, key16: bytes, key32: bytes, mask: int) -> bytes:
    padding = 8 - len(clear) % 8
    encrypted = bytearray(_tea_encrypt(clear + bytes([padding]) * padding, key16))
    chain._rc4(encrypted, key32)
    stored16 = bytes(value ^ mask for value in key16)
    stored32 = bytes(value ^ mask for value in key32)
    return f"""
var carrier=toHex([{",".join(map(str, encrypted))}]);
var shortKey=[{",".join(map(str, stored16))}];
var longKey=[{",".join(map(str, stored32))}];
var keyMask=0x{mask:02x};
function shape(v){{parseInt(v.substr(0,2),0x10);var d=0x9e3779b9,s=0xe3779b90;
for(var i=0;i<0x10;i++){{v=((v<<4)^(v>>>5))&0xff;}}return d+s;}}
""".encode()


def _script(marker: int) -> bytes:
    return (
        f"$marker={marker}\n"
        "$x=[Convert]::FromBase64String('QUFBQQ==')\n"
        "$g='GZipStream'\n[byte[]]$b=@(1,2,3)\n"
    ).encode()


def _table_encrypt(
    clear: bytes,
    rotation_key: bytes,
    xor_key: bytes,
    table: bytes,
    first_constant: int,
    second_constant: int,
) -> bytes:
    inverse = [0] * 256
    for index, value in enumerate(table):
        inverse[value] = index
    output = bytearray(len(clear))
    for position, desired in enumerate(clear):
        rotation = rotation_key[position % 32] & 7
        value = desired
        if rotation:
            value = ((value >> rotation) | (value << (8 - rotation))) & 0xFF
        value ^= second_constant
        value ^= position & 0xFF
        value = (~value) & 0xFF
        value ^= first_constant
        value ^= xor_key[position % 32]
        output[position] = inverse[value]
    return bytes(output)


def _powershell_fixture(*payloads: bytes) -> bytes:
    rotation_key = bytes(range(32))
    xor_key = bytes(reversed(range(32)))
    table = bytes((index * 197 + 17) & 0xFF for index in range(256))
    encoded = [
        base64.b64encode(
            _table_encrypt(
                gzip.compress(payload, mtime=0),
                rotation_key,
                xor_key,
                table,
                0xE9,
                0xA6,
            )
        ).decode()
        for payload in payloads
    ]
    literals = "\n".join(
        f'$blob{index}="{value}"' for index, value in enumerate(encoded)
    )
    return f"""
{literals}
$r=[Convert]::FromBa`se64String('{base64.b64encode(rotation_key).decode()}')
$q=[Convert]::FromBa`se64String('{base64.b64encode(xor_key).decode()}')
[byte[]]$table=@({",".join(map(str, table))})
$v=$table[$v]
$v=$v -bxor $q[$i%32]
$v=$v -bxor 0xE9
$v=[byte]((-bnot $v) -band 0xFF)
$v=$v -bxor ($i -band 0xFF)
$v=$v -bxor 0xA6
$r=$r[$i%32] -band 7
$v=(($v -shl $r) -bor ($v -shr (8-$r))) -band 0xFF
$g='IO.Comp'+'ression.G'+'ZipStream'
$m=[IO.Compression.CompressionMode]::Decompress
""".encode()


def test_javascript_rc4_tea_recovers_renamed_powershell() -> None:
    clear = _script(1)
    recovery = chain.recover_remcos_javascript_tea_rc4(
        _javascript_fixture(clear, bytes(range(16)), bytes(range(32)), 0xEB)
    )

    assert recovery.script == clear
    assert recovery.report["status"] == "powershell_recovered"
    assert recovery.report["raw_key_published"] is False


def test_javascript_rc4_tea_accepts_reviewed_shape_above_legacy_four_mib() -> None:
    """4 MiB超の既知shapeも、16 MiBの有界入口内なら静的復元する。"""

    clear = _script(7)
    fixture = _javascript_fixture(clear, bytes(range(16)), bytes(range(32)), 0xEB)
    fixture += b" " * (4 * 1024 * 1024 + 1 - len(fixture))

    recovery = chain.recover_remcos_javascript_tea_rc4(fixture)

    assert recovery.script == clear
    assert recovery.report["status"] == "powershell_recovered"


def test_javascript_rc4_tea_size_limit_is_explicitly_incomplete(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _javascript_fixture(_script(1), bytes(range(16)), bytes(range(32)), 0xEB)
    monkeypatch.setattr(chain, "MAXIMUM_JAVASCRIPT_INPUT_BYTES", len(fixture) - 1)

    recovery = chain.recover_remcos_javascript_tea_rc4(fixture)

    assert recovery.report["status"] == "input_size_rejected"
    assert recovery.report["candidate_set_complete"] is False
    assert recovery.report["candidate_set_truncated"] is True


def test_large_javascript_is_not_misrouted_to_powershell_size_rejection() -> None:
    fixture = _javascript_fixture(_script(1), bytes(range(16)), bytes(range(32)), 0xEB)
    fixture += b" " * (chain.MAXIMUM_INPUT_BYTES + 1 - len(fixture))

    recovery = chain.recover_remcos_powershell_table_gzip(fixture)

    assert recovery.report["status"] == "reviewed_shape_not_found"
    assert recovery.report["candidate_set_complete"] is True


def test_javascript_rc4_tea_rejects_corruption_quota_and_ambiguity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _javascript_fixture(_script(1), bytes(range(16)), bytes(range(32)), 0xEB)
    corrupted = first.replace(b"var carrier=toHex([", b"var carrier=toHex([255,", 1)
    assert chain.recover_remcos_javascript_tea_rc4(corrupted).script is None

    monkeypatch.setattr(chain, "MAXIMUM_TRANSFORM_WORK_BYTES", 1)
    limited = chain.recover_remcos_javascript_tea_rc4(first)
    assert limited.report["status"] == "transform_work_limit_exceeded"
    monkeypatch.setattr(chain, "MAXIMUM_TRANSFORM_WORK_BYTES", 64 * 1024 * 1024)

    second = _javascript_fixture(
        _script(2), bytes(range(16, 32)), bytes(range(32, 64)), 0xEB
    )
    combined = first + b"\n" + second
    ambiguous = chain.recover_remcos_javascript_tea_rc4(combined)
    assert ambiguous.script is None
    assert ambiguous.report["status"] == "candidate_not_unique"


def test_javascript_rc4_tea_rejects_extremely_long_decimal_without_exception() -> None:
    fixture = _javascript_fixture(_script(1), bytes(range(16)), bytes(range(32)), 0xEB)
    oversized = fixture.replace(
        b"var keyMask=0xeb;",
        b"var keyMask=" + (b"9" * 5_000) + b";",
        1,
    )

    recovery = chain.recover_remcos_javascript_tea_rc4(oversized)

    assert recovery.script is None
    assert recovery.report["status"] == "validated_output_not_found"


def test_powershell_table_gzip_recovers_only_valid_pe() -> None:
    expected = _minimal_pe()
    recovery = chain.recover_remcos_powershell_table_gzip(_powershell_fixture(expected))

    assert recovery.artifacts == (("remcos-table-gzip-pe", expected),)
    assert recovery.report["status"] == "pe_recovered"


def test_powershell_table_gzip_rejects_quota_and_ambiguity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _powershell_fixture(_minimal_pe())
    monkeypatch.setattr(chain, "MAXIMUM_TRANSFORM_WORK_BYTES", 1)
    limited = chain.recover_remcos_powershell_table_gzip(fixture)
    assert limited.report["status"] == "transform_work_limit_exceeded"
    monkeypatch.setattr(chain, "MAXIMUM_TRANSFORM_WORK_BYTES", 64 * 1024 * 1024)

    ambiguous = chain.recover_remcos_powershell_table_gzip(
        _powershell_fixture(_minimal_pe(0x41), _minimal_pe(0x42))
    )
    assert ambiguous.artifacts == ()
    assert ambiguous.report["status"] == "candidate_not_unique"


def test_unrelated_scripts_are_not_promoted() -> None:
    javascript = b"var values=[1,2,3]; function add(a,b){return a+b;}"
    powershell = b"$value = 42\nWrite-Output $value\n"

    assert chain.recover_remcos_javascript_tea_rc4(javascript).script is None
    assert chain.recover_remcos_powershell_table_gzip(powershell).artifacts == ()
