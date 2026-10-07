"""Batch／PowerShell／JavaScript polyglot静的復元器のテスト。"""

from __future__ import annotations

import base64
import gzip
import hashlib
import struct

import pytest
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad

from unpackers import batch_powershell_polyglot as target
from unpackers import static_unpacker


def _minimal_pe(marker: bytes) -> bytes:
    """異なるhashを持てる1 sectionの最小PE32 fixtureを返す。"""

    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 4, 0x200)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<I", data, optional + 24, 0x2000)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, 0x2000)
    struct.pack_into("<I", data, optional + 60, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    section = optional + 0xE0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    data[0x200 : 0x200 + len(marker)] = marker
    return bytes(data)


def _xor_gzip(data: bytes, key: int = 117) -> bytes:
    compressed = gzip.compress(data, mtime=0)
    return bytes(item ^ key for item in compressed)


def _custom_nibbles(data: bytes) -> str:
    alphabet = "dpmhqwxnvkfygtjb"
    encoded = []
    for item in data:
        swapped = ((item & 0x0F) << 4) | (item >> 4)
        encoded.extend((alphabet[swapped >> 4], alphabet[swapped & 0x0F]))
    return alphabet + "".join(encoded)


def _minimal_hcs() -> bytes:
    """field／methodを持たない最小HOI1 fixtureを返す。"""

    namespace = b"Fixture"
    class_name = b"Entry"
    return (
        b"HOI1"
        + struct.pack("<H", 1)
        + struct.pack("<H", len(namespace))
        + namespace
        + struct.pack("<H", len(class_name))
        + class_name
        + struct.pack("<HH", 0, 1)
        + struct.pack("<H", len(class_name))
        + class_name
        + struct.pack("<BihiBHH", 0, 0, 0, 0, 0, 0, 0)
    )


def _set_lines(prefix: str, value: str, width: int = 503) -> list[str]:
    return [
        f'set "{prefix}{value[offset : offset + width]}"'
        for offset in range(0, len(value), width)
    ]


def _fixture(
    *, corrupt_hashes: bool = False
) -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
    hbt_pe = _minimal_pe(b"HBT")
    hcs = _minimal_hcs()
    rsc_pe = _minimal_pe(b"RSC")
    mask = 233
    key = bytes(range(32))
    iv = bytes(range(16, 32))
    key_values = ",".join(str(item ^ mask) for item in key)
    iv_values = ",".join(str(item ^ mask) for item in iv)
    powershell = (
        "function Expand-Layer($value) { New-Object IO.MemoryStream; 'CBC'; 'PKCS7' };"
        "$RSCVALUE=__kmv 'RSC' $RSCVALUE;"
        f"$MASK={mask};"
        f"$KEY=[byte[]](@({key_values})|ForEach-Object{{[byte]($_ -bxor $MASK)}});"
        f"$IV=[byte[]](@({iv_values})|ForEach-Object{{[byte]($_ -bxor $MASK)}});"
        "$OUT=Expand-Gzip (Decrypt-Aes ([Convert]::FromBase64String($RSCVALUE)) $KEY $IV);"
    ).encode()
    ps_envelope = _xor_gzip(powershell)
    compressed_rsc = gzip.compress(rsc_pe, mtime=0)
    rsc_ciphertext = AES.new(key, AES.MODE_CBC, iv).encrypt(pad(compressed_rsc, 16))
    pld_ciphertext = bytes(range(128))

    components = {
        "HBT": hbt_pe,
        "HCS": hcs,
        "PLD": pld_ciphertext,
        "PS": ps_envelope,
        "RSC": rsc_ciphertext,
    }
    metadata = []
    for role, value in components.items():
        digest = hashlib.sha256(value).hexdigest()
        if corrupt_hashes:
            digest = "0" * 64
        metadata.append(f"::META{role}|1|{len(value)}|{digest}|0")

    lines = [
        "/*",
        "rem",
        "$bootstrap=$env:SELF;[char]34;Get'+'Method;",
        *metadata,
        *_set_lines("HBTDATA", _custom_nibbles(hbt_pe)),
        *_set_lines("HCSDATA", base64.b64encode(hcs).decode()),
        *_set_lines("PSDATA", base64.b64encode(ps_envelope).decode()),
        *_set_lines("PLDDATA", base64.b64encode(pld_ciphertext).decode()),
        *_set_lines("RSCDATA", base64.b64encode(rsc_ciphertext).decode()),
        "*/",
        "var inert = 1;",
    ]
    return (
        "\r\n".join(lines).encode(),
        powershell,
        hbt_pe,
        hcs,
        rsc_pe,
        pld_ciphertext,
    )


def test_recovers_metadata_bound_layers_and_aes_rsc_pe() -> None:
    """hash拘束したcustom nibble、PowerShell、AES/GZip PEを復元する。"""

    script, powershell, hbt_pe, hcs, rsc_pe, pld_ciphertext = _fixture()
    report, artifacts = target.recover_batch_powershell_polyglot(script)

    assert report["status"] == "artifacts_recovered"
    assert report["executed"] is False
    assert report["network_contacted"] is False
    assert {item["role"] for item in report["verified_components"]} == {
        "HBT",
        "HCS",
        "PLD",
        "PS",
        "RSC",
    }
    assert (
        report["rsc_aes_gzip"]["decoded_sha256"] == hashlib.sha256(rsc_pe).hexdigest()
    )
    assert ("batch-metadata-hbt-pe", hbt_pe) in artifacts
    assert ("batch-metadata-hcs-managed-image", hcs) in artifacts
    assert report["managed_handoff"]["status"] == "parsed"
    assert powershell in {value for _kind, value in artifacts}
    assert ("batch-metadata-pld-encrypted", pld_ciphertext) in artifacts
    assert ("batch-rsc-aes-gzip-pe", rsc_pe) in artifacts


def test_metadata_hash_mismatch_never_unlocks_binary_layers() -> None:
    """carrierが復号可能でもmetadata hash不一致ならPEを保持しない。"""

    script, _powershell, _hbt_pe, _hcs, _rsc_pe, _pld = _fixture(
        corrupt_hashes=True
    )
    report, artifacts = target.recover_batch_powershell_polyglot(script)

    assert report["verified_components"] == []
    assert report["rsc_aes_gzip"]["status"] == "recipe_not_recovered"
    assert not any(kind.endswith("-pe") for kind, _value in artifacts)


def test_size_and_line_limits_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    """入力と単一行のhard limit到達時は候補を返さない。"""

    monkeypatch.setattr(target, "MAX_SCRIPT_SIZE", 16)
    report, artifacts = target.recover_batch_powershell_polyglot(b"X" * 17)
    assert report["status"] == "size_blocked"
    assert artifacts == []

    monkeypatch.setattr(target, "MAX_SCRIPT_SIZE", 1024)
    monkeypatch.setattr(target, "MAX_LINE_SIZE", 8)
    report, artifacts = target.recover_batch_powershell_polyglot(
        b"/*\nrem\n123456789\n*/"
    )
    assert report["status"] == "line_size_blocked"
    assert artifacts == []

    monkeypatch.setattr(target, "MAX_LINE_SIZE", 1024)
    monkeypatch.setattr(target, "MAX_LINE_COUNT", 2)
    report, artifacts = target.recover_batch_powershell_polyglot(b"A\nB\nC\n")
    assert report["status"] == "line_limit_blocked"
    assert artifacts == []


def test_minified_line_uses_total_script_limit_instead_of_legacy_two_mib() -> None:
    """総入力上限内のminified一行を旧2 MiB境界だけで拒否しない。"""

    report, artifacts = target.recover_batch_powershell_polyglot(
        b"A" * (2 * 1024 * 1024 + 1)
    )

    assert report["status"] == "pattern_not_found"
    assert artifacts == []


def test_generated_script_above_legacy_line_count_remains_bounded() -> None:
    """総入力上限内なら旧16,384行境界だけで拒否しない。"""

    report, artifacts = target.recover_batch_powershell_polyglot(
        b"A\n" * 16_385
    )

    assert report["status"] == "pattern_not_found"
    assert artifacts == []


def test_static_unpacker_connects_both_script_routes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """共通script分岐がpolyglotと逆順Base64の両方を呼び出す。"""

    polyglot = b"polyglot-layer"
    reversed_layer = b"reverse-base64-layer"
    monkeypatch.setattr(
        static_unpacker,
        "recover_batch_powershell_polyglot",
        lambda _data: ({"status": "artifacts_recovered"}, [("polyglot", polyglot)]),
    )
    monkeypatch.setattr(
        static_unpacker,
        "recover_reverse_base64",
        lambda _data: (
            {"status": "artifacts_recovered"},
            [("reverse-base64", reversed_layer)],
        ),
    )

    report, artifacts = static_unpacker.unpack_bytes(b"var inert = 1;", "fixture.js")

    assert report["batch_powershell_polyglot"]["status"] == "artifacts_recovered"
    assert report["javascript_reverse_base64"]["status"] == "artifacts_recovered"
    assert ("polyglot", polyglot) in artifacts
    assert ("reverse-base64", reversed_layer) in artifacts
