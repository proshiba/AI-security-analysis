"""RemusStealer memory config 静的復元の単体テスト。"""

from __future__ import annotations

import json
import os
import struct
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

FRAMEWORK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FRAMEWORK))

from common import remus_memory_config as remus

IMAGE_SIZE = 0x3000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
KEY_RVA = 0x2000
CIPHER_RVA = 0x2030
TAG_RVA = 0x2160
TOKEN_RVA = 0x21D0
STATE_RVA = 0x2200
RUNTIME_ENDPOINT_RVA = 0x2280
SELECTOR_RVA = 0x23F0
CODE_RVA = 0x1100
KEY = bytes(range(1, 33))
NONCE = bytes.fromhex("1020304050607080")
TAG = "844bd1dce6c8ac2a8b8a026e61811dac"
TOKEN = "11111111-2222-4333-8444-555555555555"
ENDPOINTS = (
    "http://none",
    "http://onesdto.shop:2535",
    "http://slyfogx.shop:5776",
)


def _chacha(value: bytes, counter: int) -> bytes:
    transform = Cipher(
        algorithms.ChaCha20(KEY, counter.to_bytes(8, "little") + NONCE),
        mode=None,
    ).encryptor()
    return transform.update(value) + transform.finalize()


def _headers() -> bytes:
    data = bytearray(0x400)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664, 2, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B)
    struct.pack_into("<I", data, optional + 16, CODE_RVA)
    struct.pack_into("<I", data, optional + 20, TEXT_RVA)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", data, optional + 56, IMAGE_SIZE)
    struct.pack_into("<I", data, optional + 60, 0x400)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + 108, 16)

    section = optional + 0xF0
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x400, TEXT_RVA, 0x400, 0x400)
    struct.pack_into("<I", data, section + 36, 0x60000020)
    section += 40
    data[section : section + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x1000, DATA_RVA, 0x1000, 0x800)
    struct.pack_into("<I", data, section + 36, 0xC0000040)
    return bytes(data)


def _virtual_sections(
    *,
    selector_index: int = 1,
    include_token: bool = True,
    include_selector_pattern: bool = True,
    first_uri: str = ENDPOINTS[0],
) -> tuple[bytes, bytes]:
    text = bytearray(0x400)
    data = bytearray(0x1000)
    data[KEY_RVA - DATA_RVA : KEY_RVA - DATA_RVA + 32] = KEY
    data[KEY_RVA - DATA_RVA + 32 : KEY_RVA - DATA_RVA + 40] = NONCE
    data[KEY_RVA - DATA_RVA + 40 : KEY_RVA - DATA_RVA + 48] = b"\0" * 8
    uris = (first_uri, ENDPOINTS[1], ENDPOINTS[2], "not-a-url")
    for index, uri in enumerate(uris):
        plain = (uri.encode("ascii") + b"\0").ljust(remus.SLOT_SIZE, b"\0")
        start = CIPHER_RVA - DATA_RVA + index * remus.SLOT_SIZE
        data[start : start + remus.SLOT_SIZE] = _chacha(plain, index)

    data[TAG_RVA - DATA_RVA : TAG_RVA - DATA_RVA + len(TAG)] = TAG.encode("ascii")
    if include_token:
        data[TOKEN_RVA - DATA_RVA : TOKEN_RVA - DATA_RVA + len(TOKEN)] = TOKEN.encode("ascii")
    state = STATE_RVA - DATA_RVA
    data[state : state + 16] = remus.CHACHA_CONSTANT
    data[state + 16 : state + 48] = KEY
    struct.pack_into("<Q", data, state + 48, selector_index + 1)
    data[state + 56 : state + 64] = NONCE
    chosen = uris[selector_index]
    wide = chosen.encode("utf-16le") + b"\0\0"
    runtime = RUNTIME_ENDPOINT_RVA - DATA_RVA
    data[runtime : runtime + len(wide)] = wide
    data[SELECTOR_RVA - DATA_RVA] = selector_index ^ 0x16

    if include_selector_pattern:
        code = bytearray()
        code += b"\x0f\xb6\x05" + struct.pack("<i", SELECTOR_RVA - (CODE_RVA + 7))
        code += b"\x83\xf0\x16\xc1\xe0\x06"
        code += b"\x48\x8d\x15" + struct.pack("<i", CIPHER_RVA - (CODE_RVA + 20))
        code += b"\x48\x01\xc2"
        code += b"\x48\x8d\x0d" + struct.pack("<i", STATE_RVA - (CODE_RVA + 30))
        offset = CODE_RVA - TEXT_RVA
        text[offset : offset + len(code)] = code
    return bytes(text), bytes(data)


def _fixture(
    layout: str,
    *,
    selector_index: int = 1,
    include_token: bool = True,
    include_selector_pattern: bool = True,
    first_uri: str = ENDPOINTS[0],
) -> bytes:
    headers = _headers()
    text, data_section = _virtual_sections(
        selector_index=selector_index,
        include_token=include_token,
        include_selector_pattern=include_selector_pattern,
        first_uri=first_uri,
    )
    if layout == "mapped":
        output = bytearray(IMAGE_SIZE)
        output[: len(headers)] = headers
        output[TEXT_RVA : TEXT_RVA + len(text)] = text
        output[DATA_RVA : DATA_RVA + len(data_section)] = data_section
        return bytes(output)
    if layout == "file":
        output = bytearray(0x1800)
        output[: len(headers)] = headers
        output[0x400:0x800] = text
        output[0x800:0x1800] = data_section
        return bytes(output)
    raise AssertionError(layout)


@pytest.mark.parametrize("layout", ["mapped", "file"])
def test_extracts_same_config_from_mapped_and_file_layout(layout: str) -> None:
    report = remus.extract_remus_memory_config(_fixture(layout))

    assert report["status"] == "extracted"
    assert report["input"]["selected_layout"] == layout
    assert [item["uri"] for item in report["config"]["sentinels"]] == ["http://none"]
    assert [item["uri"] for item in report["config"]["endpoints"]] == list(ENDPOINTS[1:])
    assert report["config"]["tag"]["value"] == TAG
    assert report["config"]["tag"]["confidence"] == "high"
    assert report["config"]["exp"]["status"] == "not_recovered"
    assert report["config"]["selector"]["selected_index"] == 1
    assert report["config"]["runtime"]["selected_endpoint"]["present"] is True
    assert report["config"]["runtime"]["access_token"]["present"] is True
    assert report["crypto"]["first_non_uri_slot"] == 3
    assert report["safety"]["sample_executed"] is False
    assert report["safety"]["network_contacted"] is False


def test_auto_layout_prefers_file_sections_for_sizeofimage_padded_file() -> None:
    file_data = _fixture("file")
    padded = file_data + bytes(IMAGE_SIZE - len(file_data))

    report = remus.extract_remus_memory_config(padded)

    assert report["input"]["selected_layout"] == "file"
    assert report["config"]["selector"]["status"] == "recovered"
    assert report["config"]["tag"]["confidence"] == "high"


def test_runtime_token_and_endpoint_values_are_not_published() -> None:
    report = remus.extract_remus_memory_config(_fixture("mapped"))
    runtime = report["config"]["runtime"]

    assert "value" not in runtime["access_token"]
    assert "value" not in runtime["selected_endpoint"]
    assert runtime["access_token"]["sha256"]
    assert TOKEN not in json.dumps(runtime)
    assert report["safety"]["access_token_value_published"] is False


def test_early_snapshot_retains_sentinel_and_has_no_access_token() -> None:
    report = remus.extract_remus_memory_config(_fixture("mapped", selector_index=0, include_token=False))

    assert report["config"]["selector"]["selected_index"] == 0
    assert report["config"]["selector"]["selected_slot_is_sentinel"] is True
    assert report["config"]["runtime"]["selected_endpoint"]["present"] is True
    assert report["config"]["runtime"]["access_token"]["present"] is False


def test_selector_pattern_absence_does_not_hide_static_endpoints() -> None:
    report = remus.extract_remus_memory_config(_fixture("mapped", include_selector_pattern=False))

    assert report["config"]["selector"]["status"] == "not_recovered"
    assert len(report["config"]["endpoints"]) == 2
    assert report["config"]["runtime"]["selected_endpoint"]["present"] is False


def test_rejects_ambiguous_chacha_state() -> None:
    data = bytearray(_fixture("mapped"))
    data[0x2C00:0x2C40] = data[STATE_RVA : STATE_RVA + 0x40]

    with pytest.raises(remus.RemusMemoryConfigError, match="ChaCha state"):
        remus.extract_remus_memory_config(bytes(data))


def test_rejects_static_duplicate_with_nonce_or_padding_mismatch() -> None:
    data = bytearray(_fixture("mapped"))
    data[KEY_RVA + 40] = 1

    with pytest.raises(remus.RemusMemoryConfigError, match="key/nonce/padding"):
        remus.extract_remus_memory_config(bytes(data))


def test_rejects_config_without_none_sentinel() -> None:
    data = _fixture("mapped", first_uri="http://bad.example:80")

    with pytest.raises(remus.RemusMemoryConfigError, match="sentinel"):
        remus.extract_remus_memory_config(data)


def test_multiple_32_hex_values_make_tag_ambiguous_only() -> None:
    data = bytearray(_fixture("mapped"))
    data[0x2D00:0x2D20] = b"0123456789abcdef0123456789abcdef"
    report = remus.extract_remus_memory_config(bytes(data))

    assert report["config"]["tag"]["status"] == "ambiguous"
    assert report["config"]["tag"]["candidate_count"] == 2
    assert len(report["config"]["endpoints"]) == 2


def test_rejects_input_and_image_budget_overruns() -> None:
    data = _fixture("mapped")
    with pytest.raises(remus.RemusMemoryConfigError, match="入力サイズ"):
        remus.extract_remus_memory_config(data, max_input_bytes=len(data) - 1)
    with pytest.raises(remus.RemusMemoryConfigError, match="SizeOfImage"):
        remus.extract_remus_memory_config(data, max_image_bytes=IMAGE_SIZE - 1)


def test_rejects_overlapping_virtual_sections() -> None:
    data = bytearray(_fixture("mapped"))
    second_section = 0x98 + 0xF0 + 40
    struct.pack_into("<I", data, second_section + 12, 0x1200)

    with pytest.raises(remus.RemusMemoryConfigError, match=r"仮想.*範囲が重複"):
        remus.extract_remus_memory_config(bytes(data))


def test_rejects_truncated_file_layout() -> None:
    data = _fixture("file")[:-1]

    with pytest.raises(remus.RemusMemoryConfigError, match="file layout"):
        remus.extract_remus_memory_config(data, layout="file")


def test_rejects_non_pe_and_invalid_slot_budget() -> None:
    with pytest.raises(remus.RemusMemoryConfigError, match="MZ"):
        remus.extract_remus_memory_config(b"not a PE")
    with pytest.raises(remus.RemusMemoryConfigError, match="max_slots"):
        remus.extract_remus_memory_config(_fixture("mapped"), max_slots=0)


def test_read_bounded_rejects_size_or_mtime_change(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"stable input")
    original_fstat = os.fstat
    initial = sample.stat()
    changed = False

    def changing_fstat(file_descriptor: int) -> os.stat_result:
        nonlocal changed
        if not changed:
            os.utime(
                sample,
                ns=(initial.st_atime_ns, initial.st_mtime_ns + 1_000_000_000),
            )
            changed = True
        return original_fstat(file_descriptor)

    monkeypatch.setattr(os, "fstat", changing_fstat)
    with pytest.raises(remus.RemusMemoryConfigError, match="size/mtime"):
        remus._read_bounded(sample, 1024)


def test_read_bounded_rejects_hardlinked_input(tmp_path: Path) -> None:
    sample = tmp_path / "sample.bin"
    alias = tmp_path / "sample-hardlink.bin"
    sample.write_bytes(b"stable input")
    try:
        os.link(sample, alias)
    except OSError as exc:
        pytest.skip(f"このfilesystemではhardlinkを作成できません: {exc}")

    with pytest.raises(remus.RemusMemoryConfigError, match="単一リンク"):
        remus._read_bounded(sample, 1024)


def test_exclusive_output_rejects_existing_file(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    output = tmp_path / "report.json"
    source.write_bytes(b"sample")
    output.write_text("preserve", encoding="utf-8")

    with pytest.raises(remus.RemusMemoryConfigError, match="既存"):
        remus._write_json_exclusive(source, output, "replacement\n")

    assert output.read_text(encoding="utf-8") == "preserve"


def test_exclusive_output_rejects_same_file_identity(tmp_path: Path) -> None:
    source = tmp_path / "sample.bin"
    alias = tmp_path / "sample-hardlink.bin"
    source.write_bytes(b"sample")
    os.link(source, alias)

    with pytest.raises(remus.RemusMemoryConfigError, match="同一ファイル"):
        remus._write_json_exclusive(source, alias, "replacement\n")

    assert source.read_bytes() == b"sample"
