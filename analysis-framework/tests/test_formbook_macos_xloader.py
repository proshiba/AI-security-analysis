"""macOS版XLoaderのfail-closed静的抽出器を人工dataで検証する。"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK = ROOT / "analysis-framework"
if str(FRAMEWORK) not in sys.path:
    sys.path.insert(0, str(FRAMEWORK))

from malware.formbook_loader import macos_xloader as MACOS  # noqa: E402
from malware.formbook_loader import extract_config as FORMBOOK_EXTRACT  # noqa: E402


def _minimal_macho(*, trailer: bytes = b"") -> bytes:
    """LC_UNIXTHREAD entryを持つ最小64-bit x86_64 Mach-Oを作る。"""

    image_size = 0x200
    vmaddr = 0x100000000
    segment = struct.pack(
        "<II16sQQQQIIII",
        MACOS.LC_SEGMENT_64,
        72,
        b"__TEXT".ljust(16, b"\x00"),
        vmaddr,
        image_size,
        0,
        image_size,
        7,
        5,
        0,
        0,
    )
    registers = [0] * 21
    registers[16] = vmaddr + 0x180
    unix_thread = (
        struct.pack("<4I", MACOS.LC_UNIXTHREAD, 184, 4, 42)
        + struct.pack("<21Q", *registers)
    )
    commands = segment + unix_thread
    header = struct.pack(
        "<IiiIIIII",
        MACOS.MACHO64_LE_MAGIC,
        MACOS.CPU_TYPE_X86_64,
        3,
        MACOS.MH_EXECUTE,
        2,
        len(commands),
        0,
        0,
    )
    return (header + commands).ljust(image_size, b"\x90") + trailer


def test_decode_encbuf_layout_recovers_operands_without_execution() -> None:
    encoded = (
        MACOS.ENCODED_PROLOGUE
        + b"\x80\xc0A"  # imm8 operand
        + b"\x68BCDE"  # imm32 operand
        + b"\x90"  # direct opcode byte
    )

    assert MACOS.decode_encbuf_layout(encoded, 6) == b"ABCDE\x90"


def test_decode_encbuf_layout_matches_original_logical_length_truncation() -> None:
    # 元routineは最後の4-byte operand全体をcopyしてからlogical lengthで利用する。
    encoded = MACOS.ENCODED_PROLOGUE + b"\x85\x00\x00ABCD"

    assert MACOS.decode_encbuf_layout(encoded, 2) == b"AB"


@pytest.mark.parametrize(
    "encoded",
    (
        b"not-a-prologue",
        MACOS.ENCODED_PROLOGUE + b"\x06",
        MACOS.ENCODED_PROLOGUE + b"\x68\x01",
    ),
)
def test_decode_encbuf_layout_rejects_unreviewed_or_truncated_shapes(
    encoded: bytes,
) -> None:
    with pytest.raises(MACOS.MacOSXLoaderError):
        MACOS.decode_encbuf_layout(encoded, 4)


def test_parse_macho_accepts_only_valid_bounded_pkcs7_trailer() -> None:
    canonical = _minimal_macho()
    padded = _minimal_macho(trailer=b"\x10" * 16)

    plain_view = MACOS.parse_macho_view(canonical)
    padded_view = MACOS.parse_macho_view(padded)

    assert plain_view.entry_file_offset == 0x180
    assert plain_view.trailing_padding_size == 0
    assert padded_view.canonical == canonical
    assert padded_view.canonical_sha256 == hashlib.sha256(canonical).hexdigest()
    assert padded_view.trailing_padding_size == 16


@pytest.mark.parametrize("trailer", (b"\x00", b"\x10" * 15, b"A" * 17))
def test_parse_macho_rejects_unknown_trailing_data(trailer: bytes) -> None:
    with pytest.raises(MACOS.MacOSXLoaderError):
        MACOS.parse_macho_view(_minimal_macho(trailer=trailer))


def test_decrypt_collection_record_parser_can_be_tested_without_crypto(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(MACOS, "decrypt_rc4_sub", lambda data, _key: data)
    stream = b"\x03abc\x02de"
    master = b"M" * 20

    records, chain_keys, item_keys = MACOS.decrypt_encbuf_collection(
        (stream,) * 5,
        (b"F" * 20,) * 5,
        master,
    )

    assert records == ((b"abc", b"de"),) * 5
    assert chain_keys == (master,) * 5
    assert item_keys == (master,) * 5


def test_sha1_state_memory_uses_little_endian_dwords() -> None:
    assert MACOS._sha1_state_memory(b"abc").hex() == (
        "363e99a96a81064771253eba6cc250789dd8d09c"
    )


def test_formbook_one_shot_routes_macho_without_running_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = {"family": "xloader", "platform": "macos"}
    monkeypatch.setattr(
        FORMBOOK_EXTRACT,
        "extract_reviewed_macos_xloader",
        lambda _data: (expected, {"keys": {"raw": "private"}}),
    )

    assert FORMBOOK_EXTRACT.extract_config(b"\xcf\xfa\xed\xfe" + b"synthetic") == expected


def test_reviewed_profile_keeps_raw_keys_out_of_public_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = MACOS.MACOS_XLOADER_1_1
    full_sha256 = next(iter(profile.accepted_full_sha256))
    view = MACOS.MachOView(
        canonical=b"synthetic",
        canonical_sha256=profile.canonical_sha256,
        full_sha256=full_sha256,
        declared_file_size=len(b"synthetic"),
        trailing_padding_size=0,
        cpu_type=MACOS.CPU_TYPE_X86_64,
        file_type=MACOS.MH_EXECUTE,
        command_count=1,
        entry_file_offset=profile.entry_file_offset,
        segments=(),
        symbols=(
            "radr://5614542",
            "__mh_execute_header",
            "_dlsym",
            "dyld_stub_binder",
        ),
    )
    monkeypatch.setattr(MACOS, "parse_macho_view", lambda _data: view)
    decoded_values: list[bytes] = []
    for spec in profile.data_buffers:
        decoded_values.extend((b"D" * spec.decoded_length, b"F" * 20))
    decoded_values.extend((b"M" * 20, b"C" * 20))
    decoded_iterator = iter(decoded_values)
    monkeypatch.setattr(
        MACOS,
        "_decode_accessor",
        lambda *_args, **_kwargs: next(decoded_iterator),
    )
    records = (
        (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",),
        (b"dlsym", b"ptrace", b"sqlite3_open", b"PK11SDR_Decrypt"),
        (
            b"htons",
            b"socket",
            b"setsockopt",
            b"getaddrinfo",
            b"send",
            b"recv",
            b"connect",
            b"close",
        ),
        tuple(f"d{index}.example.com".encode("ascii") for index in range(64)),
        (b"www.iregentos.info/09rb/", b"/09rb/"),
    )
    monkeypatch.setattr(
        MACOS,
        "decrypt_encbuf_collection",
        lambda *_args, **_kwargs: (records, (b"K" * 20,) * 5, (b"I" * 20,) * 5),
    )

    public, private = MACOS.extract_reviewed_macos_xloader(b"synthetic")

    assert public["config"]["primary_c2"] == "http://www.iregentos.info/09rb/"
    assert "common_c2_key_hex" not in public["config"]
    assert public["safety"]["raw_keys_included"] is False
    assert private["keys"]["common_c2_key_hex"] == (b"C" * 20).hex()
