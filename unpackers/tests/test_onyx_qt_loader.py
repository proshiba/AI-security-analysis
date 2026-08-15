from __future__ import annotations

from collections import Counter
import struct

import pytest

from unpackers.onyx_qt_loader import (
    _HuffmanNode,
    _StableMinHeap,
    _read_bounded_regular_file,
    matches_onyx_qt_profile,
    modified_chacha20_transform,
    onyx_lz_decompress,
    recover_onyx_terminal_config,
    recover_onyx_qt_payload,
    sha256_bytes,
    xor_swap_stream_transform,
)
from unpackers.static_unpacker import unpack_bytes


def _huffman_encode(data: bytes) -> bytes:
    frequencies = [0] * 256
    for value, count in Counter(data).items():
        frequencies[value] = count
    heap = _StableMinHeap()
    for symbol, weight in enumerate(frequencies):
        if weight:
            heap.push(_HuffmanNode(symbol, weight))
    while len(heap) > 1:
        left, right = heap.pop(), heap.pop()
        heap.push(_HuffmanNode(-1, left.weight + right.weight, left, right))
    root = heap.pop()
    codes: dict[int, list[int]] = {}

    def visit(node: _HuffmanNode, bits: list[int]) -> None:
        if node.left is None and node.right is None:
            codes[node.symbol] = bits or [0]
            return
        assert node.left is not None and node.right is not None
        visit(node.left, [*bits, 0])
        visit(node.right, [*bits, 1])

    visit(root, [])
    bits = [bit for value in data for bit in codes[value]]
    bitstream = bytearray()
    for offset in range(0, len(bits), 8):
        chunk = bits[offset : offset + 8]
        value = 0
        for bit in chunk:
            value = (value << 1) | bit
        bitstream.append(value << (8 - len(chunk)))
    return (
        struct.pack(">256I", *frequencies)
        + struct.pack(">I", len(data))
        + bytes(bitstream)
    )


def _literal_lz(payload: bytes) -> bytes:
    assert 1 <= len(payload) <= 0x1000
    return struct.pack("<H", len(payload) - 1) + payload + b"\0\0"


def _fixture(payload: bytes) -> bytes:
    key = bytes(range(32))
    compressed_stage = _literal_lz(payload)
    encrypted = modified_chacha20_transform(key, compressed_stage)
    envelope = bytes([len(key)]) + key + struct.pack("<I", len(encrypted)) + encrypted
    huffman = _huffman_encode(envelope)
    marker = b"\x04ABCD" + struct.pack("<I", len(huffman)) + huffman
    return b"MZ\0Onyx agent\0D3DCompile\0" + marker


def test_modified_chacha_transform_is_symmetric() -> None:
    key = bytes(range(32))
    data = bytes(range(255))
    transformed = modified_chacha20_transform(key, data)
    assert transformed != data
    assert modified_chacha20_transform(key, transformed) == data


def test_onyx_lz_literal_block() -> None:
    assert onyx_lz_decompress(_literal_lz(b"terminal-shellcode")) == b"terminal-shellcode"


def test_full_static_recovery() -> None:
    payload = b"\x48\x83\xec\x28" + b"static-shellcode" * 24
    source = _fixture(payload)
    result = recover_onyx_qt_payload(source)
    assert result is not None
    assert result.payload == payload
    assert result.payload_sha256 == sha256_bytes(payload)
    assert result.metadata()["raw_key_included"] is False
    assert result.metadata()["executed"] is False


def test_static_unpacker_routes_recovered_shellcode() -> None:
    payload = b"\x48\x83\xec\x28" + b"one-shot-static" * 20
    source = b"DATA" + _fixture(payload)[2:]
    report, artifacts = unpack_bytes(source, name="onyx-fixture.bin")
    assert report["onyx_qt_loader"]["status"] == "shellcode_recovered"
    assert report["onyx_qt_loader"]["payload_sha256"] == sha256_bytes(payload)
    assert ("onyx-qt-shellcode", payload) in artifacts


def test_profile_and_corruption_fail_closed() -> None:
    source = _fixture(b"\x90" * 128)
    assert matches_onyx_qt_profile(source)
    assert recover_onyx_qt_payload(source[:-1]) is None
    assert recover_onyx_qt_payload(
        source.replace(b"D3DCompile", b"NoGpuMarker")
    ) is None


def test_cli_reader_rejects_non_regular_oversized_and_reparse_inputs(
    tmp_path, monkeypatch
) -> None:
    with pytest.raises(ValueError, match="通常ファイル"):
        _read_bounded_regular_file(tmp_path, maximum_size=4)

    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"12345")
    with pytest.raises(ValueError, match="許容サイズ"):
        _read_bounded_regular_file(sample, maximum_size=4)
    assert _read_bounded_regular_file(sample, maximum_size=5) == b"12345"

    monkeypatch.setattr(type(sample), "is_symlink", lambda _self: True)
    with pytest.raises(ValueError, match="reparse point"):
        _read_bounded_regular_file(sample, maximum_size=8)


def _terminal_config_fixture() -> tuple[bytes, bytes]:
    slot = (
        b"utuhv.cn".ljust(0x100, b"\0")
        + struct.pack("<H", 8080)
        + "HTTP".encode("utf-16le")
        + b"\0\0"
    )
    config = (slot * 4).ljust(0xA94, b"\0")
    compressed = _literal_lz(config)
    marker = bytes.fromhex("fefaff93a9e4f2ff")
    encrypted = xor_swap_stream_transform(marker, compressed)
    shellcode = (
        b"\x90" * 0x200
        + marker
        + struct.pack("<I", len(encrypted))
        + encrypted
    )
    return shellcode, config


def test_terminal_config_static_recovery() -> None:
    shellcode, config = _terminal_config_fixture()
    result = recover_onyx_terminal_config(shellcode)
    assert result is not None
    assert result.host == "utuhv.cn"
    assert result.port == 8080
    assert result.transport == "HTTP"
    assert result.repeated_slot_count == 4
    assert result.config_sha256 == sha256_bytes(config)
    assert result.metadata()["raw_key_included"] is False
    assert result.metadata()["raw_config_included"] is False


def test_terminal_config_rejects_mismatched_slots() -> None:
    shellcode, _ = _terminal_config_fixture()
    marker_offset = 0x200
    encrypted_size = struct.unpack_from("<I", shellcode, marker_offset + 8)[0]
    encrypted = shellcode[
        marker_offset + 12 : marker_offset + 12 + encrypted_size
    ]
    marker = shellcode[marker_offset : marker_offset + 8]
    compressed = xor_swap_stream_transform(marker, encrypted)
    config = bytearray(onyx_lz_decompress(compressed, output_limit=0xA94))
    config[0x10C] = ord("x")
    mutated_compressed = _literal_lz(bytes(config))
    mutated_encrypted = xor_swap_stream_transform(marker, mutated_compressed)
    sample = (
        shellcode[: marker_offset + 8]
        + struct.pack("<I", len(mutated_encrypted))
        + mutated_encrypted
    )
    assert recover_onyx_terminal_config(sample) is None
