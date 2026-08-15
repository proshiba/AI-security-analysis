"""Onyx Qtローダーの埋め込みshellcodeを実行せず静的復元する。

対象形式は、安定順序Huffman、改変ChaCha20、独自LZの3層で構成される。
GPU処理はChaCha20鍵流とのXORを行うため、等価な変換をPythonで再現する。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import struct
from dataclasses import dataclass
from pathlib import Path

MAX_INPUT_SIZE = 32 * 1024 * 1024
MAX_HUFFMAN_SIZE = 8 * 1024 * 1024
MAX_DECODED_SIZE = 64 * 1024 * 1024
MAX_MARKER_SKIP = 0x80
MAX_TERMINAL_CONFIG_SIZE = 0x10000
ONYX_TERMINAL_CONFIG_SIZE = 0xA94
ONYX_TERMINAL_SLOT_SIZE = 0x10C
ONYX_TERMINAL_SLOT_COUNT = 4


def _is_reparse_point(metadata: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & flag)


def _read_bounded_regular_file(path: Path, *, maximum_size: int) -> bytes:
    """単一の通常ファイルだけを、事前検証した上限内で読み込む。"""

    if maximum_size <= 0:
        raise ValueError("maximum_size は正の値である必要があります")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"入力ファイルを確認できません: {path}") from exc
    if path.is_symlink() or _is_reparse_point(metadata):
        raise ValueError("入力にsymlinkまたはreparse pointは使用できません")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("入力は通常ファイルである必要があります")
    if metadata.st_size > maximum_size:
        raise ValueError("入力ファイルが許容サイズを超えています")

    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_reparse_point(opened)
                or not os.path.samestat(metadata, opened)
                or opened.st_size > maximum_size
            ):
                raise ValueError("検証後に入力ファイルの同一性または属性が変化しました")
            data = handle.read(maximum_size + 1)
    except OSError as exc:
        raise ValueError(f"入力ファイルを安全に読み込めません: {path}") from exc
    if len(data) > maximum_size or len(data) != opened.st_size:
        raise ValueError("読込中に入力ファイルのサイズが変化しました")
    return data


def sha256_bytes(data: bytes) -> str:
    """バイト列のSHA-256を返す。"""
    return hashlib.sha256(data).hexdigest()


def matches_onyx_qt_profile(data: bytes) -> bool:
    """誤検知を抑えたOnyx Qtローダーの外層preflightを返す。"""
    if len(data) > MAX_INPUT_SIZE:
        return False
    onyx = b"Onyx" in data or "Onyx".encode("utf-16le") in data
    d3d = b"D3DCompile" in data or b"d3dcompiler" in data.lower()
    return onyx and d3d


@dataclass(frozen=True)
class _HuffmanNode:
    symbol: int
    weight: int
    left: _HuffmanNode | None = None
    right: _HuffmanNode | None = None


class _StableMinHeap:
    """検体実装と同じ同値保持規則を使う最小ヒープ。"""

    def __init__(self) -> None:
        self._items: list[_HuffmanNode] = []

    def __len__(self) -> int:
        return len(self._items)

    def push(self, node: _HuffmanNode) -> None:
        index = len(self._items)
        self._items.append(node)
        while index:
            parent = (index - 1) // 2
            if node.weight >= self._items[parent].weight:
                break
            self._items[index] = self._items[parent]
            index = parent
        self._items[index] = node

    def pop(self) -> _HuffmanNode:
        if not self._items:
            raise ValueError("empty Huffman heap")
        root = self._items[0]
        tail = self._items.pop()
        if not self._items:
            return root
        index = 0
        while True:
            child = index * 2 + 1
            if child >= len(self._items):
                break
            right = child + 1
            if (
                right < len(self._items)
                and self._items[right].weight < self._items[child].weight
            ):
                child = right
            if tail.weight <= self._items[child].weight:
                break
            self._items[index] = self._items[child]
            index = child
        self._items[index] = tail
        return root


@dataclass(frozen=True)
class HuffmanEnvelope:
    marker_offset: int
    marker_skip: int
    compressed_offset: int
    compressed_size: int


@dataclass(frozen=True)
class OnyxQtRecovery:
    """検証済み静的復元結果。鍵の生値は公開しない。"""

    payload: bytes
    input_sha256: str
    huffman_offset: int
    huffman_compressed_size: int
    huffman_decoded_size: int
    huffman_decoded_sha256: str
    key_size: int
    key_sha256: str
    encrypted_size: int
    transformed_sha256: str
    payload_sha256: str

    def metadata(self) -> dict[str, object]:
        """公開可能な復元メタデータを返す。"""
        metadata: dict[str, object] = {
            "schema_version": 1,
            "status": "shellcode_recovered",
            "component": "onyx_qt_loader",
            "family_attribution": "unresolved_component_only",
            "input_sha256": self.input_sha256,
            "huffman_offset": self.huffman_offset,
            "huffman_compressed_size": self.huffman_compressed_size,
            "huffman_decoded_size": self.huffman_decoded_size,
            "huffman_decoded_sha256": self.huffman_decoded_sha256,
            "key_size": self.key_size,
            "key_sha256": self.key_sha256,
            "raw_key_included": False,
            "encrypted_size": self.encrypted_size,
            "transformed_sha256": self.transformed_sha256,
            "payload_size": len(self.payload),
            "payload_sha256": self.payload_sha256,
            "transforms": [
                "stable_huffman_be_frequency_table",
                "modified_chacha20_gpu_xor",
                "onyx_lz",
            ],
            "executed": False,
            "network_contacted": False,
        }
        terminal_config = recover_onyx_terminal_config(self.payload)
        metadata["terminal_config_recovery"] = (
            terminal_config.metadata()
            if terminal_config is not None
            else {
                "status": "not_recovered",
                "executed": False,
                "network_contacted": False,
            }
        )
        return metadata


@dataclass(frozen=True)
class OnyxTerminalConfig:
    """終端シェルコードから検証した設定。設定本体と鍵の生値は保持しない。"""

    marker_offset: int
    encrypted_size: int
    encrypted_sha256: str
    key_sha256: str
    config_size: int
    config_sha256: str
    host: str
    port: int
    transport: str
    repeated_slot_count: int

    def metadata(self) -> dict[str, object]:
        """C2検知へ渡せる公開メタデータを返す。"""
        return {
            "status": "static_config_recovered",
            "marker_offset": self.marker_offset,
            "encrypted_size": self.encrypted_size,
            "encrypted_sha256": self.encrypted_sha256,
            "key_sha256": self.key_sha256,
            "raw_key_included": False,
            "config_size": self.config_size,
            "config_sha256": self.config_sha256,
            "raw_config_included": False,
            "host": self.host,
            "port": self.port,
            "transport": self.transport,
            "repeated_slot_count": self.repeated_slot_count,
            "endpoints": [
                {
                    "host": self.host,
                    "port": self.port,
                    "transport": self.transport.lower(),
                    "role": "control",
                    "evidence": "confirmed_static_config",
                }
            ],
            "executed": False,
            "network_contacted": False,
        }


def find_huffman_envelopes(data: bytes) -> list[HuffmanEnvelope]:
    """境界と頻度総和を検証してHuffman envelopeを列挙する。"""
    found: list[HuffmanEnvelope] = []
    if len(data) < 0x40A or len(data) > MAX_INPUT_SIZE:
        return found
    end = len(data) - (4 + 0x404)
    for marker_offset in range(end):
        marker_skip = data[marker_offset]
        if not 1 <= marker_skip <= MAX_MARKER_SKIP:
            continue
        length_offset = marker_offset + 1 + marker_skip
        if length_offset + 4 + 0x404 > len(data):
            continue
        compressed_size = struct.unpack_from("<I", data, length_offset)[0]
        if not 0x404 <= compressed_size <= MAX_HUFFMAN_SIZE:
            continue
        compressed_offset = length_offset + 4
        if compressed_offset + compressed_size > len(data):
            continue
        expected = struct.unpack_from(">I", data, compressed_offset + 0x400)[0]
        if not 1 <= expected <= MAX_DECODED_SIZE:
            continue
        frequencies = struct.unpack_from(">256I", data, compressed_offset)
        if sum(frequencies) != expected:
            continue
        found.append(
            HuffmanEnvelope(
                marker_offset,
                marker_skip,
                compressed_offset,
                compressed_size,
            )
        )
    return found


def stable_huffman_decode(compressed: bytes) -> bytes:
    """安定ヒープ順序とMSB-first bitstreamで復号する。"""
    if not 0x404 <= len(compressed) <= MAX_HUFFMAN_SIZE:
        raise ValueError("invalid Huffman size")
    frequencies = struct.unpack_from(">256I", compressed)
    expected = struct.unpack_from(">I", compressed, 0x400)[0]
    if not 1 <= expected <= MAX_DECODED_SIZE or sum(frequencies) != expected:
        raise ValueError("invalid Huffman frequency total")
    heap = _StableMinHeap()
    for symbol, weight in enumerate(frequencies):
        if weight:
            heap.push(_HuffmanNode(symbol, weight))
    if not len(heap):
        raise ValueError("empty Huffman tree")
    if len(heap) == 1:
        node = heap.pop()
        return bytes([node.symbol]) * expected
    while len(heap) > 1:
        left, right = heap.pop(), heap.pop()
        heap.push(_HuffmanNode(-1, left.weight + right.weight, left, right))
    root = heap.pop()
    node = root
    output = bytearray()
    for value in compressed[0x404:]:
        for bit_index in range(7, -1, -1):
            node = node.right if (value >> bit_index) & 1 else node.left
            if node is None:
                raise ValueError("invalid Huffman edge")
            if node.left is None and node.right is None:
                output.append(node.symbol)
                if len(output) == expected:
                    return bytes(output)
                node = root
    raise ValueError("truncated Huffman bitstream")


def _rotate_left(value: int, count: int) -> int:
    return ((value << count) & 0xFFFFFFFF) | (value >> (32 - count))


def _quarter_round(state: list[int], a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotate_left(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotate_left(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotate_left(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotate_left(state[b] ^ state[c], 7)


def modified_chacha20_transform(key: bytes, data: bytes) -> bytes:
    """64-bit nonce型ChaCha20とGPU XORマスクを等価に再現する。"""
    if not key or len(key) > 32:
        raise ValueError("invalid ChaCha key size")
    padded_key = key + b"\0" * (32 - len(key))
    state = [
        0x61707865,
        0x3320646E,
        0x79622D32,
        0x6B206574,
        *struct.unpack("<8I", padded_key),
        1,
        0,
        *struct.unpack("<2I", padded_key[:8]),
    ]
    output = bytearray()
    position = 0
    while position < len(data):
        working = state.copy()
        for _ in range(10):
            _quarter_round(working, 0, 4, 8, 12)
            _quarter_round(working, 1, 5, 9, 13)
            _quarter_round(working, 2, 6, 10, 14)
            _quarter_round(working, 3, 7, 11, 15)
            _quarter_round(working, 0, 5, 10, 15)
            _quarter_round(working, 1, 6, 11, 12)
            _quarter_round(working, 2, 7, 8, 13)
            _quarter_round(working, 3, 4, 9, 14)
        keystream = struct.pack(
            "<16I",
            *((working[index] + state[index]) & 0xFFFFFFFF for index in range(16)),
        )
        block = data[position : position + 64]
        output.extend(
            value if index % 3 == 0 else value ^ keystream[index]
            for index, value in enumerate(block)
        )
        position += len(block)
        state[12] = (state[12] + 1) & 0xFFFFFFFF
        if state[12] == 0:
            state[13] = (state[13] + 1) & 0xFFFFFFFF
    return bytes(output)


def _match_length_bits(size: int) -> int:
    for threshold, bits in (
        (0x10, 12),
        (0x20, 11),
        (0x40, 10),
        (0x80, 9),
        (0x100, 8),
        (0x200, 7),
        (0x400, 6),
        (0x800, 5),
    ):
        if size < threshold:
            return bits
    return 4


def onyx_lz_decompress(data: bytes, *, output_limit: int | None = None) -> bytes:
    """Onyx独自LZ block streamを境界検証付きで復号する。"""
    limit = output_limit if output_limit is not None else min(
        MAX_DECODED_SIZE, len(data) * 2
    )
    output = bytearray()
    position = 0
    while position + 1 < len(data):
        token = struct.unpack_from("<H", data, position)[0]
        position += 2
        if token == 0:
            break
        block_size = (token & 0x0FFF) + 1
        block_end = position + block_size
        if block_end > len(data):
            raise ValueError("truncated Onyx LZ block")
        block_output_base = len(output)
        if not token & 0x8000:
            if len(output) + block_size > limit:
                raise ValueError("Onyx LZ output limit exceeded")
            output.extend(data[position:block_end])
            position = block_end
            continue
        while position < block_end:
            flags = data[position]
            position += 1
            for bit_index in range(8):
                if position >= block_end:
                    break
                if not (flags >> bit_index) & 1:
                    if len(output) >= limit:
                        raise ValueError("Onyx LZ output limit exceeded")
                    output.append(data[position])
                    position += 1
                    continue
                if position + 2 > block_end:
                    raise ValueError("truncated Onyx LZ match")
                match = struct.unpack_from("<H", data, position)[0]
                position += 2
                block_output_size = len(output) - block_output_base
                if not block_output_size:
                    raise ValueError("Onyx LZ match before literal")
                bits = _match_length_bits(block_output_size)
                match_length = (match & ((1 << bits) - 1)) + 3
                distance = (match >> bits) + 1
                if distance > len(output) or len(output) + match_length > limit:
                    raise ValueError("invalid Onyx LZ match")
                for _ in range(match_length):
                    output.append(output[-distance])
    if not output:
        raise ValueError("empty Onyx LZ output")
    return bytes(output)


def xor_swap_stream_transform(key: bytes, data: bytes) -> bytes:
    """終端が使うRC4類似のXOR-swap streamを等価に適用する。"""
    if not key or len(key) > 0x100:
        raise ValueError("invalid XOR-swap key size")
    state = list(range(0x100))
    swap_index = 0
    for index in range(0x100):
        swap_index = (swap_index + state[index] + key[index % len(key)]) & 0xFF
        state[index], state[swap_index] = state[swap_index], state[index]
    index = 0
    swap_index = 0
    output = bytearray()
    for value in data:
        index = (index + 1) & 0xFF
        swap_index = (swap_index + state[index]) & 0xFF
        state[index], state[swap_index] = state[swap_index], state[index]
        output.append(value ^ state[index] ^ state[swap_index])
    return bytes(output)


def _decode_terminal_slot(config: bytes, offset: int) -> tuple[str, int, str] | None:
    end = offset + ONYX_TERMINAL_SLOT_SIZE
    if end > len(config):
        return None
    host_raw = config[offset : offset + 0x100].split(b"\0", 1)[0]
    try:
        host = host_raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    if not host or len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        return None
    port = struct.unpack_from("<H", config, offset + 0x100)[0]
    if not 1 <= port <= 0xFFFF:
        return None
    transport_raw = config[offset + 0x102 : end]
    try:
        transport = transport_raw.decode("utf-16le").rstrip("\0")
    except UnicodeDecodeError:
        return None
    if transport not in {"HTTP", "HTTPS", "TCP"}:
        return None
    return host, port, transport


def recover_onyx_terminal_config(shellcode: bytes) -> OnyxTerminalConfig | None:
    """終端シェルコードのmarker、暗号、LZ、反復slotを検証して設定を復元する。"""
    recovered: dict[str, OnyxTerminalConfig] = {}
    scan_end = min(len(shellcode), 0x1000)
    for marker_offset in range(max(0, scan_end - 12)):
        marker = shellcode[marker_offset : marker_offset + 8]
        if (
            len(marker) != 8
            or marker[0] != 0xFE
            or marker[1] != 0xFA
            or marker[7] != 0xFF
            or sum(marker) != 0x708
        ):
            continue
        encrypted_size = struct.unpack_from("<I", shellcode, marker_offset + 8)[0]
        encrypted_start = marker_offset + 12
        encrypted_end = encrypted_start + encrypted_size
        if not 2 <= encrypted_size <= MAX_TERMINAL_CONFIG_SIZE:
            continue
        if encrypted_end > len(shellcode):
            continue
        encrypted = shellcode[encrypted_start:encrypted_end]
        try:
            transformed = xor_swap_stream_transform(marker, encrypted)
            config = onyx_lz_decompress(
                transformed,
                output_limit=ONYX_TERMINAL_CONFIG_SIZE,
            )
        except ValueError:
            continue
        if len(config) != ONYX_TERMINAL_CONFIG_SIZE:
            continue
        slots = [
            _decode_terminal_slot(config, index * ONYX_TERMINAL_SLOT_SIZE)
            for index in range(ONYX_TERMINAL_SLOT_COUNT)
        ]
        if any(slot is None for slot in slots):
            continue
        typed_slots = [slot for slot in slots if slot is not None]
        if len(set(typed_slots)) != 1:
            continue
        host, port, transport = typed_slots[0]
        item = OnyxTerminalConfig(
            marker_offset=marker_offset,
            encrypted_size=encrypted_size,
            encrypted_sha256=sha256_bytes(encrypted),
            key_sha256=sha256_bytes(marker),
            config_size=len(config),
            config_sha256=sha256_bytes(config),
            host=host,
            port=port,
            transport=transport,
            repeated_slot_count=len(typed_slots),
        )
        recovered[item.config_sha256] = item
    return next(iter(recovered.values())) if len(recovered) == 1 else None


def recover_onyx_qt_payload(data: bytes) -> OnyxQtRecovery | None:
    """一意に検証できるOnyx Qt shellcodeを静的復元する。"""
    if not matches_onyx_qt_profile(data):
        return None
    recovered: list[OnyxQtRecovery] = []
    for envelope in find_huffman_envelopes(data):
        compressed = data[
            envelope.compressed_offset : envelope.compressed_offset
            + envelope.compressed_size
        ]
        try:
            decoded = stable_huffman_decode(compressed)
            key_size = decoded[0]
            if not 1 <= key_size <= 32 or len(decoded) < key_size + 5:
                continue
            key = decoded[1 : 1 + key_size]
            encrypted_size = struct.unpack_from("<I", decoded, 1 + key_size)[0]
            encrypted = decoded[5 + key_size :]
            if not encrypted_size or encrypted_size != len(encrypted):
                continue
            transformed = modified_chacha20_transform(key, encrypted)
            payload = onyx_lz_decompress(
                transformed,
                output_limit=min(MAX_DECODED_SIZE, encrypted_size * 2),
            )
        except (IndexError, struct.error, ValueError):
            continue
        recovered.append(
            OnyxQtRecovery(
                payload,
                sha256_bytes(data),
                envelope.compressed_offset,
                envelope.compressed_size,
                len(decoded),
                sha256_bytes(decoded),
                key_size,
                sha256_bytes(key),
                encrypted_size,
                sha256_bytes(transformed),
                sha256_bytes(payload),
            )
        )
    unique = {item.payload_sha256: item for item in recovered}
    return next(iter(unique.values())) if len(unique) == 1 else None


def build_parser() -> argparse.ArgumentParser:
    """非実行型復元器のCLI parserを構築する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="復元shellcodeの任意出力先")
    parser.add_argument("--report", type=Path, help="公開可能JSONの任意出力先")
    return parser


def main(argv: list[str] | None = None) -> int:
    """検体を実行せず、要求された成果物だけを書き出す。"""
    args = build_parser().parse_args(argv)
    result = recover_onyx_qt_payload(
        _read_bounded_regular_file(args.input, maximum_size=MAX_INPUT_SIZE)
    )
    if result is None:
        raise SystemExit("supported Onyx Qt loader envelope was not recovered")
    metadata = result.metadata()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(result.payload)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(
            json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
    print(json.dumps(metadata, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
