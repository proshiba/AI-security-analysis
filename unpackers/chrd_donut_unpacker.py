"""Unpack the reviewed CHRD/WAV resource loader through Donut and its .NET loader."""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import json
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

import dnfile
import pefile

from unpackers.donut_unpacker import DonutResult, unpack_donut


OUTER_TABLE = (0xE4D0A9CE, 0xBB3D2A3F, 0x9C9B387F, 0x8B58A5EC, 0xF64AD6AE, 0x4FA149D2, 0x77CDA856, 0x9971884C)
OUTER_SEED_BYTES = bytes.fromhex("379ea404")


@dataclass(frozen=True)
class ChrdResult:
    """Recovered CHRD chain metadata and terminal managed payload."""

    wave: bytes
    numeric_stream: bytes
    outer_blob: bytes
    donut_shellcode: bytes
    donut: DonutResult
    managed_loader: bytes
    terminal_payload: bytes
    metadata: dict


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def rol8(value: int, count: int) -> int:
    """Rotate one byte left."""
    count &= 7
    return ((value << count) | (value >> ((8 - count) & 7))) & 0xFF


def ror8(value: int, count: int) -> int:
    """Rotate one byte right."""
    count &= 7
    return ((value >> count) | (value << ((8 - count) & 7))) & 0xFF


def rol32(value: int, count: int) -> int:
    """Rotate a 32-bit integer left."""
    count &= 31
    return ((value << count) | (value >> ((32 - count) & 31))) & 0xFFFFFFFF


def pe_resources(data: bytes) -> dict[int, bytes]:
    """Return numeric PE resources keyed by ID with strict size bounds."""
    pe = pefile.PE(data=data, fast_load=False)
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return {}
    image = pe.get_memory_mapped_image()
    resources: dict[int, bytes] = {}
    for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for name in resource_type.directory.entries:
            if name.name is not None:
                continue
            for language in name.directory.entries:
                descriptor = language.data.struct
                end = descriptor.OffsetToData + descriptor.Size
                if end > len(image):
                    raise ValueError("resource exceeds mapped PE image")
                resources[int(name.struct.Id)] = bytes(image[descriptor.OffsetToData:end])
    return resources


def parse_chrd_config(config: bytes) -> dict:
    """Parse the reviewed CHRD inverse-transform configuration structure."""
    if len(config) < 0x61F or config[:4] != b"CHRD":
        raise ValueError("invalid or truncated CHRD configuration")
    offset = 0x16
    base, step = struct.unpack_from("<II", config, offset)
    offset += 8
    stride = config[offset]
    offset += 1
    group_count = struct.unpack_from("<I", config, offset)[0]
    offset += 4
    if not 1 <= group_count <= 64:
        raise ValueError("invalid CHRD transform group count")
    groups = []
    for _ in range(group_count):
        count = struct.unpack_from("<I", config, offset)[0]
        offset += 4
        if count > 64 or offset + count * 3 > len(config):
            raise ValueError("invalid CHRD transform operation count")
        groups.append([tuple(config[offset + i * 3 : offset + i * 3 + 3]) for i in range(count)])
        offset += count * 3
    permutation = config[offset : offset + 256]
    offset += 256
    lanes = [config[offset + index * 8 : offset + (index + 1) * 8] for index in range(5)]
    offset += 40
    slope = config[offset]
    offset += 1
    seed = struct.unpack_from("<I", config, offset)[0]
    offset += 4
    table = struct.unpack_from("<256I", config, offset)
    offset += 1024
    multiply, rotate, mix = struct.unpack_from("<IBI", config, offset)
    offset += 9
    if offset != len(config):
        raise ValueError("unexpected trailing CHRD configuration bytes")
    return {"version": config[4], "expected": struct.unpack_from("<I", config, 5)[0], "base": base, "step": step, "stride": stride, "groups": groups, "permutation": permutation, "lanes": lanes, "slope": slope, "seed": seed, "table": table, "multiply": multiply, "rotate": rotate, "mix": mix}


def decode_low_nibbles(resources: dict[int, bytes], first_id: int = 15000) -> bytes:
    """Join contiguous RCDATA chunks and reconstruct bytes from their low nibbles."""
    chunks = []
    resource_id = first_id
    while resource_id in resources:
        chunks.append(resources[resource_id])
        resource_id += 1
    if not chunks:
        raise ValueError("no contiguous CHRD data resources found")
    encoded = b"".join(chunks)
    if len(encoded) % 2:
        raise ValueError("CHRD nibble stream has odd length")
    return bytes(((encoded[index] & 15) << 4) | (encoded[index + 1] & 15) for index in range(0, len(encoded), 2))


def _decode_audio_payload(wave: bytes, config: dict) -> bytearray:
    skip = {0: 0x36, 1: 0x10, 2: 0x2C, 3: 8, 4: 0x10}.get(config["version"])
    if skip is None or len(wave) <= skip:
        raise ValueError("unsupported CHRD carrier version")
    data = bytearray(wave[skip:])
    state = (config["mix"] ^ len(data)) & 0xFFFFFFFF
    for index, value in enumerate(data):
        mixed = (((state ^ (state >> 16)) * 0x85EBCA6B) & 0xFFFFFFFF)
        mixed = (((mixed ^ (mixed >> 13)) * 0xC2B2AE35) & 0xFFFFFFFF)
        value = (value - ((mixed ^ (mixed >> 16)) & 0xFF)) & 0xFF
        data[index] = value
        state = rol32((state * config["multiply"] + value) & 0xFFFFFFFF, config["rotate"])
    seed = config["seed"]
    table = config["table"]
    for index, value in enumerate(data):
        next_value = table[(value ^ seed) & 0xFF]
        data[index] = (value - ((seed & 0xFF) ^ (table[(seed >> 8) & 0xFF] & 0xFF))) & 0xFF
        seed = (seed * 0x41C64E6D + next_value + 0x3039) & 0xFFFFFFFF
    operations, adds, _unused, multipliers, rotations = config["lanes"]
    for block in range(4, len(data), 0x1000):
        limit = min(block + 0x1000, len(data))
        for lane in range(8):
            for position in range(lane, limit - block, 8):
                target = block + position
                value = (data[target] - config["slope"] * position) & 0xFF
                operation = operations[lane]
                if operation == 0:
                    value = ((value - adds[lane]) * multipliers[lane]) & 0xFF
                elif operation == 1:
                    value = (ror8(value, rotations[lane]) - adds[lane]) & 0xFF
                elif operation == 2:
                    value = ((~value) + adds[lane]) & 0xFF
                elif operation == 3:
                    value = (value - adds[lane]) & 0xFF
                    value = ((value >> 4) | (value << 4)) & 0xFF
                elif operation == 4:
                    value = ror8((multipliers[lane] * value) & 0xFF, rotations[lane])
                elif operation == 5:
                    value = ((~value) * multipliers[lane]) & 0xFF
                elif operation == 6:
                    value = (rol8(value, rotations[lane]) - adds[lane]) & 0xFF
                elif operation == 7:
                    value = (adds[lane] - value) & 0xFF
                data[target] = value
    return data


def recover_numeric_stream(wave: bytes, config: dict) -> bytes:
    """Reverse CHRD audio transforms and recover the serialized numeric stream."""
    data = _decode_audio_payload(wave, config)
    expected = config["expected"]
    if len(data) < expected + 4 or struct.unpack_from("<I", data)[0] != expected:
        raise ValueError("CHRD decoded-length sentinel mismatch")
    inverse = bytearray(256)
    for index, value in enumerate(config["permutation"]):
        inverse[value] = index
    source = bytes(inverse[value] for value in data[4 : 4 + expected])
    reordered = bytearray(expected)
    cursor = 0
    for index in range(expected):
        reordered[index] = source[cursor]
        cursor = (cursor + config["step"]) % expected
    for index, value in enumerate(reordered):
        dynamic = (config["stride"] * (index & 0xFF) + (config["base"] & 0xFF)) & 0xFF
        for operation, first, second in reversed(config["groups"][(index >> 12) % len(config["groups"])]):
            if operation == 0:
                value = (value - dynamic) & 0xFF
            elif operation == 1:
                value = (value + dynamic) & 0xFF
            elif operation == 2:
                value = (value - first) & 0xFF
            elif operation == 3:
                value = (value + first) & 0xFF
            elif operation == 4:
                value = (value * second) & 0xFF
            elif operation == 5:
                value = ror8(value, first)
            elif operation == 6:
                value = rol8(value, first)
            elif operation == 7:
                value = ((value >> 4) | (value << 4)) & 0xFF
            elif operation == 8:
                value = (value - index) & 0xFF
            elif operation == 9:
                value = (value + index) & 0xFF
        reordered[index] = value
    return bytes(reordered)


def decode_numeric_stream(stream: bytes) -> bytes:
    """Expand CHRD numeric segments, including Jacobi and affine segment types."""
    try:
        import numpy as np
    except ImportError as error:
        raise RuntimeError("CHRD numeric recovery requires numpy") from error
    if len(stream) < 4:
        raise ValueError("truncated numeric stream")
    chunks = struct.unpack_from("<I", stream)[0]
    offset = 4
    output = bytearray()
    for _ in range(chunks):
        if offset + 13 > len(stream):
            raise ValueError("truncated numeric segment header")
        segment_type = stream[offset]
        count = struct.unpack_from("<I", stream, offset + 9)[0]
        cursor = offset + 13
        if segment_type == 0:
            required = count * 32 + 4
            if cursor + required > len(stream):
                raise ValueError("truncated Jacobi segment")
            tri = np.frombuffer(stream, dtype="<f8", count=count * 3, offset=cursor).reshape(count, 3)
            cursor += count * 24
            rhs = np.frombuffer(stream, dtype="<f8", count=count, offset=cursor)
            cursor += count * 8
            iterations = struct.unpack_from("<I", stream, cursor)[0]
            cursor += 4
            values = np.zeros(count, dtype=np.float64)
            for _ in range(iterations):
                neighbors = np.zeros(count, dtype=np.float64)
                neighbors[1:] += tri[1:, 1] * values[:-1]
                neighbors[:-1] += tri[:-1, 2] * values[1:]
                values = (rhs - neighbors) / tri[:, 0]
            values = (values + 0.5) * 255.0
        elif segment_type == 1:
            if cursor + count * 32 > len(stream):
                raise ValueError("truncated affine segment")
            arrays = []
            for _ in range(4):
                arrays.append(np.frombuffer(stream, dtype="<f8", count=count, offset=cursor))
                cursor += count * 8
            values = np.maximum(0.0, arrays[0] + arrays[1]) * arrays[2] + arrays[3]
        else:
            raise ValueError(f"unsupported CHRD numeric segment type: {segment_type}")
        output.extend(np.floor(np.clip(values, 0.0, 255.0) + 0.5).astype(np.uint8).tobytes())
        offset = cursor
    return bytes(output)


def decrypt_outer_blob(data: bytes, table: tuple[int, ...] = OUTER_TABLE, seed_bytes: bytes = OUTER_SEED_BYTES) -> bytes:
    """Reverse the reviewed outer loader's DWORD stream transform."""
    if len(table) != 8 or len(seed_bytes) != 4:
        raise ValueError("outer transform requires eight words and four seed bytes")
    output = bytearray(data)
    state = 0xFC57BE7A
    multiplier = 0x2BD4C30D
    for word_index in range(len(output) // 4):
        base = table[word_index & 7] ^ ((word_index * multiplier) & 0xFFFFFFFF)
        for byte_index in range(4):
            position = word_index * 4 + byte_index
            output[position] ^= (state & 0xFF) ^ (base & 0xFF) ^ seed_bytes[byte_index]
            state = rol32((state * multiplier + output[position]) & 0xFFFFFFFF, 26)
    return bytes(output)


def _user_strings(pe: dnfile.dnPE) -> list[str]:
    values = []
    heap = pe.net.user_strings
    offset = 1
    while offset < heap.sizeof():
        item = heap.get(offset, errors="replace")
        if item is None or item.raw_size <= 0:
            offset += 1
            continue
        if isinstance(item.value, str):
            values.append(item.value)
        offset += item.raw_size
    return values


def extract_managed_resource_payload(loader: bytes) -> bytes:
    """Recover a TripleDES-CBC/GZip PayloadSource resource from the managed loader."""
    try:
        from Cryptodome.Cipher import DES3
    except ImportError as error:
        raise RuntimeError("managed resource recovery requires pycryptodomex") from error
    pe = dnfile.dnPE(data=loader)
    if not pe.net or not pe.net.mdtables.ManifestResource:
        raise ValueError("managed loader has no manifest resources")
    target = next((row for row in pe.net.mdtables.ManifestResource.rows if str(row.Name) == "PayloadSource.zip"), None)
    if target is None:
        raise ValueError("PayloadSource.zip resource was not found")
    resource_offset = int(target.Offset)
    size = struct.unpack("<I", pe.get_data(pe.net.struct.ResourcesRva + resource_offset, 4))[0]
    encrypted = pe.get_data(pe.net.struct.ResourcesRva + resource_offset + 4, size)
    decoded = []
    for value in _user_strings(pe):
        try:
            raw = base64.b64decode(value, validate=True)
        except (ValueError, TypeError):
            continue
        if len(raw) in (8, 24):
            decoded.append(raw)
    keys = [item for item in decoded if len(item) == 24]
    ivs = [item for item in decoded if len(item) == 8]
    for key in keys:
        for iv in ivs:
            try:
                clear = DES3.new(key, DES3.MODE_CBC, iv).decrypt(encrypted)
                padding = clear[-1]
                if not 1 <= padding <= 8 or clear[-padding:] != bytes([padding]) * padding:
                    continue
                clear = clear[:-padding]
                expected = struct.unpack_from("<I", clear)[0]
                payload = gzip.decompress(clear[4:])
                if len(payload) == expected and payload[:2] == b"MZ":
                    return payload
            except (ValueError, EOFError, OSError, zlib.error):
                continue
    raise ValueError("no valid TripleDES/GZip resource recipe was found")


def unpack_chrd_donut(data: bytes) -> ChrdResult:
    """Recover every embedded layer through the terminal managed PureRAT payload."""
    resources = pe_resources(data)
    config = parse_chrd_config(resources.get(4000, b""))
    wave = decode_low_nibbles(resources)
    numeric_stream = recover_numeric_stream(wave, config)
    outer_blob = decode_numeric_stream(numeric_stream)
    donut_shellcode = decrypt_outer_blob(outer_blob)
    donut = unpack_donut(donut_shellcode)
    managed_loader = donut.payload
    terminal = extract_managed_resource_payload(managed_loader)
    metadata = {
        "resource_count": len([key for key in resources if 15000 <= key < 16000]),
        "wave_sha256": sha256_bytes(wave),
        "numeric_stream_sha256": sha256_bytes(numeric_stream),
        "outer_blob_sha256": sha256_bytes(outer_blob),
        "donut_shellcode_sha256": sha256_bytes(donut_shellcode),
        "managed_loader_sha256": sha256_bytes(managed_loader),
        "terminal_payload_sha256": sha256_bytes(terminal),
        "donut": donut.metadata,
    }
    return ChrdResult(wave, numeric_stream, outer_blob, donut_shellcode, donut, managed_loader, terminal, metadata)


def build_parser() -> argparse.ArgumentParser:
    """Build the reviewed CHRD/Donut chain command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--json", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the full static CHRD/Donut recovery chain."""
    args = build_parser().parse_args(argv)
    result = unpack_chrd_donut(args.input.read_bytes())
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        artifacts = {"carrier.wav": result.wave, "numeric.bin": result.numeric_stream, "outer.bin": result.outer_blob, "donut.bin": result.donut_shellcode, "managed-loader.exe": result.managed_loader, "terminal-payload.bin": result.terminal_payload}
        for name, content in artifacts.items():
            (args.output_dir / name).write_bytes(content)
    report = {**result.metadata, "executed": False, "network_contacted": False}
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())