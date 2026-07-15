"""Statically recover embedded modules from legacy and modern Donut shellcode."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DonutLayout:
    """Offsets for one observed Donut instance layout."""

    name: str
    crypt_start: int
    api_count: int
    dll_names: int
    instance_type: int
    module_length: int
    module: int


@dataclass(frozen=True)
class DonutResult:
    """Recovered Donut metadata and bytes without executing loader code."""

    layout: str
    instance: bytes
    module: bytes
    payload: bytes
    metadata: dict


LAYOUTS = (
    DonutLayout("modern-0x290", 0x290, 0x290, 0x294, 0x974, 0xDA8, 0xDB0),
    DonutLayout("legacy-0x23c", 0x23C, 0x23C, 0x240, 0x920, 0xD58, 0xD60),
)


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def rotr32(value: int, count: int) -> int:
    """Rotate a 32-bit integer right."""
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def chaskey_block(key: bytes, block: bytes) -> bytes:
    """Apply Donut's 16-round Chaskey permutation to one 16-byte block."""
    if len(key) != 16 or len(block) != 16:
        raise ValueError("Chaskey key and block must be 16 bytes")
    words = list(struct.unpack("<4I", block))
    master = struct.unpack("<4I", key)
    for index in range(4):
        words[index] ^= master[index]
    for _ in range(16):
        words[0] = (words[0] + words[1]) & 0xFFFFFFFF
        words[1] = rotr32(words[1], 27) ^ words[0]
        words[2] = (words[2] + words[3]) & 0xFFFFFFFF
        words[3] = rotr32(words[3], 24) ^ words[2]
        words[2] = (words[2] + words[1]) & 0xFFFFFFFF
        words[0] = (rotr32(words[0], 16) + words[3]) & 0xFFFFFFFF
        words[3] = rotr32(words[3], 19) ^ words[0]
        words[1] = rotr32(words[1], 25) ^ words[2]
        words[2] = rotr32(words[2], 16)
    for index in range(4):
        words[index] ^= master[index]
    return struct.pack("<4I", *words)


def chaskey_ctr(key: bytes, counter: bytes, data: bytes) -> bytes:
    """Encrypt or decrypt bytes with Donut's big-endian-counter Chaskey CTR."""
    if len(counter) != 16:
        raise ValueError("counter must be 16 bytes")
    output = bytearray(data)
    current = bytearray(counter)
    for offset in range(0, len(output), 16):
        stream = chaskey_block(key, current)
        count = min(16, len(output) - offset)
        for index in range(count):
            output[offset + index] ^= stream[index]
        for index in range(15, -1, -1):
            current[index] = (current[index] + 1) & 0xFF
            if current[index]:
                break
    return bytes(output)


def is_donut_shellcode(data: bytes) -> bool:
    """Return true when bytes have Donut's call-over-instance layout."""
    if len(data) < 10 or data[0] != 0xE8:
        return False
    length = struct.unpack_from("<I", data, 1)[0]
    code = 5 + length
    return 0 < length <= len(data) - 5 and data[code : code + 5] == b"YU\x48\x89\xe5"


def _ascii_field(data: bytes, offset: int, size: int = 256) -> str:
    return data[offset : offset + size].split(b"\0", 1)[0].decode("ascii", errors="replace")


def decrypt_instance(shellcode: bytes) -> tuple[bytes, DonutLayout]:
    """Decrypt a Donut instance and auto-select a supported structure layout."""
    if not is_donut_shellcode(shellcode):
        raise ValueError("input is not a supported Donut shellcode layout")
    length = struct.unpack_from("<I", shellcode, 1)[0]
    raw = shellcode[5 : 5 + length]
    if len(raw) < 0x240:
        raise ValueError("truncated Donut instance")
    entropy = struct.unpack_from("<I", raw, 0x234)[0]
    for layout in LAYOUTS:
        if len(raw) <= layout.module_length + 8:
            continue
        instance = bytearray(raw)
        if entropy == 3:
            instance[layout.crypt_start :] = chaskey_ctr(
                bytes(instance[4:20]), bytes(instance[20:36]), bytes(instance[layout.crypt_start :])
            )
        api_count = struct.unpack_from("<I", instance, layout.api_count)[0]
        dlls = _ascii_field(instance, layout.dll_names)
        if 1 <= api_count <= 64 and dlls and all(31 < ord(char) < 127 for char in dlls):
            return bytes(instance), layout
    raise ValueError("Donut instance decryption did not validate against known layouts")


def parse_module(module: bytes) -> dict:
    """Parse the fixed Donut module header and return publish-safe metadata."""
    if len(module) < 1320:
        raise ValueError("truncated Donut module")
    zlen, length = struct.unpack_from("<II", module, 1312)
    return {
        "type": struct.unpack_from("<I", module, 0)[0],
        "thread": struct.unpack_from("<I", module, 4)[0],
        "compression": struct.unpack_from("<I", module, 8)[0],
        "runtime": _ascii_field(module, 12),
        "domain": _ascii_field(module, 268),
        "class": _ascii_field(module, 524),
        "method": _ascii_field(module, 780),
        "arguments_present": bool(_ascii_field(module, 1036)),
        "zlen": zlen,
        "length": length,
    }


def recover_module_payload(module: bytes) -> bytes:
    """Recover an uncompressed or aPLib-compressed Donut module payload."""
    metadata = parse_module(module)
    stored = metadata["zlen"] or metadata["length"]
    payload = module[1320 : 1320 + stored]
    if len(payload) != stored:
        raise ValueError("Donut module payload exceeds module bounds")
    compression = metadata["compression"]
    if compression == 1:
        return payload
    if compression == 2:
        try:
            from refinery.lib.fast.aplib import aplib_decompress
        except ImportError as error:
            raise RuntimeError("aPLib recovery requires binary-refinery") from error
        recovered = bytes(aplib_decompress(payload))
        if len(recovered) != metadata["length"]:
            raise ValueError("aPLib output length does not match Donut metadata")
        return recovered
    raise ValueError(f"unsupported Donut compression engine: {compression}")


def unpack_donut(shellcode: bytes) -> DonutResult:
    """Decrypt an embedded Donut instance and recover its terminal module bytes."""
    instance, layout = decrypt_instance(shellcode)
    module_length = struct.unpack_from("<Q", instance, layout.module_length)[0]
    if not 1320 <= module_length <= len(instance) - layout.module:
        raise ValueError("invalid Donut module length")
    module = instance[layout.module : layout.module + module_length]
    metadata = parse_module(module)
    payload = recover_module_payload(module)
    metadata.update(
        {
            "layout": layout.name,
            "instance_sha256": sha256_bytes(instance),
            "module_sha256": sha256_bytes(module),
            "payload_sha256": sha256_bytes(payload),
            "api_count": struct.unpack_from("<I", instance, layout.api_count)[0],
            "dll_names": _ascii_field(instance, layout.dll_names).split(";"),
            "instance_type": struct.unpack_from("<I", instance, layout.instance_type)[0],
        }
    )
    return DonutResult(layout.name, instance, module, payload, metadata)


def build_parser() -> argparse.ArgumentParser:
    """Build the offline Donut unpacker command-line parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--json", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the static Donut unpacker and optionally write recovered layers."""
    args = build_parser().parse_args(argv)
    result = unpack_donut(args.input.read_bytes())
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "donut.instance.bin").write_bytes(result.instance)
        (args.output_dir / "donut.module.bin").write_bytes(result.module)
        (args.output_dir / "donut.payload.bin").write_bytes(result.payload)
    report = {**result.metadata, "executed": False, "network_contacted": False}
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())