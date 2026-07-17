"""Statically recover embedded modules from legacy and modern Donut shellcode."""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
import pefile



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


@dataclass(frozen=True)
class DonutCandidate:
    """One strictly validated contiguous or sparse Donut shellcode candidate."""

    offset: int
    stride: int
    data: bytes



LAYOUTS = (
    DonutLayout("current-0x240-array", 0x240, 0x240, 0x244, -1, -1, -1),
    DonutLayout("current-0x230-array", 0x230, 0x230, 0x238, -1, -1, -1),
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
    prologue = data[code : code + 5]
    return 0 < length <= len(data) - 5 and (
        prologue.startswith(b"YU\x48\x89\xe5")
        or prologue.startswith(b"\x59\x31\xc0\x48\x0f")
        or prologue.startswith(b"\x59\x48\x89\x5c\x24")
    )


def find_donut_shellcodes(data: bytes, strides: tuple[int, ...] = (1, 4)) -> list[DonutCandidate]:
    """Find strict call-over-instance Donut shellcode in contiguous or sparse lanes."""
    candidates: list[DonutCandidate] = []
    for stride in strides:
        if stride < 1:
            raise ValueError("stride must be positive")
        for phase in range(stride):
            lane = data[phase::stride]
            cursor = 0
            while True:
                offset = lane.find(b"\xe8", cursor)
                if offset < 0:
                    break
                cursor = offset + 1
                if offset + 10 > len(lane):
                    continue
                length = struct.unpack_from("<I", lane, offset + 1)[0]
                code = offset + 5 + length
                if length <= 0 or code + 5 > len(lane):
                    continue
                prologue = lane[code : code + 5]
                if not (
                    prologue.startswith(b"YU\x48\x89\xe5")
                    or prologue.startswith(b"\x59\x31\xc0\x48\x0f")
                    or prologue.startswith(b"\x59\x48\x89\x5c\x24")
                ):
                    continue
                shellcode = lane[offset : code + 5]
                candidates.append(DonutCandidate(phase + offset * stride, stride, shellcode))
    unique: dict[tuple[str, int], DonutCandidate] = {}
    for item in candidates:
        unique[(sha256_bytes(item.data), item.stride)] = item
    return sorted(unique.values(), key=lambda item: (item.offset, item.stride))


def _ascii_field(data: bytes, offset: int, size: int = 256) -> str:
    return data[offset : offset + size].split(b"\0", 1)[0].decode("ascii", errors="replace")


def _valid_dll_names(value: str) -> bool:
    """Validate the bounded Donut DLL basename list."""
    allowed = {
        "advapi32",
        "combase",
        "crypt32",
        "kernel32",
        "kernelbase",
        "mscoree",
        "ntdll",
        "ole32",
        "oleaut32",
        "shell32",
        "shlwapi",
        "user32",
        "wininet",
    }
    raw_names = [item.lower() for item in value.split(";") if item]
    names = [item.removesuffix(".dll") for item in raw_names]
    known = bool(names) and all(item in allowed for item in names)
    explicit_single = len(raw_names) == 1 and raw_names[0].endswith(".dll")
    return known and (len(names) >= 2 or explicit_single)


def decrypt_instance(shellcode: bytes) -> tuple[bytes, DonutLayout]:
    """Decrypt a Donut instance and auto-select a supported structure layout."""
    if not is_donut_shellcode(shellcode):
        raise ValueError("input is not a supported Donut shellcode layout")
    length = struct.unpack_from("<I", shellcode, 1)[0]
    raw = shellcode[5 : 5 + length]
    if len(raw) < 0x240:
        raise ValueError("truncated Donut instance")
    for layout in LAYOUTS:
        if len(raw) <= layout.dll_names:
            continue
        candidates = [raw]
        for instance in candidates:
            api_count = struct.unpack_from("<I", instance, layout.api_count)[0]
            dlls = _ascii_field(instance, layout.dll_names)
            if (
                1 <= api_count <= 64
                and _valid_dll_names(dlls)
                and all(31 < ord(char) < 127 for char in dlls)
            ):
                return bytes(instance), layout
        decrypted = bytearray(raw)
        decrypted[layout.crypt_start :] = chaskey_ctr(
            bytes(decrypted[4:20]),
            bytes(decrypted[20:36]),
            bytes(decrypted[layout.crypt_start :]),
        )
        instance = bytes(decrypted)
        api_count = struct.unpack_from("<I", instance, layout.api_count)[0]
        dlls = _ascii_field(instance, layout.dll_names)
        if (
            1 <= api_count <= 64
            and _valid_dll_names(dlls)
            and all(31 < ord(char) < 127 for char in dlls)
        ):
            return instance, layout
    raise ValueError("Donut instance decryption did not validate against known layouts")


def _pe_extent(data: bytes, offset: int) -> int | None:
    """Return one bounded PE file extent from a decrypted instance."""
    if offset < 0 or offset + 0x40 > len(data) or data[offset : offset + 2] != b"MZ":
        return None
    try:
        image = pefile.PE(data=data[offset:], fast_load=True)
        extent = int(image.OPTIONAL_HEADER.SizeOfHeaders)
        for section in image.sections:
            extent = max(extent, int(section.PointerToRawData + section.SizeOfRawData))
        security = image.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if security.VirtualAddress and security.Size:
            extent = max(extent, int(security.VirtualAddress + security.Size))
        if not 0 < extent <= len(data) - offset:
            return None
        return extent
    except (AttributeError, IndexError, ValueError, pefile.PEFormatError):
        return None


def recover_donut_payloads(data: bytes) -> tuple[dict, list[tuple[str, bytes]]]:
    """Decrypt strict Donut candidates and recover validated terminal modules."""
    reports: list[dict] = []
    artifacts: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    for candidate in find_donut_shellcodes(data):
        item = {
            "offset": candidate.offset,
            "stride": candidate.stride,
            "shellcode_sha256": sha256_bytes(candidate.data),
        }
        try:
            instance, layout = decrypt_instance(candidate.data)
            item.update(
                status="instance_decrypted",
                layout=layout.name,
                instance_sha256=sha256_bytes(instance),
            )
            recovered: list[bytes] = []
            if layout.module < 0:
                cursor = 0
                while len(recovered) < 16:
                    offset = instance.find(b"MZ", cursor)
                    if offset < 0:
                        break
                    extent = _pe_extent(instance, offset)
                    if extent:
                        recovered.append(instance[offset : offset + extent])
                        cursor = offset + extent
                    else:
                        cursor = offset + 2
            else:
                recovered.append(unpack_donut(candidate.data).payload)
            payloads = []
            for payload in recovered:
                digest = sha256_bytes(payload)
                if digest in seen:
                    continue
                seen.add(digest)
                payloads.append({"sha256": digest, "size": len(payload)})
                artifacts.append(("donut-terminal-payload", payload))
            item["payloads"] = payloads
            if payloads:
                item["status"] = "payload_recovered"
        except (RuntimeError, ValueError, struct.error) as exc:
            item.update(status="decode_failed", error=type(exc).__name__)
        reports.append(item)
    return {
        "status": "payload_recovered" if artifacts else "no_payload_recovered",
        "candidates": reports,
    }, artifacts


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