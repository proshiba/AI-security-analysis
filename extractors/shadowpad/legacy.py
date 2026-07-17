"""Static Casper-era ShadowPad loader, module, and config primitives.

The routines in this module transform byte strings only.  They do not map a
module into executable memory, invoke an entry point, or contact recovered
infrastructure.
"""

from __future__ import annotations

import ipaddress
import struct
from dataclasses import dataclass

import pefile

LEGACY_X86_PREFIX = bytes.fromhex("8b4c24045589e5")
LEGACY_X64_PREFIX = bytes.fromhex("554889e55168")
LEGACY_CONFIG_LABELS = (
    "campaign_id",
    "install_name",
    "install_path",
    "service_name",
    "service_display_name",
    "service_description",
    "registry_key_path",
    "registry_value_name",
    "injection_target_1",
    "injection_target_2",
    "injection_target_3",
    "injection_target_4",
    "c2_1",
    "c2_2",
    "c2_3",
    "c2_4",
    "c2_5",
    "c2_6",
    "c2_7",
    "c2_8",
    "c2_9",
    "reserved_1",
    "reserved_2",
    "reserved_3",
    "reserved_4",
    "reserved_5",
    "reserved_6",
    "reserved_7",
    "proxy_1",
    "proxy_2",
    "proxy_3",
    "proxy_4",
)
CASPER_FLAGS = 0x12345678
MODULE_FLAGS = 0x00650001


@dataclass(frozen=True)
class LegacyDecode:
    """A structurally identified Casper-era outer-loader decode."""

    data: bytes
    architecture: str
    seed_rva: int
    encrypted_rva: int
    encrypted_length: int
    module_offset: int
    module_size: int


def legacy_x86_stream(data: bytes, seed: int) -> bytes:
    """Decode the older 32-bit Casper loader's evolving XOR stream."""
    output = bytearray(len(data))
    key = seed & 0xFFFFFFFF
    for index, value in enumerate(data):
        output[index] = value ^ (key & 0xFF)
        key = (key * 0x6A730000 - (key >> 16) * 0x39F3958D - 0x5C0BB335) & 0xFFFFFFFF
    return bytes(output)


def legacy_x64_stream(data: bytes, seed: int) -> bytes:
    """Decode the older 64-bit Casper loader's evolving XOR stream."""
    output = bytearray(len(data))
    key = seed & 0xFFFFFFFF
    for index, value in enumerate(data):
        output[index] = value ^ (key & 0xFF)
        rotated = ((key << 16) & 0xFFFFFFFF) + (key >> 16)
        key = (rotated * 0x4A220157 - 0x708F34C1) & 0xFFFFFFFF
    return bytes(output)


def quicklz_header(data: bytes) -> dict:
    """Parse and validate a QuickLZ 1.5 framing header."""
    if len(data) < 3:
        raise ValueError("QuickLZ input is too short")
    header_size = 9 if data[0] & 2 else 3
    if len(data) < header_size:
        raise ValueError("QuickLZ header is truncated")
    width = 4 if header_size == 9 else 1
    compressed_size = int.from_bytes(data[1 : 1 + width], "little")
    decompressed_size = int.from_bytes(data[1 + width : 1 + 2 * width], "little")
    level = (data[0] >> 2) & 0x03
    if compressed_size < header_size or compressed_size > len(data):
        raise ValueError("QuickLZ compressed size is invalid")
    if decompressed_size <= 0:
        raise ValueError("QuickLZ decompressed size is invalid")
    return {
        "header_size": header_size,
        "compressed_size": compressed_size,
        "decompressed_size": decompressed_size,
        "level": level,
        "is_compressed": bool(data[0] & 1),
    }


def _quicklz_hash(buffer: bytearray, position: int) -> int:
    value = buffer[position] | buffer[position + 1] << 8 | buffer[position + 2] << 16
    return ((value >> 12) ^ value) & 0x0FFF


def quicklz_decompress(data: bytes) -> bytes:
    """Decompress QuickLZ 1.5 level-1 data used by legacy ShadowPad."""
    header = quicklz_header(data)
    source = header["header_size"]
    output_size = header["decompressed_size"]
    if not header["is_compressed"]:
        end = source + output_size
        if end > len(data):
            raise ValueError("QuickLZ uncompressed body is truncated")
        return data[source:end]
    if header["level"] != 1:
        raise ValueError(f"unsupported QuickLZ level: {header['level']}")

    output = bytearray()
    hash_offsets = [0] * 4096
    last_hashed = -1
    control_word = 1

    def update_hash(position: int) -> None:
        if position + 2 < len(output):
            hash_offsets[_quicklz_hash(output, position)] = position

    while len(output) < output_size:
        if control_word == 1:
            if source + 4 > len(data):
                raise ValueError("QuickLZ control word is truncated")
            control_word = int.from_bytes(data[source : source + 4], "little")
            source += 4
        if control_word & 1:
            if source + 3 > len(data):
                raise ValueError("QuickLZ match token is truncated")
            fetch = int.from_bytes(data[source : source + 4], "little")
            match_offset = hash_offsets[(fetch >> 4) & 0x0FFF]
            if fetch & 0x0F:
                match_length = (fetch & 0x0F) + 2
                source += 2
            else:
                match_length = data[source + 2]
                source += 3
            if match_offset < 0 or match_offset >= len(output):
                raise ValueError("QuickLZ match offset is invalid")
            match_start = len(output)
            for index in range(match_length):
                if len(output) >= output_size:
                    break
                output.append(output[match_offset + index])
            while last_hashed < match_start:
                last_hashed += 1
                update_hash(last_hashed)
            last_hashed = len(output) - 1
        else:
            if source >= len(data):
                raise ValueError("QuickLZ literal is truncated")
            output.append(data[source])
            source += 1
            while last_hashed < len(output) - 3:
                last_hashed += 1
                update_hash(last_hashed)
        control_word >>= 1
    return bytes(output)


def decrypt_casper_block(data: bytes) -> bytes:
    """Decrypt an old four-state Casper module/config block."""
    if len(data) < 4:
        raise ValueError("Casper block is too short")
    initial = int.from_bytes(data[:4], "big")
    keys = [initial] * 4
    state = 0
    output = bytearray(len(data))
    constants = (
        (0x9150017B, 0x0D45A840),
        (0x95D6A3A8, 0x645EE710),
        (0xD608D41B, 0x1ED33670),
        (0xD94925D3, 0x68208D35),
    )
    for index, value in enumerate(data):
        slot = index & 3
        subtractor, multiplier = constants[slot]
        keys[slot] = (subtractor - keys[slot] * multiplier) & 0xFFFFFFFF
        key = keys[slot]
        state = (state - (key & 0xFF)) & 0xFF
        state ^= (key >> 8) & 0xFF
        state = (state - ((key >> 16) & 0xFF)) & 0xFF
        state ^= (key >> 24) & 0xFF
        output[index] = value ^ state
    return bytes(output)


def decrypt_xor_block(data: bytes) -> bytes:
    """Decrypt a newer Casper block using its fourth byte as the XOR key."""
    if len(data) < 4:
        raise ValueError("Casper XOR block is too short")
    key = data[3]
    return bytes(value ^ key for value in data)


def unpack_casper_block(data: bytes, cipher: str) -> tuple[dict, bytes]:
    """Decrypt, validate, and QuickLZ-decompress a Casper block."""
    decrypt = decrypt_casper_block if cipher == "four-state" else decrypt_xor_block
    if cipher not in {"four-state", "xor-byte"}:
        raise ValueError(f"unsupported Casper cipher: {cipher}")
    header = decrypt(data[:20])
    if len(header) < 20:
        raise ValueError("Casper header is truncated")
    key, flags, code, compressed_size, decompressed_size = struct.unpack(
        ">IIIII", header
    )
    if flags not in {CASPER_FLAGS, MODULE_FLAGS}:
        raise ValueError("Casper flags are invalid")
    if compressed_size <= 0 or 20 + compressed_size > len(data):
        raise ValueError("Casper compressed size is invalid")
    decoded = decrypt(data[: 20 + compressed_size])
    payload = quicklz_decompress(decoded[20 : 20 + compressed_size])
    if len(payload) != decompressed_size:
        raise ValueError("Casper decompressed size mismatch")
    return (
        {
            "key": key,
            "flags": flags,
            "code": code,
            "compressed_size": compressed_size,
            "decompressed_size": decompressed_size,
            "cipher": cipher,
        },
        payload,
    )


def decrypt_legacy_string(data: bytes, variant: str) -> str:
    """Decrypt a NUL-terminated legacy Config-module string."""
    if len(data) < 3:
        raise ValueError("legacy string is too short")
    key = int.from_bytes(data[:2], "little")
    output = bytearray()
    for value in data[2:]:
        decoded = value ^ (key & 0xFF)
        if decoded == 0:
            break
        output.append(decoded)
        if variant == "x86":
            key = (
                (key >> 16) * 0x1447208B + key * 0x208B0000 - 0x04875A15
            ) & 0xFFFFFFFF
        elif variant == "x64":
            rotated = ((key << 16) & 0xFFFFFFFF) + (key >> 16)
            key = (rotated * 0x9C67DA34 + 0xF88A61D7) & 0xFFFFFFFF
        else:
            raise ValueError(f"unsupported legacy string variant: {variant}")
    else:
        raise ValueError("legacy string is not terminated")
    return output.decode("utf-8", errors="replace")


def parse_legacy_config(config: bytes, architecture: str) -> dict:
    """Parse the 0x858/0x85c Casper-era Config-module structure."""
    if architecture not in {"x86", "x64"}:
        raise ValueError(f"unsupported legacy architecture: {architecture}")
    minimum, pool_base = (0x858, 0x58) if architecture == "x86" else (0x85C, 0x5C)
    if len(config) < minimum:
        raise ValueError("legacy configuration is truncated")
    strings: dict[str, str] = {}
    for index, label in enumerate(LEGACY_CONFIG_LABELS):
        relative = struct.unpack_from("<H", config, index * 2)[0]
        if relative == 0 and index != 0:
            strings[label] = ""
            continue
        start = pool_base + relative
        if start >= len(config):
            strings[label] = ""
            continue
        try:
            strings[label] = decrypt_legacy_string(config[start:], architecture)
        except ValueError:
            strings[label] = ""
    dns = []
    for index in range(4):
        raw = config[0x40 + 4 * index : 0x44 + 4 * index]
        dns.append(str(ipaddress.ip_address(raw)))
    return {
        "format": f"shadowpad-casper-{architecture}",
        "size": minimum,
        "strings": strings,
        "dns_servers": dns,
        "timeout_multiplier": struct.unpack_from("<I", config, 0x50)[0],
        "field_54": struct.unpack_from("<I", config, 0x54)[0],
    }


def find_legacy_configs(payload: bytes, architecture: str) -> list[dict]:
    """Find, unpack, and parse structurally valid legacy configs."""
    cipher = "four-state" if architecture == "x86" else "xor-byte"
    expected_size = 0x858 if architecture == "x86" else 0x85C
    output: list[dict] = []
    for offset in range(0, max(0, len(payload) - 20)):
        try:
            header = (
                decrypt_casper_block(payload[offset : offset + 20])
                if cipher == "four-state"
                else decrypt_xor_block(payload[offset : offset + 20])
            )
            _, flags, _, compressed_size, decompressed_size = struct.unpack(
                ">IIIII", header
            )
            if flags != CASPER_FLAGS or decompressed_size != expected_size:
                continue
            end = offset + 20 + compressed_size
            if compressed_size <= 0 or end > len(payload):
                continue
            block_header, config = unpack_casper_block(payload[offset:end], cipher)
            parsed = parse_legacy_config(config, architecture)
            parsed.update({"offset": offset, "block_header": block_header})
            output.append(parsed)
        except (IndexError, struct.error, ValueError):
            continue
    return output


def _module_extent(decoded: bytes, architecture: str) -> tuple[int, int] | None:
    """Return the shell-stub module offset and declared module size."""
    if (
        architecture == "x86"
        and decoded.startswith(LEGACY_X86_PREFIX)
        and len(decoded) >= 0x18
    ):
        if decoded[0x0E] != 0x68:
            return None
        return 0x18, struct.unpack_from("<I", decoded, 0x0F)[0]
    if (
        architecture == "x64"
        and decoded.startswith(LEGACY_X64_PREFIX)
        and len(decoded) >= 0x17
    ):
        if decoded[5] != 0x68:
            return None
        return 0x17, struct.unpack_from("<I", decoded, 6)[0]
    return None


def _stream_prefix(data: bytes, offset: int, architecture: str) -> bool:
    if offset + 11 > len(data):
        return False
    seed = struct.unpack_from("<I", data, offset)[0]
    cipher = legacy_x86_stream if architecture == "x86" else legacy_x64_stream
    prefix = LEGACY_X86_PREFIX if architecture == "x86" else LEGACY_X64_PREFIX
    return cipher(data[offset + 4 : offset + 4 + len(prefix)], seed) == prefix


def decode_legacy_pe(data: bytes) -> list[LegacyDecode]:
    """Structurally locate and decode Casper-era streams in PE sections."""
    try:
        pe = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        return []
    output: list[LegacyDecode] = []
    for section in pe.sections:
        raw_start = int(section.PointerToRawData)
        raw_end = min(len(data), raw_start + int(section.SizeOfRawData))
        if raw_end - raw_start < 16:
            continue
        for architecture in ("x86", "x64"):
            for seed_offset in range(raw_start, raw_end - 11):
                if not _stream_prefix(data, seed_offset, architecture):
                    continue
                seed = struct.unpack_from("<I", data, seed_offset)[0]
                encrypted = data[seed_offset + 4 : raw_end]
                cipher = (
                    legacy_x86_stream if architecture == "x86" else legacy_x64_stream
                )
                decoded = cipher(encrypted, seed)
                extent = _module_extent(decoded, architecture)
                if extent is None:
                    continue
                module_offset, module_size = extent
                declared_end = module_offset + module_size
                if module_size < 0x1000 or declared_end > len(decoded):
                    continue
                seed_rva = int(section.VirtualAddress) + seed_offset - raw_start
                output.append(
                    LegacyDecode(
                        data=decoded[:declared_end],
                        architecture=architecture,
                        seed_rva=seed_rva,
                        encrypted_rva=seed_rva + 4,
                        encrypted_length=len(encrypted),
                        module_offset=module_offset,
                        module_size=module_size,
                    )
                )
                break
    return output
