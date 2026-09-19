#!/usr/bin/env python3
"""PEBを走査するROR13 API解決処理の定数を静的に照合する。"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path

import capstone
import pefile

MASK32 = 0xFFFFFFFF
DLL_NAMES = (
    "kernel32.dll", "kernelbase.dll", "ntdll.dll", "user32.dll",
    "ws2_32.dll", "msvcrt.dll", "advapi32.dll", "wininet.dll",
    "winhttp.dll", "crypt32.dll", "shlwapi.dll",
)


def ror13(value: int) -> int:
    return ((value >> 13) | (value << 19)) & MASK32


def hash_bytes(data: bytes, *, uppercase_ascii: bool = False) -> int:
    value = 0
    for byte in data:
        value = ror13(value)
        if uppercase_ascii and byte >= 0x61:
            byte -= 0x20
        value = (value + byte) & MASK32
    return value


def api_hash(dll: str, function: str) -> int:
    # 観測した解決関数はUNICODE_STRING.MaximumLengthの範囲をhash化し、
    # export名は終端NULも含めてhash化する。
    module = hash_bytes((dll + "\0").encode("utf-16le"), uppercase_ascii=True)
    export = hash_bytes(function.encode("ascii") + b"\0")
    return (module + export) & MASK32


def load_export_map(dll_dir: Path) -> dict[int, list[str]]:
    mapping: dict[int, list[str]] = {}
    for dll in DLL_NAMES:
        path = dll_dir / dll
        if not path.is_file():
            continue
        image = pefile.PE(str(path), fast_load=True)
        try:
            image.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            directory = getattr(image, "DIRECTORY_ENTRY_EXPORT", None)
            if directory is None:
                continue
            for symbol in directory.symbols:
                if not symbol.name:
                    continue
                try:
                    name = symbol.name.decode("ascii")
                except UnicodeDecodeError:
                    continue
                mapping.setdefault(api_hash(dll, name), []).append(f"{dll}!{name}")
        finally:
            image.close()
    return mapping


def stack_route_fragments(instructions: list[capstone.CsInsn]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    fragments: list[dict[str, object]] = []
    ports: list[dict[str, object]] = []
    for index, instruction in enumerate(instructions):
        if instruction.mnemonic == "mov" and instruction.op_str.startswith("eax, 0x"):
            try:
                candidate = int(instruction.op_str.split("0x", 1)[1], 16)
            except ValueError:
                candidate = 0
            if 0 < candidate <= 0xFFFF and any(
                later.mnemonic == "mov"
                and later.op_str.startswith("word ptr [")
                and later.op_str.endswith(", ax")
                for later in instructions[index + 1 : index + 7]
            ):
                ports.append({
                    "address": f"0x{instruction.address:x}",
                    "port": int.from_bytes(candidate.to_bytes(2, "little"), "big"),
                })
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if destination.type != capstone.x86.X86_OP_MEM or source.type != capstone.x86.X86_OP_IMM:
            continue
        if destination.mem.base not in {
            capstone.x86.X86_REG_RBP, capstone.x86.X86_REG_RSP,
            capstone.x86.X86_REG_EBP, capstone.x86.X86_REG_ESP,
        }:
            continue
        if destination.size not in {1, 2, 4}:
            continue
        raw = (source.imm & ((1 << (8 * destination.size)) - 1)).to_bytes(destination.size, "little")
        address = f"0x{instruction.address:x}"
        if raw[:2] == b"\x02\x00" and len(raw) == 4:
            ports.append({"address": address, "port": int.from_bytes(raw[2:], "big")})
        literal = raw.rstrip(b"\0")
        if literal and any(0x30 <= byte <= 0x39 for byte in literal) and all(
            byte in b"0123456789." for byte in literal
        ):
            fragments.append({"address": address, "text": literal.decode("ascii")})
    return fragments[:128], ports[:32]


def endpoint_candidate(
    fragments: list[dict[str, object]],
    ports: list[dict[str, object]],
    matches: list[dict[str, object]],
) -> dict[str, object] | None:
    exports = {name for match in matches for name in match["exports"]}
    required = {"ws2_32.dll!connect", "ws2_32.dll!inet_addr", "user32.dll!wsprintfA"}
    unique_ports = {int(item["port"]) for item in ports if 1 <= int(item["port"]) <= 65535}
    if not required.issubset(exports) or len(unique_ports) != 1:
        return None
    texts = [str(item["text"]) for item in fragments]
    candidates: list[tuple[int, str, list[str]]] = []
    for start in range(len(texts)):
        combined = ""
        selected: list[str] = []
        for part in texts[start : start + 8]:
            combined += part
            selected.append(part)
            if len(combined) > 15 or combined.count(".") > 3:
                break
            try:
                address = ipaddress.IPv4Address(combined)
            except ipaddress.AddressValueError:
                continue
            if address.is_global:
                candidates.append((len(combined), str(address), selected.copy()))
    if not candidates:
        return None
    longest = max(size for size, _address, _parts in candidates)
    best = [(address, parts) for size, address, parts in candidates if size == longest]
    if len({address for address, _parts in best}) != 1:
        return None
    address, parts = best[0]
    return {
        "host": address,
        "port": next(iter(unique_ports)),
        "transport": "tcp",
        "confidence": "static_candidate_dataflow_review_required",
        "evidence": {
            "stack_fragments": parts,
            "sockaddr_port_candidate_count": len(ports),
            "required_api_hashes_resolved": sorted(required),
        },
    }


def review_sample(path: Path, exports: dict[int, list[str]]) -> dict[str, object]:
    data = path.read_bytes()
    if len(data) > 128 * 1024 * 1024:
        raise ValueError("入力PEが上限を超えています")
    image = pefile.PE(data=data, fast_load=True)
    try:
        mode = capstone.CS_MODE_64 if image.FILE_HEADER.Machine == 0x8664 else capstone.CS_MODE_32
        decoder = capstone.Cs(capstone.CS_ARCH_X86, mode)
        decoder.detail = True
        base = int(image.OPTIONAL_HEADER.ImageBase)
        calls: dict[int, list[int]] = {}
        route_fragments: list[dict[str, object]] = []
        port_candidates: list[dict[str, object]] = []
        memory_xor_byte_constants: set[int] = set()
        for section in image.sections:
            if not int(section.Characteristics) & 0x20000000:
                continue
            instructions = list(decoder.disasm(section.get_data(), base + int(section.VirtualAddress)))
            fragments, ports = stack_route_fragments(instructions)
            route_fragments.extend(fragments)
            port_candidates.extend(ports)
            for instruction in instructions:
                if instruction.mnemonic != "xor" or len(instruction.operands) != 2:
                    continue
                destination, source = instruction.operands
                if (
                    destination.type == capstone.x86.X86_OP_MEM
                    and destination.size == 1
                    and source.type == capstone.x86.X86_OP_IMM
                ):
                    memory_xor_byte_constants.add(source.imm & 0xFF)
            for index, following in enumerate(instructions):
                if following.mnemonic != "call" or not following.op_str.startswith("0x"):
                    continue
                constant = None
                for current in reversed(instructions[max(0, index - 6) : index]):
                    if current.mnemonic == "call":
                        break
                    _reads, writes = current.regs_access()
                    if not {capstone.x86.X86_REG_ECX, capstone.x86.X86_REG_RCX}.intersection(writes):
                        continue
                    if current.mnemonic == "mov" and current.op_str.startswith("ecx, 0x"):
                        constant = int(current.op_str.split("0x", 1)[1], 16)
                    break
                if constant is None:
                    continue
                try:
                    target = int(following.op_str, 16)
                except ValueError:
                    continue
                calls.setdefault(target, []).append(constant)
        if not calls:
            return {"sha256": hashlib.sha256(data).hexdigest(), "status": "no_pattern", "matches": []}
        resolver, hashes = max(calls.items(), key=lambda item: len(item[1]))
        matches = [
            {"hash": f"0x{value:08x}", "exports": sorted(exports.get(value, []))}
            for value in dict.fromkeys(hashes)
        ]
        route = endpoint_candidate(route_fragments, port_candidates, matches)
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "status": "pattern_observed",
            "resolver_va": f"0x{resolver:x}",
            "call_count": len(hashes),
            "matched_count": sum(bool(item["exports"]) for item in matches),
            "matches": matches,
            "route_fragments": route_fragments[:128],
            "sockaddr_port_candidates": port_candidates[:32],
            "endpoint_candidate": route,
            "memory_xor_byte_constants": [f"0x{value:02x}" for value in sorted(memory_xor_byte_constants)],
            "safety": {"sample_executed": False, "network_contacted": False},
        }
    finally:
        image.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, action="append", required=True)
    parser.add_argument("--dll-dir", type=Path, default=Path("C:/Windows/System32"))
    args = parser.parse_args()
    exports = load_export_map(args.dll_dir)
    print(json.dumps([review_sample(path, exports) for path in args.sample], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
