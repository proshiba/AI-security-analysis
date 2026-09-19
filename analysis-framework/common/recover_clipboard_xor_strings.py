#!/usr/bin/env python3
"""clipboard改変DLLの二系列XOR文字列を、PEを実行せずに復元する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

import capstone
import pefile

MASK64 = (1 << 64) - 1
ADDRESS_LITERAL = re.compile(r"[A-Za-z0-9_-]{30,95}\Z")


def decode_blob(blob: bytes, length: int) -> str:
    """観測済みx64命令列のindex演算とXORを写像する。"""

    if not 1 <= length <= 120:
        raise ValueError("復号長が上限外です")
    values = []
    for offset in range(length):
        first = (offset | 4) + ((offset ^ (MASK64 - 4)) & (offset | 4))
        second = (1 + offset + (((~offset) & MASK64) | 3)) & MASK64
        if first >= len(blob) or second >= len(blob):
            raise ValueError("復号byteがPE領域外です")
        values.append(blob[first] ^ blob[second])
    raw = bytes(values).split(b"\0", 1)[0]
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return ""


def recover_strings_from_bytes(data: bytes) -> dict[str, object]:
    """同一bytes snapshotから文字列を復元し、path/dataの取り違えを防ぐ。"""

    if len(data) > 128 * 1024 * 1024:
        raise ValueError("入力PEが上限を超えています")
    image = pefile.PE(data=data, fast_load=False)
    try:
        if image.FILE_HEADER.Machine != 0x8664 or not image.FILE_HEADER.Characteristics & 0x2000:
            return {"sha256": hashlib.sha256(data).hexdigest(), "status": "not_x64_dll", "strings": []}
        decoder = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        decoder.detail = True
        base = int(image.OPTIONAL_HEADER.ImageBase)
        strings: list[dict[str, object]] = []
        for section in image.sections:
            if not int(section.Characteristics) & 0x20000000:
                continue
            instructions = list(decoder.disasm(section.get_data(), base + int(section.VirtualAddress)))
            for index, instruction in enumerate(instructions):
                if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
                    continue
                destination, source = instruction.operands
                if (
                    destination.type != capstone.x86.X86_OP_REG
                    or destination.reg != capstone.x86.X86_REG_RAX
                    or source.type != capstone.x86.X86_OP_MEM
                    or source.mem.base != capstone.x86.X86_REG_RIP
                ):
                    continue
                slot = instruction.address + instruction.size + source.mem.disp - base
                if slot < 0 or slot + 8 > int(image.OPTIONAL_HEADER.SizeOfImage):
                    continue
                following = instructions[index + 1 : index + 48]
                if not {"movsx", "sub", "xor"}.issubset({item.mnemonic for item in following}):
                    continue
                lengths = [
                    item.operands[1].imm
                    for item in following
                    if item.mnemonic == "cmp"
                    and len(item.operands) == 2
                    and item.operands[0].type == capstone.x86.X86_OP_REG
                    and item.operands[0].reg == capstone.x86.X86_REG_RDX
                    and item.operands[1].type == capstone.x86.X86_OP_IMM
                    and 30 <= item.operands[1].imm <= 120
                ]
                if len(lengths) != 1:
                    continue
                pointer = image.get_qword_at_rva(slot)
                if not base <= pointer < base + int(image.OPTIONAL_HEADER.SizeOfImage):
                    continue
                blob = image.get_data(pointer - base, 2 * lengths[0] + 16)
                try:
                    value = decode_blob(blob, lengths[0])
                except ValueError:
                    continue
                if ADDRESS_LITERAL.fullmatch(value) is None:
                    continue
                strings.append({
                    "value": value,
                    "pointer_slot_rva": f"0x{slot:x}",
                    "decoded_length": len(value),
                    "loop_bound": lengths[0],
                })
        unique = {item["value"]: item for item in strings}
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "status": "candidate_strings_recovered" if unique else "no_candidate_strings",
            "strings": [unique[key] for key in sorted(unique)],
            "safety": {"sample_executed": False, "network_contacted": False},
        }
    finally:
        image.close()


def recover_strings(path: Path) -> dict[str, object]:
    """従来CLI用のpath入口。"""

    return recover_strings_from_bytes(path.read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, action="append", required=True)
    args = parser.parse_args()
    print(json.dumps([recover_strings(path) for path in args.sample], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
