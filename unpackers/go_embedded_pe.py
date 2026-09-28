"""Go関数表と明示的なbyte復号処理から埋込みPEを有界静的回収する。

Go、復元PE、CPU命令を実行せず、ファイル書込みや外部通信もしない。
包装形式の復元を、終端到達・ファミリー・C2の確認とは扱わない。
"""

from __future__ import annotations

import hashlib
import re
import struct
import time
from collections.abc import Callable
from dataclasses import dataclass

import capstone
import pefile

import unpackers.go_decoder_shape as go_decoder_shape
from unpackers.bounded_pe_scan import inspect_structural_pe_extent

MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_FUNCTIONS = 8192
MAX_FUNCTION_BYTES = 512 * 1024
MAX_NAMES_BYTES = 1024 * 1024
MAX_TABLE_CANDIDATES = 8
MAX_COPY_CANDIDATES = 4
MAX_ELAPSED_SECONDS = 10.0
PCLNTAB_MAGIC = b"\xf1\xff\xff\xff\x00\x00\x01\x08"
BUILDINFO_MAGIC = b"\xff Go buildinf:"

# レビュー済み数学block。アドレス、検体hash、鍵、module名を含まない。
# register名は照合時に別名化するが、幅と同一registerの使用関係を保持する。
_EVEN_BLOCKS = (
    """movabs rax, 0x4d4873ecade304d5
mov r8, rdx
imul rcx
sar rdx, 4
mov r9, rcx
sar rcx, 0x3f
sub rdx, rcx
imul rcx, rdx, 0x35
mov rdx, r9
sub r9, rcx
sub esi, r9d
mov rcx, rbx
shl rbx, 4
add rbx, rcx
sub esi, ebx
mov byte ptr [rdi + rcx], sil""",
    """movabs rax, 0x4d4873ecade304d5
mov rbx, rdx
imul rsi
sar rdx, 4
mov r10, rsi
sar rsi, 0x3f
sub rdx, rsi
imul rdx, rdx, 0x35
mov rsi, r10
sub r10, rdx
sub r9d, r10d
mov rdx, rcx
shl rcx, 4
lea r10, [rdx + rcx]
sub r9d, r10d
mov byte ptr [rbx + rdx], r9b""",
    """movabs rax, 0x4d4873ecade304d5
mov r8, rdx
imul rdx
sar rdx, 4
mov r9, r8
sar r8, 0x3f
sub rdx, r8
imul rdx, rdx, 0x35
mov r8, r9
sub r9, rdx
sub esi, r9d
mov rdx, rbx
shl rbx, 4
lea r9, [rdx + rbx]
sub esi, r9d
mov byte ptr [rdi + rdx], sil""",
)
_ODD_BLOCKS = (
    """movabs rax, 0xa8e83f5717c0a8e9
mov r8, rdx
imul rcx
add rdx, rcx
sar rdx, 6
mov r9, rcx
sar rcx, 0x3f
sub rdx, rcx
imul rcx, rdx, 0x61
mov rdx, r9
sub r9, rcx
xor r9d, esi
mov rcx, rbx
shl rbx, 5
sub rbx, rcx
xor ebx, r9d
mov byte ptr [rdi + rcx], bl""",
    """movabs rax, 0xa8e83f5717c0a8e9
mov rbx, rdx
imul rsi
add rdx, rsi
sar rdx, 6
mov r10, rsi
sar rsi, 0x3f
sub rdx, rsi
imul rdx, rdx, 0x61
mov rsi, r10
sub r10, rdx
xor r10d, r9d
mov rdx, rcx
shl rcx, 5
sub rcx, rdx
xor ecx, r10d
mov byte ptr [rbx + rdx], cl""",
    """movabs rax, 0xa8e83f5717c0a8e9
mov r8, rdx
imul rdx
add rdx, r8
sar rdx, 6
mov r9, r8
sar r8, 0x3f
sub rdx, r8
imul rdx, rdx, 0x61
mov r8, r9
sub r9, rdx
xor r9d, esi
mov rdx, rbx
shl rbx, 5
sub rbx, rdx
xor ebx, r9d
mov byte ptr [rdi + rdx], bl""",
)
_REVERSE_BLOCK = """movzx edi, byte ptr [rax + rdx]
mov byte ptr [rdx + rbx], dil
mov byte ptr [rdx + rax], sil
inc rbx
dec rax"""
_PAIR_BLOCK = """movzx ebx, byte ptr [rdx + rax + 1]
mov byte ptr [rax + rdx], bl
mov byte ptr [rdx + rax + 1], sil
add rdx, 2"""
_SUBTRACT_BLOCK = """movzx esi, byte ptr [rbx + rax]
mov rdi, rcx
sar rdi, 8
sub esi, edi
lea rdi, [rbx + rbx*2]
sub esi, edi
mov byte ptr [rax + rbx], sil"""
_XOR_BLOCKS = (
    """movzx esi, byte ptr [rbx + rax]
xor esi, ecx
lea rdi, [rbx + rbx*4]
xor edi, esi
mov byte ptr [rax + rbx], dil""",
    """movzx esi, byte ptr [rbx + rax]
xor esi, edx
lea r8, [rbx + rbx*4]
xor esi, r8d
mov byte ptr [rax + rbx], sil""",
)


def _canonical_block(text: str) -> str:
    implicit_multiply = any(
        line.startswith("imul ") and "," not in line for line in text.splitlines()
    )
    registers: dict[str, int] = {}
    aliases = {}
    for name, names in {
        "rax": ("rax", "eax", "ax", "al"),
        "rbx": ("rbx", "ebx", "bx", "bl"),
        "rcx": ("rcx", "ecx", "cx", "cl"),
        "rdx": ("rdx", "edx", "dx", "dl"),
        "rsi": ("rsi", "esi", "si", "sil"),
        "rdi": ("rdi", "edi", "di", "dil"),
    }.items():
        for width, alias in zip((64, 32, 16, 8), names):
            aliases[alias] = (name, width)
    for n in range(8, 16):
        for suffix, width in (("", 64), ("d", 32), ("w", 16), ("b", 8)):
            aliases[f"r{n}{suffix}"] = (f"r{n}", width)

    def replace(match: re.Match) -> str:
        value = match.group()
        if value not in aliases:
            return value
        name, width = aliases[value]
        if implicit_multiply and name in {"rax", "rdx"}:
            return f"{name}_{width}"
        if name not in registers:
            registers[name] = len(registers)
        return f"v{registers[name]}_{width}"

    return re.sub(
        r"\b(?:r(?:[abcd]x|si|di|[89]|1[0-5])[dwb]?|e[abcd]x|[abcd][xl]|e(?:si|di)|(?:si|di)l?)\b",
        replace,
        text,
    )


class GoRecoveryError(ValueError):
    """不正構造や上限超過の理由だけを保持する安全な例外。"""


@dataclass(frozen=True)
class _Function:
    name: str
    va: int
    offset: int
    size: int


@dataclass(frozen=True)
class _Instruction:
    address: int
    size: int
    mnemonic: str
    operands: str


def _check_time(deadline: float, clock: Callable[[], float]) -> None:
    if clock() >= deadline:
        raise GoRecoveryError("elapsed_time_limit")


def _offset(pe: pefile.PE, data: bytes, va: int, size: int) -> int:
    rva = va - pe.OPTIONAL_HEADER.ImageBase
    matches = []
    for section in pe.sections:
        relative = rva - section.VirtualAddress
        if 0 <= relative and relative + size <= section.SizeOfRawData:
            start = section.PointerToRawData + relative
            if start + size <= len(data):
                matches.append(start)
    if len(matches) != 1:
        raise GoRecoveryError("unmapped_or_ambiguous_range")
    return matches[0]


def _functions(
    data: bytes, pe: pefile.PE, deadline: float, clock: Callable[[], float]
) -> list[_Function]:
    tables = []
    cursor = 0
    checked = 0
    while True:
        _check_time(deadline, clock)
        offset = data.find(PCLNTAB_MAGIC, cursor)
        if offset < 0:
            break
        checked += 1
        if checked > MAX_TABLE_CANDIDATES:
            raise GoRecoveryError("pclntab_candidate_limit")
        cursor = offset + 8
        if offset + 72 > len(data):
            continue
        nfunc, nfiles, text, names, cu, files, pc, funcs = struct.unpack_from(
            "<8Q", data, offset + 8
        )
        if not 1 <= nfunc <= MAX_FUNCTIONS:
            if nfunc > MAX_FUNCTIONS:
                raise GoRecoveryError("function_count_limit")
            continue
        if (
            not 1 <= nfiles <= MAX_FUNCTIONS
            or not 72 <= names <= cu <= files <= pc <= funcs
        ):
            continue
        if cu - names > MAX_NAMES_BYTES or offset + funcs + (nfunc + 1) * 8 > len(data):
            continue
        try:
            found = []
            previous = -1
            for index in range(nfunc):
                if index % 128 == 0:
                    _check_time(deadline, clock)
                entry, function_offset = struct.unpack_from(
                    "<II", data, offset + funcs + index * 8
                )
                next_entry = struct.unpack_from(
                    "<I", data, offset + funcs + (index + 1) * 8
                )[0]
                record = offset + funcs + function_offset
                if function_offset < (nfunc + 1) * 8 or record + 8 > len(data):
                    raise GoRecoveryError("function_record_out_of_bounds")
                confirmed, name_offset = struct.unpack_from("<Ii", data, record)
                if (
                    confirmed != entry
                    or entry <= previous
                    or next_entry <= entry
                    or name_offset < 0
                ):
                    raise GoRecoveryError("inconsistent_function_table")
                start = offset + names + name_offset
                end = data.find(b"\0", start, min(offset + cu, start + 1024))
                if start < offset + names or end < start:
                    raise GoRecoveryError("function_name_out_of_bounds")
                name = data[start:end].decode("utf-8", errors="strict")
                va = text + entry
                size = next_entry - entry
                raw = _offset(pe, data, va, size)
                executable = [
                    s
                    for s in pe.sections
                    if s.PointerToRawData <= raw < s.PointerToRawData + s.SizeOfRawData
                    and s.Characteristics & 0x20000000
                ]
                if len(executable) != 1:
                    raise GoRecoveryError("function_not_executable_section")
                found.append(_Function(name, va, raw, size))
                previous = entry
            tables.append(found)
        except GoRecoveryError as exc:
            if str(exc) == "elapsed_time_limit":
                raise
            continue
        except (UnicodeError, struct.error):
            continue
    if len(tables) != 1:
        raise GoRecoveryError("pclntab_missing_or_ambiguous")
    return tables[0]


def _disassemble(
    data: bytes, function: _Function, deadline: float, clock: Callable[[], float]
) -> list[_Instruction]:
    if function.size > MAX_FUNCTION_BYTES:
        raise GoRecoveryError("function_byte_limit")
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    output = []
    decoded = 0
    for index, instruction in enumerate(
        md.disasm(data[function.offset : function.offset + function.size], function.va)
    ):
        if index % 128 == 0:
            _check_time(deadline, clock)
        output.append(
            _Instruction(
                instruction.address,
                instruction.size,
                instruction.mnemonic,
                instruction.op_str,
            )
        )
        decoded += instruction.size
    if decoded != function.size:
        raise GoRecoveryError("function_disassembly_incomplete")
    return output


def _immediate(operands: str) -> int | None:
    match = re.search(r", (0x[0-9a-f]+|[0-9]+)$", operands)
    return int(match.group(1), 0) if match else None


def _candidate_constants(
    instructions: list[_Instruction],
    functions: list[_Function],
    deadline: float,
    clock: Callable[[], float],
) -> list[dict]:
    known = {f.va: f for f in functions}
    candidates = []
    for index, instruction in enumerate(instructions):
        if index % 128 == 0:
            _check_time(deadline, clock)
        if instruction.mnemonic != "rep movsq":
            continue
        pre = instructions[max(0, index - 12) : index]
        post = instructions[index + 1 : index + 15]
        source = [
            i
            for i in pre
            if i.mnemonic == "lea"
            and re.fullmatch(r"rsi, \[rip \+ 0x[0-9a-f]+\]", i.operands)
        ]
        counts = [
            _immediate(i.operands)
            for i in pre
            if i.mnemonic == "mov" and i.operands.startswith("ecx, ")
        ]
        lengths = [
            _immediate(i.operands)
            for i in post
            if i.mnemonic == "mov" and i.operands.startswith("ebx, ")
        ]
        keys = [
            _immediate(i.operands)
            for i in post
            if i.mnemonic == "mov" and i.operands.startswith("edi, ")
        ]
        destinations = [
            i
            for i in pre
            if i.mnemonic == "lea"
            and re.fullmatch(r"rdi, \[rsp \+ 0x[0-9a-f]+\]", i.operands)
        ]
        starts = [
            i
            for i in post
            if i.mnemonic == "lea"
            and re.fullmatch(r"rax, \[rsp \+ 0x[0-9a-f]+\]", i.operands)
        ]
        calls = [
            i
            for i in post
            if i.mnemonic == "call"
            and i.operands.startswith("0x")
            and int(i.operands, 16) in known
        ]
        if not all(
            len(v) == 1
            for v in [source, counts, lengths, keys, destinations, starts, calls]
        ):
            continue
        length, key = lengths[0], keys[0]
        if length is None or key is None or counts[0] is None:
            continue
        prefix_size = length - counts[0] * 8
        initial = int(re.search(r"0x[0-9a-f]+", starts[0].operands).group(), 16)
        destination = int(
            re.search(r"0x[0-9a-f]+", destinations[0].operands).group(), 16
        )
        if not 1 <= prefix_size <= 16 or destination - initial != prefix_size:
            continue
        if not 512 <= length <= MAX_OUTPUT_BYTES:
            raise GoRecoveryError("output_size_limit")
        if not 0 <= key < 2**31:
            raise GoRecoveryError("key_range_unsupported")
        prefix = bytearray(prefix_size)
        covered = set()
        for n, load in enumerate(pre[:-1]):
            store = pre[n + 1]
            reg = load.operands.split(", ")[0]
            value = _immediate(load.operands)
            if load.mnemonic != "movabs" or reg not in {"rax", "rdx"} or value is None:
                continue
            match = re.fullmatch(
                r"qword ptr \[rsp \+ (0x[0-9a-f]+)\], " + reg, store.operands
            )
            if store.mnemonic != "mov" or not match:
                continue
            relative = int(match.group(1), 16) - initial
            literal = value.to_bytes(8, "little")
            for v in range(8):
                if 0 <= relative + v < prefix_size:
                    if relative + v in covered and prefix[relative + v] != literal[v]:
                        raise GoRecoveryError("conflicting_prefix_stores")
                    prefix[relative + v] = literal[v]
                    covered.add(relative + v)
        if len(covered) != prefix_size:
            continue
        decoder = known[int(calls[0].operands, 16)]
        if not decoder.name.startswith("main.") or decoder.name in {
            "main.main",
            "main.init",
        }:
            continue
        displacement = int(re.search(r"0x[0-9a-f]+", source[0].operands).group(), 16)
        candidates.append(
            {
                "source_va": source[0].address + source[0].size + displacement,
                "prefix": bytes(prefix),
                "length": length,
                "key": key,
                "decoder": decoder,
                "call_va": calls[0].address,
            }
        )
        if len(candidates) > MAX_COPY_CANDIDATES:
            raise GoRecoveryError("copy_candidate_limit")
    return candidates


def _math_profile(
    instructions: list[_Instruction], deadline: float, clock: Callable[[], float]
) -> list[int]:
    """レビュー済み5段の演算blockを順序・定数・byte storeで照合する。"""
    text = [i.mnemonic + " " + i.operands for i in instructions]

    def find(start: int, templates: tuple[str, ...]) -> int:
        canonical = {_canonical_block(template) for template in templates}
        width = len(templates[0].splitlines())
        first = {template.splitlines()[0].split(" ", 1)[0] for template in templates}
        for index in range(start, len(instructions) - width + 1):
            if index % 128 == 0:
                _check_time(deadline, clock)
            if (
                instructions[index].mnemonic in first
                and _canonical_block("\n".join(text[index : index + width]))
                in canonical
            ):
                return index
        raise GoRecoveryError("decoder_profile_mismatch")

    even = find(0, _EVEN_BLOCKS)
    odd = find(even + len(_EVEN_BLOCKS[0].splitlines()), _ODD_BLOCKS)
    reverse = find(odd + len(_ODD_BLOCKS[0].splitlines()), (_REVERSE_BLOCK,))
    pairs = find(reverse + len(_REVERSE_BLOCK.splitlines()), (_PAIR_BLOCK,))
    subtract = find(pairs + len(_PAIR_BLOCK.splitlines()), (_SUBTRACT_BLOCK,))
    xor_index = find(subtract + len(_SUBTRACT_BLOCK.splitlines()), _XOR_BLOCKS)
    return [
        instructions[n].address
        for n in [even, odd, reverse, pairs, subtract, xor_index]
    ]


def _decode(
    encoded: bytes, key: int, deadline: float, clock: Callable[[], float]
) -> bytes:
    output = bytearray(encoded)
    for index, value in enumerate(output):
        if index % 4096 == 0:
            _check_time(deadline, clock)
        output[index] = (
            ((value - key % 53 - 17 * index) & 255)
            if index % 2 == 0
            else ((value ^ (key % 97) ^ (31 * index)) & 255)
        )
    output.reverse()
    for index in range(0, len(output) - 1, 2):
        if index % 8192 == 0:
            _check_time(deadline, clock)
        output[index], output[index + 1] = output[index + 1], output[index]
    for index, value in enumerate(output):
        if index % 4096 == 0:
            _check_time(deadline, clock)
        output[index] = ((value - (key >> 8) - 3 * index) & 255) ^ (
            (key ^ (5 * index)) & 255
        )
    return bytes(output)


def recover_go_embedded_pe(
    data: bytes, *, clock: Callable[[], float] = time.monotonic
) -> tuple[dict, list[tuple[str, bytes]]]:
    """Go1.20以降の関数表と確認済み復号数学が一致する場合だけPEを返す。"""
    report = {
        "schema_version": 1,
        "status": "not_candidate",
        "method": "go_five_stage_affine_xor_embedded_pe",
        "sample_executed": False,
        "instruction_emulation_performed": False,
        "network_contacted": False,
        "raw_key_published": False,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "terminal_promotion_eligible": False,
    }
    if not isinstance(data, bytes):
        raise TypeError("入力はbytesで指定してください")
    marker_bound = min(len(data), MAX_INPUT_BYTES)
    if (
        not data.startswith(b"MZ")
        or data.find(BUILDINFO_MAGIC, 0, marker_bound) < 0
        or data.find(PCLNTAB_MAGIC, 0, marker_bound) < 0
    ):
        return report, []
    if len(data) > MAX_INPUT_BYTES:
        report["status"] = "input_limit_exceeded"
        return report, []
    deadline = clock() + MAX_ELAPSED_SECONDS
    try:
        pe = pefile.PE(data=data, fast_load=True)
        if (
            pe.FILE_HEADER.Machine != 0x8664
            or pe.OPTIONAL_HEADER.Magic != 0x20B
            or len(pe.sections) > 32
        ):
            raise GoRecoveryError("unsupported_pe_layout")
        functions = _functions(data, pe, deadline, clock)
        mains = [f for f in functions if f.name == "main.main"]
        if len(mains) != 1:
            raise GoRecoveryError("main_missing_or_ambiguous")
        instructions = _disassemble(data, mains[0], deadline, clock)
        candidates = _candidate_constants(instructions, functions, deadline, clock)
        report["function_count"] = len(functions)
        report["copy_candidate_count"] = len(candidates)
        if not candidates:
            return report, []
        if len(candidates) != 1:
            raise GoRecoveryError("ambiguous_copy_candidates")
        candidate = candidates[0]
        decoder = candidate["decoder"]
        decoder_instructions = _disassemble(data, decoder, deadline, clock)
        profile = _math_profile(decoder_instructions, deadline, clock)

        def read_shape_data(va: int, size: int) -> bytes:
            start = _offset(pe, data, va, size)
            return data[start : start + size]

        shape = go_decoder_shape.function_shape(
            [
                {
                    "va": i.address,
                    "bytes": data[
                        decoder.offset + i.address - decoder.va : decoder.offset
                        + i.address
                        - decoder.va
                        + i.size
                    ].hex(),
                    "mnemonic": i.mnemonic,
                    "operands": i.operands,
                }
                for i in decoder_instructions
            ],
            {"va": decoder.va, "size": decoder.size},
            [{"va": f.va, "size": f.size, "name": f.name} for f in functions],
            read_shape_data,
            deadline=deadline,
            clock=clock,
        )
        shape_profile = go_decoder_shape.require_reviewed_shape(
            shape, go_decoder_shape.REVIEWED_SHAPES
        )
        report["reviewed_decoder_shape"] = {
            **shape,
            "profile_id": shape_profile["profile_id"],
        }
        copied_size = candidate["length"] - len(candidate["prefix"])
        source = _offset(pe, data, candidate["source_va"], copied_size)
        encoded = candidate["prefix"] + data[source : source + copied_size]
        payload = _decode(encoded, candidate["key"], deadline, clock)
        extent = inspect_structural_pe_extent(payload, max_extent=MAX_OUTPUT_BYTES)
        if extent.extent is None:
            raise GoRecoveryError("decoded_pe_structure_invalid")
        child = pefile.PE(data=payload, fast_load=True)
        if child.FILE_HEADER.Machine != 0x8664 or child.OPTIONAL_HEADER.Magic != 0x20B:
            raise GoRecoveryError("decoded_pe_architecture_mismatch")
        entry = child.OPTIONAL_HEADER.AddressOfEntryPoint
        _offset(child, payload, child.OPTIONAL_HEADER.ImageBase + entry, 1)
        if not any(
            s.VirtualAddress <= entry < s.VirtualAddress + s.SizeOfRawData
            and s.Characteristics & 0x20000000
            for s in child.sections
        ):
            raise GoRecoveryError("decoded_pe_entry_not_executable")
        _check_time(deadline, clock)
        report.update(
            {
                "status": "recovered",
                "parent_sha256": hashlib.sha256(data).hexdigest(),
                "recovered_sha256": hashlib.sha256(payload).hexdigest(),
                "recovered_size": len(payload),
                "encoded_sha256": hashlib.sha256(encoded).hexdigest(),
                "encoded_size": len(encoded),
                "copy_source_file_offset": source,
                "copy_call_rva": candidate["call_va"] - pe.OPTIONAL_HEADER.ImageBase,
                "decoder_rva": decoder.va - pe.OPTIONAL_HEADER.ImageBase,
                "decoder_name_sha256": hashlib.sha256(
                    decoder.name.encode("utf-8")
                ).hexdigest(),
                "math_evidence_rvas": [
                    va - pe.OPTIONAL_HEADER.ImageBase for va in profile
                ],
                "decoded_pe_structural_extent": extent.extent,
                "candidate_only": True,
            }
        )
        return report, [("go-five-stage-decoded-pe", payload)]
    except (GoRecoveryError, go_decoder_shape.ShapeError) as exc:
        report["status"] = "rejected"
        report["reason"] = str(exc)
    except (
        pefile.PEFormatError,
        struct.error,
        UnicodeError,
        ValueError,
        OverflowError,
    ):
        report["status"] = "rejected"
        report["reason"] = "invalid_static_structure"
    return report, []
