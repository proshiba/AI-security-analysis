"""Remcos配布chainのraw x86定数writerを静的に復元する。

対象profileは、埋め込み鍵をcall/popで参照するcyclic XOR helperと、呼出先bufferへ
4 byte単位で定数を書き込む直線的なx86関数の組合せである。検体、復元code、
PowerShellは実行しない。一般的なemulatorにもせず、検証済み命令だけを有界に
解釈する。profile、鍵参照、writer framingのいずれかが一意でなければfail closed
とする。
"""

from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass
from urllib.parse import urlsplit

try:
    import capstone
    from capstone import x86_const
except ImportError:  # pragma: no cover - 呼出側へ明示statusを返す
    capstone = None
    x86_const = None


_MASK32 = 0xFFFFFFFF
_WRITER_PROLOGUE = b"\x8b\x54\x24\x04"
_KEY_LENGTH_EXPRESSION = re.compile(rb"\xb8(.{4})\x35(.{4})\x05(.{4})\x50", re.DOTALL)
_HELPER_PREFIX = bytes.fromhex(
    "8b5424048b4c240801caf7d98b5c240c8b44241001d889c6f7db89df"
)
_HELPER_MIDDLE = bytes.fromhex("8a040a01f33203")
_HELPER_LOOP = bytes.fromhex("29f343750289fb88040a4175")
_SEMANTIC_HELPER = re.compile(
    rb"\x8b\x54\x24\x04"  # mov edx,[esp+4]
    rb".{0,32}?\x8b\x4c\x24\x08"  # mov ecx,[esp+8]
    rb".{0,32}?\x01\xca"  # add edx,ecx
    rb".{0,16}?\xf7\xd9"  # neg ecx
    rb".{0,32}?\x8b\x5c\x24\x0c"  # mov ebx,[esp+c]
    rb".{0,32}?\x8b\x44\x24\x10"  # mov eax,[esp+10]
    rb".{0,96}?\x01\xd8"  # add eax,ebx
    rb".{0,16}?\x89\xc6"  # mov esi,eax
    rb".{0,32}?\xf7\xdb"  # neg ebx
    rb".{0,32}?\x89\xdf"  # mov edi,ebx
    rb".{0,96}?(?P<load>\x8a\x04\x0a)"  # mov al,[edx+ecx]
    rb".{0,32}?\x01\xf3"  # add ebx,esi
    rb".{0,16}?\x32\x03"  # xor al,[ebx]
    rb".{0,1024}?\x29\xf3"  # sub ebx,esi（直jmpで分離される変種を含む）
    rb".{0,16}?\x43"  # inc ebx
    rb".{0,32}?\x89\xfb"  # mov ebx,edi
    rb".{0,32}?\x88\x04\x0a"  # mov [edx+ecx],al
    rb".{0,16}?\x41"  # inc ecx
    rb".{0,16}?(?P<branch>\x75.|\x0f\x85.{4})"  # jne rel8/rel32
    rb".{0,16}?\xc2\x10\x00",  # ret 0x10
    re.DOTALL,
)
_HOST_PATH = re.compile(
    r"(?i)^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}/[^\x00\s]{1,2048}$"
)


@dataclass(frozen=True)
class RemcosNativeConstantLimits:
    """raw code解析のhard limit。"""

    max_input_bytes: int = 4 * 1024 * 1024
    max_helper_gap_bytes: int = 64
    max_wrapper_bytes: int = 160
    max_wrapper_flow_bytes: int = 2048
    max_wrapper_instructions: int = 256
    max_wrapper_jumps: int = 32
    max_key_bytes: int = 4096
    max_candidates: int = 128
    max_writer_instructions: int = 20_000
    max_write_operations: int = 32_768
    max_writer_output_bytes: int = 1024 * 1024
    max_total_output_bytes: int = 8 * 1024 * 1024
    max_artifacts: int = 128


DEFAULT_LIMITS = RemcosNativeConstantLimits()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _u32(value: int) -> int:
    return value & _MASK32


def _signed32(value: int) -> int:
    value &= _MASK32
    return value - 0x1_0000_0000 if value & 0x8000_0000 else value


def _rol32(value: int, amount: int) -> int:
    amount &= 31
    return _u32((value << amount) | (value >> ((32 - amount) & 31)))


def _ror32(value: int, amount: int) -> int:
    amount &= 31
    return _u32((value >> amount) | (value << ((32 - amount) & 31)))


def _direct_call_target(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 5 > len(data) or data[offset] != 0xE8:
        return None
    displacement = int.from_bytes(data[offset + 1 : offset + 5], "little", signed=True)
    target = offset + 5 + displacement
    return target if 0 <= target < len(data) else None


def _direct_call_index(data: bytes) -> dict[int, list[int]]:
    calls: dict[int, list[int]] = {}
    for offset in range(max(0, len(data) - 4)):
        target = _direct_call_target(data, offset)
        if target is not None:
            calls.setdefault(target, []).append(offset)
    return calls


def _unique_helper(data: bytes, limits: RemcosNativeConstantLimits) -> int | None:
    """Reviewed helperの4個の順序付きanchorが一意な場合だけ返す。"""

    matches: list[int] = []
    cursor = 0
    while True:
        start = data.find(_HELPER_PREFIX, cursor)
        if start < 0:
            break
        middle = data.find(
            _HELPER_MIDDLE,
            start + len(_HELPER_PREFIX),
            start + len(_HELPER_PREFIX) + limits.max_helper_gap_bytes,
        )
        loop = (
            data.find(
                _HELPER_LOOP,
                middle + len(_HELPER_MIDDLE),
                middle + len(_HELPER_MIDDLE) + limits.max_helper_gap_bytes,
            )
            if middle >= 0
            else -1
        )
        ret = (
            data.find(
                b"\xc2\x10\x00",
                loop + len(_HELPER_LOOP),
                loop + len(_HELPER_LOOP) + limits.max_helper_gap_bytes,
            )
            if loop >= 0
            else -1
        )
        if middle >= 0 and loop >= 0 and ret >= 0:
            matches.append(start)
        cursor = start + 1
    if len(matches) == 1:
        return matches[0]
    semantic: list[int] = []
    for match in _SEMANTIC_HELPER.finditer(data):
        branch_offset = match.start("branch")
        branch = match.group("branch")
        displacement = int.from_bytes(
            branch[1:] if branch[0] == 0x75 else branch[2:],
            "little",
            signed=True,
        )
        branch_target = branch_offset + len(branch) + displacement
        load_offset = match.start("load")
        if match.start() <= branch_target <= load_offset:
            semantic.append(match.start())
    semantic = sorted(set(semantic))
    return semantic[0] if len(semantic) == 1 else None


def _helper_entry_targets(
    data: bytes,
    helper: int,
    calls: dict[int, list[int]],
) -> list[int]:
    """prologue直前のsemantics-preserving instructionを含むcall targetを返す。"""

    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    accepted: list[int] = []
    for target in calls:
        if not helper - 4 <= target <= helper:
            continue
        cursor = target
        reached = target == helper
        try:
            for instruction in engine.disasm(data[target : helper + 4], target):
                if int(instruction.address) != cursor:
                    break
                if int(instruction.address) == helper:
                    reached = True
                    break
                if instruction.mnemonic.casefold() not in {
                    "nop",
                    "xchg",
                    "cld",
                    "cmp",
                    "test",
                }:
                    break
                cursor += int(instruction.size)
        except (TypeError, ValueError, capstone.CsError):
            reached = False
        if reached:
            accepted.append(target)
    return sorted(set(accepted))


def _semantic_key_lengths(
    data: bytes,
    wrapper: int,
    helper_call: int,
    limits: RemcosNativeConstantLimits,
) -> list[int]:
    """wrapper内のregister定数演算からpushされた鍵長だけを復元する。"""

    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    cursor = wrapper
    visited: set[int] = set()
    values: dict[int, int] = {}
    pushed: list[int] = []
    stack_top: int | None = None
    reached_call = False
    instruction_count = 0
    jump_count = 0

    def finish_stack_top() -> None:
        if stack_top is not None and 1 <= stack_top <= limits.max_key_bytes:
            pushed.append(stack_top)

    try:
        while cursor not in visited:
            if not wrapper <= cursor <= helper_call:
                break
            if cursor - wrapper > limits.max_wrapper_flow_bytes:
                break
            visited.add(cursor)
            instruction = next(engine.disasm(data[cursor : cursor + 16], cursor), None)
            if instruction is None or int(instruction.address) != cursor:
                break
            instruction_count += 1
            if instruction_count > limits.max_wrapper_instructions:
                break
            address = cursor
            next_cursor = cursor + int(instruction.size)
            if address == helper_call:
                reached_call = instruction.mnemonic.casefold() == "call"
                break
            if instruction.group(capstone.CS_GRP_CALL):
                break
            operands = tuple(instruction.operands)
            mnemonic = instruction.mnemonic.casefold()
            if instruction.group(capstone.CS_GRP_JUMP):
                jump_count += 1
                if jump_count > limits.max_wrapper_jumps:
                    break
                if mnemonic == "jmp":
                    if len(operands) != 1 or operands[0].type != x86_const.X86_OP_IMM:
                        break
                    target = int(operands[0].imm)
                    if not wrapper <= target <= helper_call:
                        break
                    cursor = target
                    continue
                cursor = next_cursor
                continue
            if mnemonic == "push" and len(operands) == 1:
                finish_stack_top()
                if operands[0].type == x86_const.X86_OP_REG:
                    stack_top = values.get(int(operands[0].reg))
                else:
                    stack_top = _immediate(operands[0])
                cursor = next_cursor
                continue
            if (
                operands
                and operands[0].type == x86_const.X86_OP_MEM
                and int(operands[0].mem.base) == x86_const.X86_REG_ESP
                and int(operands[0].mem.index) == x86_const.X86_REG_INVALID
                and int(operands[0].mem.disp) == 0
                and int(operands[0].size) == 4
                and len(operands) == 2
                and (immediate := _immediate(operands[1])) is not None
                and stack_top is not None
                and mnemonic in {"add", "sub", "xor"}
            ):
                if mnemonic == "add":
                    stack_top = _u32(stack_top + immediate)
                elif mnemonic == "sub":
                    stack_top = _u32(stack_top - immediate)
                else:
                    stack_top ^= immediate
                cursor = next_cursor
                continue
            if not operands or operands[0].type != x86_const.X86_OP_REG:
                cursor = next_cursor
                continue
            destination = int(operands[0].reg)
            immediate = _immediate(operands[1]) if len(operands) == 2 else None
            if mnemonic == "mov" and immediate is not None:
                values[destination] = immediate
            elif (
                mnemonic in {"add", "sub", "xor"}
                and immediate is not None
                and destination in values
            ):
                current = values[destination]
                if mnemonic == "add":
                    values[destination] = _u32(current + immediate)
                elif mnemonic == "sub":
                    values[destination] = _u32(current - immediate)
                else:
                    values[destination] = current ^ immediate
            else:
                values.pop(destination, None)
            cursor = next_cursor
    except (AttributeError, TypeError, ValueError, capstone.CsError):
        reached_call = False
    return sorted(set(pushed)) if reached_call else []


def _wrapper_key(
    data: bytes,
    helper: int,
    calls: dict[int, list[int]],
    limits: RemcosNativeConstantLimits,
) -> tuple[bytes, dict[str, int]] | None:
    """helper call、定数式、wrapper callからcall/pop鍵を一意に復元する。"""

    helper_targets = _helper_entry_targets(data, helper, calls)
    helper_callers = sorted(
        {caller for target in helper_targets for caller in calls.get(target, [])}
    )
    candidates: list[tuple[bytes, dict[str, int]]] = []
    for helper_call in helper_callers:
        window_start = max(0, helper_call - limits.max_wrapper_bytes)
        window = data[window_start:helper_call]
        for expression in _KEY_LENGTH_EXPRESSION.finditer(window):
            key_length = _u32(
                int.from_bytes(expression.group(1), "little")
                ^ int.from_bytes(expression.group(2), "little")
            )
            key_length = _u32(
                key_length + int.from_bytes(expression.group(3), "little")
            )
            if not 1 <= key_length <= limits.max_key_bytes:
                continue
            expression_offset = window_start + expression.start()
            # wrapper entryは定数式の直前32 byte以内で、外部direct callが一意に
            # 指す位置に限定する。任意位置のrandom E8を鍵参照とは扱わない。
            wrapper_refs: list[tuple[int, int]] = []
            for target, references in calls.items():
                if (
                    not max(window_start, expression_offset - 32)
                    <= target
                    <= expression_offset
                ):
                    continue
                if (
                    not target
                    <= expression_offset
                    < helper_call
                    < target + limits.max_wrapper_bytes
                ):
                    continue
                wrapper_refs.extend((target, reference) for reference in references)
            for wrapper, caller in wrapper_refs:
                key_offset = caller + 5
                if key_offset + key_length > len(data):
                    continue
                # call先からhelper callまでの直線decodeを要求する。opaque conditional
                # branchはbyte列中にあっても実行せず、helper call自体の境界だけを検証する。
                engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
                cursor = wrapper
                decoded_helper_call = False
                try:
                    for instruction in engine.disasm(
                        data[wrapper : helper_call + 5], wrapper
                    ):
                        if int(instruction.address) != cursor:
                            break
                        cursor += int(instruction.size)
                        if int(instruction.address) == helper_call:
                            decoded_helper_call = (
                                instruction.mnemonic.lower() == "call"
                                and _direct_call_target(data, helper_call) == helper
                            )
                            break
                except (TypeError, ValueError, capstone.CsError):
                    decoded_helper_call = False
                if not decoded_helper_call:
                    continue
                key = data[key_offset : key_offset + key_length]
                candidates.append(
                    (
                        key,
                        {
                            "helper_offset": helper,
                            "helper_call_offset": helper_call,
                            "wrapper_offset": wrapper,
                            "wrapper_call_offset": caller,
                            "key_offset": key_offset,
                            "key_size": key_length,
                        },
                    )
                )
        semantic_wrappers = [
            target
            for target, references in calls.items()
            if references
            and max(0, helper_call - limits.max_wrapper_flow_bytes)
            <= target
            <= helper_call
        ]
        for wrapper in semantic_wrappers:
            key_lengths = _semantic_key_lengths(data, wrapper, helper_call, limits)
            for key_length in key_lengths:
                for caller in calls.get(wrapper, []):
                    key_offset = caller + 5
                    if key_offset + key_length > len(data):
                        continue
                    key = data[key_offset : key_offset + key_length]
                    candidates.append(
                        (
                            key,
                            {
                                "helper_offset": helper,
                                "helper_call_offset": helper_call,
                                "wrapper_offset": wrapper,
                                "wrapper_call_offset": caller,
                                "key_offset": key_offset,
                                "key_size": key_length,
                            },
                        )
                    )
    unique = {
        (value[0], tuple(sorted(value[1].items()))): value for value in candidates
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _is_edx_register(operand: object) -> bool:
    return bool(
        getattr(operand, "type", None) == x86_const.X86_OP_REG
        and int(getattr(operand, "reg", 0)) == x86_const.X86_REG_EDX
    )


def _immediate(operand: object) -> int | None:
    if getattr(operand, "type", None) != x86_const.X86_OP_IMM:
        return None
    return _u32(int(operand.imm))


def _evaluate_writer(
    data: bytes,
    start: int,
    limits: RemcosNativeConstantLimits,
) -> tuple[bytes | None, dict[str, object]]:
    """review済みの直線命令だけでdword writerを復元する。"""

    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    edx: int | None = None
    memory: dict[int, int] = {}
    written: set[int] = set()
    instruction_count = 0
    write_operations = 0
    cursor = start
    termination = "decode_failed"
    termination_offset: int | None = None
    try:
        instructions = engine.disasm(data[start:], start)
        for instruction in instructions:
            if int(instruction.address) != cursor:
                termination = "decode_gap"
                termination_offset = cursor
                break
            cursor += int(instruction.size)
            instruction_count += 1
            if instruction_count > limits.max_writer_instructions:
                termination = "instruction_limit_exceeded"
                termination_offset = int(instruction.address)
                break
            operands = tuple(instruction.operands)
            mnemonic = instruction.mnemonic.lower()
            if instruction_count == 1:
                if (
                    mnemonic != "mov"
                    or len(operands) != 2
                    or not _is_edx_register(operands[0])
                    or operands[1].type != x86_const.X86_OP_MEM
                    or int(operands[1].mem.base) != x86_const.X86_REG_ESP
                    or int(operands[1].mem.index) != x86_const.X86_REG_INVALID
                    or int(operands[1].mem.disp) != 4
                ):
                    termination = "prologue_rejected"
                    termination_offset = int(instruction.address)
                    break
                edx = 0
                continue
            if instruction.group(capstone.CS_GRP_RET):
                termination = "ret"
                termination_offset = int(instruction.address)
                break
            if instruction.group(capstone.CS_GRP_CALL) or instruction.group(
                capstone.CS_GRP_JUMP
            ):
                termination = "control_flow_rejected"
                termination_offset = int(instruction.address)
                break
            if operands and _is_edx_register(operands[0]):
                if edx is None:
                    termination = "edx_uninitialized"
                    termination_offset = int(instruction.address)
                    break
                immediate = _immediate(operands[1]) if len(operands) == 2 else None
                if mnemonic in {"inc", "dec"} and len(operands) == 1:
                    edx = _signed32(edx + (1 if mnemonic == "inc" else -1))
                elif mnemonic in {"add", "sub", "xor"} and immediate is not None:
                    if mnemonic == "add":
                        edx = _signed32(edx + immediate)
                    elif mnemonic == "sub":
                        edx = _signed32(edx - immediate)
                    else:
                        edx = _signed32(edx ^ immediate)
                elif mnemonic in {"neg", "not"} and len(operands) == 1:
                    edx = _signed32(-edx if mnemonic == "neg" else ~edx)
                elif mnemonic in {"rol", "ror"} and immediate is not None:
                    value = (
                        _rol32(edx, immediate)
                        if mnemonic == "rol"
                        else _ror32(edx, immediate)
                    )
                    edx = _signed32(value)
                else:
                    termination = "edx_operation_rejected"
                    termination_offset = int(instruction.address)
                    break
                continue
            if operands and operands[0].type == x86_const.X86_OP_MEM:
                destination = operands[0].mem
                if not (
                    int(destination.base) == x86_const.X86_REG_EDX
                    and int(destination.index) == x86_const.X86_REG_INVALID
                    and int(destination.disp) == 0
                    and int(operands[0].size) == 4
                    and edx is not None
                    and 0 <= edx <= limits.max_writer_output_bytes - 4
                ):
                    termination = "memory_destination_rejected"
                    termination_offset = int(instruction.address)
                    break
                offset = edx
                immediate = _immediate(operands[1]) if len(operands) == 2 else None
                write_operations += 1
                if write_operations > limits.max_write_operations:
                    termination = "write_limit_exceeded"
                    termination_offset = int(instruction.address)
                    break
                if mnemonic == "mov" and immediate is not None:
                    memory[offset] = immediate
                    written.add(offset)
                elif (
                    mnemonic in {"add", "sub", "xor", "and", "or"}
                    and immediate is not None
                    and offset in memory
                ):
                    current = memory[offset]
                    if mnemonic == "add":
                        memory[offset] = _u32(current + immediate)
                    elif mnemonic == "sub":
                        memory[offset] = _u32(current - immediate)
                    elif mnemonic == "xor":
                        memory[offset] = current ^ immediate
                    elif mnemonic == "and":
                        memory[offset] = current & immediate
                    else:
                        memory[offset] = current | immediate
                elif (
                    mnemonic in {"neg", "not"}
                    and len(operands) == 1
                    and offset in memory
                ):
                    memory[offset] = _u32(
                        -memory[offset] if mnemonic == "neg" else ~memory[offset]
                    )
                elif (
                    mnemonic in {"rol", "ror"}
                    and immediate is not None
                    and offset in memory
                ):
                    memory[offset] = (
                        _rol32(memory[offset], immediate)
                        if mnemonic == "rol"
                        else _ror32(memory[offset], immediate)
                    )
                else:
                    termination = "memory_operation_rejected"
                    termination_offset = int(instruction.address)
                    break
                continue
            # unrelated register/stack/flag instructionを無視しない。profile driftや
            # code/data誤認を成功扱いしないため、未知命令は即座にrejectする。
            termination = "instruction_rejected"
            termination_offset = int(instruction.address)
            break
    except (AttributeError, TypeError, ValueError, capstone.CsError):
        termination = "disassembly_failed"

    offsets = sorted(written)
    contiguous = bool(offsets) and offsets == list(range(0, offsets[-1] + 1, 4))
    output = (
        b"".join(memory[offset].to_bytes(4, "little") for offset in offsets)
        if termination == "ret" and contiguous
        else None
    )
    return output, {
        "entry_offset": start,
        "instruction_count": instruction_count,
        "write_operation_count": write_operations,
        "dword_count": len(offsets),
        "termination": termination,
        "termination_offset": termination_offset,
        "contiguous_dword_writes": contiguous,
        "framed_output_size": len(output) if output is not None else 0,
        "framed_output_sha256": _sha256(output) if output is not None else None,
    }


def _decode_text(value: bytes) -> tuple[str, list[str], str] | None:
    if not value:
        return None
    if len(value) % 2 == 0 and value[1::2].count(0) >= max(1, len(value) // 4):
        try:
            text = value.decode("utf-16-le").rstrip("\x00")
        except UnicodeDecodeError:
            text = ""
        if text and all(
            character.isprintable() or character in "\r\n\t" for character in text
        ):
            return text, [text], "utf-16-le"
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError:
        return None
    parts = text.rstrip("\x00").split("\x00")
    if not parts or any(not part for part in parts):
        return None
    if not all(
        all(character.isprintable() or character in "\r\n\t" for character in part)
        for part in parts
    ):
        return None
    return (
        text.rstrip("\x00"),
        parts,
        "utf-8-c-string-list" if len(parts) > 1 else "utf-8",
    )


def _network_candidates(
    parts: list[str], source_sequence: int
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    for order, part in enumerate(parts, 1):
        if not _HOST_PATH.fullmatch(part):
            continue
        parsed = urlsplit("//" + part)
        if not parsed.hostname or parsed.username or parsed.password or parsed.port:
            continue
        candidates.append(
            {
                "source_sequence": source_sequence,
                "order": order,
                "role": "payload_retrieval_candidate",
                "host": parsed.hostname.lower(),
                "path": parsed.path,
                "scheme": "unresolved",
                "c2_confirmed": False,
            }
        )
    return candidates


def recover_remcos_native_constants(
    data: bytes,
    *,
    limits: RemcosNativeConstantLimits = DEFAULT_LIMITS,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """検証済みraw x86 profileから暗号化定数と配布候補を復元する。"""

    report: dict[str, object] = {
        "schema_version": 1,
        "profile": "remcos-raw-x86-call-pop-cyclic-xor-writer-v1",
        "status": "rejected",
        "input_size": len(data) if isinstance(data, bytes) else None,
        "input_sha256": _sha256(data) if isinstance(data, bytes) else None,
        "candidate_set_complete": False,
        "candidate_set_truncated": False,
        "candidate_count": 0,
        "limits": asdict(limits),
        "candidates": [],
        "network_candidates": [],
        "rejections": {},
        "safety": {
            "sample_executed": False,
            "shellcode_executed": False,
            "network_contacted": False,
            "general_emulator_used": False,
            "raw_key_included": False,
        },
        "evidence_boundary": {
            "family_attribution_allowed": False,
            "c2_confirmation_allowed": False,
            "network_candidate_is_payload_delivery": True,
            "scheme_inferred": False,
            "terminal_payload_confirmed": False,
        },
    }
    if not isinstance(data, bytes):
        raise TypeError("dataはbytesである必要があります")
    if not data or len(data) > limits.max_input_bytes:
        report["status"] = "input_size_rejected"
        return report, []
    if capstone is None or x86_const is None:
        report["status"] = "dependency_unavailable"
        return report, []
    # 汎用data層へ無条件統合されるため、review済みhelperの構造signalが
    # まったく無い入力は「候補集合を列挙できなかった」のではなく非該当である。
    # ここをincompleteのまま返すと、無関係なdata childが1個あるだけで親case
    # 全体がpartialへ誤昇格する。完全prefixまたはsemantic helperのどちらかを
    # 観測した後だけ、一意性失敗をfail-closedなincompleteとして扱う。
    helper_signal_present = _HELPER_PREFIX in data or _SEMANTIC_HELPER.search(data)
    if not helper_signal_present:
        report.update(
            {
                "status": "not_applicable_profile",
                "candidate_set_complete": True,
            }
        )
        return report, []
    helper = _unique_helper(data, limits)
    if helper is None:
        report["status"] = "decrypt_helper_not_unique"
        return report, []
    calls = _direct_call_index(data)
    context = _wrapper_key(data, helper, calls, limits)
    if context is None:
        report["status"] = "key_context_not_unique"
        return report, []
    key, context_report = context
    report["decrypt_context"] = {
        **context_report,
        "key_sha256": _sha256(key),
    }

    starts: list[int] = []
    cursor = 0
    while True:
        start = data.find(_WRITER_PROLOGUE, cursor)
        if start < 0:
            break
        starts.append(start)
        cursor = start + 1
    if len(starts) > limits.max_candidates:
        report.update(
            {
                "status": "candidate_limit_exceeded",
                "candidate_set_truncated": True,
                "candidate_count_lower_bound": len(starts),
            }
        )
        return report, []

    candidates: list[dict[str, object]] = []
    network: list[dict[str, object]] = []
    artifacts: list[tuple[str, bytes]] = []
    rejections: Counter[str] = Counter()
    total_output = 0
    sequence = 0
    seen: set[str] = set()
    for start in starts:
        references = calls.get(start, [])
        framed, metrics = _evaluate_writer(data, start, limits)
        if framed is None:
            rejections[str(metrics["termination"])] += 1
            continue
        if len(framed) < 5:
            rejections["framing_too_short"] += 1
            continue
        payload_size = int.from_bytes(framed[:4], "little")
        if not 1 <= payload_size <= len(framed) - 4:
            rejections["framing_length_rejected"] += 1
            continue
        padding = framed[4 + payload_size :]
        if len(padding) > 3 or any(padding):
            rejections["framing_padding_rejected"] += 1
            continue
        ciphertext = framed[4 : 4 + payload_size]
        plaintext = bytes(
            value ^ key[index % len(key)] for index, value in enumerate(ciphertext)
        )
        decoded = _decode_text(plaintext)
        if decoded is None:
            rejections["plaintext_validation_rejected"] += 1
            continue
        _text, parts, encoding = decoded
        total_output += len(plaintext)
        if total_output > limits.max_total_output_bytes:
            report.update(
                {
                    "status": "total_output_limit_exceeded",
                    "candidate_set_truncated": True,
                }
            )
            return report, []
        digest = _sha256(plaintext)
        if digest in seen:
            rejections["duplicate_plaintext"] += 1
            continue
        seen.add(digest)
        sequence += 1
        candidate_network = _network_candidates(parts, sequence)
        network.extend(candidate_network)
        candidate = {
            **metrics,
            "sequence": sequence,
            "direct_call_reference_present": bool(references),
            "call_reference_offsets": references[:16],
            "plaintext_size": len(plaintext),
            "plaintext_sha256": digest,
            "text_encoding": encoding,
            "string_count": len(parts),
            "network_candidate_count": len(candidate_network),
            "artifact_emitted": True,
        }
        candidates.append(candidate)
        if len(artifacts) >= limits.max_artifacts:
            report.update(
                {
                    "status": "artifact_limit_exceeded",
                    "candidate_set_truncated": True,
                }
            )
            return report, []
        extension = "txt" if encoding.startswith("utf-") else "bin"
        artifacts.append(
            (f"remcos-native-constant-{sequence:03d}.{extension}", plaintext)
        )

    report.update(
        {
            "status": "constants_recovered"
            if candidates
            else "writer_candidates_rejected",
            "candidate_set_complete": True,
            "candidate_count": len(candidates),
            "writer_prologue_count": len(starts),
            "candidates": candidates,
            "network_candidates": network,
            "rejections": dict(sorted(rejections.items())),
        }
    )
    return report, artifacts


__all__ = [
    "DEFAULT_LIMITS",
    "RemcosNativeConstantLimits",
    "recover_remcos_native_constants",
]
