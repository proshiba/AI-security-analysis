"""MSI／CAB／AutoHotkey経路のAES-GCM設定候補を静的に復元する。

この復元器は、同一CAB内のAutoHotkey runtime、定数pathとBase64URL復号・連結syntax、
carrierを相関し、x64 shellcodeのentry、container parser、AES-256 key導出、
GCM認証、inner config候補を復元する。MSI Component／Directoryからinstall pathへの
結合、AHK decode引数、shellcode内の完全なconfig-to-network data-flowは証明しない。
結果は手動確認用候補だけであり、検体や復元payloadは実行せず、外部通信も行わない。
"""

from __future__ import annotations

import base64
import io
import ipaddress
import re
import struct
from dataclasses import dataclass

import cabarchive
import olefile
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AH,
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_CH,
    X86_REG_CL,
    X86_REG_CX,
    X86_REG_DH,
    X86_REG_DL,
    X86_REG_DX,
    X86_REG_EAX,
    X86_REG_ECX,
    X86_REG_EDX,
    X86_REG_ESP,
    X86_REG_INVALID,
    X86_REG_R8,
    X86_REG_R8B,
    X86_REG_R8D,
    X86_REG_R8W,
    X86_REG_R9,
    X86_REG_R9B,
    X86_REG_R9D,
    X86_REG_R9W,
    X86_REG_RAX,
    X86_REG_RCX,
    X86_REG_RDX,
    X86_REG_RIP,
    X86_REG_RSP,
    X86_REG_SP,
    X86_REG_SPL,
)
from Cryptodome.Cipher import AES

MINIMUM_MSI_SIZE = 4 * 1024
MAXIMUM_MSI_SIZE = 64 * 1024 * 1024
MAXIMUM_OLE_STREAMS = 4_096
MAXIMUM_OLE_STREAM_SIZE = 64 * 1024 * 1024
MAXIMUM_OLE_TOTAL_SIZE = 128 * 1024 * 1024
MAXIMUM_CAB_MEMBERS = 256
MAXIMUM_CAB_MEMBER_SIZE = 64 * 1024 * 1024
MAXIMUM_CAB_TOTAL_SIZE = 96 * 1024 * 1024
MAXIMUM_SCRIPT_SIZE = 128 * 1024
MAXIMUM_CARRIER_SIZE = 8 * 1024 * 1024
MAXIMUM_SHELLCODE_SIZE = 4 * 1024 * 1024
MAXIMUM_FUNCTION_BYTES = 0x4000
MAXIMUM_FUNCTION_INSTRUCTIONS = 24_000
MAXIMUM_REACHABLE_FUNCTIONS = 96
MAXIMUM_CALL_DEPTH = 2
MAXIMUM_CFG_BLOCKS = 1_024
MAXIMUM_DECRYPTOR_PATH_STATES = 65_536
MAXIMUM_MSI_STRINGS = 16_384
MAXIMUM_MSI_STRING_DATA = 16 * 1024 * 1024
OUTER_HEADER_SIZE = 0x34
MAXIMUM_CIPHERTEXT_SIZE = 0x7CC
INNER_HEADER_SIZE = 0x11
INNER_MAGIC = 0x91D47B2E
INNER_VERSION = 7

_OLE_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
_MSI_DATABASE_CLSID = "000C1084-0000-0000-C000-000000000046"
_MSI_NAME_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"
_BASE64URL = re.compile(rb"[A-Za-z0-9_-]+={0,2}")
_DOMAIN = re.compile(
    r"(?i)(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}\Z"
)
_BCRYPT_GCM_STRINGS = frozenset(
    {"AES", "ChainingModeGCM", "ChainingMode", "ObjectLength"}
)
_BCRYPT_GCM_STRING_ORDER = (
    "AES",
    "ChainingModeGCM",
    "ChainingMode",
    "ObjectLength",
)
_DECRYPTOR_SCHEMA_IMMEDIATES = (
    1,
    OUTER_HEADER_SIZE,
    INNER_HEADER_SIZE,
    MAXIMUM_CIPHERTEXT_SIZE,
    INNER_MAGIC,
    INNER_VERSION,
    0x100,
    0x110,
    0x200,
    0x210,
    0x310,
    10,
)
_DECRYPTOR_SCHEMA_DISPLACEMENTS = (0x10, 0x12, 0x14, 0x510)
_WINSOCK_API_HASHES = {
    "WSAStartup": 0x1C80EC1F,
    "socket": 0x9012766C,
    "connect": 0xAAE0CCF9,
    "getaddrinfo": 0x9467F52C,
    "freeaddrinfo": 0x36BC6608,
}
_WINSOCK_API_SLOTS = {
    "WSAStartup": 0xA0,
    "socket": 0xA8,
    "connect": 0xB8,
    "getaddrinfo": 0xE0,
    "freeaddrinfo": 0xE8,
}
_REGISTER_NAMES = {
    X86_REG_AH: "ah",
    X86_REG_AL: "al",
    X86_REG_AX: "ax",
    X86_REG_EAX: "eax",
    X86_REG_RAX: "rax",
    X86_REG_CH: "ch",
    X86_REG_CL: "cl",
    X86_REG_CX: "cx",
    X86_REG_ECX: "ecx",
    X86_REG_RCX: "rcx",
    X86_REG_DH: "dh",
    X86_REG_DL: "dl",
    X86_REG_DX: "dx",
    X86_REG_EDX: "edx",
    X86_REG_RDX: "rdx",
    X86_REG_SPL: "spl",
    X86_REG_SP: "sp",
    X86_REG_ESP: "esp",
    X86_REG_RSP: "rsp",
    X86_REG_R8B: "r8b",
    X86_REG_R8W: "r8w",
    X86_REG_R8D: "r8d",
    X86_REG_R8: "r8",
    X86_REG_R9B: "r9b",
    X86_REG_R9W: "r9w",
    X86_REG_R9D: "r9d",
    X86_REG_R9: "r9",
}
_REGISTER_FAMILIES = {
    "al": "rax",
    "ah": "rax",
    "ax": "rax",
    "eax": "rax",
    "rax": "rax",
    "cl": "rcx",
    "ch": "rcx",
    "cx": "rcx",
    "ecx": "rcx",
    "rcx": "rcx",
    "dl": "rdx",
    "dh": "rdx",
    "dx": "rdx",
    "edx": "rdx",
    "rdx": "rdx",
    "spl": "rsp",
    "sp": "rsp",
    "esp": "rsp",
    "rsp": "rsp",
    "r8b": "r8",
    "r8w": "r8",
    "r8d": "r8",
    "r8": "r8",
    "r9b": "r9",
    "r9w": "r9",
    "r9d": "r9",
    "r9": "r9",
}


@dataclass(frozen=True)
class _MainProfile:
    container_offset: int
    parser_offset: int


@dataclass(frozen=True)
class _OuterContainer:
    offset: int
    magic: bytes
    nonce: bytes
    tag: bytes
    aad: bytes
    ciphertext: bytes


@dataclass(frozen=True)
class _InnerConfig:
    host: str
    port: int
    auxiliary_lengths: tuple[int, int, int]
    flag: int

    @property
    def endpoint(self) -> str:
        """hostとportを曖昧性のないendpoint表現へ変換する。"""

        if ":" in self.host:
            return f"[{self.host}]:{self.port}"
        return f"{self.host}:{self.port}"


@dataclass(frozen=True)
class _CabMember:
    """MSI File tableへ結合済みのCAB memberを保持する。"""

    key: str
    installed_name: str
    data: bytes


@dataclass(frozen=True)
class _MsiFileRecord:
    """File tableで検証したCAB key、配置名、size、sequenceを保持する。"""

    installed_name: str
    size: int
    sequence: int


@dataclass(frozen=True)
class _MsiMediaRecord:
    """Media tableで検証した埋込Cabinetとsequence境界を保持する。"""

    disk_id: int
    last_sequence: int
    cabinet_stream: str


@dataclass(frozen=True)
class _AhkScriptProfile:
    """AHKの定数carrier pathと復号・実行data-flowを保持する。"""

    carrier_basename: str


@dataclass(frozen=True)
class _WinsockResolution:
    """検証済みresolverとWinsock API table slotを保持する。"""

    initializer_offset: int
    export_resolver_offset: int
    slots: dict[str, int]


@dataclass(frozen=True)
class _FunctionGraph:
    """到達可能命令、CFG edge、dominatorを保持する。"""

    entry: int
    instructions: tuple[object, ...]
    by_address: dict[int, object]
    successors: dict[int, tuple[int, ...]]
    predecessors: dict[int, tuple[int, ...]]
    dominators: dict[int, frozenset[int]]


@dataclass(frozen=True)
class MsiAhkAesGcmRecovery:
    """公開可能な構造観測と復元済み手動確認候補を保持する。"""

    source_size: int
    cab_member_count: int
    shellcode: bytes
    endpoint: str
    auxiliary_lengths: tuple[int, int, int]
    flag: int
    evidence: dict[str, object]


def _immediate_values(instructions: tuple[object, ...]) -> set[int]:
    """命令列に現れる非負即値を有界集合へ正規化する。"""

    return {
        int(operand.imm) & 0xFFFFFFFFFFFFFFFF
        for instruction in instructions
        for operand in instruction.operands
        if operand.type == X86_OP_IMM
    }


def _memory_displacements(instructions: tuple[object, ...]) -> set[int]:
    """RIP相対以外のmemory displacementを収集する。"""

    return {
        int(operand.mem.disp)
        for instruction in instructions
        for operand in instruction.operands
        if operand.type == X86_OP_MEM
        and operand.mem.base not in {X86_REG_INVALID, X86_REG_RIP}
    }


def _rip_target(instruction: object, operand: object) -> int | None:
    """RIP相対operandが参照するshellcode内offsetを返す。"""

    if operand.type != X86_OP_MEM or operand.mem.base != X86_REG_RIP:
        return None
    return int(instruction.address + instruction.size + operand.mem.disp)


def _function_instructions(data: bytes, offset: int) -> _FunctionGraph | None:
    """明示offsetから到達可能なx64命令とCFG・dominatorを有界復元する。"""

    if not 0 <= offset < len(data):
        return None
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    decoded: list[object] = []
    for instruction in disassembler.disasm(
        data[offset : min(len(data), offset + MAXIMUM_FUNCTION_BYTES)],
        offset,
    ):
        decoded.append(instruction)
        if len(decoded) > MAXIMUM_FUNCTION_INSTRUCTIONS:
            return None
    by_address = {int(item.address): item for item in decoded}
    if offset not in by_address:
        return None
    pending = [offset]
    reachable: dict[int, object] = {}
    successors: dict[int, tuple[int, ...]] = {}
    blocks = 0
    returned = False
    while pending:
        address = pending.pop()
        if address in reachable:
            continue
        blocks += 1
        if blocks > MAXIMUM_CFG_BLOCKS:
            return None
        while address not in reachable:
            instruction = by_address.get(address)
            if instruction is None:
                return None
            reachable[address] = instruction
            mnemonic = str(instruction.mnemonic).casefold()
            if mnemonic.startswith("ret"):
                returned = True
                successors[address] = ()
                break
            next_address = int(instruction.address + instruction.size)
            is_jump = mnemonic == "jmp"
            is_conditional = (
                mnemonic.startswith("j") and not is_jump
            ) or mnemonic.startswith("loop")
            if is_jump or is_conditional:
                if (
                    len(instruction.operands) != 1
                    or instruction.operands[0].type != X86_OP_IMM
                ):
                    return None
                target = int(instruction.operands[0].imm)
                if target not in by_address:
                    return None
                pending.append(target)
                if is_jump:
                    successors[address] = (target,)
                    break
                successors[address] = (target, next_address)
            else:
                successors[address] = (next_address,)
            if next_address not in by_address:
                return None
            address = next_address
    if not returned:
        return None
    reachable_addresses = frozenset(reachable)
    if any(
        target not in reachable_addresses
        for values in successors.values()
        for target in values
    ):
        return None
    predecessors_mutable: dict[int, list[int]] = {
        address: [] for address in reachable_addresses
    }
    for source, targets in successors.items():
        for target in targets:
            predecessors_mutable[target].append(source)
    dominators: dict[int, set[int]] = {
        address: ({offset} if address == offset else set(reachable_addresses))
        for address in reachable_addresses
    }
    changed = True
    iterations = 0
    while changed:
        changed = False
        iterations += 1
        if iterations > len(reachable_addresses) + 1:
            return None
        for address in sorted(reachable_addresses):
            if address == offset:
                continue
            predecessors = predecessors_mutable[address]
            if not predecessors:
                return None
            shared = set(dominators[predecessors[0]])
            for predecessor in predecessors[1:]:
                shared &= dominators[predecessor]
            updated = {address, *shared}
            if updated != dominators[address]:
                dominators[address] = updated
                changed = True
    ordered = tuple(reachable[address] for address in sorted(reachable))
    return _FunctionGraph(
        entry=offset,
        instructions=ordered,
        by_address={address: reachable[address] for address in sorted(reachable)},
        successors={address: successors[address] for address in sorted(reachable)},
        predecessors={
            address: tuple(sorted(predecessors_mutable[address]))
            for address in sorted(reachable)
        },
        dominators={
            address: frozenset(dominators[address]) for address in sorted(reachable)
        },
    )


def _linear_window(
    graph: _FunctionGraph,
    start: int,
    length: int,
) -> tuple[object, ...] | None:
    """address順配列上で実CFG edgeが連続するwindowだけを返す。"""

    if start < 0 or length <= 0 or start + length > len(graph.instructions):
        return None
    window = graph.instructions[start : start + length]
    if any(
        int(window[index + 1].address)
        not in graph.successors[int(window[index].address)]
        for index in range(len(window) - 1)
    ):
        return None
    return window


def _dominates(graph: _FunctionGraph, source: object, target: object) -> bool:
    """source命令がtarget命令をCFG上で支配するか返す。"""

    return int(source.address) in graph.dominators[int(target.address)]


def _straight_line_window(
    graph: _FunctionGraph,
    start: int,
    length: int,
) -> tuple[object, ...] | None:
    """分岐・mergeを跨がない単一successor/predecessorのwindowだけを返す。"""

    window = _linear_window(graph, start, length)
    if window is None:
        return None
    if any(
        graph.successors[int(window[index].address)]
        != (int(window[index + 1].address),)
        or graph.predecessors[int(window[index + 1].address)]
        != (int(window[index].address),)
        for index in range(len(window) - 1)
    ):
        return None
    return window


def _direct_calls(instructions: tuple[object, ...], data_size: int) -> tuple[int, ...]:
    """shellcode内へ向かうdirect call targetだけを返す。"""

    targets: list[int] = []
    for instruction in instructions:
        if instruction.mnemonic != "call" or len(instruction.operands) != 1:
            continue
        operand = instruction.operands[0]
        if operand.type != X86_OP_IMM:
            continue
        target = int(operand.imm)
        if 0 <= target < data_size and target not in targets:
            targets.append(target)
    return tuple(targets)


def _register_name(instruction: object, operand: object) -> str | None:
    """register operandをCapstoneの正規名へ変換する。"""

    if operand.type != X86_OP_REG:
        return None
    return _REGISTER_NAMES.get(operand.reg)


def _register_family(name: str | None) -> str | None:
    """部分register名を64-bit canonical familyへ正規化する。"""

    if name is None:
        return None
    return _REGISTER_FAMILIES.get(name)


def _memory_base_name(instruction: object, operand: object) -> str | None:
    """memory operandのbase register名を返す。"""

    if operand.type != X86_OP_MEM or operand.mem.base == X86_REG_INVALID:
        return None
    return _REGISTER_NAMES.get(operand.mem.base)


def _stack_displacement(operand: object) -> int | None:
    """indexなしRSP相対operandのdisplacementだけを返す。"""

    if (
        operand.type != X86_OP_MEM
        or operand.mem.base != X86_REG_RSP
        or operand.mem.index != X86_REG_INVALID
    ):
        return None
    return int(operand.mem.disp)


def _direct_call_target(instruction: object) -> int | None:
    """direct callのtargetを返す。"""

    if (
        instruction.mnemonic != "call"
        or len(instruction.operands) != 1
        or instruction.operands[0].type != X86_OP_IMM
    ):
        return None
    return int(instruction.operands[0].imm)


def _prologue_argument_slots(
    instructions: tuple[object, ...],
) -> dict[str, int] | None:
    """Windows x64引数registerのprologue保存先をframe後RSP相対へ変換する。"""

    saved: dict[str, int] = {}
    frame_size = 0
    allocation_seen = False
    for instruction in instructions[:16]:
        if instruction.mnemonic == "push":
            frame_size += 8
            continue
        if (
            instruction.mnemonic == "sub"
            and len(instruction.operands) == 2
            and _register_name(instruction, instruction.operands[0]) == "rsp"
            and instruction.operands[1].type == X86_OP_IMM
        ):
            frame_size += int(instruction.operands[1].imm)
            allocation_seen = True
            break
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
            continue
        displacement = _stack_displacement(instruction.operands[0])
        source = _register_name(instruction, instruction.operands[1])
        if displacement is not None and source in {"rcx", "rdx", "r8", "r9"}:
            saved[source] = displacement
    if not allocation_seen or not saved:
        return None
    return {name: displacement + frame_size for name, displacement in saved.items()}


def _lowercase_ascii_profile(instructions: tuple[object, ...]) -> bool:
    """ASCII A-Zだけへ0x20を加えるhelper形状を検証する。"""

    immediates = _immediate_values(instructions)
    mnemonics = {item.mnemonic for item in instructions}
    return {0x41, 0x5A, 0x20}.issubset(immediates) and {
        "cmp",
        "add",
        "ret",
    }.issubset(mnemonics)


def _fnv1a_lower_profile(data: bytes, instructions: tuple[object, ...]) -> bool:
    """lowercase ASCII FNV-1a export名hash実装を検証する。"""

    immediates = _immediate_values(instructions)
    targets = _direct_calls(instructions, len(data))
    lower_matches = [
        target
        for target in targets
        if (callee := _function_instructions(data, target)) is not None
        and _lowercase_ascii_profile(callee.instructions)
    ]
    mnemonics = {item.mnemonic for item in instructions}
    return bool(
        {0x811C9DC5, 0x1000193}.issubset(immediates)
        and {"xor", "imul", "ret"}.issubset(mnemonics)
        and len(lower_matches) == 1
    )


def _export_resolver_profile(data: bytes, instructions: tuple[object, ...]) -> bool:
    """PE export tableをlowercase FNV-1aで探索するresolverを検証する。"""

    immediates = _immediate_values(instructions)
    displacements = _memory_displacements(instructions)
    targets = _direct_calls(instructions, len(data))
    hash_matches = [
        target
        for target in targets
        if (callee := _function_instructions(data, target)) is not None
        and _fnv1a_lower_profile(data, callee.instructions)
    ]
    return bool(
        {0x5A4D, 0x4550}.issubset(immediates)
        and {0x3C, 0x88, 0x18, 0x1C, 0x20, 0x24}.issubset(displacements)
        and len(hash_matches) == 1
    )


def _xor_copy_profile(instructions: tuple[object, ...]) -> bool:
    """入力byte列を単一byte keyでXORし別bufferへ終端付きで写すhelperを検証する。"""

    mnemonics = [item.mnemonic for item in instructions]
    byte_writes = [
        item
        for item in instructions
        if item.mnemonic == "mov"
        and len(item.operands) == 2
        and item.operands[0].type == X86_OP_MEM
        and item.operands[0].size == 1
    ]
    return bool(
        "xor" in mnemonics
        and any(name.startswith("j") for name in mnemonics)
        and len(byte_writes) >= 2
        and any(item.mnemonic.startswith("ret") for item in instructions)
    )


def _mov_stack_byte(instruction: object) -> tuple[int, int] | None:
    """mov byte ptr [rsp+disp], imm8を返す。"""

    if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
        return None
    displacement = _stack_displacement(instruction.operands[0])
    if (
        displacement is None
        or instruction.operands[0].size != 1
        or instruction.operands[1].type != X86_OP_IMM
    ):
        return None
    return displacement, int(instruction.operands[1].imm) & 0xFF


def _decoded_module_loads(
    data: bytes,
    graph: _FunctionGraph,
    context_slot: int,
) -> list[tuple[str, int, int]]:
    """XOR復号module名、module handle stack slot、decode call位置を返す。"""

    instructions = graph.instructions
    stores: dict[int, int] = {}
    results: list[tuple[str, int, int]] = []
    for index, instruction in enumerate(instructions):
        if (item := _mov_stack_byte(instruction)) is not None:
            stores[item[0]] = item[1]
        decoder_target = _direct_call_target(instruction)
        if decoder_target is None or index < 5 or index + 6 >= len(instructions):
            continue
        decoder = _function_instructions(data, decoder_target)
        if decoder is None or not _xor_copy_profile(decoder.instructions):
            continue
        path = _straight_line_window(graph, index - 5, 6)
        if path is None:
            continue
        prefix = path[:5]
        if [item.mnemonic for item in prefix] != ["mov", "lea", "mov", "mov", "lea"]:
            continue
        output_size_operand = (
            prefix[0].operands[1] if len(prefix[0].operands) == 2 else None
        )
        output_disp = (
            _stack_displacement(prefix[1].operands[1])
            if len(prefix[1].operands) == 2
            and _register_name(prefix[1], prefix[1].operands[0]) == "r9"
            else None
        )
        key_operand = prefix[2].operands[1] if len(prefix[2].operands) == 2 else None
        length_operand = prefix[3].operands[1] if len(prefix[3].operands) == 2 else None
        input_disp = (
            _stack_displacement(prefix[4].operands[1])
            if len(prefix[4].operands) == 2
            and _register_name(prefix[4], prefix[4].operands[0]) == "rcx"
            else None
        )
        if (
            output_disp is None
            or input_disp is None
            or output_size_operand is None
            or output_size_operand.type != X86_OP_IMM
            or key_operand is None
            or key_operand.type != X86_OP_IMM
            or length_operand is None
            or length_operand.type != X86_OP_IMM
        ):
            continue
        length = int(length_operand.imm)
        output_size = int(output_size_operand.imm)
        key = int(key_operand.imm) & 0xFF
        if (
            not 1 <= length <= 64
            or output_size < length + 1
            or output_size > length + 8
        ):
            continue
        encoded_values = [
            stores.get(input_disp + offset, -1) for offset in range(length)
        ]
        if any(value < 0 for value in encoded_values):
            continue
        encoded = bytes(encoded_values)
        try:
            module = bytes(value ^ key for value in encoded).decode(
                "ascii", errors="strict"
            )
        except UnicodeError:
            continue
        suffix = _straight_line_window(graph, index + 1, 6)
        if suffix is None:
            continue
        if len(suffix) != 6 or [item.mnemonic for item in suffix] != [
            "mov",
            "mov",
            "mov",
            "lea",
            "call",
            "mov",
        ]:
            continue
        if any(len(item.operands) != 2 for item in (*suffix[:4], suffix[5])):
            continue
        if len(suffix[4].operands) != 1:
            continue
        first_source = _stack_displacement(suffix[0].operands[1])
        load_library_slot = _stack_displacement(suffix[2].operands[0])
        passed_output = _stack_displacement(suffix[3].operands[1])
        indirect_slot = _stack_displacement(suffix[4].operands[0])
        module_slot = _stack_displacement(suffix[5].operands[0])
        if (
            first_source != context_slot
            or _memory_base_name(suffix[1], suffix[1].operands[1]) != "rax"
            or int(suffix[1].operands[1].mem.disp) != 0
            or load_library_slot is None
            or passed_output != output_disp
            or indirect_slot != load_library_slot
            or module_slot is None
            or _register_name(suffix[5], suffix[5].operands[1]) != "rax"
        ):
            continue
        results.append((module.casefold(), module_slot, index))
    return results


def _winsock_resolution_profile(
    data: bytes,
    offset: int,
    graph: _FunctionGraph,
) -> _WinsockResolution | None:
    """ws2_32.dll load、export resolver、API hash→table slotを同一関数で検証する。"""

    instructions = graph.instructions
    arguments = _prologue_argument_slots(instructions)
    if arguments is None:
        return None
    context_slot = arguments.get("rcx")
    if context_slot is None:
        return None
    module_loads = [
        item
        for item in _decoded_module_loads(data, graph, context_slot)
        if item[0] == "ws2_32.dll"
    ]
    if len(module_loads) != 1:
        return None
    _module_name, module_slot, module_call_index = module_loads[0]
    assignments: dict[int, list[tuple[int, int]]] = {}
    for index in range(module_call_index + 1, len(instructions) - 4):
        window = _straight_line_window(graph, index, 5)
        if window is None:
            continue
        if [item.mnemonic for item in window] != ["mov", "mov", "call", "mov", "mov"]:
            continue
        hash_operand = window[0].operands[1] if len(window[0].operands) == 2 else None
        module_source = (
            _stack_displacement(window[1].operands[1])
            if len(window[1].operands) == 2
            and _register_name(window[1], window[1].operands[0]) == "rcx"
            else None
        )
        resolver_target = _direct_call_target(window[2])
        context_source = (
            _stack_displacement(window[3].operands[1])
            if len(window[3].operands) == 2
            and _register_name(window[3], window[3].operands[0]) == "rcx"
            else None
        )
        destination = window[4].operands[0] if len(window[4].operands) == 2 else None
        if (
            hash_operand is None
            or hash_operand.type != X86_OP_IMM
            or module_source != module_slot
            or resolver_target is None
            or context_source != context_slot
            or destination is None
            or destination.type != X86_OP_MEM
            or _memory_base_name(window[4], destination) != "rcx"
            or _register_name(window[4], window[4].operands[1]) != "rax"
        ):
            continue
        slot = int(destination.mem.disp)
        if slot not in assignments:
            assignments[slot] = []
        assignments[slot].append((int(hash_operand.imm) & 0xFFFFFFFF, resolver_target))
    expected = {
        _WINSOCK_API_SLOTS[name]: _WINSOCK_API_HASHES[name]
        for name in _WINSOCK_API_HASHES
    }
    if any(
        len(assignments.get(slot, ())) != 1 or assignments[slot][0][0] != digest
        for slot, digest in expected.items()
    ):
        return None
    resolver_targets = {assignments[slot][0][1] for slot in expected}
    if len(resolver_targets) != 1:
        return None
    resolver_offset = next(iter(resolver_targets))
    resolver = _function_instructions(data, resolver_offset)
    if resolver is None or not _export_resolver_profile(data, resolver.instructions):
        return None
    return _WinsockResolution(
        initializer_offset=offset,
        export_resolver_offset=resolver_offset,
        slots=dict(_WINSOCK_API_SLOTS),
    )


def _main_profile(data: bytes) -> _MainProfile | None:
    """entry jump、container pointer、parser call、停止loopを一意に確認する。"""

    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    entry = tuple(disassembler.disasm(data[:16], 0))
    if (
        not entry
        or entry[0].address != 0
        or entry[0].mnemonic != "jmp"
        or len(entry[0].operands) != 1
        or entry[0].operands[0].type != X86_OP_IMM
    ):
        return None
    main_offset = int(entry[0].operands[0].imm)
    if not 0x100 <= main_offset < len(data):
        return None
    main = tuple(disassembler.disasm(data[main_offset : main_offset + 64], main_offset))
    if len(main) < 4 or [item.mnemonic for item in main[:4]] != [
        "sub",
        "lea",
        "call",
        "jmp",
    ]:
        return None
    lea = main[1]
    if len(lea.operands) != 2:
        return None
    container_offset = _rip_target(lea, lea.operands[1])
    call_operand = main[2].operands[0] if len(main[2].operands) == 1 else None
    loop_operand = main[3].operands[0] if len(main[3].operands) == 1 else None
    if (
        container_offset is None
        or call_operand is None
        or call_operand.type != X86_OP_IMM
        or loop_operand is None
        or loop_operand.type != X86_OP_IMM
        or int(loop_operand.imm) != int(main[3].address)
    ):
        return None
    parser_offset = int(call_operand.imm)
    if not 0 <= container_offset <= len(data) - OUTER_HEADER_SIZE:
        return None
    if not 0 <= parser_offset < len(data):
        return None
    return _MainProfile(container_offset=container_offset, parser_offset=parser_offset)


def _outer_container(data: bytes, offset: int) -> _OuterContainer | None:
    """固定headerと有界ciphertextを解釈する。"""

    if not 0 <= offset <= len(data) - OUTER_HEADER_SIZE:
        return None
    version, header_size, ciphertext_size = struct.unpack_from(
        "<HHI", data, offset + 0x10
    )
    if (
        version != 1
        or header_size != OUTER_HEADER_SIZE
        or not INNER_HEADER_SIZE <= ciphertext_size <= MAXIMUM_CIPHERTEXT_SIZE
        or offset + OUTER_HEADER_SIZE + ciphertext_size > len(data)
    ):
        return None
    return _OuterContainer(
        offset=offset,
        magic=data[offset : offset + 0x10],
        nonce=data[offset + 0x18 : offset + 0x24],
        tag=data[offset + 0x24 : offset + 0x34],
        aad=data[offset : offset + 0x24],
        ciphertext=data[
            offset + OUTER_HEADER_SIZE : offset + OUTER_HEADER_SIZE + ciphertext_size
        ],
    )


def _reachable_functions(
    data: bytes,
    root: int,
) -> dict[int, _FunctionGraph] | None:
    """direct callだけを深さ制限付きで辿る。"""

    pending: list[tuple[int, int]] = [(root, 0)]
    result: dict[int, _FunctionGraph] = {}
    while pending:
        offset, depth = pending.pop(0)
        if offset in result:
            continue
        if len(result) >= MAXIMUM_REACHABLE_FUNCTIONS:
            return None
        graph = _function_instructions(data, offset)
        if graph is None:
            return None
        result[offset] = graph
        if depth >= MAXIMUM_CALL_DEPTH:
            continue
        for target in _direct_calls(graph.instructions, len(data)):
            if target not in result:
                pending.append((target, depth + 1))
    return result


def _stack_byte_store(instruction: object) -> tuple[int, int] | None:
    """mov byte ptr [rsp+disp], imm8だけを抽出する。"""

    if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
        return None
    destination, source = instruction.operands
    if (
        destination.type != X86_OP_MEM
        or destination.size != 1
        or destination.mem.base != X86_REG_RSP
        or destination.mem.index != X86_REG_INVALID
        or source.type != X86_OP_IMM
    ):
        return None
    return int(destination.mem.disp), int(source.imm) & 0xFF


def _decoded_stack_strings(instructions: tuple[object, ...]) -> frozenset[str]:
    """連続stack byte storeのXOR対からASCII文字列を復元する。"""

    strings: set[str] = set()
    run: list[tuple[int, int]] = []

    def finish() -> None:
        if len(run) < 4 or len(run) % 2:
            return
        values = [value for _offset, value in run]
        keys = values[1::2]
        if not keys or len(set(keys)) != 1:
            return
        decoded = bytes(value ^ keys[0] for value in values[0::2])
        if not decoded or any(value < 0x20 or value > 0x7E for value in decoded):
            return
        try:
            strings.add(decoded.decode("ascii", errors="strict"))
        except UnicodeError:
            return

    for instruction in instructions:
        item = _stack_byte_store(instruction)
        if item is not None and (not run or item[0] == run[-1][0] + 1):
            run.append(item)
            continue
        finish()
        run = [item] if item is not None else []
    finish()
    return frozenset(strings)


def _decoded_stack_string_runs(
    graph: _FunctionGraph,
) -> dict[str, tuple[tuple[object, object], ...]]:
    """同一straight-line CFG上のXOR stack文字列runと両端命令を返す。"""

    runs: dict[str, list[tuple[object, object]]] = {}
    current: list[tuple[object, int, int]] = []

    def finish() -> None:
        if len(current) < 4 or len(current) % 2:
            return
        values = [value for _instruction, _offset, value in current]
        keys = values[1::2]
        if not keys or len(set(keys)) != 1:
            return
        decoded = bytes(value ^ keys[0] for value in values[0::2])
        if not decoded or any(value < 0x20 or value > 0x7E for value in decoded):
            return
        try:
            text = decoded.decode("ascii", errors="strict")
        except UnicodeError:
            return
        if text not in runs:
            runs[text] = []
        runs[text].append((current[0][0], current[-1][0]))

    for instruction in graph.instructions:
        item = _stack_byte_store(instruction)
        connected = bool(
            current
            and item is not None
            and item[0] == current[-1][1] + 1
            and graph.successors[int(current[-1][0].address)]
            == (int(instruction.address),)
            and graph.predecessors[int(instruction.address)]
            == (int(current[-1][0].address),)
        )
        if item is not None and (not current or connected):
            current.append((instruction, item[0], item[1]))
            continue
        finish()
        current = [(instruction, item[0], item[1])] if item is not None else []
    finish()
    return {name: tuple(values) for name, values in runs.items()}


def _instruction_has_immediate(instruction: object, value: int) -> bool:
    """命令operandに指定即値があるか返す。"""

    return any(
        operand.type == X86_OP_IMM and int(operand.imm) & 0xFFFFFFFFFFFFFFFF == value
        for operand in instruction.operands
    )


def _instruction_has_displacement(instruction: object, value: int) -> bool:
    """命令のmemory operandに指定displacementがあるか返す。"""

    return any(
        operand.type == X86_OP_MEM and int(operand.mem.disp) == value
        for operand in instruction.operands
    )


def _memory_write_immediate(instruction: object, value: int) -> bool:
    """memoryへの指定即値書込みを判定する。"""

    return (
        instruction.mnemonic == "mov"
        and len(instruction.operands) == 2
        and instruction.operands[0].type == X86_OP_MEM
        and instruction.operands[1].type == X86_OP_IMM
        and int(instruction.operands[1].imm) & 0xFFFFFFFFFFFFFFFF == value
    )


def _add_immediate(instruction: object, value: int) -> bool:
    """registerへの指定即値加算を判定する。"""

    return (
        instruction.mnemonic == "add"
        and len(instruction.operands) == 2
        and instruction.operands[1].type == X86_OP_IMM
        and int(instruction.operands[1].imm) & 0xFFFFFFFFFFFFFFFF == value
    )


def _gcm_layout_stage_matches(instruction: object, stage: int) -> bool:
    """GCM認証構造体の指定stageに対応する命令か返す。"""

    if stage == 0:
        return _memory_write_immediate(instruction, 0x58)
    if stage == 1:
        return _memory_write_immediate(instruction, 1)
    if stage == 2:
        return _add_immediate(instruction, 0x18)
    if stage == 3:
        return _memory_write_immediate(instruction, 0x0C)
    if stage == 4:
        return _memory_write_immediate(instruction, 0x24)
    if stage == 5:
        return _add_immediate(instruction, 0x24)
    if stage == 6:
        return _memory_write_immediate(instruction, 0x10)
    if stage == 7:
        return _add_immediate(instruction, 0x34)
    return False


def _decryptor_evidence_bits(
    instruction: object,
    *,
    magic_call_address: int,
    key_call_address: int,
    string_end_bits: dict[int, int],
) -> int:
    """一命令が満たす復号器schema／identity evidenceをbit集合で返す。"""

    address = int(instruction.address)
    result = 0
    if address == magic_call_address:
        result |= 1
    if address == key_call_address:
        result |= 1 << 1
    result |= string_end_bits.get(address, 0)
    bit = 2 + len(_BCRYPT_GCM_STRING_ORDER)
    for value in _DECRYPTOR_SCHEMA_IMMEDIATES:
        if _instruction_has_immediate(instruction, value):
            result |= 1 << bit
        bit += 1
    for value in _DECRYPTOR_SCHEMA_DISPLACEMENTS:
        if _instruction_has_displacement(instruction, value):
            result |= 1 << bit
        bit += 1
    if instruction.mnemonic == "div":
        result |= 1 << bit
    return result


def _unique_decryptor_cfg_path(
    graph: _FunctionGraph,
    *,
    magic_call: object,
    key_call: object,
    string_runs: dict[str, tuple[tuple[object, object], ...]],
) -> bool:
    """identity、GCM layout、schemaが同じ実CFG pathにある場合だけ受理する。

    schemaの同値なbounds checkが複数branchに複製されることは許す一方、identityを
    持つcall、四つのstack string run、GCM layoutの証拠chainは一意でなければならない。
    path stateは単調なbit集合として伝播し、merge後に相互排他的branchの証拠を混ぜない。
    """

    string_end_bits: dict[int, int] = {}
    identity: list[int] = [int(magic_call.address), int(key_call.address)]
    for index, name in enumerate(_BCRYPT_GCM_STRING_ORDER):
        runs = string_runs.get(name, ())
        if len(runs) != 1:
            return False
        start, end = runs[0]
        if not _dominates(graph, start, end):
            return False
        end_address = int(end.address)
        string_end_bits[end_address] = string_end_bits.get(end_address, 0) | (
            1 << (2 + index)
        )
        identity.extend((int(start.address), end_address))

    evidence_count = (
        2
        + len(_BCRYPT_GCM_STRING_ORDER)
        + len(_DECRYPTOR_SCHEMA_IMMEDIATES)
        + len(_DECRYPTOR_SCHEMA_DISPLACEMENTS)
        + 1
    )
    required_evidence = (1 << evidence_count) - 1
    pending: list[tuple[int, int, int, tuple[int, ...]]] = [(graph.entry, 0, 0, ())]
    cursor = 0
    seen: set[tuple[int, int, int, tuple[int, ...]]] = set()
    accepted_signatures: set[tuple[int, ...]] = set()
    while cursor < len(pending):
        address, evidence, layout_stage, layout_signature = pending[cursor]
        cursor += 1
        state = (address, evidence, layout_stage, layout_signature)
        if state in seen:
            continue
        if len(seen) >= MAXIMUM_DECRYPTOR_PATH_STATES:
            return False
        seen.add(state)
        instruction = graph.by_address[address]
        evidence |= _decryptor_evidence_bits(
            instruction,
            magic_call_address=int(magic_call.address),
            key_call_address=int(key_call.address),
            string_end_bits=string_end_bits,
        )
        if _gcm_layout_stage_matches(instruction, layout_stage):
            layout_signature = (*layout_signature, address)
            layout_stage += 1
        if evidence == required_evidence and layout_stage == 8:
            accepted_signatures.add((*identity, *layout_signature))
            if len(accepted_signatures) > 1:
                return False
        for successor in graph.successors[address]:
            pending.append((successor, evidence, layout_stage, layout_signature))
    return len(accepted_signatures) == 1


def _gcm_layout_profile(instructions: tuple[object, ...]) -> bool:
    """BCRYPT_AUTHENTICATED_CIPHER_MODE_INFOの固定data-flowを確認する。"""

    state = 0
    for instruction in instructions:
        if state == 0 and _memory_write_immediate(instruction, 0x58):
            state = 1
        elif state == 1 and _memory_write_immediate(instruction, 1):
            state = 2
        elif state == 2 and _add_immediate(instruction, 0x18):
            state = 3
        elif state == 3 and _memory_write_immediate(instruction, 0x0C):
            state = 4
        elif state == 4 and _memory_write_immediate(instruction, 0x24):
            state = 5
        elif state == 5 and _add_immediate(instruction, 0x24):
            state = 6
        elif state == 6 and _memory_write_immediate(instruction, 0x10):
            state = 7
        elif state == 7 and _add_immediate(instruction, 0x34):
            return True
    return False


def _header_and_inner_schema_profile(instructions: tuple[object, ...]) -> bool:
    """outer headerと認証後inner parserの固定schemaを確認する。"""

    immediates = _immediate_values(instructions)
    displacements = _memory_displacements(instructions)
    return (
        {1, OUTER_HEADER_SIZE, INNER_HEADER_SIZE, MAXIMUM_CIPHERTEXT_SIZE}.issubset(
            immediates
        )
        and {0x10, 0x12, 0x14}.issubset(displacements)
        and {
            INNER_MAGIC,
            INNER_VERSION,
            0x100,
            0x110,
            0x200,
            0x210,
            0x310,
        }.issubset(immediates)
        and 0x510 in displacements
        and 10 in immediates
        and any(item.mnemonic == "div" for item in instructions)
    )


def _magic_validator_profile(
    instructions: tuple[object, ...],
    expected_magic_offset: int,
) -> bool:
    """16-byte定数時間風XOR/OR validatorとmagic参照を確認する。"""

    immediates = _immediate_values(instructions)
    references = {
        target
        for instruction in instructions
        for operand in instruction.operands
        if (target := _rip_target(instruction, operand)) is not None
    }
    mnemonics = {item.mnemonic for item in instructions}
    return (
        0x10 in immediates
        and references == {expected_magic_offset}
        and {"xor", "or", "cmp", "ret"}.issubset(mnemonics)
    )


def _key_derivation_profile(
    instructions: tuple[object, ...],
    seed_offsets: tuple[int, int],
) -> bool:
    """二つの32-byte RIP相対seedを同一indexでXORするloopを確認する。"""

    references = [
        target
        for instruction in instructions
        for operand in instruction.operands
        if (target := _rip_target(instruction, operand)) is not None
    ]
    mnemonics = [item.mnemonic for item in instructions]
    byte_stores = [
        item
        for item in instructions
        if item.mnemonic == "mov"
        and len(item.operands) == 2
        and item.operands[0].type == X86_OP_MEM
        and item.operands[0].size == 1
    ]
    return (
        0x20 in _immediate_values(instructions)
        and tuple(references) == seed_offsets
        and mnemonics.count("movzx") >= 2
        and "xor" in mnemonics
        and any(
            item.mnemonic == "jmp"
            and item.operands
            and item.operands[0].type == X86_OP_IMM
            and int(item.operands[0].imm) < int(item.address)
            for item in instructions
        )
        and bool(byte_stores)
    )


def _decryptor_profile(
    data: bytes,
    graph: _FunctionGraph,
    duplicate_magic_offset: int,
) -> tuple[bytes, dict[str, object]] | None:
    """decryptorからmagic validator、key loop、GCM、inner parserを一意に結ぶ。"""

    instructions = graph.instructions
    if not _BCRYPT_GCM_STRINGS.issubset(_decoded_stack_strings(instructions)):
        return None
    if not _gcm_layout_profile(instructions):
        return None
    if not _header_and_inner_schema_profile(instructions):
        return None
    magic_matches: list[tuple[object, int]] = []
    key_matches: list[tuple[object, int, bytes]] = []
    seed_offsets = (duplicate_magic_offset + 0x10, duplicate_magic_offset + 0x30)
    for instruction in instructions:
        target = _direct_call_target(instruction)
        if target is None or not 0 <= target < len(data):
            continue
        target_graph = _function_instructions(data, target)
        if target_graph is None:
            continue
        target_instructions = target_graph.instructions
        if _magic_validator_profile(target_instructions, duplicate_magic_offset):
            magic_matches.append((instruction, target))
        if _key_derivation_profile(target_instructions, seed_offsets):
            if seed_offsets[1] + 0x20 > len(data):
                return None
            key = bytes(
                first ^ second
                for first, second in zip(
                    data[seed_offsets[0] : seed_offsets[0] + 0x20],
                    data[seed_offsets[1] : seed_offsets[1] + 0x20],
                    strict=True,
                )
            )
            key_matches.append((instruction, target, key))
    if len(magic_matches) != 1 or len(key_matches) != 1:
        return None
    string_runs = _decoded_stack_string_runs(graph)
    if not _unique_decryptor_cfg_path(
        graph,
        magic_call=magic_matches[0][0],
        key_call=key_matches[0][0],
        string_runs=string_runs,
    ):
        return None
    return key_matches[0][2], {
        "outer_header_parser": True,
        "constant_time_magic_validator": True,
        "unique_two_seed_xor_key_derivation": True,
        "bcrypt_aes_gcm_strings": True,
        "authenticated_cipher_layout": True,
        "strict_inner_schema_parser": True,
        "decryptor_unique_cfg_evidence_chain": True,
    }


def _rsp_memory_source(instruction: object, register: str) -> int | None:
    """mov register,[rsp+disp]のsource displacementを返す。"""

    if (
        instruction.mnemonic != "mov"
        or len(instruction.operands) != 2
        or _register_name(instruction, instruction.operands[0]) != register
    ):
        return None
    return _stack_displacement(instruction.operands[1])


def _rsp_memory_destination(instruction: object, register: str) -> int | None:
    """mov [rsp+disp],registerのdestination displacementを返す。"""

    if (
        instruction.mnemonic != "mov"
        or len(instruction.operands) != 2
        or _register_name(instruction, instruction.operands[1]) != register
    ):
        return None
    return _stack_displacement(instruction.operands[0])


def _rsp_write_span(instruction: object) -> tuple[int, int] | None:
    """RSP相対memoryへの書込み候補をoffsetと幅で返す。"""

    if not instruction.operands or str(instruction.mnemonic).casefold() in {
        "call",
        "cmp",
        "jmp",
        "push",
        "test",
    }:
        return None
    destination = instruction.operands[0]
    displacement = _stack_displacement(destination)
    if displacement is None:
        return None
    width = int(destination.size)
    if not 1 <= width <= 64:
        return None
    return displacement, width


def _spans_overlap(left: tuple[int, int], right: tuple[int, int]) -> bool:
    """二つのstack byte範囲が重なるか返す。"""

    return left[0] < right[0] + right[1] and right[0] < left[0] + left[1]


def _changes_rsp_basis(instruction: object) -> bool:
    """RSP基準を変更する命令または未知のstack effectを検出する。"""

    mnemonic = str(instruction.mnemonic).casefold()
    if (
        mnemonic == "call"
        or mnemonic == "enter"
        or mnemonic == "leave"
        or mnemonic.startswith(("iret", "pop", "push", "ret"))
    ):
        return True
    stack_aliases = {"rsp", "esp", "sp", "spl"}
    register_operands = [
        name
        for operand in instruction.operands
        if (name := _register_name(instruction, operand)) is not None
    ]
    if mnemonic == "xchg" and any(name in stack_aliases for name in register_operands):
        return True
    return bool(
        register_operands
        and register_operands[0] in stack_aliases
        and mnemonic not in {"cmp", "test"}
    )


def _rsp_lea_source(instruction: object, register: str) -> int | None:
    """lea register,[rsp+disp]のsource displacementを返す。"""

    if (
        instruction.mnemonic != "lea"
        or len(instruction.operands) != 2
        or _register_name(instruction, instruction.operands[0]) != register
    ):
        return None
    return _stack_displacement(instruction.operands[1])


def _latest_register_definition(
    graph: _FunctionGraph,
    use: object,
    register: str,
    *,
    maximum_backtrack: int = 12,
) -> object | None:
    """同一straight-line CFG block内の直前register定義命令を返す。"""

    register_family = _register_family(register)
    if register_family is None:
        return None
    current = int(use.address)
    for _step in range(maximum_backtrack):
        predecessors = graph.predecessors.get(current, ())
        if len(predecessors) != 1:
            return None
        address = predecessors[0]
        if graph.successors.get(address) != (current,):
            return None
        instruction = graph.by_address[address]
        mnemonic = str(instruction.mnemonic).casefold()
        if mnemonic == "call" or mnemonic.startswith(("j", "ret")):
            return None
        destination = (
            _register_name(instruction, instruction.operands[0])
            if instruction.operands
            else None
        )
        if _register_family(destination) == register_family:
            return instruction
        current = address
    return None


def _latest_register_source(
    graph: _FunctionGraph,
    use: object,
    register: str,
    *,
    maximum_backtrack: int = 12,
) -> tuple[str, int | str] | None:
    """同一straight-line CFG block内の直前register定義sourceを返す。"""

    instruction = _latest_register_definition(
        graph,
        use,
        register,
        maximum_backtrack=maximum_backtrack,
    )
    if instruction is None or len(instruction.operands) != 2:
        return None
    if _register_name(instruction, instruction.operands[0]) != register:
        return None
    if instruction.mnemonic == "mov":
        if (source := _stack_displacement(instruction.operands[1])) is not None:
            return "stack", source
        if (
            source_register := _register_name(instruction, instruction.operands[1])
        ) is not None:
            return "register", source_register
    if (
        instruction.mnemonic == "lea"
        and (source := _stack_displacement(instruction.operands[1])) is not None
    ):
        return "lea", source
    return None


def _context_api_slots_called(
    graph: _FunctionGraph,
    context_argument_slot: int,
    *,
    dominated_by: object,
) -> set[int]:
    """context API tableから取得後に間接callされたslotを返す。"""

    instructions = graph.instructions
    called: set[int] = set()
    for index in range(len(instructions) - 2):
        prefix = _straight_line_window(graph, index, 3)
        if prefix is None:
            continue
        first, second, third = prefix
        if not _dominates(graph, dominated_by, first):
            continue
        if _rsp_memory_source(first, "rax") != context_argument_slot:
            continue
        if (
            second.mnemonic != "mov"
            or len(second.operands) != 2
            or _register_name(second, second.operands[0]) != "rax"
            or second.operands[1].type != X86_OP_MEM
            or _memory_base_name(second, second.operands[1]) != "rax"
            or second.operands[1].mem.index != X86_REG_INVALID
        ):
            continue
        api_slot = int(second.operands[1].mem.disp)
        function_slot = _rsp_memory_destination(third, "rax")
        if function_slot is None:
            continue
        for candidate_index in range(index + 3, min(len(instructions), index + 35)):
            path = _straight_line_window(
                graph,
                index,
                candidate_index - index + 1,
            )
            if path is None:
                break
            candidate = instructions[candidate_index]
            if (
                candidate.mnemonic == "call"
                and len(candidate.operands) == 1
                and _stack_displacement(candidate.operands[0]) == function_slot
            ):
                called.add(api_slot)
                break
            if _changes_rsp_basis(candidate):
                break
            write_span = _rsp_write_span(candidate)
            if write_span is not None and _spans_overlap(
                write_span,
                (function_slot, 8),
            ):
                break
    return called


def _network_worker_profile(
    graph: _FunctionGraph,
    resolution: _WinsockResolution,
) -> bool:
    """API identity付きでconfig host/service→getaddrinfoのdef-useを検証する。"""

    instructions = graph.instructions
    arguments = _prologue_argument_slots(instructions)
    if arguments is None or not {"rcx", "rdx", "r8", "r9"}.issubset(arguments):
        return False
    context_slot = arguments["rcx"]
    config_slot = arguments["rdx"]
    host_slot = arguments["r9"]
    getaddrinfo_slot = resolution.slots["getaddrinfo"]
    getaddrinfo_matches = 0
    hints_offsets: set[int] = set()
    getaddrinfo_call: object | None = None
    for index in range(len(instructions) - 9):
        window = _straight_line_window(graph, index, 10)
        if window is None:
            continue
        if [item.mnemonic for item in window] != [
            "mov",
            "mov",
            "mov",
            "mov",
            "add",
            "lea",
            "lea",
            "mov",
            "mov",
            "call",
        ]:
            continue
        if _rsp_memory_source(window[0], "rax") != context_slot:
            continue
        api_operand = window[1].operands[1] if len(window[1].operands) == 2 else None
        if (
            api_operand is None
            or api_operand.type != X86_OP_MEM
            or _register_name(window[1], window[1].operands[0]) != "rax"
            or _memory_base_name(window[1], api_operand) != "rax"
            or int(api_operand.mem.disp) != getaddrinfo_slot
        ):
            continue
        function_slot = _rsp_memory_destination(window[2], "rax")
        if function_slot is None or _rsp_memory_source(window[3], "rax") != config_slot:
            continue
        if not _add_immediate(window[4], 0x100):
            continue
        output_slot = _rsp_lea_source(window[5], "r9")
        hints_slot = _rsp_lea_source(window[6], "r8")
        if output_slot is None or hints_slot is None:
            continue
        if (
            _register_name(window[7], window[7].operands[0]) != "rdx"
            or _register_name(window[7], window[7].operands[1]) != "rax"
            or _rsp_memory_source(window[8], "rcx") != host_slot
            or len(window[9].operands) != 1
            or _stack_displacement(window[9].operands[0]) != function_slot
        ):
            continue
        getaddrinfo_matches += 1
        hints_offsets.add(hints_slot)
        getaddrinfo_call = window[9]
    if getaddrinfo_matches != 1 or len(hints_offsets) != 1 or getaddrinfo_call is None:
        return False
    hints_slot = next(iter(hints_offsets))
    hint_values: dict[int, list[tuple[int, object]]] = {}
    for item in instructions:
        if not (
            item.mnemonic == "mov"
            and len(item.operands) == 2
            and item.operands[0].type == X86_OP_MEM
            and item.operands[0].mem.base == X86_REG_RSP
            and item.operands[0].mem.index == X86_REG_INVALID
            and item.operands[1].type == X86_OP_IMM
        ):
            continue
        displacement = int(item.operands[0].mem.disp)
        if displacement not in hint_values:
            hint_values[displacement] = []
        hint_values[displacement].append((int(item.operands[1].imm), item))
    expected_hints = {
        hints_slot + 4: 0,
        hints_slot + 8: 1,
        hints_slot + 12: 6,
    }
    if any(
        len(hint_values.get(displacement, ())) != 1
        or hint_values[displacement][0][0] != value
        or not _dominates(
            graph,
            hint_values[displacement][0][1],
            getaddrinfo_call,
        )
        for displacement, value in expected_hints.items()
    ):
        return False
    required_calls = {
        resolution.slots["socket"],
        resolution.slots["connect"],
        resolution.slots["freeaddrinfo"],
    }
    return required_calls.issubset(
        _context_api_slots_called(
            graph,
            context_slot,
            dominated_by=getaddrinfo_call,
        )
    )


def _network_caller_profile(
    graph: _FunctionGraph,
    worker_offset: int,
) -> bool:
    """callerが同じconfig baseをworkerのhost/service両引数へ渡すことを検証する。"""

    instructions = graph.instructions
    arguments = _prologue_argument_slots(instructions)
    if arguments is None or not {"rcx", "rdx", "r8"}.issubset(arguments):
        return False
    calls = [
        instruction
        for instruction in instructions
        if _direct_call_target(instruction) == worker_offset
    ]
    if not 1 <= len(calls) <= 16:
        return False
    direct_config_calls = 0
    for call in calls:
        if _latest_register_source(graph, call, "rcx") != (
            "stack",
            arguments["rcx"],
        ):
            return False
        if _latest_register_source(graph, call, "rdx") != (
            "stack",
            arguments["rdx"],
        ):
            return False
        if _latest_register_source(graph, call, "r8") != (
            "stack",
            arguments["r8"],
        ):
            return False
        r9_source = _latest_register_source(graph, call, "r9")
        if r9_source != ("register", "rax"):
            continue
        r9_definition = _latest_register_definition(graph, call, "r9")
        if r9_definition is None:
            continue
        if _latest_register_source(graph, r9_definition, "rax") != (
            "stack",
            arguments["rdx"],
        ):
            continue
        direct_config_calls += 1
    return direct_config_calls >= 1


def _parser_source_to_sink_profile(
    graph: _FunctionGraph,
    *,
    initializer_offset: int,
    decryptor_offset: int,
    network_caller_offset: int,
    resolution: _WinsockResolution,
) -> bool:
    """API table初期化、decrypt出力、WSAStartup、network callerを同一frameで結ぶ。"""

    instructions = graph.instructions
    initializer_calls = [
        instruction
        for instruction in instructions
        if _direct_call_target(instruction) == initializer_offset
    ]
    decryptor_calls = [
        instruction
        for instruction in instructions
        if _direct_call_target(instruction) == decryptor_offset
    ]
    network_calls = [
        instruction
        for instruction in instructions
        if _direct_call_target(instruction) == network_caller_offset
    ]
    if not (
        len(initializer_calls) == len(decryptor_calls) == 1
        and 1 <= len(network_calls) <= 4
    ):
        return False
    initializer_call = initializer_calls[0]
    initializer_rcx = _latest_register_source(
        graph, initializer_call, "rcx", maximum_backtrack=4
    )
    if initializer_rcx is None or initializer_rcx[0] != "lea":
        return False
    api_table_slot = int(initializer_rcx[1])
    decryptor_call = decryptor_calls[0]
    if not _dominates(graph, initializer_call, decryptor_call):
        return False
    if _latest_register_source(graph, decryptor_call, "rcx", maximum_backtrack=6) != (
        "lea",
        api_table_slot,
    ):
        return False
    config_source = _latest_register_source(
        graph, decryptor_call, "r8", maximum_backtrack=6
    )
    if config_source is None or config_source[0] != "lea":
        return False
    config_slot = int(config_source[1])
    wsa_matches = 0
    wsa_call: object | None = None
    for index in range(len(instructions) - 4):
        window = _straight_line_window(graph, index, 5)
        if window is None:
            continue
        if [item.mnemonic for item in window] != ["mov", "mov", "lea", "mov", "call"]:
            continue
        if (
            _rsp_memory_source(window[0], "rax")
            != api_table_slot + resolution.slots["WSAStartup"]
        ):
            continue
        function_slot = _rsp_memory_destination(window[1], "rax")
        if (
            function_slot is None
            or _rsp_lea_source(window[2], "rdx") is None
            or _register_name(window[3], window[3].operands[0])
            not in {"cx", "ecx", "rcx"}
            or window[3].operands[1].type != X86_OP_IMM
            or int(window[3].operands[1].imm) != 0x202
            or len(window[4].operands) != 1
            or _stack_displacement(window[4].operands[0]) != function_slot
        ):
            continue
        wsa_matches += 1
        wsa_call = window[4]
    if (
        wsa_matches != 1
        or wsa_call is None
        or not _dominates(graph, decryptor_call, wsa_call)
    ):
        return False
    for call in network_calls:
        if (
            not _dominates(graph, wsa_call, call)
            or _latest_register_source(graph, call, "rcx", maximum_backtrack=6)
            != ("lea", api_table_slot)
            or _latest_register_source(graph, call, "rdx", maximum_backtrack=6)
            != ("lea", config_slot)
            or _latest_register_source(graph, call, "r8", maximum_backtrack=6) is None
        ):
            return False
    return True


def _decrypt_gcm(container: _OuterContainer, key: bytes) -> bytes | None:
    """AADとtagを必須にしてAES-256-GCM plaintextを復元する。"""

    if len(key) != 0x20 or len(container.nonce) != 0x0C or len(container.tag) != 0x10:
        return None
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=container.nonce, mac_len=0x10)
        cipher.update(container.aad)
        return cipher.decrypt_and_verify(container.ciphertext, container.tag)
    except ValueError:
        return None


def _external_host(value: str) -> str | None:
    """loopback等を除外したASCII hostを正規化する。"""

    if not value or value != value.strip() or len(value) > 255:
        return None
    try:
        ascii_value = value.encode("ascii", errors="strict").decode("ascii")
    except UnicodeError:
        return None
    try:
        address = ipaddress.ip_address(ascii_value)
    except ValueError:
        lowered = ascii_value.casefold()
        if lowered == "localhost" or _DOMAIN.fullmatch(lowered) is None:
            return None
        return lowered
    if (
        address.is_loopback
        or address.is_unspecified
        or address.is_multicast
        or address.is_link_local
    ):
        return None
    return address.compressed


def _inner_config(plaintext: bytes) -> _InnerConfig | None:
    """認証済みplaintextを固定長headerと四つのUTF-8 fieldとして検証する。"""

    if not INNER_HEADER_SIZE <= len(plaintext) <= MAXIMUM_CIPHERTEXT_SIZE:
        return None
    magic, version, port, host_size, second_size, third_size, fourth_size, flag = (
        struct.unpack_from("<IHHHHHHB", plaintext, 0)
    )
    sizes = (host_size, second_size, third_size, fourth_size)
    if (
        magic != INNER_MAGIC
        or version != INNER_VERSION
        or not 1 <= port <= 0xFFFF
        or not 1 <= host_size <= 255
        or not 0 <= second_size <= 255
        or not 0 <= third_size <= 255
        or not 0 <= fourth_size <= 511
        or flag not in {0, 1}
        or INNER_HEADER_SIZE + sum(sizes) != len(plaintext)
    ):
        return None
    cursor = INNER_HEADER_SIZE
    fields: list[str] = []
    for size in sizes:
        raw = plaintext[cursor : cursor + size]
        cursor += size
        if b"\x00" in raw:
            return None
        try:
            fields.append(raw.decode("utf-8", errors="strict"))
        except UnicodeError:
            return None
    host = _external_host(fields[0])
    if host is None:
        return None
    return _InnerConfig(
        host=host,
        port=port,
        auxiliary_lengths=(second_size, third_size, fourth_size),
        flag=flag,
    )


def _recover_shellcode(data: bytes) -> tuple[_InnerConfig, dict[str, object]] | None:
    """x64 shellcodeの構造gateから手動確認用設定候補だけを返す。"""

    if not 4 * 1024 <= len(data) <= MAXIMUM_SHELLCODE_SIZE:
        return None
    main = _main_profile(data)
    if main is None:
        return None
    container = _outer_container(data, main.container_offset)
    if container is None:
        return None
    magic_offsets = [
        index
        for index in range(len(data) - len(container.magic) + 1)
        if data.startswith(container.magic, index)
    ]
    if len(magic_offsets) != 2 or main.container_offset not in magic_offsets:
        return None
    duplicate_magic_offset = next(
        offset for offset in magic_offsets if offset != main.container_offset
    )
    if duplicate_magic_offset + 0x50 > len(data):
        return None
    reachable = _reachable_functions(data, main.parser_offset)
    if reachable is None:
        return None
    parser = reachable.get(main.parser_offset)
    if parser is None:
        return None
    decryptors: list[tuple[int, bytes, dict[str, object]]] = []
    for offset, graph in reachable.items():
        decryptor = _decryptor_profile(
            data,
            graph,
            duplicate_magic_offset,
        )
        if decryptor is not None:
            decryptors.append((offset, decryptor[0], decryptor[1]))
    if len(decryptors) != 1:
        return None
    expected_hashes = set(_WINSOCK_API_HASHES.values())
    resolutions: list[_WinsockResolution] = []
    for offset, graph in reachable.items():
        if not expected_hashes.issubset(_immediate_values(graph.instructions)):
            continue
        resolution = _winsock_resolution_profile(data, offset, graph)
        if resolution is not None:
            resolutions.append(resolution)
    if len(resolutions) != 1:
        return None
    resolution = resolutions[0]
    network_workers = [
        offset
        for offset, graph in reachable.items()
        if _network_worker_profile(graph, resolution)
    ]
    if len(network_workers) != 1:
        return None
    network_callers = [
        offset
        for offset, graph in reachable.items()
        if _network_caller_profile(graph, network_workers[0])
    ]
    if len(network_callers) != 1:
        return None
    if not _parser_source_to_sink_profile(
        parser,
        initializer_offset=resolution.initializer_offset,
        decryptor_offset=decryptors[0][0],
        network_caller_offset=network_callers[0],
        resolution=resolution,
    ):
        return None
    plaintext = _decrypt_gcm(container, decryptors[0][1])
    if plaintext is None:
        return None
    config = _inner_config(plaintext)
    if config is None:
        return None
    proof = dict(decryptors[0][2])
    proof.update(
        {
            "entry_to_container_parser": True,
            "gcm_authentication_succeeded": True,
            "inner_schema_validated": True,
            "network_related_shape_observed": True,
            "network_caller_stack_frame_integrity_proven": False,
            "post_getaddrinfo_api_calls_single_path_proven": False,
            "api_hash_to_slot_assignments_single_path_proven": False,
            "decryptor_output_and_service_producer_dataflow_proven": False,
            "config_to_getaddrinfo_tcp_sink": False,
            "config_host_service_def_use": False,
            "ws2_32_export_resolver_identity": False,
            "winsock_api_hash_slots_validated": False,
            "wsa_2_2_initialization": False,
        }
    )
    return config, proof


def _ahk_comment_line_boundary(text: str, index: int) -> bool:
    """indexが行頭または行頭から空白だけの位置か返す。"""

    line_start = max(text.rfind("\n", 0, index), text.rfind("\r", 0, index)) + 1
    return all(character in " \t" for character in text[line_start:index])


def _ahk_code_without_comments(text: str) -> str | None:
    """string literalを保護しつつAHKの行・block commentを除去する。"""

    output: list[str] = []
    index = 0
    in_string = False
    in_block_comment = False
    while index < len(text):
        character = text[index]
        following = text[index + 1] if index + 1 < len(text) else ""
        if in_block_comment:
            if (
                character == "*"
                and following == "/"
                and _ahk_comment_line_boundary(text, index)
            ):
                in_block_comment = False
                index += 2
                continue
            if character in "\r\n":
                output.append(character)
            index += 1
            continue
        if in_string:
            output.append(character)
            if character == "`" and following:
                output.append(following)
                index += 2
                continue
            if character == '"':
                if following == '"':
                    output.append(following)
                    index += 2
                    continue
                in_string = False
            index += 1
            continue
        if character == '"':
            in_string = True
            output.append(character)
            index += 1
            continue
        if character == ";" and (
            _ahk_comment_line_boundary(text, index)
            or (index > 0 and text[index - 1] in " \t")
        ):
            while index < len(text) and text[index] not in "\r\n":
                index += 1
            continue
        if (
            character == "/"
            and following == "*"
            and _ahk_comment_line_boundary(text, index)
        ):
            in_block_comment = True
            index += 2
            continue
        output.append(character)
        index += 1
    if in_string or in_block_comment:
        return None
    return "".join(output)


def _ahk_script(data: bytes) -> _AhkScriptProfile | None:
    """定数carrier pathとlinewise decode・連結syntaxを検証する。"""

    if not 256 <= len(data) <= MAXIMUM_SCRIPT_SIZE:
        return None
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeError:
        return None
    code = _ahk_code_without_comments(text)
    if code is None:
        return None
    path_matches = list(
        re.finditer(r'(?im)^\s*payloadpath\s*:=\s*"([^"\r\n]+)"\s*$', code)
    )
    if len(path_matches) != 1:
        return None
    path = path_matches[0].group(1)
    carrier_basename = path.replace("\\", "/").rsplit("/", 1)[-1]
    if (
        not carrier_basename
        or len(carrier_basename) > 255
        or carrier_basename in {".", ".."}
        or any(character in carrier_basename for character in '\x00:"<>|')
    ):
        return None
    statement_patterns = (
        r"(?im)^\s*#requires\s+autohotkey\s+v2\.0\s*$",
        r"(?im)^\s*filedata\s*:=\s*loadlinechunks\(\s*payloadpath\s*\)\s*$",
        r"(?im)^\s*loadlinechunks\(\s*path\s*\)\s*\{\s*$",
        r"(?im)^\s*loop\s+read\s*,\s*path\s*\{\s*$",
        r"(?im)^\s*chunk\s*:=\s*decodebase64url\(\s*text\s*\)\s*$",
        r"(?im)^\s*chunks\.push\(\s*chunk\s*\)\s*$",
        r"(?im)^\s*totalsize\s*\+=\s*chunk\.size\s*$",
        r"(?im)^\s*data\s*:=\s*buffer\(\s*totalsize\s*\)\s*$",
        r'(?im)^\s*dllcall\(\s*"kernel32\\rtlmovememory".*"ptr"\s*,\s*data\.ptr\s*\+\s*offset.*"ptr"\s*,\s*chunk\.ptr.*"uptr"\s*,\s*chunk\.size\s*\)\s*$',
        r"(?im)^\s*offset\s*\+=\s*chunk\.size\s*$",
        r"(?im)^\s*return\s+data\s*$",
        r"(?im)^\s*decodebase64url\(\s*text\s*\)\s*\{\s*$",
        r'(?im)^\s*text\s*:=\s*strreplace\(\s*strreplace\(\s*text\s*,\s*"-"\s*,\s*"\+"\s*\)\s*,\s*"_"\s*,\s*"/"\s*\)\s*$',
        r'(?im)^\s*(?:if\s+!\s*)?dllcall\(\s*"crypt32\\cryptstringtobinaryw"',
    )
    positions: list[int] = []
    for pattern in statement_patterns:
        matches = list(re.finditer(pattern, code))
        later = [
            match.start()
            for match in matches
            if not positions or match.start() > positions[-1]
        ]
        if not later:
            return None
        positions.append(later[0])
    if path_matches[0].start() >= positions[1]:
        return None
    return _AhkScriptProfile(carrier_basename=carrier_basename.casefold())


def _autohotkey_runtime(data: bytes) -> bool:
    """同梱されたx64 AutoHotkey v2 runtime候補を限定する。"""

    return (
        256 * 1024 <= len(data) <= 16 * 1024 * 1024
        and data.startswith(b"MZ")
        and b"AutoHotkey" in data
        and "AutoHotkey".encode("utf-16le") in data
        and re.search(rb"2\.\d{1,2}\.\d{1,3}", data) is not None
    )


def _decode_base64url_lines(data: bytes) -> bytes | None:
    """AHK scriptと同じline単位Base64URL変換を上限付きで再現する。"""

    if not 16 <= len(data) <= MAXIMUM_CARRIER_SIZE:
        return None
    chunks: list[bytes] = []
    total = 0
    for line in data.splitlines():
        compact = b"".join(line.split())
        if not compact:
            continue
        if len(compact) > 1024 * 1024 or _BASE64URL.fullmatch(compact) is None:
            return None
        remainder = len(compact) % 4
        if remainder == 1:
            return None
        normalized = compact.replace(b"-", b"+").replace(b"_", b"/")
        normalized += b"=" * ((4 - remainder) % 4)
        try:
            chunk = base64.b64decode(normalized, validate=True)
        except ValueError:
            return None
        total += len(chunk)
        if total > MAXIMUM_SHELLCODE_SIZE:
            return None
        chunks.append(chunk)
    if not chunks:
        return None
    return b"".join(chunks)


def _recover_from_cab_members(
    members: tuple[_CabMember, ...],
    source_size: int,
    *,
    msi_schema_validated: bool,
) -> MsiAhkAesGcmRecovery | None:
    """MSI File tableとCAB内runtime、script、carrierの構造候補を相関する。"""

    if msi_schema_validated is not True:
        return None
    scripts = [
        (index, profile)
        for index, member in enumerate(members)
        if (profile := _ahk_script(member.data)) is not None
    ]
    runtimes = [
        index
        for index, member in enumerate(members)
        if _autohotkey_runtime(member.data)
    ]
    carriers: list[tuple[int, bytes, _InnerConfig, dict[str, object]]] = []
    for index, member in enumerate(members):
        shellcode = _decode_base64url_lines(member.data)
        if shellcode is None:
            continue
        recovered = _recover_shellcode(shellcode)
        if recovered is not None:
            carriers.append((index, shellcode, recovered[0], recovered[1]))
    if len(scripts) != 1 or len(runtimes) != 1 or len(carriers) != 1:
        return None
    carrier = carriers[0]
    script_index, script_profile = scripts[0]
    if len({script_index, runtimes[0], carrier[0]}) != 3:
        return None
    if members[carrier[0]].installed_name.casefold() != script_profile.carrier_basename:
        return None
    proof = dict(carrier[3])
    proof.update(
        {
            "msi_database_table_shape_validated": True,
            "msi_media_cabinet_file_sequence_shape_observed": True,
            "msi_file_table_to_cab_member_shape_observed": True,
            "same_cab_autohotkey_v2_runtime": True,
            "ahk_constant_basename_matches_cab_carrier": True,
            "ahk_base64url_related_syntax_observed": True,
            "unique_base64url_carrier_candidate": True,
            "msi_component_directory_install_path_binding_proven": False,
            "ahk_installed_path_binding_proven": False,
            "ahk_cryptstring_decode_arguments_and_buffer_size_proven": False,
        }
    )
    return MsiAhkAesGcmRecovery(
        source_size=source_size,
        cab_member_count=len(members),
        shellcode=carrier[1],
        endpoint=carrier[2].endpoint,
        auxiliary_lengths=carrier[2].auxiliary_lengths,
        flag=carrier[2].flag,
        evidence=proof,
    )


def _decode_msi_stream_name(value: str) -> str | None:
    """MSI structured-storage stream名圧縮をboundedに復号する。"""

    decoded: list[str] = []
    for character in value:
        codepoint = ord(character)
        if 0x3800 <= codepoint <= 0x47FF:
            packed = codepoint - 0x3800
            decoded.append(_MSI_NAME_ALPHABET[packed & 0x3F])
            decoded.append(_MSI_NAME_ALPHABET[(packed >> 6) & 0x3F])
        elif 0x4800 <= codepoint <= 0x483F:
            decoded.append(_MSI_NAME_ALPHABET[codepoint - 0x4800])
        elif codepoint == 0x4840:
            decoded.append("!")
        elif character == "\x05" or 0x20 <= codepoint <= 0x7E:
            decoded.append(character)
        else:
            return None
    result = "".join(decoded)
    return result if 1 <= len(result) <= 255 else None


def _msi_string_table(streams: dict[str, bytes]) -> tuple[str, ...] | None:
    """_StringPool/_StringDataをID順のbounded文字列表へ復元する。"""

    pool = streams.get("!_StringPool")
    raw_data = streams.get("!_StringData")
    if (
        pool is None
        or raw_data is None
        or len(pool) < 4
        or len(pool) % 4 != 0
        or len(pool) > 4 + MAXIMUM_MSI_STRINGS * 4
        or len(raw_data) > MAXIMUM_MSI_STRING_DATA
    ):
        return None
    codepage, reserved = struct.unpack_from("<HH", pool)
    if codepage not in {0, 1252, 65001} or reserved != 0:
        return None
    encoding = "utf-8" if codepage == 65001 else "cp1252"
    cursor = 0
    values = [""]
    for offset in range(4, len(pool), 4):
        length, _reference_count = struct.unpack_from("<HH", pool, offset)
        if cursor + length > len(raw_data):
            return None
        raw = raw_data[cursor : cursor + length]
        cursor += length
        try:
            value = raw.decode(encoding, errors="strict")
        except UnicodeError:
            return None
        if "\x00" in value:
            return None
        values.append(value)
    if cursor != len(raw_data):
        return None
    return tuple(values)


def _msi_string(value: int, strings: tuple[str, ...]) -> str | None:
    """MSI string IDを範囲検証して返す。"""

    if not 0 <= value < len(strings):
        return None
    return strings[value]


def _msi_schema(
    streams: dict[str, bytes],
    strings: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[tuple[str, int, str, int], ...]] | None:
    """_Tables/_Columnsをboundedに復元し、table/column schemaを返す。"""

    tables = streams.get("!_Tables")
    columns = streams.get("!_Columns")
    if (
        tables is None
        or columns is None
        or len(tables) == 0
        or len(tables) % 2 != 0
        or len(columns) == 0
        or len(columns) % 8 != 0
    ):
        return None
    table_names = tuple(
        _msi_string(value, strings)
        for value in struct.unpack(f"<{len(tables) // 2}H", tables)
    )
    if any(value is None for value in table_names):
        return None
    row_count = len(columns) // 8
    if not 1 <= row_count <= 2048:
        return None
    column_rows: list[tuple[str, int, str, int]] = []
    for row in range(row_count):
        values = [
            struct.unpack_from("<H", columns, 2 * (column * row_count + row))[0]
            for column in range(4)
        ]
        table_name = _msi_string(values[0], strings)
        column_name = _msi_string(values[2], strings)
        if table_name is None or column_name is None:
            return None
        column_rows.append((table_name, values[1] ^ 0x8000, column_name, values[3]))
    return tuple(value for value in table_names if value is not None), tuple(
        column_rows
    )


def _msi_table_layout(
    column_rows: tuple[tuple[str, int, str, int], ...],
    table_name: str,
    expected_names: tuple[str, ...],
) -> tuple[int, ...] | None:
    """tableの列順・型を検証してcolumn幅を返す。"""

    selected = sorted(
        (item for item in column_rows if item[0] == table_name),
        key=lambda item: item[1],
    )
    if (
        len(selected) != len(expected_names)
        or tuple(item[1] for item in selected)
        != tuple(range(1, len(expected_names) + 1))
        or tuple(item[2] for item in selected) != expected_names
    ):
        return None
    widths: list[int] = []
    for _schema_table, _number, _name, kind in selected:
        if kind & 0x0800:
            widths.append(2)
        elif kind & 0xFF in {2, 4}:
            widths.append(kind & 0xFF)
        else:
            return None
    return tuple(widths)


def _msi_table_rows(
    table: bytes,
    widths: tuple[int, ...],
    *,
    maximum_rows: int,
) -> tuple[tuple[int, ...], ...] | None:
    """MSI column-major table streamをboundedなrow列へ変換する。"""

    row_width = sum(widths)
    if row_width == 0 or len(table) % row_width != 0:
        return None
    row_count = len(table) // row_width
    if not 1 <= row_count <= maximum_rows:
        return None
    column_offsets: list[int] = []
    cursor = 0
    for width in widths:
        column_offsets.append(cursor)
        cursor += width * row_count
    return tuple(
        tuple(
            int.from_bytes(
                table[
                    column_offsets[column] + row * width : column_offsets[column]
                    + (row + 1) * width
                ],
                "little",
            )
            for column, width in enumerate(widths)
        )
        for row in range(row_count)
    )


def _msi_file_records(
    streams: dict[str, bytes],
) -> dict[str, _MsiFileRecord] | None:
    """MSI schemaからFile key、配置名、size、sequenceを復元する。"""

    strings = _msi_string_table(streams)
    tables = streams.get("!_Tables")
    columns = streams.get("!_Columns")
    file_table = streams.get("!File")
    if (
        strings is None
        or tables is None
        or columns is None
        or file_table is None
        or len(tables) == 0
        or len(tables) % 2 != 0
        or len(columns) == 0
        or len(columns) % 8 != 0
    ):
        return None
    table_names = [
        _msi_string(value, strings)
        for value in struct.unpack(f"<{len(tables) // 2}H", tables)
    ]
    if table_names.count("File") != 1:
        return None
    row_count = len(columns) // 8
    if not 1 <= row_count <= 2048:
        return None
    column_rows: list[tuple[str, int, str, int]] = []
    for row in range(row_count):
        values = [
            struct.unpack_from("<H", columns, 2 * (column * row_count + row))[0]
            for column in range(4)
        ]
        table_name = _msi_string(values[0], strings)
        column_name = _msi_string(values[2], strings)
        if table_name is None or column_name is None:
            return None
        column_rows.append((table_name, values[1] ^ 0x8000, column_name, values[3]))
    file_columns = sorted(
        (item for item in column_rows if item[0] == "File"),
        key=lambda item: item[1],
    )
    expected_names = (
        "File",
        "Component_",
        "FileName",
        "FileSize",
        "Version",
        "Language",
        "Attributes",
        "Sequence",
    )
    if (
        len(file_columns) != len(expected_names)
        or tuple(item[1] for item in file_columns) != tuple(range(1, 9))
        or tuple(item[2] for item in file_columns) != expected_names
    ):
        return None
    widths: list[int] = []
    for _table_name, _number, _name, kind in file_columns:
        if kind & 0x0800:
            widths.append(2)
        elif kind & 0xFF in {2, 4}:
            widths.append(kind & 0xFF)
        else:
            return None
    row_width = sum(widths)
    if row_width == 0 or len(file_table) % row_width != 0:
        return None
    file_row_count = len(file_table) // row_width
    if not 1 <= file_row_count <= MAXIMUM_CAB_MEMBERS:
        return None
    column_offsets: list[int] = []
    cursor = 0
    for width in widths:
        column_offsets.append(cursor)
        cursor += width * file_row_count
    records: dict[str, _MsiFileRecord] = {}
    sequences: set[int] = set()
    for row in range(file_row_count):
        raw_values = [
            int.from_bytes(
                file_table[
                    column_offsets[column] + row * width : column_offsets[column]
                    + (row + 1) * width
                ],
                "little",
            )
            for column, width in enumerate(widths)
        ]
        key = _msi_string(raw_values[0], strings)
        installed = _msi_string(raw_values[2], strings)
        if key is None or installed is None or not key or not installed:
            return None
        installed_name = installed.split("|")[-1]
        if (
            not installed_name
            or len(installed_name) > 255
            or any(character in installed_name for character in '\\/:\x00"<>')
        ):
            return None
        size = raw_values[3] ^ 0x80000000
        sequence = raw_values[7] ^ 0x80000000
        if (
            not 0 <= size <= MAXIMUM_CAB_MEMBER_SIZE
            or not 1 <= sequence <= MAXIMUM_CAB_MEMBERS
            or key in records
            or sequence in sequences
        ):
            return None
        records[key] = _MsiFileRecord(installed_name, size, sequence)
        sequences.add(sequence)
    return records


def _msi_media_record(
    streams: dict[str, bytes],
    file_records: dict[str, _MsiFileRecord],
) -> _MsiMediaRecord | None:
    """Media.CabinetとFile.Sequenceを単一埋込CABへ厳格に結合する。"""

    strings = _msi_string_table(streams)
    media_table = streams.get("!Media")
    if strings is None or media_table is None:
        return None
    schema = _msi_schema(streams, strings)
    if schema is None or schema[0].count("Media") != 1:
        return None
    widths = _msi_table_layout(
        schema[1],
        "Media",
        (
            "DiskId",
            "LastSequence",
            "DiskPrompt",
            "Cabinet",
            "VolumeLabel",
            "Source",
        ),
    )
    if widths is None:
        return None
    rows = _msi_table_rows(media_table, widths, maximum_rows=MAXIMUM_CAB_MEMBERS)
    if rows is None or len(rows) != 1:
        return None
    raw = rows[0]
    disk_id = raw[0] ^ 0x8000
    last_sequence = raw[1] ^ 0x80000000
    cabinet = _msi_string(raw[3], strings)
    sequences = {record.sequence for record in file_records.values()}
    if (
        disk_id != 1
        or cabinet is None
        or not cabinet.startswith("#")
        or len(cabinet) <= 1
        or len(cabinet) > 256
        or any(character in cabinet[1:] for character in '\\/:\x00"<>')
        or last_sequence != len(file_records)
        or sequences != set(range(1, last_sequence + 1))
    ):
        return None
    return _MsiMediaRecord(disk_id, last_sequence, cabinet[1:])


def _bound_msi_cabinet_stream(
    streams: dict[str, bytes],
    file_records: dict[str, _MsiFileRecord],
    cab_stream_names: tuple[str, ...],
) -> str | None:
    """Media.Cabinetが唯一のMSCF streamを指す場合だけその名前を返す。"""

    media_record = _msi_media_record(streams, file_records)
    if media_record is None or cab_stream_names != (media_record.cabinet_stream,):
        return None
    return media_record.cabinet_stream


def _cab_members(data: bytes) -> tuple[_CabMember, ...] | None:
    """MSI schemaで命名された単一MSZip CABをmemory内だけで展開する。"""

    if not MINIMUM_MSI_SIZE <= len(data) <= MAXIMUM_MSI_SIZE or not data.startswith(
        _OLE_MAGIC
    ):
        return None
    try:
        container = olefile.OleFileIO(io.BytesIO(data))
        streams = list(container.listdir(streams=True, storages=False))
    except (OSError, ValueError, TypeError):
        return None
    if (
        not 1 <= len(streams) <= MAXIMUM_OLE_STREAMS
        or str(container.root.clsid).upper() != _MSI_DATABASE_CLSID
        or any(len(stream) != 1 for stream in streams)
    ):
        return None
    cab_streams: list[bytes] = []
    cab_stream_names: list[str] = []
    decoded_streams: dict[str, bytes] = {}
    total = 0
    for stream in streams:
        try:
            raw = container.openstream(stream).read(MAXIMUM_OLE_STREAM_SIZE + 1)
        except (OSError, ValueError, TypeError):
            return None
        total += len(raw)
        if len(raw) > MAXIMUM_OLE_STREAM_SIZE or total > MAXIMUM_OLE_TOTAL_SIZE:
            return None
        decoded_name = _decode_msi_stream_name(stream[0])
        if decoded_name is None or decoded_name in decoded_streams:
            return None
        decoded_streams[decoded_name] = raw
        if raw.startswith(b"MSCF"):
            cab_streams.append(raw)
            cab_stream_names.append(decoded_name)
    if len(cab_streams) != 1:
        return None
    file_records = _msi_file_records(decoded_streams)
    if file_records is None:
        return None
    cabinet_stream = _bound_msi_cabinet_stream(
        decoded_streams,
        file_records,
        tuple(cab_stream_names),
    )
    if (
        cabinet_stream is None
        or decoded_streams.get(cabinet_stream) is not cab_streams[0]
    ):
        return None
    try:
        archive = cabarchive.CabArchive(cab_streams[0])
        entries = list(archive.items())
    except (
        ValueError,
        TypeError,
        cabarchive.errors.CorruptionError,
        cabarchive.errors.NotSupportedError,
    ):
        return None
    if not 1 <= len(entries) <= MAXIMUM_CAB_MEMBERS:
        return None
    members: list[_CabMember] = []
    member_keys: set[str] = set()
    total = 0
    for name, entry in entries:
        try:
            raw = bytes(entry.buf)
        except (AttributeError, TypeError, ValueError):
            return None
        total += len(raw)
        if len(raw) > MAXIMUM_CAB_MEMBER_SIZE or total > MAXIMUM_CAB_TOTAL_SIZE:
            return None
        record = file_records.get(name)
        if record is None or name in member_keys or record.size != len(raw):
            return None
        member_keys.add(name)
        members.append(
            _CabMember(key=name, installed_name=record.installed_name, data=raw)
        )
    if member_keys != set(file_records):
        return None
    return tuple(members)


def recover_msi_ahk_aes_gcm(data: bytes) -> MsiAhkAesGcmRecovery | None:
    """MSI rootから認証済み設定候補までを手動確認用に静的復元する。"""

    members = _cab_members(data)
    if members is None:
        return None
    return _recover_from_cab_members(
        members,
        len(data),
        msi_schema_validated=True,
    )


def public_recovery_summary(recovery: MsiAhkAesGcmRecovery) -> dict[str, object]:
    """secret、raw config、network値を除外した未検証候補要約を返す。"""

    return {
        "profile": "msi_ahk_base64url_aes256_gcm_unverified_candidate",
        "status": "manual_unverified_route_config_candidate",
        "candidate_only": True,
        "automatic_route_eligible": False,
        "manual_review_required": True,
        "supports_family_attribution": False,
        "family_attribution_confirmed": False,
        "terminal_family_confirmed": False,
        "final_rat_confirmed": False,
        "static_config_recovered": False,
        "c2_confirmed": False,
        "command_c2_confirmed": False,
        "qualified": False,
        "used_for_resolution": False,
        "used_for_family_resolution": False,
        "used_for_c2_confirmation": False,
        "source_size": recovery.source_size,
        "cab_member_count": recovery.cab_member_count,
        "recovered_payload_candidate_size": len(recovery.shellcode),
        "candidate_endpoint_count": 1,
        "configured_endpoint_count": 0,
        "auxiliary_field_lengths": list(recovery.auxiliary_lengths),
        "boolean_flag_present": recovery.flag in {0, 1},
        "structural_observations": dict(recovery.evidence),
        "evidence_boundary": {
            "network_caller_stack_frame_integrity_proven": False,
            "post_getaddrinfo_api_calls_single_path_proven": False,
            "api_hash_to_slot_assignments_single_path_proven": False,
            "decryptor_output_and_service_producer_dataflow_proven": False,
            "msi_component_directory_install_path_binding_proven": False,
            "ahk_cryptstring_decode_arguments_and_buffer_size_proven": False,
            "all_expected_fields_validated": False,
        },
        "raw_key_included": False,
        "raw_nonce_included": False,
        "raw_tag_included": False,
        "raw_config_included": False,
        "raw_payload_included": False,
        "network_values_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }


def probe_msi_ahk_aes_gcm(data: bytes) -> dict[str, object]:
    """network値を含まないmanual-only候補判定を返す。"""

    recovery = recover_msi_ahk_aes_gcm(data)
    if recovery is None:
        return {
            "matched": False,
            "candidate_recovered": False,
            "automatic_route_eligible": False,
            "manual_review_required": True,
            "supports_family_attribution": False,
            "family_attribution_confirmed": False,
            "terminal_family_confirmed": False,
            "final_rat_confirmed": False,
            "static_config_recovered": False,
            "candidate_config_recovered": False,
            "c2_confirmed": False,
            "command_c2_confirmed": False,
            "qualified": False,
            "used_for_resolution": False,
            "used_for_family_resolution": False,
            "used_for_c2_confirmation": False,
            "endpoint_count": 0,
            "candidate_endpoint_count": 0,
            "sample_executed": False,
            "network_contacted": False,
        }
    return {
        "matched": True,
        "candidate_recovered": True,
        "automatic_route_eligible": False,
        "manual_review_required": True,
        "family": None,
        "supports_family_attribution": False,
        "family_attribution_confirmed": False,
        "terminal_family_confirmed": False,
        "final_rat_confirmed": False,
        "static_config_recovered": False,
        "candidate_config_recovered": True,
        "c2_confirmed": False,
        "command_c2_confirmed": False,
        "qualified": False,
        "used_for_resolution": False,
        "used_for_family_resolution": False,
        "used_for_c2_confirmation": False,
        "endpoint_count": 0,
        "candidate_endpoint_count": 1,
        "profile": "msi_ahk_base64url_aes256_gcm_unverified_candidate",
        "raw_network_values_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }


__all__ = [
    "MsiAhkAesGcmRecovery",
    "probe_msi_ahk_aes_gcm",
    "public_recovery_summary",
    "recover_msi_ahk_aes_gcm",
]
