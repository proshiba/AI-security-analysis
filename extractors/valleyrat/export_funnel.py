"""export funnel型native PEを名前非依存で静的に評価する。

このmoduleは検体をload／実行せず、PE tableとfile-backed x86 codeだけを扱う。
export、TLS callback、resource、importの形状は解析経路を選ぶための証拠であり、
それだけでValleyRAT familyやC2を確定しない。
"""

from __future__ import annotations

import math
import struct
from collections import Counter
from dataclasses import dataclass
from itertools import pairwise

import pefile
from capstone import (
    CS_AC_READ,
    CS_AC_WRITE,
    CS_ARCH_X86,
    CS_GRP_CALL,
    CS_GRP_JUMP,
    CS_GRP_RET,
    CS_MODE_32,
    Cs,
    CsError,
)
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_AH,
    X86_REG_AL,
    X86_REG_AX,
    X86_REG_BH,
    X86_REG_BL,
    X86_REG_BP,
    X86_REG_BX,
    X86_REG_CH,
    X86_REG_CL,
    X86_REG_CX,
    X86_REG_DH,
    X86_REG_DI,
    X86_REG_DL,
    X86_REG_DX,
    X86_REG_EAX,
    X86_REG_EBP,
    X86_REG_EBX,
    X86_REG_ECX,
    X86_REG_EDI,
    X86_REG_EDX,
    X86_REG_ESI,
    X86_REG_ESP,
    X86_REG_INVALID,
    X86_REG_SI,
    X86_REG_SP,
)

from extractors.native_dataflow import (
    NativeFlowLimits,
    NativeSource,
    analyze_x86_pe_dataflow,
)

MAX_INPUT_SIZE = 16 * 1024 * 1024
MAX_SECTIONS = 96
MAX_EXPORTS = 4_096
MAX_TLS_CALLBACKS = 32
MAX_RESOURCE_LEAVES = 2_048
MAX_RESOURCE_BYTES = 32 * 1024 * 1024
MAX_OPAQUE_WIDE_HEX_CANDIDATES = 32
MAX_OPAQUE_WIDE_HEX_CHARACTERS = 8_192
MAX_OPAQUE_WIDE_HEX_SCAN_BYTES = 16 * 1024 * 1024
MAX_OPAQUE_WIDE_HEX_REFERENCE_MATCHES = 64
MAX_OPAQUE_WIDE_HEX_REFERENCE_SCAN_BYTES = 16 * 1024 * 1024
MAX_OPAQUE_WIDE_HEX_REFERENCE_SCAN_INSTRUCTIONS = 524_288
MAX_OPAQUE_WIDE_HEX_DIRECT_CALLS = 65_536
MAX_OPAQUE_WIDE_HEX_ENTRY_BACKTRACK_BYTES = 192
MAX_OPAQUE_WIDE_HEX_ENTRY_PADDING_BYTES = 8
MAX_OPAQUE_WIDE_HEX_CALLSITE_BYTES = 512
MAX_OPAQUE_WIDE_HEX_CALLSITE_INSTRUCTIONS = 128
MAX_OPAQUE_WIDE_HEX_ANCHORED_WINDOWS = 128
MAX_OPAQUE_WIDE_HEX_ANCHORED_SCAN_BYTES = 64 * 1024
MAX_OPAQUE_WIDE_HEX_ANCHORED_SCAN_INSTRUCTIONS = 16_384
MAX_OPAQUE_WIDE_HEX_CALL_ARGUMENTS = 8
MAX_OPAQUE_WIDE_HEX_POST_STAGE_INSTRUCTIONS = 8
MAX_OPAQUE_WIDE_HEX_TRANSFORM_BYTES = 512
MAX_OPAQUE_WIDE_HEX_TRANSFORM_INSTRUCTIONS = 128
MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_FUNCTIONS = 128
MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_DEPTH = 8
MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_BYTES = 64 * 1024
MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_INSTRUCTIONS = 16_384
MAX_OPAQUE_WIDE_HEX_LOCAL_CALLER_CANDIDATES = 128
MAX_OPAQUE_WIDE_HEX_LOCAL_SCAN_BYTES = 64 * 1024
MAX_OPAQUE_WIDE_HEX_LOCAL_SCAN_INSTRUCTIONS = 16_384
MAX_RESOURCE_RUNTIME_FUNCTIONS = 128
MAX_RESOURCE_RUNTIME_CALL_GRAPH_DEPTH = 8
MAX_RESOURCE_RUNTIME_INSTRUCTIONS = 20_000
MAX_RESOURCE_RUNTIME_MEMORY_CELLS = 64
MAX_RESOURCE_RUNTIME_CHAINS = 32
MAX_RESOURCE_IDENTIFIER_CHARACTERS = 128
MIN_OPAQUE_WIDE_HEX_TRANSFORM_KINDS = 3
MIN_FUNNEL_EXPORTS = 2
MIN_CUSTOM_HIGH_ENTROPY_RESOURCES = 2
MIN_RESOURCE_SIZE = 16 * 1024
MIN_RESOURCE_ENTROPY = 7.0
MIN_OPAQUE_WIDE_HEX_CHARACTERS = 128
MIN_OPAQUE_WIDE_HEX_ENTROPY = 5.5
_EXECUTABLE = 0x20000000
_WRITABLE = 0x80000000
_DLL = 0x2000
_STANDARD_RESOURCE_TYPES = frozenset(range(1, 25))
_BYTE_TRANSFORM_MNEMONICS = frozenset({"add", "rol", "ror", "sub", "xor"})
_CONDITIONAL_JUMP_MNEMONICS = frozenset(
    {
        "ja",
        "jae",
        "jb",
        "jbe",
        "je",
        "jecxz",
        "jg",
        "jge",
        "jl",
        "jle",
        "jne",
        "jno",
        "jnp",
        "jns",
        "jo",
        "jp",
        "js",
    }
)
_LOW_BYTE_REGISTERS = frozenset(
    {X86_REG_AL, X86_REG_BL, X86_REG_CL, X86_REG_DL}
)
_REGISTER_FAMILIES = {
    register: family
    for family, registers in {
        "eax": (X86_REG_AL, X86_REG_AH, X86_REG_AX, X86_REG_EAX),
        "ebx": (X86_REG_BL, X86_REG_BH, X86_REG_BX, X86_REG_EBX),
        "ecx": (X86_REG_CL, X86_REG_CH, X86_REG_CX, X86_REG_ECX),
        "edx": (X86_REG_DL, X86_REG_DH, X86_REG_DX, X86_REG_EDX),
        "esi": (X86_REG_SI, X86_REG_ESI),
        "edi": (X86_REG_DI, X86_REG_EDI),
        "ebp": (X86_REG_BP, X86_REG_EBP),
        "esp": (X86_REG_SP, X86_REG_ESP),
    }.items()
    for register in registers
}

_RESOURCE_GROUPS = {
    "find": frozenset(
        {"findresourcea", "findresourcew", "findresourceexa", "findresourceexw"}
    ),
    "load": frozenset({"loadresource"}),
    "lock": frozenset({"lockresource"}),
    "size": frozenset({"sizeofresource"}),
}
_NETWORK_GROUPS = {
    "startup": frozenset({"wsastartup"}),
    "socket": frozenset({"socket", "wsasocketa", "wsasocketw"}),
    "resolve": frozenset({"gethostbyname", "getaddrinfo", "getaddrinfow"}),
    "port": frozenset({"htons", "htonl"}),
    "connect": frozenset({"connect", "wsaconnect"}),
    "send": frozenset({"send", "wsasend"}),
    "receive": frozenset({"recv", "wsarecv"}),
}


@dataclass(frozen=True)
class ExternalCodeRoots:
    """PE外部entry tableから得た、検証済みcode root。"""

    roots: tuple[int, ...]
    export_roots: tuple[int, ...]
    tls_roots: tuple[int, ...]
    export_count: int
    export_target_count: int
    export_funnel: bool
    tls_directory_present: bool


@dataclass(frozen=True)
class OpaqueWideHexCandidate:
    """書込み可能section内の終端済み高entropy UTF-16LE hex候補。"""

    address: int
    byte_size: int
    character_count: int
    normalized_byte_count: int
    odd_nibble_count: int
    normalized_entropy: float


@dataclass(frozen=True)
class OpaqueWideHexInventory:
    """raw値を保持しない、有界なwide-hex候補inventory。"""

    candidates: tuple[OpaqueWideHexCandidate, ...]
    candidate_set_complete: bool
    candidate_set_truncated: bool
    scanned_byte_count: int


@dataclass(frozen=True)
class OpaqueWideHexUseInventory:
    """raw値を公開せず、同一call path上の候補使用だけを保持する。"""

    source_roots: tuple[int, ...]
    raw_reference_count: int
    source_operand_reference_count: int
    anchored_source_reference_count: int
    staging_call_chain_count: int
    semantic_transform_chain_count: int
    transform_operation_kinds: tuple[str, ...]
    reference_set_complete: bool
    reference_set_truncated: bool
    bounded_analysis_complete: bool
    scanned_byte_count: int
    decoded_literal_reference_count: int | None = None
    scanned_instruction_count: int = 0
    anchored_window_count: int = 0
    anchored_scanned_byte_count: int = 0
    anchored_scanned_instruction_count: int = 0
    resource_locator_match_count: int = 0
    resource_handle_chain_count: int = 0
    resource_pointer_size_chain_count: int = 0
    resource_runtime_source_count: int = 0
    resource_runtime_analysis_complete: bool = False
    resource_runtime_truncated: bool = False
    resource_runtime_scanned_instruction_count: int = 0
    root_derived_source_reference_count: int = 0
    root_address_lineage_analysis_complete: bool = False
    root_address_lineage_truncated: bool = False
    root_address_lineage_root_count: int = 0
    root_address_lineage_function_count: int = 0
    root_address_lineage_scanned_byte_count: int = 0
    root_address_lineage_scanned_instruction_count: int = 0
    reference_scan_mode: str = "capstone_x86_instruction_boundaries"
    raw_candidate_occurrence_count: int | None = None
    local_literal_instruction_start_count: int = 0
    local_direct_caller_count: int = 0
    local_scanned_byte_count: int = 0


@dataclass(frozen=True)
class _MappedSection:
    address: int
    mapped_end: int
    file_backed_end: int
    raw_start: int
    raw_end: int
    characteristics: int


@dataclass(frozen=True)
class _InstructionReferenceScan:
    """命令境界で検証した候補literal、source push、direct callの台帳。"""

    source_references: tuple[tuple[_MappedSection, int], ...]
    literal_reference_count: int
    direct_call_targets: tuple[tuple[int, int], ...]
    complete: bool
    truncated: bool
    scanned_byte_count: int
    scanned_instruction_count: int
    mode: str = "capstone_x86_instruction_boundaries"
    raw_candidate_occurrence_count: int | None = None
    local_literal_instruction_start_count: int = 0
    local_direct_caller_count: int = 0
    local_scanned_byte_count: int = 0
    local_source_entries: tuple[tuple[int, int], ...] = ()


@dataclass(frozen=True)
class _RootAddressValue:
    """rootに結び付く32-bit affine値。coefficient=1だけがaddress。"""

    value: int
    address_coefficient: int
    derived: bool


@dataclass(frozen=True)
class _RootAddressLineageScan:
    """検証済みexport/TLS rootから得たcandidate address生成台帳。"""

    source_references: tuple[tuple[int, int], ...]
    analysis_complete: bool
    truncated: bool
    root_count: int
    function_count: int
    scanned_byte_count: int
    scanned_instruction_count: int


@dataclass(frozen=True)
class _PushedValue:
    address: int | None
    register_family: str | None
    source: bool = False


@dataclass(frozen=True)
class _TransformObject:
    """局所transformで追跡する、wrapしない32-bit object範囲。"""

    origin: int
    extent: int


@dataclass(frozen=True)
class _TransformPointer:
    """source／destination objectからのchecked affine offset。"""

    object_name: str
    offset: int


@dataclass(frozen=True)
class _TransformSemantics:
    operation_kinds: tuple[str, ...]
    byte_memory_read: bool
    destination_memory_write: bool
    window_complete: bool

    @property
    def qualifies(self) -> bool:
        return bool(
            self.window_complete
            and self.byte_memory_read
            and self.destination_memory_write
            and len(self.operation_kinds) >= MIN_OPAQUE_WIDE_HEX_TRANSFORM_KINDS
        )


@dataclass(frozen=True)
class _SourceUseChain:
    root: int
    source_instruction: int
    staging_target: int
    transform_target: int
    semantics: _TransformSemantics


@dataclass(frozen=True)
class _ResourceLeaf:
    address: int
    size: int
    entropy: float
    custom_type: bool
    type_id: int | None = None
    name_id: int | None = None
    type_name: str | None = None
    name_name: str | None = None


@dataclass(frozen=True)
class _ResourceRuntimeValue:
    """resource API戻り値をraw値なしで表す局所taint。"""

    constant: int | None = None
    tags: frozenset[str] = frozenset()


@dataclass(frozen=True)
class _ResourceRuntimePush:
    value: _ResourceRuntimeValue
    register_family: str | None


@dataclass(frozen=True)
class _ResourceRuntimeChain:
    root: int
    source_instruction: int
    staging_target: int
    transform_target: int
    semantics: _TransformSemantics


@dataclass(frozen=True)
class _ResourceRuntimeInventory:
    chains: tuple[_ResourceRuntimeChain, ...]
    locator_match_count: int
    handle_chain_count: int
    pointer_size_chain_count: int
    source_count: int
    analysis_complete: bool
    truncated: bool
    scanned_instruction_count: int


def _bounded_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    view = data
    if len(view) > 3 * 1024 * 1024:
        window = 1024 * 1024
        middle = max(0, (len(view) - window) // 2)
        view = view[:window] + view[middle : middle + window] + view[-window:]
    counts = Counter(view)
    total = len(view)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _executable_ranges(
    image: object, data: bytes
) -> tuple[tuple[int, int], ...] | None:
    try:
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
        sections = list(image.sections)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if not sections or len(sections) > MAX_SECTIONS:
        return None
    result: list[tuple[int, int]] = []
    for section in sections:
        try:
            raw_start = int(section.PointerToRawData)
            raw_size = int(section.SizeOfRawData)
            virtual_size = int(section.Misc_VirtualSize)
            virtual_address = int(section.VirtualAddress)
            characteristics = int(section.Characteristics)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        mapped_size = min(raw_size, virtual_size or raw_size)
        if raw_start < 0 or mapped_size < 0 or raw_start + mapped_size > len(data):
            return None
        if mapped_size and characteristics & _EXECUTABLE:
            start = image_base + virtual_address
            result.append((start, start + mapped_size))
    result.sort()
    if not result or any(left[1] > right[0] for left, right in pairwise(result)):
        return None
    return tuple(result)


def _mapped_executable(address: int, ranges: tuple[tuple[int, int], ...]) -> bool:
    return any(start <= address < end for start, end in ranges)


def _hex_nibble(value: int) -> int | None:
    if 0x30 <= value <= 0x39:
        return value - 0x30
    if 0x41 <= value <= 0x46:
        return value - 0x41 + 10
    return None


def _normalized_hex_bytes(nibbles: list[int]) -> bytes:
    """odd桁は先頭に0 nibbleを補い、値を公開せずentropy計算だけに使う。"""

    padded = nibbles if len(nibbles) % 2 == 0 else [0, *nibbles]
    return bytes(
        (padded[index] << 4) | padded[index + 1] for index in range(0, len(padded), 2)
    )


def collect_opaque_wide_hex_candidates(
    image: object,
    data: bytes,
) -> OpaqueWideHexInventory | None:
    """書込み可能・非実行sectionから高entropy wide-hex候補を有界回収する。

    これは暗号文らしい静的sourceのinventoryであり、復号済み設定、C2、
    またはfamily帰属を意味しない。raw文字列、hash、file名は保持しない。
    """

    try:
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
        sections = list(image.sections)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if not sections or len(sections) > MAX_SECTIONS:
        return None

    candidates: list[OpaqueWideHexCandidate] = []
    scanned = 0
    truncated = False
    for section in sections:
        try:
            raw_start = int(section.PointerToRawData)
            raw_size = int(section.SizeOfRawData)
            virtual_size = int(section.Misc_VirtualSize)
            virtual_address = int(section.VirtualAddress)
            characteristics = int(section.Characteristics)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        mapped_size = min(raw_size, virtual_size or raw_size)
        if raw_start < 0 or mapped_size < 0 or raw_start + mapped_size > len(data):
            return None
        if (
            not mapped_size
            or not characteristics & _WRITABLE
            or characteristics & _EXECUTABLE
        ):
            continue
        if scanned > MAX_OPAQUE_WIDE_HEX_SCAN_BYTES - mapped_size:
            return OpaqueWideHexInventory(
                candidates=tuple(candidates),
                candidate_set_complete=False,
                candidate_set_truncated=True,
                scanned_byte_count=scanned,
            )
        scanned += mapped_size
        raw_end = raw_start + mapped_size
        for alignment in (0, 1):
            cursor = raw_start + alignment
            while cursor + 1 < raw_end:
                if data[cursor + 1] != 0 or _hex_nibble(data[cursor]) is None:
                    cursor += 2
                    continue
                previous = cursor - 2
                if (
                    previous >= raw_start
                    and data[previous + 1] == 0
                    and _hex_nibble(data[previous]) is not None
                ):
                    cursor += 2
                    continue

                start = cursor
                nibbles: list[int] = []
                overlong = False
                while cursor + 1 < raw_end:
                    value = data[cursor]
                    upper = data[cursor + 1]
                    if value == 0 and upper == 0:
                        break
                    nibble = _hex_nibble(value) if upper == 0 else None
                    if nibble is None:
                        break
                    if len(nibbles) >= MAX_OPAQUE_WIDE_HEX_CHARACTERS:
                        overlong = True
                    elif not overlong:
                        nibbles.append(nibble)
                    cursor += 2
                terminated = (
                    cursor + 1 < raw_end and data[cursor : cursor + 2] == b"\0\0"
                )
                if (
                    not overlong
                    and terminated
                    and len(nibbles) >= MIN_OPAQUE_WIDE_HEX_CHARACTERS
                ):
                    normalized = _normalized_hex_bytes(nibbles)
                    entropy = _bounded_entropy(normalized)
                    if entropy >= MIN_OPAQUE_WIDE_HEX_ENTROPY:
                        if len(candidates) >= MAX_OPAQUE_WIDE_HEX_CANDIDATES:
                            truncated = True
                        else:
                            candidates.append(
                                OpaqueWideHexCandidate(
                                    address=(
                                        image_base
                                        + virtual_address
                                        + (start - raw_start)
                                    ),
                                    byte_size=len(nibbles) * 2,
                                    character_count=len(nibbles),
                                    normalized_byte_count=len(normalized),
                                    odd_nibble_count=len(nibbles) % 2,
                                    normalized_entropy=entropy,
                                )
                            )
                if cursor <= start:
                    cursor = start + 2

    return OpaqueWideHexInventory(
        candidates=tuple(candidates),
        candidate_set_complete=not truncated,
        candidate_set_truncated=truncated,
        scanned_byte_count=scanned,
    )


def _mapped_sections(
    image: object,
    data: bytes,
) -> tuple[_MappedSection, ...] | None:
    """virtual tailとfile-backed範囲を混同せずPE sectionを正規化する。"""

    try:
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
        sections = list(image.sections)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if not sections or len(sections) > MAX_SECTIONS:
        return None

    result: list[_MappedSection] = []
    for section in sections:
        try:
            raw_start = int(section.PointerToRawData)
            raw_size = int(section.SizeOfRawData)
            virtual_size = int(section.Misc_VirtualSize)
            virtual_address = int(section.VirtualAddress)
            characteristics = int(section.Characteristics)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if min(raw_start, raw_size, virtual_size, virtual_address) < 0:
            return None
        file_backed_size = min(raw_size, virtual_size or raw_size)
        mapped_size = max(raw_size, virtual_size)
        if raw_start + file_backed_size > len(data):
            return None
        address = image_base + virtual_address
        mapped_end = address + mapped_size
        file_backed_end = address + file_backed_size
        if not 0 <= address <= mapped_end <= 0x1_0000_0000:
            return None
        result.append(
            _MappedSection(
                address=address,
                mapped_end=mapped_end,
                file_backed_end=file_backed_end,
                raw_start=raw_start,
                raw_end=raw_start + file_backed_size,
                characteristics=characteristics,
            )
        )
    result.sort(key=lambda item: item.address)
    if any(left.mapped_end > right.address for left, right in pairwise(result)):
        return None
    return tuple(result)


def _section_at(
    sections: tuple[_MappedSection, ...],
    address: int,
    *,
    file_backed: bool = False,
) -> _MappedSection | None:
    for section in sections:
        end = section.file_backed_end if file_backed else section.mapped_end
        if section.address <= address < end:
            return section
    return None


def _file_backed_executable(
    sections: tuple[_MappedSection, ...],
    address: int,
) -> bool:
    section = _section_at(sections, address, file_backed=True)
    return bool(section is not None and section.characteristics & _EXECUTABLE)


def _writable_non_executable(
    sections: tuple[_MappedSection, ...],
    address: int,
) -> bool:
    section = _section_at(sections, address)
    return bool(
        section is not None
        and section.characteristics & _WRITABLE
        and not section.characteristics & _EXECUTABLE
    )


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _register_family(register: int) -> str | None:
    if register == X86_REG_INVALID:
        return None
    return _REGISTER_FAMILIES.get(register)


def _written_register_families(
    instruction: object,
) -> set[str] | None:
    try:
        operands = tuple(instruction.operands)
        written = tuple(instruction.regs_write)
    except (AttributeError, CsError, TypeError, ValueError):
        return None
    try:
        register_ids = {int(register) for register in written}
        register_ids.update(
            int(operand.reg)
            for operand in operands
            if operand.type == X86_OP_REG and int(operand.access) & CS_AC_WRITE
        )
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    return {
        family
        for register in register_ids
        if (family := _register_family(register)) is not None
    }


def _decode_one_x86(
    disassembler: Cs,
    code: bytes,
    address: int,
) -> object | None:
    """bytes先頭15 byteからx86命令を最大1件だけ復号する。"""

    if type(code) is not bytes or type(address) is not int or not code:
        return None
    if not 0 <= address <= 0xFFFFFFFF:
        return None
    try:
        instructions = tuple(disassembler.disasm(code[:15], address, count=1))
    except (CsError, TypeError, ValueError):
        return None
    return instructions[0] if len(instructions) == 1 else None


def _update_register_constants(
    instruction: object,
    constants: dict[str, int],
) -> bool:
    """callsite引数に必要な、即値由来registerだけを保守的に追跡する。"""

    written = _written_register_families(instruction)
    if written is None:
        return False
    for family in written:
        constants.pop(family, None)

    mnemonic = instruction.mnemonic.casefold()
    operands = instruction.operands
    if not operands or operands[0].type != X86_OP_REG:
        return True
    destination = _register_family(operands[0].reg)
    if destination is None or int(operands[0].size) != 4:
        return True
    if (
        mnemonic == "mov"
        and len(operands) >= 2
        and operands[1].type == X86_OP_IMM
        and int(operands[1].size) == 4
    ):
        constants[destination] = _u32(int(operands[1].imm))
    elif (
        mnemonic == "lea"
        and len(operands) >= 2
        and operands[1].type == X86_OP_MEM
        and int(operands[1].size) == 4
        and operands[1].mem.base == X86_REG_INVALID
        and operands[1].mem.index == X86_REG_INVALID
    ):
        constants[destination] = _u32(int(operands[1].mem.disp))
    elif (
        mnemonic == "xor"
        and len(operands) >= 2
        and operands[1].type == X86_OP_REG
        and int(operands[1].size) == 4
        and int(operands[1].reg) == int(operands[0].reg)
    ):
        constants[destination] = 0
    return True


def _push_value(
    instruction: object,
    constants: dict[str, int],
    candidate_address: int,
) -> _PushedValue | None:
    if instruction.mnemonic.casefold() != "push" or not instruction.operands:
        return None
    operand = instruction.operands[0]
    if int(operand.size) != 4:
        return _PushedValue(None, None)
    if operand.type == X86_OP_IMM:
        address = _u32(int(operand.imm))
        return _PushedValue(
            address=address,
            register_family=None,
            source=address == candidate_address,
        )
    if operand.type != X86_OP_REG:
        return _PushedValue(None, None)
    family = _register_family(operand.reg)
    address = constants.get(family) if family is not None else None
    return _PushedValue(
        address=address,
        register_family=family,
        source=address == candidate_address,
    )


def _direct_file_backed_call_target(
    instruction: object,
    sections: tuple[_MappedSection, ...],
) -> int | None:
    if not instruction.group(CS_GRP_CALL) or not instruction.operands:
        return None
    operand = instruction.operands[0]
    if operand.type != X86_OP_IMM:
        return None
    target = _u32(int(operand.imm))
    return target if _file_backed_executable(sections, target) else None


def _bounded_linear_window(
    data: bytes,
    sections: tuple[_MappedSection, ...],
    start: int,
    disassembler: Cs,
    *,
    max_bytes: int,
    max_instructions: int,
) -> tuple[tuple[object, ...], bool]:
    """一つのlinear basic-block prefixだけを命令境界どおりに復号する。"""

    section = _section_at(sections, start, file_backed=True)
    if section is None or not section.characteristics & _EXECUTABLE:
        return (), False
    address = start
    instructions: list[object] = []
    while len(instructions) < max_instructions and address - start < max_bytes:
        if not section.address <= address < section.file_backed_end:
            return tuple(instructions), False
        offset = section.raw_start + address - section.address
        available = min(
            section.raw_end, offset + 15, offset + max_bytes - (address - start)
        )
        if available <= offset:
            return tuple(instructions), False
        instruction = _decode_one_x86(disassembler, data[offset:available], address)
        if (
            instruction is None
            or instruction.address != address
            or instruction.size <= 0
        ):
            return tuple(instructions), False
        instructions.append(instruction)
        address += int(instruction.size)
        if instruction.group(CS_GRP_RET) or instruction.group(CS_GRP_JUMP):
            return tuple(instructions), True
    return tuple(instructions), False


def _root_literal_value(
    value: int,
    image_base: int,
    sections: tuple[_MappedSection, ...],
) -> _RootAddressValue | None:
    """即値をwrapせず、既知のimage／file-backed section baseだけをanchor化する。"""

    if not 0 <= value <= 0xFFFFFFFF:
        return None
    anchored = value == image_base or any(
        section.address == value and section.file_backed_end > section.address
        for section in sections
    )
    return _RootAddressValue(
        value=value,
        address_coefficient=int(anchored),
        derived=False,
    )


def _root_register_value(
    operand: object,
    values: dict[str, _RootAddressValue],
) -> _RootAddressValue | None:
    if operand.type != X86_OP_REG or int(operand.size) != 4:
        return None
    family = _register_family(operand.reg)
    return values.get(family) if family is not None else None


def _checked_root_arithmetic(
    left: _RootAddressValue,
    right_value: int,
    right_coefficient: int,
    *,
    subtract: bool,
) -> _RootAddressValue | None:
    """32-bit wrapと複数baseを拒否してaffine演算する。"""

    value = left.value - right_value if subtract else left.value + right_value
    coefficient = (
        left.address_coefficient - right_coefficient
        if subtract
        else left.address_coefficient + right_coefficient
    )
    if not 0 <= value <= 0xFFFFFFFF or coefficient not in {0, 1}:
        return None
    return _RootAddressValue(
        value=value,
        address_coefficient=coefficient,
        derived=True,
    )


def _signed_operand_immediate(operand: object) -> int | None:
    """非負のx86算術deltaだけを返し、wrap表現を証拠化しない。"""

    try:
        size = int(operand.size)
        value = int(operand.imm)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if size not in {1, 2, 4}:
        return None
    bits = size * 8
    mask = (1 << bits) - 1
    if not -(1 << (bits - 1)) <= value <= mask:
        return None
    normalized = value & mask
    sign = 1 << (bits - 1)
    return None if normalized & sign else normalized


def _root_lea_value(
    operand: object,
    values: dict[str, _RootAddressValue],
    image_base: int,
    sections: tuple[_MappedSection, ...],
) -> _RootAddressValue | None:
    """absolute baseまたは既知registerだけから32-bit LEA結果を求める。"""

    if operand.type != X86_OP_MEM or int(operand.size) != 4:
        return None
    memory = operand.mem
    if memory.segment != X86_REG_INVALID:
        return None
    if memory.base == X86_REG_INVALID and memory.index == X86_REG_INVALID:
        return _root_literal_value(_u32(int(memory.disp)), image_base, sections)

    value = 0
    coefficient = 0
    if memory.base != X86_REG_INVALID:
        family = _register_family(memory.base)
        base = values.get(family) if family is not None else None
        if base is None:
            return None
        value += base.value
        coefficient += base.address_coefficient
    if memory.index != X86_REG_INVALID:
        family = _register_family(memory.index)
        index = values.get(family) if family is not None else None
        try:
            scale = int(memory.scale)
        except (TypeError, ValueError, OverflowError):
            return None
        if index is None or scale not in {1, 2, 4, 8}:
            return None
        value += index.value * scale
        coefficient += index.address_coefficient * scale
    try:
        displacement = int(memory.disp)
    except (TypeError, ValueError, OverflowError):
        return None
    if displacement > 0x7FFFFFFF:
        displacement -= 0x1_0000_0000
    value += displacement
    if not 0 <= value <= 0xFFFFFFFF or coefficient not in {0, 1}:
        return None
    return _RootAddressValue(
        value=value,
        address_coefficient=coefficient,
        derived=True,
    )


def _update_root_address_values(
    instruction: object,
    values: dict[str, _RootAddressValue],
    image_base: int,
    sections: tuple[_MappedSection, ...],
) -> bool:
    """root-localな32-bit register値だけを保守的に更新する。"""

    written = _written_register_families(instruction)
    if written is None:
        return False
    previous = dict(values)
    for family in written:
        values.pop(family, None)
    try:
        mnemonic = instruction.mnemonic.casefold()
        operands = tuple(instruction.operands)
    except (AttributeError, CsError, TypeError, ValueError):
        return False
    if (
        not operands
        or operands[0].type != X86_OP_REG
        or int(operands[0].size) != 4
    ):
        return True
    destination = _register_family(operands[0].reg)
    if destination is None:
        return True

    value: _RootAddressValue | None = None
    if mnemonic == "mov" and len(operands) >= 2:
        source = operands[1]
        if source.type == X86_OP_IMM:
            value = _root_literal_value(
                _u32(int(source.imm)),
                image_base,
                sections,
            )
        else:
            value = _root_register_value(source, previous)
    elif mnemonic == "lea" and len(operands) >= 2:
        value = _root_lea_value(
            operands[1],
            previous,
            image_base,
            sections,
        )
    elif (
        mnemonic == "xor"
        and len(operands) >= 2
        and operands[1].type == X86_OP_REG
        and int(operands[1].size) == 4
        and _register_family(operands[1].reg) == destination
    ):
        value = _RootAddressValue(0, 0, False)
    elif mnemonic in {"add", "sub"} and len(operands) >= 2:
        left = previous.get(destination)
        source = operands[1]
        if left is not None and source.type == X86_OP_IMM:
            immediate = _signed_operand_immediate(source)
            if immediate is not None:
                value = _checked_root_arithmetic(
                    left,
                    immediate,
                    0,
                    subtract=mnemonic == "sub",
                )
        elif left is not None:
            right = _root_register_value(source, previous)
            if right is not None:
                value = _checked_root_arithmetic(
                    left,
                    right.value,
                    right.address_coefficient,
                    subtract=mnemonic == "sub",
                )
    elif mnemonic in {"inc", "dec"}:
        left = previous.get(destination)
        if left is not None:
            value = _checked_root_arithmetic(
                left,
                1,
                0,
                subtract=mnemonic == "dec",
            )
    if value is not None:
        values[destination] = value
    return True


def _root_derived_candidate_push(
    instruction: object,
    values: dict[str, _RootAddressValue],
    candidate_address: int,
) -> bool:
    """由来付きaddressがexact candidate VAとしてpushされる場合だけtrue。"""

    try:
        operands = tuple(instruction.operands)
    except (AttributeError, CsError, TypeError, ValueError):
        return False
    if (
        instruction.mnemonic.casefold() != "push"
        or len(operands) != 1
        or operands[0].type != X86_OP_REG
        or int(operands[0].size) != 4
    ):
        return False
    family = _register_family(operands[0].reg)
    value = values.get(family) if family is not None else None
    return bool(
        value is not None
        and value.address_coefficient == 1
        and value.derived
        and value.value == candidate_address
    )


def _direct_file_backed_jump_target(
    instruction: object,
    sections: tuple[_MappedSection, ...],
) -> int | None:
    if not instruction.group(CS_GRP_JUMP) or not instruction.operands:
        return None
    operand = instruction.operands[0]
    if operand.type != X86_OP_IMM:
        return None
    target = _u32(int(operand.imm))
    return target if _file_backed_executable(sections, target) else None


def _root_address_lineage_scan(
    image: object,
    data: bytes,
    sections: tuple[_MappedSection, ...],
    candidate: OpaqueWideHexCandidate,
    external_roots: tuple[int, ...],
    disassembler: Cs,
) -> _RootAddressLineageScan:
    """検証済みrootの有界direct-call graphでaddress再構成を追跡する。"""

    roots = tuple(dict.fromkeys(external_roots))
    sources: set[tuple[int, int]] = set()
    function_count = 0
    scanned_bytes = 0
    scanned_instructions = 0

    def result(
        *,
        complete: bool,
        truncated: bool,
    ) -> _RootAddressLineageScan:
        return _RootAddressLineageScan(
            source_references=tuple(sorted(sources)),
            analysis_complete=complete,
            truncated=truncated,
            root_count=len(roots),
            function_count=function_count,
            scanned_byte_count=scanned_bytes,
            scanned_instruction_count=scanned_instructions,
        )

    if not roots:
        return result(complete=True, truncated=False)
    try:
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return result(complete=False, truncated=False)
    if not 0 <= image_base <= 0xFFFFFFFF:
        return result(complete=False, truncated=False)
    candidate_section = _section_at(
        sections,
        candidate.address,
        file_backed=True,
    )
    if (
        candidate_section is None
        or not candidate_section.characteristics & _WRITABLE
        or candidate_section.characteristics & _EXECUTABLE
        or candidate.byte_size > candidate_section.file_backed_end - candidate.address
        or any(not _file_backed_executable(sections, root) for root in roots)
    ):
        return result(complete=False, truncated=False)

    def state_key(
        address: int,
        values: dict[str, _RootAddressValue],
    ) -> tuple[int, tuple[tuple[str, _RootAddressValue], ...]]:
        return address, tuple(sorted(values.items()))

    work = [(root, 0, {}) for root in roots]
    work_index = 0
    queued = {state_key(root, {}) for root in roots}
    visited: set[tuple[int, tuple[tuple[str, _RootAddressValue], ...]]] = set()
    analysis_complete = True
    while work_index < len(work):
        entry, depth, initial_values = work[work_index]
        work_index += 1
        current_key = state_key(entry, initial_values)
        if current_key in visited:
            continue
        if function_count >= MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_FUNCTIONS:
            return result(complete=False, truncated=True)
        visited.add(current_key)
        function_count += 1
        instructions, complete = _bounded_linear_window(
            data,
            sections,
            entry,
            disassembler,
            max_bytes=MAX_OPAQUE_WIDE_HEX_CALLSITE_BYTES,
            max_instructions=MAX_OPAQUE_WIDE_HEX_CALLSITE_INSTRUCTIONS,
        )
        try:
            window_bytes = sum(int(item.size) for item in instructions)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return result(complete=False, truncated=False)
        if (
            scanned_bytes > MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_BYTES - window_bytes
            or scanned_instructions
            > MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_INSTRUCTIONS - len(instructions)
        ):
            return result(complete=False, truncated=True)
        scanned_bytes += window_bytes
        scanned_instructions += len(instructions)
        if not complete:
            analysis_complete = False

        values = dict(initial_values)
        pending_pc: int | None = None
        for instruction in instructions:
            try:
                address = int(instruction.address)
                next_address = address + int(instruction.size)
            except (AttributeError, TypeError, ValueError, OverflowError):
                return result(complete=False, truncated=False)
            if pending_pc is not None:
                operands = tuple(instruction.operands)
                if (
                    address == pending_pc
                    and instruction.mnemonic.casefold() == "pop"
                    and len(operands) == 1
                    and operands[0].type == X86_OP_REG
                    and int(operands[0].size) == 4
                ):
                    family = _register_family(operands[0].reg)
                    if family is not None:
                        values[family] = _RootAddressValue(
                            value=pending_pc,
                            address_coefficient=1,
                            derived=False,
                        )
                    pending_pc = None
                    continue
                pending_pc = None

            if _root_derived_candidate_push(
                instruction,
                values,
                candidate.address,
            ):
                sources.add((address, entry))
                if len(sources) > MAX_OPAQUE_WIDE_HEX_REFERENCE_MATCHES:
                    return result(complete=False, truncated=True)

            if instruction.group(CS_GRP_CALL):
                target = _direct_file_backed_call_target(instruction, sections)
                if target == next_address:
                    pending_pc = next_address
                    continue
                values.clear()
                target_key = state_key(target, {}) if target is not None else None
                if target is not None and target_key not in queued:
                    if depth >= MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_DEPTH:
                        return result(complete=False, truncated=True)
                    work.append((target, depth + 1, {}))
                    queued.add(target_key)
                continue
            if instruction.group(CS_GRP_RET):
                break
            if instruction.group(CS_GRP_JUMP):
                target = _direct_file_backed_jump_target(instruction, sections)
                mnemonic = instruction.mnemonic.casefold()
                if target is None:
                    analysis_complete = False
                else:
                    successor_values = dict(values)
                    if mnemonic != "jmp" and mnemonic not in _CONDITIONAL_JUMP_MNEMONICS:
                        # loop系などregisterを暗黙更新する未対応分岐は、両edgeを
                        # 走査してもlineage stateを完全には引き継げない。
                        successor_values.clear()
                        analysis_complete = False
                    target_key = state_key(target, successor_values)
                    if target_key not in queued:
                        work.append((target, depth, successor_values))
                        queued.add(target_key)
                if mnemonic != "jmp":
                    if not _file_backed_executable(sections, next_address):
                        analysis_complete = False
                    else:
                        fallthrough_values = dict(values)
                        if mnemonic not in _CONDITIONAL_JUMP_MNEMONICS:
                            fallthrough_values.clear()
                        fallthrough_key = state_key(next_address, fallthrough_values)
                        if fallthrough_key not in queued:
                            work.append((next_address, depth, fallthrough_values))
                            queued.add(fallthrough_key)
                break
            if instruction.mnemonic.casefold() in {
                "hlt",
                "int",
                "int1",
                "int3",
                "into",
                "iret",
                "iretd",
                "ud2",
            }:
                break
            if not _update_root_address_values(
                instruction,
                values,
                image_base,
                sections,
            ):
                return result(complete=False, truncated=False)
    return result(complete=analysis_complete, truncated=False)


def _preceded_by_function_separator(
    data: bytes,
    section: _MappedSection,
    entry: int,
    disassembler: Cs,
) -> bool:
    if entry == section.address:
        return True
    offset = section.raw_start + entry - section.address
    padding = 0
    while (
        offset > section.raw_start
        and padding < MAX_OPAQUE_WIDE_HEX_ENTRY_PADDING_BYTES
        and data[offset - 1] in {0x90, 0xCC}
    ):
        offset -= 1
        padding += 1
    for size in (1, 3):
        start = offset - size
        if start < section.raw_start:
            continue
        address = section.address + start - section.raw_start
        instruction = _decode_one_x86(disassembler, data[start:offset], address)
        if (
            instruction is not None
            and instruction.address == address
            and instruction.size == size
            and instruction.group(CS_GRP_RET)
        ):
            return True
    return False


def _possible_source_entries(
    data: bytes,
    section: _MappedSection,
    source_instruction: int,
    disassembler: Cs,
) -> set[int]:
    minimum = max(
        section.address, source_instruction - MAX_OPAQUE_WIDE_HEX_ENTRY_BACKTRACK_BYTES
    )
    return {
        entry
        for entry in range(minimum, source_instruction + 1)
        if _preceded_by_function_separator(data, section, entry, disassembler)
    }


def _candidate_literal_reference(
    instruction: object,
    candidate_address: int,
) -> bool:
    """candidate VAを直接生成する限定命令だけをliteral参照とする。"""

    try:
        mnemonic = instruction.mnemonic.casefold()
        operands = tuple(instruction.operands)
    except (AttributeError, CsError, TypeError, ValueError):
        return False
    if not operands:
        return False
    if (
        mnemonic == "push"
        and operands[0].type == X86_OP_IMM
        and _u32(int(operands[0].imm)) == candidate_address
    ):
        return True
    if (
        mnemonic == "mov"
        and len(operands) >= 2
        and operands[0].type == X86_OP_REG
        and operands[1].type == X86_OP_IMM
        and _u32(int(operands[1].imm)) == candidate_address
    ):
        return True
    return bool(
        mnemonic == "lea"
        and len(operands) >= 2
        and operands[0].type == X86_OP_REG
        and operands[1].type == X86_OP_MEM
        and operands[1].mem.base == X86_REG_INVALID
        and operands[1].mem.index == X86_REG_INVALID
        and _u32(int(operands[1].mem.disp)) == candidate_address
    )


def _instruction_reference_scan(
    data: bytes,
    sections: tuple[_MappedSection, ...],
    candidate_address: int,
    disassembler: Cs,
) -> _InstructionReferenceScan:
    """実行sectionを命令境界どおりに走査し、限定参照だけを回収する。"""

    literal_addresses: set[int] = set()
    source_references: dict[int, tuple[_MappedSection, int]] = {}
    direct_call_targets: dict[int, int] = {}
    direct_call_count = 0
    scanned_bytes = 0
    scanned_instructions = 0

    def result(*, complete: bool, truncated: bool) -> _InstructionReferenceScan:
        return _InstructionReferenceScan(
            source_references=tuple(
                source_references[address]
                for address in sorted(source_references)
            ),
            literal_reference_count=len(literal_addresses),
            direct_call_targets=tuple(sorted(direct_call_targets.items())),
            complete=complete,
            truncated=truncated,
            scanned_byte_count=scanned_bytes,
            scanned_instruction_count=scanned_instructions,
        )

    for section in sections:
        if (
            not section.characteristics & _EXECUTABLE
            or section.raw_end <= section.raw_start
        ):
            continue
        constants: dict[str, int] = {}
        expected_address = section.address
        while expected_address < section.file_backed_end:
            if scanned_instructions >= MAX_OPAQUE_WIDE_HEX_REFERENCE_SCAN_INSTRUCTIONS:
                return result(complete=False, truncated=True)
            offset = (
                section.raw_start + expected_address - section.address
            )
            available = min(section.raw_end, offset + 15)
            instruction = _decode_one_x86(
                disassembler,
                data[offset:available],
                expected_address,
            )
            if instruction is None:
                return result(complete=False, truncated=False)
            try:
                address = int(instruction.address)
                size = int(instruction.size)
            except (AttributeError, TypeError, ValueError, OverflowError):
                return result(complete=False, truncated=False)
            if (
                address != expected_address
                or size <= 0
                or size > section.file_backed_end - address
            ):
                return result(complete=False, truncated=False)
            if scanned_bytes > MAX_OPAQUE_WIDE_HEX_REFERENCE_SCAN_BYTES - size:
                return result(complete=False, truncated=True)
            scanned_bytes += size
            scanned_instructions += 1
            expected_address += size

            if _candidate_literal_reference(instruction, candidate_address):
                literal_addresses.add(address)
                if len(literal_addresses) > MAX_OPAQUE_WIDE_HEX_REFERENCE_MATCHES:
                    return result(complete=False, truncated=True)
            pushed = _push_value(instruction, constants, candidate_address)
            if pushed is not None and pushed.source:
                source_references[address] = (section, address)
                if len(source_references) > MAX_OPAQUE_WIDE_HEX_REFERENCE_MATCHES:
                    return result(complete=False, truncated=True)

            try:
                is_call = bool(instruction.group(CS_GRP_CALL))
                is_control_boundary = bool(
                    instruction.group(CS_GRP_RET)
                    or instruction.group(CS_GRP_JUMP)
                )
            except (CsError, TypeError, ValueError):
                return result(complete=False, truncated=False)
            if is_call:
                target = _direct_file_backed_call_target(
                    instruction,
                    sections,
                )
                if target is not None:
                    direct_call_count += 1
                    if direct_call_count > MAX_OPAQUE_WIDE_HEX_DIRECT_CALLS:
                        return result(complete=False, truncated=True)
                    direct_call_targets[target] = (
                        direct_call_targets.get(target, 0) + 1
                    )
            if is_control_boundary or instruction.mnemonic.casefold() in {
                "hlt",
                "int",
                "int1",
                "int3",
                "into",
                "iret",
                "iretd",
                "ud2",
            }:
                constants.clear()
                continue
            if not _update_register_constants(instruction, constants):
                return result(complete=False, truncated=False)
            if is_call:
                for volatile in ("eax", "ecx", "edx"):
                    constants.pop(volatile, None)
    return result(complete=True, truncated=False)


def _candidate_source_index(
    instructions: tuple[object, ...],
    source_instruction: int,
    candidate_address: int,
    *,
    root_derived: bool = False,
) -> int | None:
    """anchored window内で同じ即値lineageがsource pushへ届く位置を返す。"""

    constants: dict[str, int] = {}
    for index, instruction in enumerate(instructions):
        try:
            address = int(instruction.address)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        pushed = _push_value(instruction, constants, candidate_address)
        derived_push = bool(
            root_derived
            and instruction.mnemonic.casefold() == "push"
            and pushed is not None
            and pushed.register_family is not None
        )
        if (
            address == source_instruction
            and pushed is not None
            and (pushed.source or derived_push)
        ):
            return index
        if address >= source_instruction:
            return None
        if instruction.group(CS_GRP_RET) or instruction.group(CS_GRP_JUMP):
            return None
        if not _update_register_constants(instruction, constants):
            return None
        if instruction.group(CS_GRP_CALL):
            for volatile in ("eax", "ecx", "edx"):
                constants.pop(volatile, None)
    return None


def _candidate_literal_encoding_offset(instruction: object) -> int | None:
    """限定literal operandの先頭offsetをCapstone metadataから返す。"""

    try:
        mnemonic = instruction.mnemonic.casefold()
        encoding = instruction.encoding
        if mnemonic == "lea":
            offset = int(encoding.disp_offset)
            size = int(encoding.disp_size)
        else:
            offset = int(encoding.imm_offset)
            size = int(encoding.imm_size)
    except (AttributeError, CsError, TypeError, ValueError, OverflowError):
        return None
    return offset if offset > 0 and size == 4 else None


def _raw_candidate_occurrences(
    data: bytes,
    sections: tuple[_MappedSection, ...],
    candidate_address: int,
) -> tuple[tuple[tuple[_MappedSection, int], ...], int, bool]:
    """実行sectionのLE32 VAをoverlap込みで完全走査する。"""

    try:
        needle = struct.pack("<I", candidate_address)
    except (struct.error, TypeError, ValueError, OverflowError):
        return (), 0, False
    occurrences: list[tuple[_MappedSection, int]] = []
    scanned_bytes = 0
    for section in sections:
        if (
            not section.characteristics & _EXECUTABLE
            or section.raw_end <= section.raw_start
        ):
            continue
        section_size = section.raw_end - section.raw_start
        if scanned_bytes > MAX_OPAQUE_WIDE_HEX_REFERENCE_SCAN_BYTES - section_size:
            return tuple(occurrences), scanned_bytes, False
        scanned_bytes += section_size
        cursor = section.raw_start
        while cursor <= section.raw_end - len(needle):
            offset = data.find(needle, cursor, section.raw_end)
            if offset < 0:
                break
            occurrences.append((section, offset))
            if len(occurrences) > MAX_OPAQUE_WIDE_HEX_REFERENCE_MATCHES:
                return tuple(occurrences), scanned_bytes, False
            cursor = offset + 1
    return tuple(occurrences), scanned_bytes, True


def _local_candidate_literal_instructions(
    data: bytes,
    occurrence: tuple[_MappedSection, int],
    candidate_address: int,
    disassembler: Cs,
) -> tuple[object, ...]:
    """raw位置を実operand spanに持つ一意なx86命令start候補を返す。"""

    section, raw_offset = occurrence
    instructions: dict[int, object] = {}
    minimum = max(section.raw_start, raw_offset - 14)
    for start in range(minimum, raw_offset + 1):
        address = section.address + start - section.raw_start
        available = min(section.raw_end, start + 15)
        instruction = _decode_one_x86(
            disassembler,
            data[start:available],
            address,
        )
        if (
            instruction is None
            or not _candidate_literal_reference(
                instruction,
                candidate_address,
            )
        ):
            continue
        encoding_offset = _candidate_literal_encoding_offset(instruction)
        if (
            encoding_offset is None
            or start + encoding_offset != raw_offset
            or int(instruction.size) < encoding_offset + 4
        ):
            continue
        instruction_address = int(instruction.address)
        if instruction_address not in instructions:
            instructions[instruction_address] = instruction
    return tuple(instructions[address] for address in sorted(instructions))


def _local_source_from_entry(
    data: bytes,
    sections: tuple[_MappedSection, ...],
    entry: int,
    literal_instruction: int,
    candidate_address: int,
    disassembler: Cs,
) -> tuple[int | None, int, int]:
    """direct-call targetからliteralと唯一source pushまでをlinear検証する。"""

    instructions, complete = _bounded_linear_window(
        data,
        sections,
        entry,
        disassembler,
        max_bytes=MAX_OPAQUE_WIDE_HEX_CALLSITE_BYTES,
        max_instructions=MAX_OPAQUE_WIDE_HEX_CALLSITE_INSTRUCTIONS,
    )
    try:
        scanned_bytes = sum(int(item.size) for item in instructions)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None, 0, 0
    if not complete:
        return None, scanned_bytes, len(instructions)

    constants: dict[str, int] = {}
    literal_seen = False
    sources: list[int] = []
    for instruction in instructions:
        try:
            address = int(instruction.address)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None, scanned_bytes, len(instructions)
        if address == literal_instruction:
            if not _candidate_literal_reference(
                instruction,
                candidate_address,
            ):
                return None, scanned_bytes, len(instructions)
            literal_seen = True
        pushed = _push_value(instruction, constants, candidate_address)
        if literal_seen and pushed is not None and pushed.source:
            sources.append(address)
            if len(sources) > 1:
                return None, scanned_bytes, len(instructions)
        if instruction.group(CS_GRP_RET) or instruction.group(CS_GRP_JUMP):
            break
        if instruction.mnemonic.casefold() in {
            "hlt",
            "int",
            "int1",
            "int3",
            "into",
            "iret",
            "iretd",
            "ud2",
        }:
            break
        if not _update_register_constants(instruction, constants):
            return None, scanned_bytes, len(instructions)
        if instruction.group(CS_GRP_CALL):
            for volatile in ("eax", "ecx", "edx"):
                constants.pop(volatile, None)
    source = sources[0] if literal_seen and len(sources) == 1 else None
    return source, scanned_bytes, len(instructions)


def _local_direct_caller_path_count(
    data: bytes,
    sections: tuple[_MappedSection, ...],
    section: _MappedSection,
    callsite: int,
    target: int,
    disassembler: Cs,
) -> tuple[int, int, int]:
    """separator由来のlinear path上に同じdirect callがあるentry数を返す。"""

    entries = _possible_source_entries(data, section, callsite, disassembler)
    matches = 0
    scanned_bytes = 0
    scanned_instructions = 0
    for entry in sorted(entries):
        instructions, complete = _bounded_linear_window(
            data,
            sections,
            entry,
            disassembler,
            max_bytes=MAX_OPAQUE_WIDE_HEX_CALLSITE_BYTES,
            max_instructions=MAX_OPAQUE_WIDE_HEX_CALLSITE_INSTRUCTIONS,
        )
        try:
            scanned_bytes += sum(int(item.size) for item in instructions)
        except (AttributeError, TypeError, ValueError, OverflowError):
            continue
        scanned_instructions += len(instructions)
        if not complete:
            continue
        if any(
            int(instruction.address) == callsite
            and _direct_file_backed_call_target(instruction, sections) == target
            for instruction in instructions
        ):
            matches += 1
    return matches, scanned_bytes, scanned_instructions


def _local_reference_resynchronization(
    data: bytes,
    sections: tuple[_MappedSection, ...],
    candidate_address: int,
    disassembler: Cs,
) -> _InstructionReferenceScan:
    """global decode失敗時だけ、raw一意性から局所命令境界を再同期する。"""

    occurrences, scanned_bytes, raw_complete = _raw_candidate_occurrences(
        data,
        sections,
        candidate_address,
    )
    raw_count = len(occurrences)

    def result(
        *,
        complete: bool,
        truncated: bool,
        literal_starts: int = 0,
        caller_count: int = 0,
        scanned_instructions: int = 0,
        local_scanned_bytes: int = 0,
        source: tuple[_MappedSection, int, int] | None = None,
    ) -> _InstructionReferenceScan:
        if source is None:
            source_references: tuple[tuple[_MappedSection, int], ...] = ()
            direct_targets: tuple[tuple[int, int], ...] = ()
            source_entries: tuple[tuple[int, int], ...] = ()
        else:
            section, source_instruction, entry = source
            source_references = ((section, source_instruction),)
            direct_targets = ((entry, 1),)
            source_entries = ((source_instruction, entry),)
        return _InstructionReferenceScan(
            source_references=source_references,
            literal_reference_count=raw_count,
            direct_call_targets=direct_targets,
            complete=complete,
            truncated=truncated,
            scanned_byte_count=scanned_bytes + local_scanned_bytes,
            scanned_instruction_count=scanned_instructions,
            mode="raw_unique_local_resynchronization",
            raw_candidate_occurrence_count=raw_count,
            local_literal_instruction_start_count=literal_starts,
            local_direct_caller_count=caller_count,
            local_scanned_byte_count=local_scanned_bytes,
            local_source_entries=source_entries,
        )

    if not raw_complete:
        return result(complete=False, truncated=True)
    if raw_count != 1:
        return result(complete=True, truncated=False)
    literal_instructions = _local_candidate_literal_instructions(
        data,
        occurrences[0],
        candidate_address,
        disassembler,
    )
    literal_start_count = len(literal_instructions)
    if literal_start_count != 1:
        return result(
            complete=True,
            truncated=False,
            literal_starts=literal_start_count,
        )
    literal = literal_instructions[0]
    literal_address = int(literal.address)
    literal_section = occurrences[0][0]

    # E8列挙は上で会計済みの同じfile-backed raw範囲を再走査し、
    # 新しいbyte範囲へは広げない。命令windowだけをlocal_bytesへ加算する。
    plausible_calls: list[tuple[_MappedSection, int, int]] = []
    for section in sections:
        if (
            not section.characteristics & _EXECUTABLE
            or section.raw_end - section.raw_start < 5
        ):
            continue
        for raw_offset in range(section.raw_start, section.raw_end - 4):
            if data[raw_offset] != 0xE8:
                continue
            displacement = struct.unpack_from("<i", data, raw_offset + 1)[0]
            callsite = section.address + raw_offset - section.raw_start
            target = callsite + 5 + displacement
            if (
                not 0 <= target <= 0xFFFFFFFF
                or _section_at(sections, target, file_backed=True)
                is not literal_section
                or not 0 <= literal_address - target
                < MAX_OPAQUE_WIDE_HEX_CALLSITE_BYTES
            ):
                continue
            instruction = _decode_one_x86(
                disassembler,
                data[raw_offset : min(section.raw_end, raw_offset + 15)],
                callsite,
            )
            if (
                instruction is None
                or int(instruction.size) != 5
                or _direct_file_backed_call_target(instruction, sections)
                != target
            ):
                continue
            plausible_calls.append((section, callsite, target))
            if (
                len(plausible_calls)
                > MAX_OPAQUE_WIDE_HEX_LOCAL_CALLER_CANDIDATES
            ):
                return result(
                    complete=False,
                    truncated=True,
                    literal_starts=literal_start_count,
                )

    local_bytes = 0
    local_instructions = literal_start_count
    source_cache: dict[int, tuple[int | None, int, int]] = {}
    matches: list[tuple[_MappedSection, int, int]] = []
    for caller_section, callsite, target in plausible_calls:
        cached = source_cache.get(target)
        if cached is None:
            cached = _local_source_from_entry(
                data,
                sections,
                target,
                literal_address,
                candidate_address,
                disassembler,
            )
            source_cache[target] = cached
            local_bytes += cached[1]
            local_instructions += cached[2]
        if (
            local_bytes > MAX_OPAQUE_WIDE_HEX_LOCAL_SCAN_BYTES
            or local_instructions
            > MAX_OPAQUE_WIDE_HEX_LOCAL_SCAN_INSTRUCTIONS
        ):
            return result(
                complete=False,
                truncated=True,
                literal_starts=literal_start_count,
                scanned_instructions=local_instructions,
                local_scanned_bytes=local_bytes,
            )
        source_instruction = cached[0]
        if source_instruction is None:
            continue
        caller_paths, caller_bytes, caller_instructions = (
            _local_direct_caller_path_count(
                data,
                sections,
                caller_section,
                callsite,
                target,
                disassembler,
            )
        )
        local_bytes += caller_bytes
        local_instructions += caller_instructions
        if (
            local_bytes > MAX_OPAQUE_WIDE_HEX_LOCAL_SCAN_BYTES
            or local_instructions
            > MAX_OPAQUE_WIDE_HEX_LOCAL_SCAN_INSTRUCTIONS
        ):
            return result(
                complete=False,
                truncated=True,
                literal_starts=literal_start_count,
                scanned_instructions=local_instructions,
                local_scanned_bytes=local_bytes,
            )
        if caller_paths == 1:
            matches.append((literal_section, source_instruction, target))
            if len(matches) > MAX_OPAQUE_WIDE_HEX_REFERENCE_MATCHES:
                return result(
                    complete=False,
                    truncated=True,
                    literal_starts=literal_start_count,
                    caller_count=len(matches),
                    scanned_instructions=local_instructions,
                    local_scanned_bytes=local_bytes,
                )

    if len(matches) != 1:
        return result(
            complete=True,
            truncated=False,
            literal_starts=literal_start_count,
            caller_count=len(matches),
            scanned_instructions=local_instructions,
            local_scanned_bytes=local_bytes,
        )
    return result(
        complete=True,
        truncated=False,
        literal_starts=literal_start_count,
        caller_count=1,
        scanned_instructions=local_instructions,
        local_scanned_bytes=local_bytes,
        source=matches[0],
    )


def _stack_cleanup_matches(
    instruction: object,
    argument_count: int,
) -> bool:
    operands = instruction.operands
    return bool(
        instruction.mnemonic.casefold() == "add"
        and len(operands) >= 2
        and operands[0].type == X86_OP_REG
        and _register_family(operands[0].reg) == "esp"
        and operands[1].type == X86_OP_IMM
        and int(operands[1].imm) == argument_count * 4
    )


def _valid_transform_object(value: _TransformObject) -> bool:
    return bool(
        type(value.origin) is int
        and type(value.extent) is int
        and 0 <= value.origin <= 0xFFFFFFFF
        and 0 < value.extent <= MAX_INPUT_SIZE
        and value.origin + value.extent <= 0x1_0000_0000
    )


def _low_byte_register_family(operand: object) -> str | None:
    try:
        if (
            operand.type != X86_OP_REG
            or int(operand.size) != 1
            or int(operand.reg) not in _LOW_BYTE_REGISTERS
        ):
            return None
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    return _register_family(operand.reg)


def _effective_byte_transform_kind(
    mnemonic: str,
    operands: tuple[object, ...],
) -> bool:
    """静的にidentityと分かるbyte演算をtransform kindへ数えない。"""

    if mnemonic not in _BYTE_TRANSFORM_MNEMONICS:
        return False
    if len(operands) < 2 or operands[1].type != X86_OP_IMM:
        return True
    try:
        immediate = int(operands[1].imm) & 0xFF
    except (AttributeError, TypeError, ValueError, OverflowError):
        return False
    if mnemonic in {"add", "sub", "xor"}:
        return immediate != 0
    return immediate % 8 != 0


def _transform_pointer_for_absolute(
    value: int,
    objects: dict[str, _TransformObject],
) -> _TransformPointer | None:
    if not 0 <= value <= 0xFFFFFFFF:
        return None
    matches = [
        _TransformPointer(name, value - item.origin)
        for name, item in objects.items()
        if item.origin <= value < item.origin + item.extent
    ]
    return matches[0] if len(matches) == 1 else None


def _shift_transform_pointer(
    pointer: _TransformPointer,
    delta: int,
    objects: dict[str, _TransformObject],
) -> _TransformPointer | None:
    item = objects.get(pointer.object_name)
    if item is None:
        return None
    offset = pointer.offset + delta
    absolute = item.origin + offset
    if (
        not 0 <= absolute <= 0xFFFFFFFF
        or not 0 <= offset <= item.extent
    ):
        return None
    return _TransformPointer(pointer.object_name, offset)


def _transform_memory_pointer(
    operand: object,
    pointers: dict[str, _TransformPointer],
    objects: dict[str, _TransformObject],
) -> tuple[_TransformPointer | None, bool]:
    """memory operandをobject相対へ解決し、関連する未知aliasを併記する。"""

    if operand.type != X86_OP_MEM:
        return None, False
    memory = operand.mem
    base_family = _register_family(memory.base)
    index_family = _register_family(memory.index)
    relevant = bool(
        (base_family is not None and base_family in pointers)
        or (index_family is not None and index_family in pointers)
    )
    if memory.segment != X86_REG_INVALID:
        return None, relevant
    if memory.index != X86_REG_INVALID:
        return None, relevant
    if memory.base == X86_REG_INVALID:
        value = int(memory.disp)
        if not 0 <= value <= 0xFFFFFFFF:
            return None, False
        return _transform_pointer_for_absolute(value, objects), False
    if base_family is None:
        return None, False
    base = pointers.get(base_family)
    if base is None:
        return None, False
    shifted = _shift_transform_pointer(base, int(memory.disp), objects)
    return shifted, shifted is None


def _transform_access_in_bounds(
    pointer: _TransformPointer | None,
    size: int,
    objects: dict[str, _TransformObject],
    sections: tuple[_MappedSection, ...],
) -> bool:
    if pointer is None or size <= 0:
        return False
    item = objects.get(pointer.object_name)
    if item is None or not 0 <= pointer.offset <= item.extent - size:
        return False
    address = item.origin + pointer.offset
    file_backed = pointer.object_name == "source"
    section = _section_at(sections, item.origin, file_backed=file_backed)
    end = section.file_backed_end if file_backed and section is not None else (
        section.mapped_end if section is not None else 0
    )
    return bool(section is not None and address + size <= end)


def _transform_semantics(
    data: bytes,
    sections: tuple[_MappedSection, ...],
    target: int,
    source_object: _TransformObject,
    destination_object: _TransformObject,
    source_family: str | None,
    destination_family: str,
    disassembler: Cs,
) -> _TransformSemantics:
    empty = _TransformSemantics(
        operation_kinds=(),
        byte_memory_read=False,
        destination_memory_write=False,
        window_complete=False,
    )
    if (
        not _valid_transform_object(source_object)
        or not _valid_transform_object(destination_object)
        or destination_family not in {"ebx", "ebp", "edi", "esi"}
    ):
        return empty
    source_end = source_object.origin + source_object.extent
    destination_end = destination_object.origin + destination_object.extent
    source_section = _section_at(
        sections,
        source_object.origin,
        file_backed=True,
    )
    destination_section = _section_at(
        sections,
        destination_object.origin,
    )
    if (
        source_section is None
        or source_end > source_section.file_backed_end
        or destination_section is None
        or destination_end > destination_section.mapped_end
        or not destination_section.characteristics & _WRITABLE
        or destination_section.characteristics & _EXECUTABLE
        or (
            source_family is not None
            and source_family
            not in {"eax", "ebx", "ecx", "edx", "ebp", "edi", "esi"}
        )
        or (
            source_object.origin < destination_end
            and destination_object.origin < source_end
        )
    ):
        return empty

    instructions, complete = _bounded_linear_window(
        data,
        sections,
        target,
        disassembler,
        max_bytes=MAX_OPAQUE_WIDE_HEX_TRANSFORM_BYTES,
        max_instructions=MAX_OPAQUE_WIDE_HEX_TRANSFORM_INSTRUCTIONS,
    )
    objects = {
        "source": source_object,
        "destination": destination_object,
    }
    pointers = {
        destination_family: _TransformPointer("destination", 0),
    }
    if (
        source_family in {"ebx", "ebp", "edi", "esi"}
        and source_family != destination_family
    ):
        pointers[source_family] = _TransformPointer("source", 0)
    byte_taints: dict[str, frozenset[str]] = {}
    qualifying_operations: set[str] = set()
    byte_memory_read = False
    destination_memory_write = False
    provenance_complete = complete

    for instruction in instructions:
        if instruction.group(CS_GRP_CALL):
            provenance_complete = False
            break
        mnemonic = instruction.mnemonic.casefold()
        operands = instruction.operands
        try:
            operand_details = tuple(
                (int(operand.size), int(operand.access)) for operand in operands
            )
        except (AttributeError, TypeError, ValueError, OverflowError):
            provenance_complete = False
            break

        memory_pointers: dict[int, _TransformPointer | None] = {}
        for index, operand in enumerate(operands):
            if operand.type != X86_OP_MEM:
                continue
            pointer, unresolved = _transform_memory_pointer(
                operand,
                pointers,
                objects,
            )
            if unresolved:
                provenance_complete = False
                break
            memory_pointers[index] = pointer
            operand_size, access = operand_details[index]
            if (
                pointer is not None
                and access & (CS_AC_READ | CS_AC_WRITE)
                and not _transform_access_in_bounds(
                    pointer,
                    operand_size,
                    objects,
                    sections,
                )
            ):
                provenance_complete = False
                break
            if (
                operand_size == 1
                and access & CS_AC_READ
                and pointer is not None
                and pointer.object_name in {"source", "destination"}
                and _transform_access_in_bounds(
                    pointer,
                    operand_size,
                    objects,
                    sections,
                )
            ):
                byte_memory_read = True
        if not provenance_complete:
            break

        for index, operand in enumerate(operands):
            operand_size, access = operand_details[index]
            if (
                operand.type != X86_OP_MEM
                or operand_size != 1
                or not access & CS_AC_WRITE
            ):
                continue
            pointer = memory_pointers.get(index)
            if (
                pointer is None
                or pointer.object_name != "destination"
                or not _transform_access_in_bounds(
                    pointer,
                    operand_size,
                    objects,
                    sections,
                )
            ):
                continue
            if (
                mnemonic != "mov"
                or index != 0
                or len(operands) < 2
                or (
                    source_taint_family := _low_byte_register_family(
                        operands[1]
                    )
                )
                not in byte_taints
            ):
                continue
            store_operations = set(byte_taints[source_taint_family])
            if (
                len(store_operations)
                >= MIN_OPAQUE_WIDE_HEX_TRANSFORM_KINDS
            ):
                qualifying_operations.update(store_operations)
                destination_memory_write = True

        written = _written_register_families(instruction)
        if written is None:
            provenance_complete = False
            break

        taint_handled: set[str] = set()
        if operands and operands[0].type == X86_OP_REG:
            destination = operands[0]
            family = _register_family(destination.reg)
            if family is not None:
                destination_size = int(destination.size)
                if (
                    mnemonic in _BYTE_TRANSFORM_MNEMONICS
                    and _low_byte_register_family(destination) is not None
                ):
                    same_register_zero = bool(
                        mnemonic in {"sub", "xor"}
                        and len(operands) >= 2
                        and operands[1].type == X86_OP_REG
                        and int(operands[1].reg) == int(destination.reg)
                    )
                    taint_inputs = []
                    if not same_register_zero and family in byte_taints:
                        taint_inputs.append(byte_taints[family])
                    if not same_register_zero and mnemonic not in {"rol", "ror"}:
                        taint_inputs.extend(
                            byte_taints[taint_family]
                            for source in operands[1:]
                            if (
                                taint_family := _low_byte_register_family(
                                    source
                                )
                            )
                            in byte_taints
                        )
                        taint_inputs.extend(
                            frozenset()
                            for index, source in enumerate(operands[1:], start=1)
                            if source.type == X86_OP_MEM
                            and operand_details[index][0] == 1
                            and operand_details[index][1] & CS_AC_READ
                            and (
                                pointer := memory_pointers.get(index)
                            )
                            is not None
                            and pointer.object_name
                            in {"source", "destination"}
                            and _transform_access_in_bounds(
                                pointer,
                                1,
                                objects,
                                sections,
                            )
                        )
                    if taint_inputs:
                        operations = {
                            operation
                            for taint_input in taint_inputs
                            for operation in taint_input
                        }
                        if _effective_byte_transform_kind(mnemonic, operands):
                            operations.add(mnemonic)
                        byte_taints[family] = frozenset(operations)
                    else:
                        byte_taints.pop(family, None)
                    taint_handled.add(family)
                elif (
                    mnemonic == "mov"
                    and _low_byte_register_family(destination) is not None
                ) or (
                    mnemonic in {"movsx", "movzx"}
                    and destination_size == 4
                ):
                    taint: frozenset[str] | None = None
                    if len(operands) >= 2:
                        source = operands[1]
                        source_register_family = _low_byte_register_family(source)
                        if source_register_family is not None:
                            taint = byte_taints.get(source_register_family)
                        elif (
                            source.type == X86_OP_MEM
                            and operand_details[1][0] == 1
                            and operand_details[1][1] & CS_AC_READ
                        ):
                            pointer = memory_pointers.get(1)
                            if (
                                pointer is not None
                                and pointer.object_name
                                in {"source", "destination"}
                                and _transform_access_in_bounds(
                                    pointer,
                                    1,
                                    objects,
                                    sections,
                                )
                            ):
                                taint = frozenset()
                    if taint is None:
                        byte_taints.pop(family, None)
                    else:
                        byte_taints[family] = taint
                    taint_handled.add(family)
                elif (
                    mnemonic in {"neg", "not"}
                    and _low_byte_register_family(destination) is not None
                    and family in byte_taints
                ):
                    taint_handled.add(family)

        pointer_handled: set[str] = set()
        if operands and operands[0].type == X86_OP_REG:
            destination = operands[0]
            family = _register_family(destination.reg)
            if family is not None and int(destination.size) == 4:
                pointer: _TransformPointer | None = None
                pointer_assignment = False
                if mnemonic == "mov" and len(operands) >= 2:
                    source = operands[1]
                    if source.type == X86_OP_REG:
                        source_register_family = _register_family(source.reg)
                        pointer = pointers.get(source_register_family)
                        pointer_assignment = True
                    elif source.type == X86_OP_IMM:
                        pointer = _transform_pointer_for_absolute(
                            int(source.imm),
                            objects,
                        )
                        pointer_assignment = True
                elif (
                    mnemonic == "lea"
                    and len(operands) >= 2
                    and operands[1].type == X86_OP_MEM
                ):
                    pointer, unresolved = _transform_memory_pointer(
                        operands[1],
                        pointers,
                        objects,
                    )
                    if unresolved:
                        provenance_complete = False
                        break
                    pointer_assignment = True
                elif mnemonic in {"add", "sub"} and len(operands) >= 2:
                    source = operands[1]
                    current = pointers.get(family)
                    if current is not None:
                        if source.type != X86_OP_IMM:
                            provenance_complete = False
                            break
                        immediate = _signed_operand_immediate(source)
                        if immediate is None:
                            provenance_complete = False
                            break
                        delta = immediate if mnemonic == "add" else -immediate
                        pointer = _shift_transform_pointer(
                            current,
                            delta,
                            objects,
                        )
                        if pointer is None:
                            provenance_complete = False
                            break
                        pointer_assignment = True
                elif mnemonic in {"dec", "inc"}:
                    current = pointers.get(family)
                    if current is not None:
                        pointer = _shift_transform_pointer(
                            current,
                            1 if mnemonic == "inc" else -1,
                            objects,
                        )
                        if pointer is None:
                            provenance_complete = False
                            break
                        pointer_assignment = True
                if pointer_assignment:
                    if pointer is None:
                        pointers.pop(family, None)
                    else:
                        pointers[family] = pointer
                    pointer_handled.add(family)

        for family in written:
            if family not in taint_handled:
                destination_operand = operands[0] if operands else None
                if (
                    family in byte_taints
                    and destination_operand is not None
                    and destination_operand.type == X86_OP_REG
                    and _register_family(destination_operand.reg) == family
                    and int(destination_operand.size) in {1, 2}
                ):
                    provenance_complete = False
                    break
                byte_taints.pop(family, None)
            if family not in pointer_handled and family in pointers:
                operands_zero = operands[0] if operands else None
                if (
                    operands_zero is not None
                    and operands_zero.type == X86_OP_REG
                    and _register_family(operands_zero.reg) == family
                    and int(operands_zero.size) != 4
                ):
                    provenance_complete = False
                    break
                pointers.pop(family, None)
        if not provenance_complete:
            break

    return _TransformSemantics(
        operation_kinds=tuple(sorted(qualifying_operations)),
        byte_memory_read=byte_memory_read,
        destination_memory_write=destination_memory_write,
        window_complete=provenance_complete,
    )


def _source_use_chain(
    data: bytes,
    sections: tuple[_MappedSection, ...],
    root: int,
    source_instruction: int,
    candidate_address: int,
    candidate_extent: int,
    instructions: tuple[object, ...],
    disassembler: Cs,
    *,
    root_derived: bool = False,
) -> _SourceUseChain | None:
    constants: dict[str, int] = {}
    pushes: list[_PushedValue] = []
    source_seen = False
    stage_index: int | None = None
    stage_target: int | None = None
    destination: _PushedValue | None = None

    for index, instruction in enumerate(instructions):
        pushed = _push_value(instruction, constants, candidate_address)
        if pushed is not None:
            if (
                root_derived
                and int(instruction.address) == source_instruction
                and pushed.register_family is not None
            ):
                pushed = _PushedValue(
                    address=candidate_address,
                    register_family=pushed.register_family,
                    source=True,
                )
            if len(pushes) >= MAX_OPAQUE_WIDE_HEX_CALL_ARGUMENTS:
                pushes.clear()
                source_seen = False
            else:
                pushes.append(pushed)
                if int(instruction.address) == source_instruction and pushed.source:
                    source_seen = True
        if instruction.group(CS_GRP_CALL):
            if source_seen:
                target = _direct_file_backed_call_target(instruction, sections)
                destinations = [
                    value
                    for value in pushes
                    if not value.source
                    and value.address is not None
                    and _writable_non_executable(sections, value.address)
                ]
                if (
                    target is not None
                    and 2 <= len(pushes) <= MAX_OPAQUE_WIDE_HEX_CALL_ARGUMENTS
                    and sum(value.source for value in pushes) == 1
                    and len(destinations) == 1
                    and destinations[0].register_family
                    in {"ebx", "ebp", "edi", "esi"}
                    and constants.get(destinations[0].register_family)
                    == destinations[0].address
                ):
                    stage_index = index
                    stage_target = target
                    destination = destinations[0]
                break
            pushes.clear()
            for volatile in ("eax", "ecx", "edx"):
                constants.pop(volatile, None)
        if instruction.group(CS_GRP_RET) or instruction.group(CS_GRP_JUMP):
            break
        if not _update_register_constants(instruction, constants):
            return None

    if stage_index is None or stage_target is None or destination is None:
        return None
    cleanup_index = stage_index + 1
    if cleanup_index >= len(instructions) or not _stack_cleanup_matches(
        instructions[cleanup_index], len(pushes)
    ):
        return None

    destination_family = destination.register_family
    assert destination_family is not None
    source_family = next(
        value.register_family for value in pushes if value.source
    )
    if (
        source_family not in {"ebx", "ebp", "edi", "esi"}
        or constants.get(source_family) != candidate_address
    ):
        source_family = None
    stop = min(
        len(instructions),
        cleanup_index + 1 + MAX_OPAQUE_WIDE_HEX_POST_STAGE_INSTRUCTIONS,
    )
    for instruction in instructions[cleanup_index + 1 : stop]:
        if instruction.group(CS_GRP_RET) or instruction.group(CS_GRP_JUMP):
            return None
        if instruction.group(CS_GRP_CALL):
            transform_target = _direct_file_backed_call_target(instruction, sections)
            if transform_target is None:
                return None
            semantics = _transform_semantics(
                data,
                sections,
                transform_target,
                _TransformObject(candidate_address, candidate_extent),
                _TransformObject(
                    int(destination.address),
                    candidate_extent,
                ),
                source_family,
                destination_family,
                disassembler,
            )
            return _SourceUseChain(
                root=root,
                source_instruction=source_instruction,
                staging_target=stage_target,
                transform_target=transform_target,
                semantics=semantics,
            )
        written = _written_register_families(instruction)
        if written is None or destination_family in written:
            return None
        if source_family in written:
            source_family = None
    return None


def _resource_memory_key(
    operand: object,
    registers: dict[str, _ResourceRuntimeValue],
) -> tuple[str, int] | None:
    """明示的なabsolute／EBP frame slotだけを局所memoryとして扱う。"""

    if operand.type != X86_OP_MEM or operand.mem.index != X86_REG_INVALID:
        return None
    base = _register_family(operand.mem.base)
    displacement = int(operand.mem.disp)
    if operand.mem.base == X86_REG_INVALID:
        if not -(1 << 31) <= displacement <= 0xFFFFFFFF:
            return None
        return ("absolute", _u32(displacement))
    if base == "ebp":
        return ("ebp", displacement)
    value = registers.get(base) if base is not None else None
    if value is not None and value.constant is not None:
        absolute = value.constant + displacement
        if 0 <= absolute <= 0xFFFFFFFF:
            return ("absolute", absolute)
    return None


def _resource_operand_value(
    operand: object,
    registers: dict[str, _ResourceRuntimeValue],
    memory: dict[tuple[str, int], _ResourceRuntimeValue],
) -> _ResourceRuntimeValue:
    if operand.type == X86_OP_IMM:
        return _ResourceRuntimeValue(constant=_u32(int(operand.imm)))
    if operand.type == X86_OP_REG:
        if int(operand.size) != 4:
            return _ResourceRuntimeValue()
        family = _register_family(operand.reg)
        return registers.get(family, _ResourceRuntimeValue())
    if operand.type != X86_OP_MEM or int(operand.size) != 4:
        return _ResourceRuntimeValue()
    key = _resource_memory_key(operand, registers)
    return memory.get(key, _ResourceRuntimeValue()) if key is not None else _ResourceRuntimeValue()


def _resource_overlapping_memory_cells(
    memory: dict[tuple[str, int], _ResourceRuntimeValue],
    key: tuple[str, int],
    size: int,
) -> tuple[tuple[str, int], ...]:
    if size <= 0:
        return tuple(memory)
    namespace, start = key
    end = start + size
    return tuple(
        stored
        for stored in memory
        if stored[0] == namespace
        and start < stored[1] + 4
        and stored[1] < end
    )


def _read_resource_identifier(
    data: bytes,
    sections: tuple[_MappedSection, ...],
    address: int,
    *,
    wide: bool,
) -> str | None:
    section = _section_at(sections, address, file_backed=True)
    if section is None:
        return None
    offset = section.raw_start + address - section.address
    unit = 2 if wide else 1
    limit = min(
        section.raw_end,
        offset + (MAX_RESOURCE_IDENTIFIER_CHARACTERS + 1) * unit,
    )
    cursor = offset
    while cursor + unit <= limit:
        if data[cursor : cursor + unit] == b"\0" * unit:
            raw = data[offset:cursor]
            if not raw:
                return None
            try:
                return raw.decode("utf-16le" if wide else "ascii", errors="strict")
            except UnicodeError:
                return None
        cursor += unit
    return None


def _resource_identifier_matches(
    value: _ResourceRuntimeValue,
    expected_id: int | None,
    expected_name: str | None,
    data: bytes,
    sections: tuple[_MappedSection, ...],
    *,
    wide: bool,
) -> bool:
    if value.tags or value.constant is None:
        return False
    if expected_id is not None:
        return value.constant == expected_id
    return bool(
        expected_name is not None
        and _read_resource_identifier(
            data,
            sections,
            value.constant,
            wide=wide,
        )
        == expected_name
    )


def _resource_find_matches(
    api_name: str,
    pushes: list[_ResourceRuntimePush],
    leaf: _ResourceLeaf,
    data: bytes,
    sections: tuple[_MappedSection, ...],
) -> bool:
    folded = api_name.casefold()
    extended = folded in {"findresourceexa", "findresourceexw"}
    count = 4 if extended else 3
    if len(pushes) < count:
        return False
    arguments = pushes[-count:]
    if extended:
        # push lang, name, type, module (x86 stdcallの右から左)。
        name_value = arguments[1].value
        type_value = arguments[2].value
    else:
        # push type, name, module。
        type_value = arguments[0].value
        name_value = arguments[1].value
    wide = folded.endswith("w")
    return bool(
        _resource_identifier_matches(
            type_value,
            leaf.type_id,
            leaf.type_name,
            data,
            sections,
            wide=wide,
        )
        and _resource_identifier_matches(
            name_value,
            leaf.name_id,
            leaf.name_name,
            data,
            sections,
            wide=wide,
        )
    )


def _resource_tag_ids(value: _ResourceRuntimeValue, prefix: str) -> set[int]:
    result: set[int] = set()
    marker = f"{prefix}:"
    for tag in value.tags:
        if not tag.startswith(marker):
            continue
        remainder = tag.removeprefix(marker).split(":", maxsplit=1)[0]
        try:
            result.add(int(remainder))
        except ValueError:
            continue
    return result


def _resource_pointer_ids(
    value: _ResourceRuntimeValue,
    expected_offset: int,
) -> set[int]:
    result: set[int] = set()
    for tag in value.tags:
        if not tag.startswith("pointer:"):
            continue
        parts = tag.split(":")
        if len(parts) != 3:
            continue
        try:
            resource_id = int(parts[1])
            offset = int(parts[2])
        except ValueError:
            continue
        if offset == expected_offset:
            result.add(resource_id)
    return result


def _adjust_resource_pointer(
    value: _ResourceRuntimeValue,
    delta: int,
) -> _ResourceRuntimeValue:
    adjusted: set[str] = set()
    for tag in value.tags:
        if not tag.startswith("pointer:"):
            continue
        parts = tag.split(":")
        if len(parts) != 3:
            continue
        try:
            resource_id = int(parts[1])
            offset = int(parts[2]) + delta
        except ValueError:
            continue
        if 0 <= offset <= MAX_RESOURCE_BYTES:
            adjusted.add(f"pointer:{resource_id}:{offset}")
    return _ResourceRuntimeValue(tags=frozenset(adjusted))


def _iat_api_name(
    instruction: object,
    import_addresses: dict[int, str],
) -> str | None:
    try:
        if not instruction.group(CS_GRP_CALL) or not instruction.operands:
            return None
        operand = instruction.operands[0]
        if (
            operand.type != X86_OP_MEM
            or operand.mem.base != X86_REG_INVALID
            or operand.mem.index != X86_REG_INVALID
        ):
            return None
        return import_addresses.get(_u32(int(operand.mem.disp)))
    except (AttributeError, CsError, TypeError, ValueError, OverflowError):
        return None


def _resource_runtime_push(
    instruction: object,
    registers: dict[str, _ResourceRuntimeValue],
    memory: dict[tuple[str, int], _ResourceRuntimeValue],
) -> _ResourceRuntimePush | None:
    if instruction.mnemonic.casefold() != "push" or not instruction.operands:
        return None
    operand = instruction.operands[0]
    if int(operand.size) != 4:
        return _ResourceRuntimePush(
            value=_ResourceRuntimeValue(),
            register_family=None,
        )
    family = _register_family(operand.reg) if operand.type == X86_OP_REG else None
    return _ResourceRuntimePush(
        value=_resource_operand_value(operand, registers, memory),
        register_family=family,
    )


def _resource_decoder_chain(
    data: bytes,
    sections: tuple[_MappedSection, ...],
    leaf: _ResourceLeaf,
    root: int,
    instructions: tuple[object, ...],
    call_index: int,
    pushes: list[_ResourceRuntimePush],
    registers: dict[str, _ResourceRuntimeValue],
    lock_sites: dict[int, int],
    disassembler: Cs,
    expected_offset: int,
    candidate_extent: int,
) -> _ResourceRuntimeChain | None:
    if not 3 <= len(pushes) <= MAX_OPAQUE_WIDE_HEX_CALL_ARGUMENTS:
        return None
    pointer_occurrences: dict[int, int] = {}
    size_occurrences: dict[int, int] = {}
    for pushed in pushes:
        for resource_id in _resource_pointer_ids(pushed.value, expected_offset):
            pointer_occurrences[resource_id] = pointer_occurrences.get(resource_id, 0) + 1
        for resource_id in _resource_tag_ids(pushed.value, "size"):
            size_occurrences[resource_id] = size_occurrences.get(resource_id, 0) + 1
    identities = {
        resource_id
        for resource_id, count in pointer_occurrences.items()
        if count == 1 and size_occurrences.get(resource_id) == 1
    }
    if len(identities) != 1:
        return None
    resource_id = next(iter(identities))
    source_pushes = [
        pushed
        for pushed in pushes
        if resource_id
        in _resource_pointer_ids(pushed.value, expected_offset)
    ]
    if len(source_pushes) != 1:
        return None
    source_family = source_pushes[0].register_family
    if (
        source_family not in {"ebx", "ebp", "edi", "esi"}
        or registers.get(source_family) != source_pushes[0].value
    ):
        source_family = None
    destinations = [
        pushed
        for pushed in pushes
        if pushed.value.constant is not None
        and not pushed.value.tags
        and _writable_non_executable(sections, pushed.value.constant)
        and not leaf.address <= pushed.value.constant < leaf.address + leaf.size
        and pushed.register_family in {"ebx", "ebp", "edi", "esi"}
    ]
    if len(destinations) != 1:
        return None
    destination_value = destinations[0].value.constant
    destination_family = destinations[0].register_family
    if (
        destination_value is None
        or destination_family is None
        or registers.get(destination_family)
        != _ResourceRuntimeValue(constant=destination_value)
    ):
        return None
    staging_target = _direct_file_backed_call_target(
        instructions[call_index],
        sections,
    )
    if staging_target is None:
        return None
    cleanup_index = call_index + 1
    if cleanup_index >= len(instructions) or not _stack_cleanup_matches(
        instructions[cleanup_index],
        len(pushes),
    ):
        return None
    stop = min(
        len(instructions),
        cleanup_index + 1 + MAX_OPAQUE_WIDE_HEX_POST_STAGE_INSTRUCTIONS,
    )
    for instruction in instructions[cleanup_index + 1 : stop]:
        if instruction.group(CS_GRP_RET) or instruction.group(CS_GRP_JUMP):
            return None
        if instruction.group(CS_GRP_CALL):
            transform_target = _direct_file_backed_call_target(instruction, sections)
            if transform_target is None:
                return None
            semantics = _transform_semantics(
                data,
                sections,
                transform_target,
                _TransformObject(
                    leaf.address + expected_offset,
                    candidate_extent,
                ),
                _TransformObject(
                    int(destinations[0].value.constant),
                    candidate_extent,
                ),
                source_family,
                destination_family,
                disassembler,
            )
            return _ResourceRuntimeChain(
                root=root,
                source_instruction=lock_sites[resource_id],
                staging_target=staging_target,
                transform_target=transform_target,
                semantics=semantics,
            )
        written = _written_register_families(instruction)
        if written is None or destination_family in written:
            return None
        if source_family in written:
            source_family = None
    return None


def _resource_runtime_function(
    data: bytes,
    sections: tuple[_MappedSection, ...],
    leaf: _ResourceLeaf,
    root: int,
    instructions: tuple[object, ...],
    import_addresses: dict[int, str],
    disassembler: Cs,
    expected_offset: int,
    candidate_extent: int,
) -> tuple[list[_ResourceRuntimeChain], int, int, int, int, bool]:
    registers: dict[str, _ResourceRuntimeValue] = {}
    memory: dict[tuple[str, int], _ResourceRuntimeValue] = {}
    pushes: list[_ResourceRuntimePush] = []
    lock_sites: dict[int, int] = {}
    locator_matches = 0
    handle_chains = 0
    pointer_size_chains: set[int] = set()
    source_ids: set[int] = set()
    chains: list[_ResourceRuntimeChain] = []
    complete = True

    for index, instruction in enumerate(instructions):
        mnemonic = instruction.mnemonic.casefold()
        operands = instruction.operands
        pushed = _resource_runtime_push(instruction, registers, memory)
        if pushed is not None:
            if len(pushes) >= MAX_OPAQUE_WIDE_HEX_CALL_ARGUMENTS:
                pushes.clear()
            else:
                pushes.append(pushed)
            continue

        if instruction.group(CS_GRP_CALL):
            api_name = _iat_api_name(instruction, import_addresses)
            result = _ResourceRuntimeValue()
            if api_name in _RESOURCE_GROUPS["find"] and _resource_find_matches(
                api_name,
                pushes,
                leaf,
                data,
                sections,
            ):
                resource_id = int(instruction.address)
                result = _ResourceRuntimeValue(tags=frozenset({f"hrsrc:{resource_id}"}))
                locator_matches += 1
            elif api_name in _RESOURCE_GROUPS["size"] and len(pushes) >= 2:
                ids = _resource_tag_ids(pushes[-2].value, "hrsrc")
                if len(ids) == 1:
                    resource_id = next(iter(ids))
                    result = _ResourceRuntimeValue(tags=frozenset({f"size:{resource_id}"}))
            elif api_name in _RESOURCE_GROUPS["load"] and len(pushes) >= 2:
                ids = _resource_tag_ids(pushes[-2].value, "hrsrc")
                if len(ids) == 1:
                    resource_id = next(iter(ids))
                    result = _ResourceRuntimeValue(tags=frozenset({f"hglobal:{resource_id}"}))
                    handle_chains += 1
            elif api_name in _RESOURCE_GROUPS["lock"] and pushes:
                ids = _resource_tag_ids(pushes[-1].value, "hglobal")
                if len(ids) == 1:
                    resource_id = next(iter(ids))
                    result = _ResourceRuntimeValue(
                        tags=frozenset({f"pointer:{resource_id}:0"})
                    )
                    source_ids.add(resource_id)
                    lock_sites[resource_id] = int(instruction.address)
            elif api_name is None:
                chain = _resource_decoder_chain(
                    data,
                    sections,
                    leaf,
                    root,
                    instructions,
                    index,
                    pushes,
                    registers,
                    lock_sites,
                    disassembler,
                    expected_offset,
                    candidate_extent,
                )
                if chain is not None:
                    pointer_size_chains.add(chain.source_instruction)
                    chains.append(chain)
                    if len(chains) > MAX_RESOURCE_RUNTIME_CHAINS:
                        return [], locator_matches, handle_chains, 0, 0, False
            pushes.clear()
            for volatile in ("eax", "ecx", "edx"):
                registers.pop(volatile, None)
            if result.tags or result.constant is not None:
                registers["eax"] = result
            continue

        if mnemonic == "pop" and operands:
            value = pushes.pop().value if pushes else _ResourceRuntimeValue()
            if operands[0].type == X86_OP_REG:
                family = _register_family(operands[0].reg)
                if family is not None:
                    if int(operands[0].size) == 4:
                        registers[family] = value
                    else:
                        if family in registers:
                            complete = False
                        registers.pop(family, None)
            continue
        if mnemonic == "lea" and len(operands) >= 2 and operands[0].type == X86_OP_REG:
            family = _register_family(operands[0].reg)
            source = operands[1]
            value = _ResourceRuntimeValue()
            if (
                int(operands[0].size) == 4
                and source.type == X86_OP_MEM
                and int(source.size) == 4
            ):
                key = _resource_memory_key(source, registers)
                if key is not None and key[0] == "absolute":
                    value = _ResourceRuntimeValue(constant=key[1])
            if family is not None:
                if int(operands[0].size) != 4 and family in registers:
                    complete = False
                if value.constant is None:
                    registers.pop(family, None)
                else:
                    registers[family] = value
            continue
        if mnemonic == "mov" and len(operands) >= 2:
            value = _resource_operand_value(operands[1], registers, memory)
            destination = operands[0]
            if destination.type == X86_OP_REG:
                family = _register_family(destination.reg)
                if family is not None:
                    if int(destination.size) != 4:
                        if family in registers:
                            complete = False
                        registers.pop(family, None)
                    elif value.tags or value.constant is not None:
                        registers[family] = value
                    else:
                        registers.pop(family, None)
            elif destination.type == X86_OP_MEM:
                key = _resource_memory_key(destination, registers)
                size = int(destination.size)
                if key is None:
                    if memory:
                        complete = False
                    for stored in tuple(memory):
                        memory.pop(stored, None)
                else:
                    overlapping = _resource_overlapping_memory_cells(
                        memory,
                        key,
                        size,
                    )
                    if any(stored != key or size != 4 for stored in overlapping):
                        complete = False
                    for stored in overlapping:
                        memory.pop(stored, None)
                    if size == 4 and (value.tags or value.constant is not None):
                        if (
                            key not in memory
                            and len(memory) >= MAX_RESOURCE_RUNTIME_MEMORY_CELLS
                        ):
                            return [], locator_matches, handle_chains, 0, 0, False
                        memory[key] = value
            continue
        if (
            mnemonic in {"add", "sub"}
            and len(operands) >= 2
            and operands[0].type == X86_OP_REG
            and int(operands[0].size) == 4
            and operands[1].type == X86_OP_IMM
        ):
            family = _register_family(operands[0].reg)
            value = registers.get(family) if family is not None else None
            if family is not None and value is not None:
                immediate = _signed_operand_immediate(operands[1])
                if immediate is None:
                    complete = False
                    registers.pop(family, None)
                else:
                    delta = immediate if mnemonic == "add" else -immediate
                    if value.tags:
                        adjusted = _adjust_resource_pointer(value, delta)
                        if not adjusted.tags:
                            complete = False
                            registers.pop(family, None)
                        else:
                            registers[family] = adjusted
                    elif value.constant is not None:
                        constant = value.constant + delta
                        if not 0 <= constant <= 0xFFFFFFFF:
                            complete = False
                            registers.pop(family, None)
                        else:
                            registers[family] = _ResourceRuntimeValue(
                                constant=constant
                            )
            elif family is not None:
                registers.pop(family, None)
            continue
        if (
            mnemonic == "xor"
            and len(operands) >= 2
            and operands[0].type == X86_OP_REG
            and int(operands[0].size) == 4
            and operands[1].type == X86_OP_REG
            and int(operands[1].size) == 4
            and int(operands[0].reg) == int(operands[1].reg)
        ):
            family = _register_family(operands[0].reg)
            if family is not None:
                registers[family] = _ResourceRuntimeValue(constant=0)
            continue

        for operand in operands:
            if operand.type != X86_OP_MEM or not int(operand.access) & CS_AC_WRITE:
                continue
            key = _resource_memory_key(operand, registers)
            if key is None:
                if memory:
                    complete = False
                for stored in tuple(memory):
                    memory.pop(stored, None)
                continue
            overlapping = _resource_overlapping_memory_cells(
                memory,
                key,
                int(operand.size),
            )
            if overlapping:
                complete = False
            for stored in overlapping:
                memory.pop(stored, None)

        written = _written_register_families(instruction)
        if written is None:
            complete = False
        else:
            destination = operands[0] if operands else None
            for family in written:
                if (
                    family in registers
                    and destination is not None
                    and destination.type == X86_OP_REG
                    and _register_family(destination.reg) == family
                    and int(destination.size) != 4
                ):
                    complete = False
                registers.pop(family, None)

    return (
        chains,
        locator_matches,
        handle_chains,
        len(pointer_size_chains),
        len(source_ids),
        complete,
    )


def _collect_resource_runtime_use(
    image: object,
    data: bytes,
    leaf: _ResourceLeaf,
    candidate_address: int,
    candidate_extent: int,
    external_roots: tuple[int, ...],
    import_addresses: dict[int, str],
) -> _ResourceRuntimeInventory | None:
    sections = _mapped_sections(image, data)
    expected_offset = candidate_address - leaf.address
    if (
        sections is None
        or type(candidate_extent) is not int
        or candidate_extent <= 0
        or not external_roots
        or not 0 <= expected_offset < leaf.size
        or expected_offset + candidate_extent > leaf.size
    ):
        return None
    if any(
        type(address) is not int
        or not 0 < address <= 0xFFFFFFFF
        or not isinstance(name, str)
        or not name
        for address, name in import_addresses.items()
    ):
        return None
    try:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
    except CsError:
        return None

    pending = [(root, 0) for root in external_roots]
    queued = set(external_roots)
    seen: set[int] = set()
    chains: list[_ResourceRuntimeChain] = []
    locator_matches = 0
    handle_chains = 0
    pointer_size_chains = 0
    source_count = 0
    scanned_instructions = 0
    complete = True
    truncated = False
    while pending:
        root, depth = pending.pop(0)
        queued.discard(root)
        if root in seen:
            continue
        if len(seen) >= MAX_RESOURCE_RUNTIME_FUNCTIONS or depth > MAX_RESOURCE_RUNTIME_CALL_GRAPH_DEPTH:
            truncated = True
            complete = False
            break
        instructions, window_complete = _bounded_linear_window(
            data,
            sections,
            root,
            disassembler,
            max_bytes=MAX_OPAQUE_WIDE_HEX_CALLSITE_BYTES,
            max_instructions=MAX_OPAQUE_WIDE_HEX_CALLSITE_INSTRUCTIONS,
        )
        if scanned_instructions > MAX_RESOURCE_RUNTIME_INSTRUCTIONS - len(instructions):
            truncated = True
            complete = False
            break
        scanned_instructions += len(instructions)
        seen.add(root)
        if not window_complete or (
            instructions and instructions[-1].group(CS_GRP_JUMP)
        ) or any(
            instruction.mnemonic.casefold()
            in {"hlt", "int", "int1", "int3", "into", "iret", "iretd", "ud2"}
            for instruction in instructions
        ):
            complete = False
            continue
        result = _resource_runtime_function(
            data,
            sections,
            leaf,
            root,
            instructions,
            import_addresses,
            disassembler,
            expected_offset,
            candidate_extent,
        )
        function_chains, locators, handles, pointer_sizes, sources, function_complete = result
        if not function_complete and (locators or handles or pointer_sizes or sources):
            complete = False
        chains.extend(function_chains)
        locator_matches += locators
        handle_chains += handles
        pointer_size_chains += pointer_sizes
        source_count += sources
        if len(chains) > MAX_RESOURCE_RUNTIME_CHAINS:
            truncated = True
            complete = False
            chains.clear()
            break
        for instruction in instructions:
            target = _direct_file_backed_call_target(instruction, sections)
            if target is None or target in seen or target in queued:
                continue
            if depth >= MAX_RESOURCE_RUNTIME_CALL_GRAPH_DEPTH:
                truncated = True
                complete = False
                continue
            if len(pending) >= MAX_RESOURCE_RUNTIME_FUNCTIONS:
                truncated = True
                complete = False
                break
            pending.append((target, depth + 1))
            queued.add(target)
    return _ResourceRuntimeInventory(
        chains=tuple(chains),
        locator_match_count=locator_matches,
        handle_chain_count=handle_chains,
        pointer_size_chain_count=pointer_size_chains,
        source_count=source_count,
        analysis_complete=complete,
        truncated=truncated,
        scanned_instruction_count=scanned_instructions,
    )


def _with_resource_runtime_use(
    inventory: OpaqueWideHexUseInventory,
    runtime: _ResourceRuntimeInventory | None,
) -> OpaqueWideHexUseInventory:
    """direct VA証拠がない場合だけ、独立したresource runtime証拠を併記する。"""

    if runtime is None:
        return inventory
    semantic_chains = tuple(
        chain for chain in runtime.chains if chain.semantics.qualifies
    )
    unique_operations = (
        semantic_chains[0].semantics.operation_kinds
        if runtime.analysis_complete
        and not runtime.truncated
        and len(runtime.chains) == 1
        and len(semantic_chains) == 1
        else ()
    )
    direct_source_proven = bool(
        inventory.raw_reference_count or inventory.source_operand_reference_count
    )
    return OpaqueWideHexUseInventory(
        source_roots=(
            inventory.source_roots
            if direct_source_proven
            else tuple(sorted({chain.root for chain in semantic_chains}))
        ),
        raw_reference_count=inventory.raw_reference_count,
        source_operand_reference_count=inventory.source_operand_reference_count,
        anchored_source_reference_count=(
            inventory.anchored_source_reference_count
            if direct_source_proven
            else runtime.source_count
        ),
        staging_call_chain_count=(
            inventory.staging_call_chain_count
            if direct_source_proven
            else len(runtime.chains)
        ),
        semantic_transform_chain_count=(
            inventory.semantic_transform_chain_count
            if direct_source_proven
            else len(semantic_chains)
        ),
        transform_operation_kinds=(
            inventory.transform_operation_kinds
            if direct_source_proven
            else tuple(unique_operations)
        ),
        reference_set_complete=inventory.reference_set_complete,
        reference_set_truncated=inventory.reference_set_truncated,
        bounded_analysis_complete=(
            inventory.bounded_analysis_complete
            if direct_source_proven
            else runtime.analysis_complete
        ),
        scanned_byte_count=inventory.scanned_byte_count,
        decoded_literal_reference_count=inventory.decoded_literal_reference_count,
        scanned_instruction_count=inventory.scanned_instruction_count,
        anchored_window_count=inventory.anchored_window_count,
        anchored_scanned_byte_count=inventory.anchored_scanned_byte_count,
        anchored_scanned_instruction_count=(
            inventory.anchored_scanned_instruction_count
        ),
        resource_locator_match_count=runtime.locator_match_count,
        resource_handle_chain_count=runtime.handle_chain_count,
        resource_pointer_size_chain_count=runtime.pointer_size_chain_count,
        resource_runtime_source_count=runtime.source_count,
        resource_runtime_analysis_complete=runtime.analysis_complete,
        resource_runtime_truncated=runtime.truncated,
        resource_runtime_scanned_instruction_count=runtime.scanned_instruction_count,
        root_derived_source_reference_count=(
            inventory.root_derived_source_reference_count
        ),
        root_address_lineage_analysis_complete=(
            inventory.root_address_lineage_analysis_complete
        ),
        root_address_lineage_truncated=(
            inventory.root_address_lineage_truncated
        ),
        root_address_lineage_root_count=(
            inventory.root_address_lineage_root_count
        ),
        root_address_lineage_function_count=(
            inventory.root_address_lineage_function_count
        ),
        root_address_lineage_scanned_byte_count=(
            inventory.root_address_lineage_scanned_byte_count
        ),
        root_address_lineage_scanned_instruction_count=(
            inventory.root_address_lineage_scanned_instruction_count
        ),
        reference_scan_mode=inventory.reference_scan_mode,
        raw_candidate_occurrence_count=(
            inventory.raw_candidate_occurrence_count
        ),
        local_literal_instruction_start_count=(
            inventory.local_literal_instruction_start_count
        ),
        local_direct_caller_count=inventory.local_direct_caller_count,
        local_scanned_byte_count=inventory.local_scanned_byte_count,
    )


def collect_opaque_wide_hex_use_evidence(
    image: object,
    data: bytes,
    candidate: OpaqueWideHexCandidate,
    *,
    external_roots: tuple[int, ...] = (),
    resource_leaf: _ResourceLeaf | None = None,
    import_addresses: dict[int, str] | None = None,
) -> OpaqueWideHexUseInventory | None:
    """候補sourceから同一linear path上のstaging/変換callを有界評価する。

    復号関数の実行や一般symbolic executionは行わない。direct-call target、
    cdecl stack cleanup、candidate／staged object内のbyte read、同一taint上の
    byte変換、およびstaged object範囲内のbyte storeが同じcall chainで揃った
    場合だけroute証拠を強める。
    復号済み設定、parser、network lineageの証明には使用しない。
    """

    if (
        not isinstance(data, bytes)
        or len(data) > MAX_INPUT_SIZE
        or not isinstance(candidate, OpaqueWideHexCandidate)
        or not 0 <= candidate.address <= 0xFFFFFFFF
        or candidate.byte_size <= 0
        or any(
            type(root) is not int or not 0 <= root <= 0xFFFFFFFF
            for root in external_roots
        )
        or len(external_roots) > MAX_EXPORTS + MAX_TLS_CALLBACKS
        or (resource_leaf is None) != (import_addresses is None)
        or (
            resource_leaf is not None
            and (
                candidate.address < resource_leaf.address
                or candidate.address + candidate.byte_size
                > resource_leaf.address + resource_leaf.size
            )
        )
    ):
        return None
    sections = _mapped_sections(image, data)
    if sections is None:
        return None
    executable = tuple(
        section
        for section in sections
        if section.characteristics & _EXECUTABLE and section.raw_end > section.raw_start
    )
    if not executable:
        return None
    try:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
    except CsError:
        return None

    runtime_inventory = (
        _collect_resource_runtime_use(
            image,
            data,
            resource_leaf,
            candidate.address,
            candidate.byte_size,
            external_roots,
            import_addresses,
        )
        if resource_leaf is not None and import_addresses is not None
        else None
    )

    root_lineage = _root_address_lineage_scan(
        image,
        data,
        sections,
        candidate,
        external_roots,
        disassembler,
    )
    root_lineage_fields = {
        "root_derived_source_reference_count": len(
            root_lineage.source_references
        ),
        "root_address_lineage_analysis_complete": (
            root_lineage.analysis_complete
        ),
        "root_address_lineage_truncated": root_lineage.truncated,
        "root_address_lineage_root_count": root_lineage.root_count,
        "root_address_lineage_function_count": root_lineage.function_count,
        "root_address_lineage_scanned_byte_count": (
            root_lineage.scanned_byte_count
        ),
        "root_address_lineage_scanned_instruction_count": (
            root_lineage.scanned_instruction_count
        ),
    }
    reference_scan = _instruction_reference_scan(
        data,
        executable,
        candidate.address,
        disassembler,
    )
    if (
        not reference_scan.complete
        and not reference_scan.truncated
        and root_lineage.analysis_complete
        and not root_lineage.truncated
    ):
        reference_scan = _local_reference_resynchronization(
            data,
            executable,
            candidate.address,
            disassembler,
        )
    reference_scan_fields = {
        "reference_scan_mode": reference_scan.mode,
        "raw_candidate_occurrence_count": (
            reference_scan.raw_candidate_occurrence_count
        ),
        "local_literal_instruction_start_count": (
            reference_scan.local_literal_instruction_start_count
        ),
        "local_direct_caller_count": (
            reference_scan.local_direct_caller_count
        ),
        "local_scanned_byte_count": (
            reference_scan.local_scanned_byte_count
        ),
    }
    raw_references = reference_scan.literal_reference_count
    source_references = list(reference_scan.source_references)
    if not reference_scan.complete:
        return OpaqueWideHexUseInventory(
            source_roots=(),
            raw_reference_count=raw_references,
            source_operand_reference_count=0,
            anchored_source_reference_count=0,
            staging_call_chain_count=0,
            semantic_transform_chain_count=0,
            transform_operation_kinds=(),
            reference_set_complete=False,
            reference_set_truncated=reference_scan.truncated,
            bounded_analysis_complete=False,
            scanned_byte_count=reference_scan.scanned_byte_count,
            decoded_literal_reference_count=raw_references,
            scanned_instruction_count=reference_scan.scanned_instruction_count,
            **root_lineage_fields,
            **reference_scan_fields,
        )

    derived_source_references = tuple(root_lineage.source_references)
    exact_source_addresses = {source for _section, source in source_references}
    all_source_addresses = exact_source_addresses | {
        source for source, _entry in derived_source_references
    }
    if len(all_source_addresses) > MAX_OPAQUE_WIDE_HEX_REFERENCE_MATCHES:
        return OpaqueWideHexUseInventory(
            source_roots=(),
            raw_reference_count=raw_references,
            source_operand_reference_count=len(all_source_addresses),
            anchored_source_reference_count=0,
            staging_call_chain_count=0,
            semantic_transform_chain_count=0,
            transform_operation_kinds=(),
            reference_set_complete=False,
            reference_set_truncated=True,
            bounded_analysis_complete=False,
            scanned_byte_count=reference_scan.scanned_byte_count,
            decoded_literal_reference_count=raw_references,
            scanned_instruction_count=reference_scan.scanned_instruction_count,
            **root_lineage_fields,
            **reference_scan_fields,
        )

    possible_entries: set[int] = set()
    entries_by_source: dict[int, set[int]] = {}
    local_entries_by_source = {
        source: entry
        for source, entry in reference_scan.local_source_entries
    }
    for section, source in source_references:
        local_entry = local_entries_by_source.get(source)
        entries = (
            {local_entry}
            if local_entry is not None
            else _possible_source_entries(data, section, source, disassembler)
        )
        entries_by_source[source] = entries
        possible_entries.update(entries)
    direct_call_targets = dict(reference_scan.direct_call_targets)
    external_root_set = set(external_roots)
    matching_direct_calls = sum(
        direct_call_targets.get(entry, 0) for entry in possible_entries
    )
    if matching_direct_calls > MAX_OPAQUE_WIDE_HEX_REFERENCE_MATCHES:
        return OpaqueWideHexUseInventory(
            source_roots=(),
            raw_reference_count=raw_references,
            source_operand_reference_count=len(all_source_addresses),
            anchored_source_reference_count=0,
            staging_call_chain_count=0,
            semantic_transform_chain_count=0,
            transform_operation_kinds=(),
            reference_set_complete=False,
            reference_set_truncated=True,
            bounded_analysis_complete=False,
            scanned_byte_count=reference_scan.scanned_byte_count,
            decoded_literal_reference_count=raw_references,
            scanned_instruction_count=reference_scan.scanned_instruction_count,
            **root_lineage_fields,
            **reference_scan_fields,
        )
    called_entries = {
        entry
        for entry in possible_entries
        if entry in external_root_set or direct_call_targets.get(entry, 0)
    }
    anchored_work = {
        (source, entry): False
        for _section, source in source_references
        for entry in entries_by_source.get(source, set()) & called_entries
    }
    if root_lineage.analysis_complete:
        for source, entry in derived_source_references:
            key = (source, entry)
            if key not in anchored_work:
                anchored_work[key] = True
    if len(anchored_work) > MAX_OPAQUE_WIDE_HEX_ANCHORED_WINDOWS:
        return OpaqueWideHexUseInventory(
            source_roots=(),
            raw_reference_count=raw_references,
            source_operand_reference_count=len(all_source_addresses),
            anchored_source_reference_count=0,
            staging_call_chain_count=0,
            semantic_transform_chain_count=0,
            transform_operation_kinds=(),
            reference_set_complete=False,
            reference_set_truncated=True,
            bounded_analysis_complete=False,
            scanned_byte_count=reference_scan.scanned_byte_count,
            decoded_literal_reference_count=raw_references,
            scanned_instruction_count=reference_scan.scanned_instruction_count,
            **root_lineage_fields,
            **reference_scan_fields,
        )

    bounded_complete = bool(
        root_lineage.analysis_complete and not root_lineage.truncated
    )
    anchored_sources: set[int] = set()
    chains: dict[tuple[int, int, int, int], _SourceUseChain] = {}
    anchored_window_count = 0
    anchored_scanned_bytes = 0
    anchored_scanned_instructions = 0
    for (source, entry), root_derived in sorted(anchored_work.items()):
        instructions, complete = _bounded_linear_window(
            data,
            sections,
            entry,
            disassembler,
            max_bytes=MAX_OPAQUE_WIDE_HEX_CALLSITE_BYTES,
            max_instructions=MAX_OPAQUE_WIDE_HEX_CALLSITE_INSTRUCTIONS,
        )
        try:
            window_bytes = sum(int(instruction.size) for instruction in instructions)
        except (AttributeError, TypeError, ValueError, OverflowError):
            bounded_complete = False
            continue
        if (
            anchored_scanned_bytes
            > MAX_OPAQUE_WIDE_HEX_ANCHORED_SCAN_BYTES - window_bytes
            or anchored_scanned_instructions
            > MAX_OPAQUE_WIDE_HEX_ANCHORED_SCAN_INSTRUCTIONS - len(instructions)
        ):
            return OpaqueWideHexUseInventory(
                source_roots=(),
                raw_reference_count=raw_references,
                source_operand_reference_count=len(all_source_addresses),
                anchored_source_reference_count=0,
                staging_call_chain_count=0,
                semantic_transform_chain_count=0,
                transform_operation_kinds=(),
                reference_set_complete=False,
                reference_set_truncated=True,
                bounded_analysis_complete=False,
                scanned_byte_count=reference_scan.scanned_byte_count,
                decoded_literal_reference_count=raw_references,
                scanned_instruction_count=(
                    reference_scan.scanned_instruction_count
                ),
                anchored_window_count=anchored_window_count,
                anchored_scanned_byte_count=anchored_scanned_bytes,
                anchored_scanned_instruction_count=(
                    anchored_scanned_instructions
                ),
                **root_lineage_fields,
                **reference_scan_fields,
            )
        anchored_window_count += 1
        anchored_scanned_bytes += window_bytes
        anchored_scanned_instructions += len(instructions)
        if not complete:
            bounded_complete = False
        source_index = _candidate_source_index(
            instructions,
            source,
            candidate.address,
            root_derived=root_derived,
        )
        if source_index is None:
            continue
        anchored_sources.add(source)
        chain = _source_use_chain(
            data,
            sections,
            entry,
            source,
            candidate.address,
            candidate.byte_size,
            instructions,
            disassembler,
            root_derived=root_derived,
        )
        if chain is not None:
            if not chain.semantics.window_complete:
                bounded_complete = False
            key = (
                chain.root,
                chain.source_instruction,
                chain.staging_target,
                chain.transform_target,
            )
            chains[key] = chain

    semantic_chains = tuple(
        chain for chain in chains.values() if chain.semantics.qualifies
    )
    unique_semantics = (
        tuple(semantic_chains[0].semantics.operation_kinds)
        if bounded_complete and len(chains) == 1 and len(semantic_chains) == 1
        else ()
    )
    return _with_resource_runtime_use(
        OpaqueWideHexUseInventory(
            source_roots=tuple(sorted({chain.root for chain in semantic_chains})),
            raw_reference_count=raw_references,
            source_operand_reference_count=len(all_source_addresses),
            anchored_source_reference_count=len(anchored_sources),
            staging_call_chain_count=len(chains),
            semantic_transform_chain_count=len(semantic_chains),
            transform_operation_kinds=unique_semantics,
            reference_set_complete=True,
            reference_set_truncated=False,
            bounded_analysis_complete=bounded_complete,
            scanned_byte_count=reference_scan.scanned_byte_count,
            decoded_literal_reference_count=raw_references,
            scanned_instruction_count=reference_scan.scanned_instruction_count,
            anchored_window_count=anchored_window_count,
            anchored_scanned_byte_count=anchored_scanned_bytes,
            anchored_scanned_instruction_count=anchored_scanned_instructions,
            **root_lineage_fields,
            **reference_scan_fields,
        ),
        runtime_inventory,
    )


def _tls_callbacks(
    image: object,
    data: bytes,
    ranges: tuple[tuple[int, int], ...],
) -> tuple[bool, tuple[int, ...]] | None:
    try:
        directory = image.DIRECTORY_ENTRY_TLS
    except AttributeError:
        return False, ()
    try:
        explicit = directory.callbacks
    except AttributeError:
        explicit = None
    if explicit is not None:
        try:
            callbacks = tuple(int(value) for value in explicit)
        except (TypeError, ValueError, OverflowError):
            return None
    else:
        try:
            image_base = int(image.OPTIONAL_HEADER.ImageBase)
            magic = int(image.OPTIONAL_HEADER.Magic)
            callback_table = int(directory.struct.AddressOfCallBacks)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if callback_table == 0:
            return True, ()
        pointer_size = 8 if magic == 0x20B else 4
        table_rva = callback_table - image_base
        try:
            table_offset = int(image.get_offset_from_rva(table_rva))
        except (
            AttributeError,
            TypeError,
            ValueError,
            OverflowError,
            pefile.PEFormatError,
        ):
            return None
        callbacks_list: list[int] = []
        terminated = False
        for index in range(MAX_TLS_CALLBACKS + 1):
            offset = table_offset + index * pointer_size
            if offset < 0 or offset + pointer_size > len(data):
                return None
            value = struct.unpack_from(
                "<Q" if pointer_size == 8 else "<I", data, offset
            )[0]
            if value == 0:
                terminated = True
                break
            callbacks_list.append(int(value))
        if not terminated:
            return None
        callbacks = tuple(callbacks_list)
    if len(callbacks) > MAX_TLS_CALLBACKS or any(
        not _mapped_executable(value, ranges) for value in callbacks
    ):
        return None
    return True, tuple(dict.fromkeys(callbacks))


def collect_external_code_roots(image: object, data: bytes) -> ExternalCodeRoots | None:
    """export/TLS tableから名称非依存のfile-backed code rootを回収する。"""

    ranges = _executable_ranges(image, data)
    if ranges is None:
        return None
    try:
        export_directory = image.DIRECTORY_ENTRY_EXPORT
        symbols = list(export_directory.symbols)
    except AttributeError:
        symbols = []
    if len(symbols) > MAX_EXPORTS:
        return None
    try:
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    export_targets: list[int] = []
    for symbol in symbols:
        try:
            rva = int(symbol.address)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        try:
            forwarder = symbol.forwarder
        except AttributeError:
            forwarder = None
        if forwarder:
            continue
        target = image_base + rva
        if not _mapped_executable(target, ranges):
            return None
        export_targets.append(target)
    tls = _tls_callbacks(image, data, ranges)
    if tls is None:
        return None
    tls_present, tls_targets = tls
    unique_exports = tuple(dict.fromkeys(export_targets))
    roots = tuple(dict.fromkeys((*unique_exports, *tls_targets)))
    return ExternalCodeRoots(
        roots=roots,
        export_roots=unique_exports,
        tls_roots=tls_targets,
        export_count=len(symbols),
        export_target_count=len(unique_exports),
        export_funnel=(
            len(symbols) >= MIN_FUNNEL_EXPORTS
            and len(export_targets) == len(symbols)
            and len(unique_exports) == 1
        ),
        tls_directory_present=tls_present,
    )


def _resource_leaves(image: object, data: bytes) -> tuple[_ResourceLeaf, ...] | None:
    try:
        root = image.DIRECTORY_ENTRY_RESOURCE
    except AttributeError:
        return ()
    try:
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
        type_entries = list(root.entries)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    leaves: list[_ResourceLeaf] = []
    total_bytes = 0
    for type_entry in type_entries:
        try:
            type_name = (
                str(type_entry.name) if type_entry.name is not None else None
            )
            type_id = (
                None if type_name is not None else int(type_entry.struct.Id)
            )
            if type_name is not None and not 1 <= len(type_name) <= MAX_RESOURCE_IDENTIFIER_CHARACTERS:
                return None
            if type_id is not None and not 0 <= type_id <= 0xFFFF:
                return None
            custom_type = bool(
                type_name is not None
                or (type_id is not None and type_id not in _STANDARD_RESOURCE_TYPES)
            )
            name_entries = list(type_entry.directory.entries)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        for name_entry in name_entries:
            try:
                raw_name = getattr(name_entry, "name", None)
                name_name = (
                    str(raw_name) if raw_name is not None else None
                )
                raw_name_id = getattr(getattr(name_entry, "struct", None), "Id", None)
                name_id = (
                    None
                    if name_name is not None or raw_name_id is None
                    else int(raw_name_id)
                )
                if name_name is not None and not 1 <= len(name_name) <= MAX_RESOURCE_IDENTIFIER_CHARACTERS:
                    return None
                if name_id is not None and not 0 <= name_id <= 0xFFFF:
                    return None
                language_entries = list(name_entry.directory.entries)
            except (AttributeError, TypeError, ValueError, OverflowError):
                return None
            for language_entry in language_entries:
                if len(leaves) >= MAX_RESOURCE_LEAVES:
                    return None
                try:
                    item = language_entry.data.struct
                    rva = int(item.OffsetToData)
                    size = int(item.Size)
                    offset = int(image.get_offset_from_rva(rva))
                except (
                    AttributeError,
                    TypeError,
                    ValueError,
                    OverflowError,
                    pefile.PEFormatError,
                ):
                    # 壊れた／virtual-onlyの無関係leafはroute-only inventoryから
                    # 除外する。候補を終端設定へ昇格する処理では使用しない。
                    continue
                if size < 0 or offset < 0 or offset + size > len(data):
                    continue
                total_bytes += size
                if total_bytes > MAX_RESOURCE_BYTES:
                    return None
                blob = data[offset : offset + size]
                leaves.append(
                    _ResourceLeaf(
                        address=image_base + rva,
                        size=size,
                        entropy=_bounded_entropy(blob),
                        custom_type=custom_type,
                        type_id=type_id,
                        name_id=name_id,
                        type_name=type_name,
                        name_name=name_name,
                    )
                )
    return tuple(leaves)


def _imports(
    image: object,
) -> tuple[dict[int, str], dict[str, bool], dict[str, bool]] | None:
    try:
        descriptors = list(image.DIRECTORY_ENTRY_IMPORT)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if not 1 <= len(descriptors) <= 1_024:
        return None
    addresses: dict[int, str] = {}
    names: set[str] = set()
    count = 0
    for descriptor in descriptors:
        try:
            entries = list(descriptor.imports)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        for item in entries:
            count += 1
            if count > 65_536:
                return None
            try:
                raw_name = item.name
            except AttributeError:
                raw_name = None
            if raw_name is None:
                continue
            try:
                address = item.address
            except AttributeError:
                return None
            if not isinstance(raw_name, bytes) or not 1 <= len(raw_name) <= 128:
                return None
            try:
                name = raw_name.decode("ascii", errors="strict").casefold()
                normalized_address = int(address)
            except (UnicodeError, TypeError, ValueError, OverflowError):
                return None
            if normalized_address <= 0:
                return None
            previous = addresses.get(normalized_address)
            if previous is not None and previous != name:
                return None
            addresses[normalized_address] = name
            names.add(name)
    resource = {
        group: bool(candidates & names)
        for group, candidates in _RESOURCE_GROUPS.items()
    }
    network = {
        group: bool(candidates & names) for group, candidates in _NETWORK_GROUPS.items()
    }
    return addresses, resource, network


def _iat_calls(
    image: object,
    data: bytes,
    imports: dict[int, str],
) -> set[str] | None:
    try:
        sections = list(image.sections)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    names: set[str] = set()
    for section in sections:
        try:
            if not int(section.Characteristics) & _EXECUTABLE:
                continue
            start = int(section.PointerToRawData)
            size = min(
                int(section.SizeOfRawData),
                int(section.Misc_VirtualSize) or int(section.SizeOfRawData),
            )
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if start < 0 or size < 0 or start + size > len(data):
            return None
        blob = data[start : start + size]
        for offset in range(max(0, len(blob) - 5)):
            if blob[offset : offset + 2] not in {b"\xff\x15", b"\xff\x25"}:
                continue
            address = struct.unpack_from("<I", blob, offset + 2)[0]
            name = imports.get(address)
            if name is not None:
                names.add(name)
    return names


def _public_groups(
    names: set[str],
    groups: dict[str, frozenset[str]],
) -> dict[str, bool]:
    return {group: bool(candidates & names) for group, candidates in groups.items()}


def _public_flow_summary(flow: dict[str, object]) -> dict[str, object]:
    """addressやsource値を含めずdataflowの判定根拠だけを返す。"""

    proof = flow.get("proof")
    coverage = flow.get("coverage")
    return {
        "status": str(flow.get("status", "unknown")),
        "analysis_complete": flow.get("analysis_complete") is True,
        "terminal_network_lineage_proven": (
            flow.get("terminal_network_lineage_proven") is True
        ),
        "proof": dict(proof) if isinstance(proof, dict) else {},
        "missing_proof_codes": (
            list(flow.get("missing_proof_codes", []))
            if isinstance(flow.get("missing_proof_codes"), list)
            else []
        ),
        "coverage": dict(coverage) if isinstance(coverage, dict) else {},
        "raw_addresses_included": False,
        "raw_source_values_included": False,
    }


def _unique_opaque_source_use(
    inventory: OpaqueWideHexUseInventory | None,
) -> bool:
    decoded_literal_count = (
        (
            inventory.raw_reference_count
            if inventory.decoded_literal_reference_count is None
            else inventory.decoded_literal_reference_count
        )
        if inventory is not None
        else 0
    )
    if inventory is None:
        return False
    common = bool(
        inventory.bounded_analysis_complete
        and inventory.staging_call_chain_count == 1
        and inventory.semantic_transform_chain_count == 1
        and len(inventory.source_roots) == 1
        and len(inventory.transform_operation_kinds)
        >= MIN_OPAQUE_WIDE_HEX_TRANSFORM_KINDS
    )
    direct_shape = bool(
        inventory.reference_set_complete
        and not inventory.reference_set_truncated
        and inventory.source_operand_reference_count == 1
        and inventory.anchored_source_reference_count == 1
    )
    exact_direct = bool(
        direct_shape
        and decoded_literal_count == 1
        and inventory.root_derived_source_reference_count == 0
        and inventory.root_address_lineage_analysis_complete
        and not inventory.root_address_lineage_truncated
    )
    root_derived_direct = bool(
        direct_shape
        and decoded_literal_count == 0
        and inventory.root_derived_source_reference_count == 1
        and inventory.root_address_lineage_analysis_complete
        and not inventory.root_address_lineage_truncated
        and inventory.root_address_lineage_root_count >= 1
    )
    resource_runtime = bool(
        decoded_literal_count == 0
        and inventory.source_operand_reference_count == 0
        and inventory.root_derived_source_reference_count == 0
        and inventory.resource_runtime_analysis_complete
        and not inventory.resource_runtime_truncated
        and inventory.resource_locator_match_count == 1
        and inventory.resource_handle_chain_count == 1
        and inventory.resource_pointer_size_chain_count == 1
        and inventory.resource_runtime_source_count == 1
    )
    return bool(common and (exact_direct or root_derived_direct or resource_runtime))


def _public_opaque_source_use_summary(
    inventory: OpaqueWideHexUseInventory | None,
) -> dict[str, object]:
    """addressやcandidate値を含めず、同一pathの局所証拠だけを返す。"""

    unique = _unique_opaque_source_use(inventory)
    operations = (
        set(inventory.transform_operation_kinds)
        if inventory is not None and unique
        else set()
    )
    if inventory is None:
        status = "invalid_or_unavailable_pe_view"
    elif not inventory.reference_set_complete:
        status = (
            "reference_scan_limit_exceeded"
            if inventory.reference_set_truncated
            else "reference_instruction_decode_incomplete"
        )
    elif (
        inventory.source_operand_reference_count == 0
        and inventory.root_derived_source_reference_count == 0
        and inventory.resource_runtime_source_count == 0
    ):
        status = "candidate_source_operand_not_proven"
    elif not inventory.bounded_analysis_complete:
        status = "bounded_callsite_analysis_incomplete"
    elif unique:
        status = "bounded_same_path_transform_semantics_observed"
    else:
        status = "candidate_use_not_unique_or_transform_unproven"
    return {
        "status": status,
        "bounded_analysis_complete": bool(
            inventory is not None
            and inventory.reference_set_complete
            and inventory.bounded_analysis_complete
        ),
        "reference_set_complete": bool(
            inventory is not None and inventory.reference_set_complete
        ),
        "reference_set_truncated": bool(
            inventory is not None and inventory.reference_set_truncated
        ),
        "candidate_address_occurrence_count_in_executable": (
            (
                inventory.raw_reference_count
                if inventory.decoded_literal_reference_count is None
                else inventory.decoded_literal_reference_count
            )
            if inventory is not None
            else 0
        ),
        "decoded_source_operand_reference_count": (
            inventory.source_operand_reference_count if inventory is not None else 0
        ),
        "root_derived_source_operand_reference_count": (
            inventory.root_derived_source_reference_count
            if inventory is not None
            else 0
        ),
        "anchored_source_reference_count": (
            inventory.anchored_source_reference_count if inventory is not None else 0
        ),
        "same_path_staging_call_chain_count": (
            inventory.staging_call_chain_count if inventory is not None else 0
        ),
        "same_path_semantic_transform_chain_count": (
            inventory.semantic_transform_chain_count if inventory is not None else 0
        ),
        "source_function_count": (
            len(inventory.source_roots) if inventory is not None else 0
        ),
        "unique_same_path_transform_chain": unique,
        "resource_runtime_pointer_lineage": {
            "locator_match_count": (
                inventory.resource_locator_match_count if inventory is not None else 0
            ),
            "handle_chain_count": (
                inventory.resource_handle_chain_count if inventory is not None else 0
            ),
            "pointer_size_chain_count": (
                inventory.resource_pointer_size_chain_count
                if inventory is not None
                else 0
            ),
            "runtime_source_count": (
                inventory.resource_runtime_source_count if inventory is not None else 0
            ),
            "analysis_complete": bool(
                inventory is not None
                and inventory.resource_runtime_analysis_complete
            ),
            "truncated": bool(
                inventory is not None and inventory.resource_runtime_truncated
            ),
            "scanned_instruction_count": (
                inventory.resource_runtime_scanned_instruction_count
                if inventory is not None
                else 0
            ),
            "root_strategy": "export_tls_verified_direct_call_graph",
            "resource_identifiers_included": False,
            "raw_resource_pointer_included": False,
            "raw_addresses_included": False,
        },
        "root_address_lineage": {
            "derived_source_reference_count": (
                inventory.root_derived_source_reference_count
                if inventory is not None
                else 0
            ),
            "analysis_complete": bool(
                inventory is not None
                and inventory.root_address_lineage_analysis_complete
            ),
            "truncated": bool(
                inventory is not None
                and inventory.root_address_lineage_truncated
            ),
            "verified_root_count": (
                inventory.root_address_lineage_root_count
                if inventory is not None
                else 0
            ),
            "reachable_function_count": (
                inventory.root_address_lineage_function_count
                if inventory is not None
                else 0
            ),
            "scanned_bytes": (
                inventory.root_address_lineage_scanned_byte_count
                if inventory is not None
                else 0
            ),
            "scanned_instructions": (
                inventory.root_address_lineage_scanned_instruction_count
                if inventory is not None
                else 0
            ),
            "maximum_functions": (
                MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_FUNCTIONS
            ),
            "maximum_call_graph_depth": (
                MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_DEPTH
            ),
            "maximum_bytes": MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_BYTES,
            "maximum_instructions": (
                MAX_OPAQUE_WIDE_HEX_ROOT_LINEAGE_INSTRUCTIONS
            ),
            "root_strategy": "export_tls_verified_file_backed_direct_call_graph",
            "accepted_constructions": [
                "image_base_plus_rva",
                "file_backed_section_base_plus_offset",
                "adjacent_call_pop_pic_plus_offset",
                "known_32_bit_register_affine_value",
            ],
            "memory_aliases_followed": False,
            "arithmetic_wrap_allowed": False,
            "raw_addresses_included": False,
        },
        "candidate_and_writable_destination_share_staging_call": unique,
        "cdecl_stack_cleanup_matches_staging_arguments": unique,
        "destination_register_preserved_to_next_direct_call": unique,
        "transform_writes_through_destination_register": unique,
        "transform_reads_candidate_or_staged_object_byte": unique,
        "connected_in_bounds_destination_byte_store": unique,
        "byte_transform_operations": {
            mnemonic: mnemonic in operations
            for mnemonic in sorted(_BYTE_TRANSFORM_MNEMONICS)
        },
        "minimum_distinct_byte_transform_operations": (
            MIN_OPAQUE_WIDE_HEX_TRANSFORM_KINDS
        ),
        "reference_scan": {
            "mode": (
                inventory.reference_scan_mode
                if inventory is not None
                else "unavailable"
            ),
            "raw_candidate_va_occurrence_count": (
                inventory.raw_candidate_occurrence_count
                if inventory is not None
                else None
            ),
            "local_literal_instruction_start_count": (
                inventory.local_literal_instruction_start_count
                if inventory is not None
                else 0
            ),
            "local_direct_caller_count": (
                inventory.local_direct_caller_count
                if inventory is not None
                else 0
            ),
            "local_scanned_bytes": (
                inventory.local_scanned_byte_count
                if inventory is not None
                else 0
            ),
            "scanned_bytes": (
                inventory.scanned_byte_count if inventory is not None else 0
            ),
            "maximum_bytes": (
                MAX_OPAQUE_WIDE_HEX_REFERENCE_SCAN_BYTES
                + (
                    MAX_OPAQUE_WIDE_HEX_LOCAL_SCAN_BYTES
                    if inventory is not None
                    and inventory.reference_scan_mode
                    == "raw_unique_local_resynchronization"
                    else 0
                )
            ),
            "maximum_raw_scan_bytes": (
                MAX_OPAQUE_WIDE_HEX_REFERENCE_SCAN_BYTES
            ),
            "scanned_instructions": (
                inventory.scanned_instruction_count
                if inventory is not None
                else 0
            ),
            "maximum_instructions": (
                MAX_OPAQUE_WIDE_HEX_REFERENCE_SCAN_INSTRUCTIONS
            ),
            "maximum_literal_or_source_references": (
                MAX_OPAQUE_WIDE_HEX_REFERENCE_MATCHES
            ),
            "maximum_direct_calls": MAX_OPAQUE_WIDE_HEX_DIRECT_CALLS,
            "maximum_local_caller_candidates": (
                MAX_OPAQUE_WIDE_HEX_LOCAL_CALLER_CANDIDATES
            ),
            "maximum_local_scan_bytes": (
                MAX_OPAQUE_WIDE_HEX_LOCAL_SCAN_BYTES
            ),
            "maximum_local_scan_instructions": (
                MAX_OPAQUE_WIDE_HEX_LOCAL_SCAN_INSTRUCTIONS
            ),
            "anchored_window_count": (
                inventory.anchored_window_count if inventory is not None else 0
            ),
            "maximum_anchored_windows": MAX_OPAQUE_WIDE_HEX_ANCHORED_WINDOWS,
            "maximum_callsite_bytes_per_window": (
                MAX_OPAQUE_WIDE_HEX_CALLSITE_BYTES
            ),
            "maximum_callsite_instructions_per_window": (
                MAX_OPAQUE_WIDE_HEX_CALLSITE_INSTRUCTIONS
            ),
            "anchored_scanned_bytes": (
                inventory.anchored_scanned_byte_count
                if inventory is not None
                else 0
            ),
            "maximum_anchored_scan_bytes": (
                MAX_OPAQUE_WIDE_HEX_ANCHORED_SCAN_BYTES
            ),
            "anchored_scanned_instructions": (
                inventory.anchored_scanned_instruction_count
                if inventory is not None
                else 0
            ),
            "maximum_anchored_scan_instructions": (
                MAX_OPAQUE_WIDE_HEX_ANCHORED_SCAN_INSTRUCTIONS
            ),
            "maximum_post_stage_instructions": (
                MAX_OPAQUE_WIDE_HEX_POST_STAGE_INSTRUCTIONS
            ),
            "maximum_transform_bytes_per_target": (
                MAX_OPAQUE_WIDE_HEX_TRANSFORM_BYTES
            ),
            "maximum_transform_instructions_per_target": (
                MAX_OPAQUE_WIDE_HEX_TRANSFORM_INSTRUCTIONS
            ),
            "exact_candidate_va_operands_only": bool(
                inventory is None
                or inventory.root_derived_source_reference_count == 0
            ),
            "arbitrary_four_byte_matches_used_as_evidence": False,
            "candidate_rva_used_as_reference": False,
            "immediate_register_lineage_tracked": True,
            "root_derived_candidate_va_lineage_tracked": True,
        },
        "concrete_decoder_recovered": False,
        "decoded_plaintext_recovered": False,
        "config_parser_proven": False,
        "runtime_endpoint_to_connect_proven": False,
        "same_socket_send_receive_proven": False,
        "evidence_scope": "route_refinement_only",
        "raw_values_included": False,
        "raw_addresses_included": False,
    }


def probe_export_funnel_route(data: bytes) -> dict[str, object]:
    """未復号export-funnel型をroute-onlyで検出する。

    import/resource/exportの形状とfile内IAT call候補は、次の静的解析器を
    選ぶためにだけ使う。family/C2確定には使わない。
    """

    unmatched = {
        "matched": False,
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "terminal_network_lineage_proven": False,
        "sample_executed": False,
        "network_contacted": False,
    }
    if (
        not isinstance(data, bytes)
        or not data.startswith(b"MZ")
        or len(data) > MAX_INPUT_SIZE
    ):
        return unmatched
    try:
        image = pefile.PE(data=data, fast_load=False)
        machine = int(image.FILE_HEADER.Machine)
        characteristics = int(image.FILE_HEADER.Characteristics)
    except (pefile.PEFormatError, AttributeError, TypeError, ValueError, OverflowError):
        return unmatched
    if machine != 0x14C or not characteristics & _DLL:
        return unmatched
    roots = collect_external_code_roots(image, data)
    resources = _resource_leaves(image, data)
    opaque_inventory = collect_opaque_wide_hex_candidates(image, data)
    imported = _imports(image)
    if roots is None or resources is None or imported is None:
        return unmatched
    import_addresses, imported_resource, imported_network = imported
    called_names = _iat_calls(image, data, import_addresses)
    if called_names is None:
        return unmatched
    called_resource = _public_groups(called_names, _RESOURCE_GROUPS)
    called_network = _public_groups(called_names, _NETWORK_GROUPS)
    high_entropy_custom = tuple(
        leaf
        for leaf in resources
        if leaf.custom_type
        and leaf.size >= MIN_RESOURCE_SIZE
        and leaf.entropy >= MIN_RESOURCE_ENTROPY
    )
    matched = bool(
        roots.export_funnel
        and roots.roots
        and len(high_entropy_custom) >= MIN_CUSTOM_HIGH_ENTROPY_RESOURCES
        and all(imported_resource.values())
        and all(imported_network.values())
        and all(called_resource.values())
        and all(called_network.values())
    )
    if not matched:
        return unmatched

    cfg_status = "not_attempted"
    cfg_complete = False
    cfg_coverage: dict[str, object] = {}
    if high_entropy_custom:
        first = high_entropy_custom[0]
        flow = analyze_x86_pe_dataflow(
            data,
            image,
            roots=roots.roots,
            sources=(
                NativeSource(
                    "resource_candidate",
                    first.address,
                    min(first.size, 0x10000),
                    "opaque",
                ),
            ),
            limits=NativeFlowLimits(
                max_functions=128,
                max_instructions=20_000,
                max_instructions_per_function=2_048,
                max_block_states=30_000,
                max_memory_cells=128,
                max_value_tokens=32,
            ),
        )
        cfg_status = str(flow.get("status", "unknown"))
        cfg_complete = flow.get("analysis_complete") is True
        coverage = flow.get("coverage")
        if isinstance(coverage, dict):
            cfg_coverage = {
                key: coverage.get(key)
                for key in (
                    "function_count",
                    "instruction_count",
                    "direct_edge_count",
                    "callback_edge_count",
                    "unresolved_indirect_count",
                    "invalid_decode_count",
                    "budget_exhausted",
                )
            }

    opaque_candidates = (
        opaque_inventory.candidates if opaque_inventory is not None else ()
    )
    opaque_unique = bool(
        opaque_inventory is not None
        and opaque_inventory.candidate_set_complete
        and len(opaque_candidates) == 1
    )
    opaque_flow_summary: dict[str, object] = {
        "status": "not_attempted_candidate_not_unique",
        "analysis_complete": False,
        "terminal_network_lineage_proven": False,
        "proof": {},
        "missing_proof_codes": ["opaque_config_candidate_not_unique"],
        "coverage": {},
        "raw_addresses_included": False,
        "raw_source_values_included": False,
        "analysis_root_scope": "external_entry_roots",
    }
    opaque_use_inventory: OpaqueWideHexUseInventory | None = None
    opaque_source_use_unique = False
    if opaque_unique:
        candidate = opaque_candidates[0]
        containing_resource_leaves = tuple(
            leaf
            for leaf in resources
            if leaf.address <= candidate.address
            and candidate.address + candidate.byte_size <= leaf.address + leaf.size
        )
        resource_leaf = (
            containing_resource_leaves[0]
            if len(containing_resource_leaves) == 1
            else None
        )
        opaque_use_inventory = collect_opaque_wide_hex_use_evidence(
            image,
            data,
            candidate,
            external_roots=roots.roots,
            resource_leaf=resource_leaf,
            import_addresses=(import_addresses if resource_leaf is not None else None),
        )
        opaque_source_use_unique = _unique_opaque_source_use(opaque_use_inventory)
        opaque_analysis_roots = (
            opaque_use_inventory.source_roots
            if opaque_source_use_unique and opaque_use_inventory is not None
            else roots.roots
        )
        opaque_flow = analyze_x86_pe_dataflow(
            data,
            image,
            roots=opaque_analysis_roots,
            sources=(
                NativeSource(
                    "opaque_wide_hex_candidate",
                    candidate.address,
                    min(candidate.byte_size, 0x10000),
                    "opaque",
                ),
            ),
            limits=NativeFlowLimits(
                max_functions=128,
                max_instructions=20_000,
                max_instructions_per_function=2_048,
                max_block_states=30_000,
                max_memory_cells=128,
                max_value_tokens=32,
            ),
        )
        opaque_flow_summary = _public_flow_summary(opaque_flow)
        opaque_flow_summary["analysis_root_scope"] = (
            "single_bounded_source_function"
            if opaque_source_use_unique
            else "external_entry_roots"
        )

    opaque_source_use_summary = _public_opaque_source_use_summary(opaque_use_inventory)

    character_counts = [item.character_count for item in opaque_candidates]
    normalized_counts = [item.normalized_byte_count for item in opaque_candidates]
    entropies = [item.normalized_entropy for item in opaque_candidates]
    opaque_summary = {
        "candidate_count": len(opaque_candidates),
        "candidate_set_complete": (
            opaque_inventory.candidate_set_complete
            if opaque_inventory is not None
            else False
        ),
        "candidate_set_truncated": (
            opaque_inventory.candidate_set_truncated
            if opaque_inventory is not None
            else False
        ),
        "unique_candidate": opaque_unique,
        "scanned_byte_count": (
            opaque_inventory.scanned_byte_count if opaque_inventory is not None else 0
        ),
        "minimum_character_count": min(character_counts, default=0),
        "maximum_character_count": max(character_counts, default=0),
        "minimum_normalized_byte_count": min(normalized_counts, default=0),
        "maximum_normalized_byte_count": max(normalized_counts, default=0),
        "odd_nibble_candidate_count": sum(
            item.odd_nibble_count for item in opaque_candidates
        ),
        "minimum_normalized_entropy": round(min(entropies, default=0.0), 4),
        "source_permissions": "writable_non_executable_mapped_section",
        "nul_terminated": bool(opaque_candidates),
        "raw_values_included": False,
        "raw_addresses_included": False,
    }
    return {
        "matched": True,
        "variant": "native_export_funnel_resource_network_route",
        "attribution_scope": "component_handler_route",
        "supports_family_attribution": False,
        "decoded_config_recovered": False,
        "candidate_config_recovered": False,
        "encoded_config_candidate_observed": opaque_unique,
        "recovery_status": (
            "opaque_candidate_transform_path_only"
            if opaque_source_use_unique
            else "opaque_encoded_candidate_only"
            if opaque_unique
            else "not_recovered"
        ),
        "terminal_family_confirmed": False,
        "terminal_network_lineage_proven": False,
        "evidence": {
            "architecture": "x86",
            "dll": True,
            "export_count": roots.export_count,
            "export_target_count": roots.export_target_count,
            "all_exports_share_one_target": roots.export_funnel,
            "tls_directory_present": roots.tls_directory_present,
            "tls_callback_root_count": len(roots.tls_roots),
            "external_cfg_root_count": len(roots.roots),
            "resource_leaf_count": len(resources),
            "custom_high_entropy_resource_count": len(high_entropy_custom),
            "imported_resource_groups": imported_resource,
            "imported_network_groups": imported_network,
            "file_backed_iat_resource_call_groups": called_resource,
            "file_backed_iat_network_call_groups": called_network,
            "external_root_cfg_status": cfg_status,
            "external_root_cfg_complete": cfg_complete,
            "external_root_cfg_coverage": cfg_coverage,
            "opaque_wide_hex_candidate": opaque_summary,
            "opaque_wide_hex_source_flow": opaque_flow_summary,
            "opaque_wide_hex_source_use": opaque_source_use_summary,
            "recovery_boundary": {
                "encoded_representation_observed": opaque_unique,
                "encoded_source_operand_reference_proven": (opaque_source_use_unique),
                "bounded_staging_transform_path_observed": (opaque_source_use_unique),
                "decoded_plaintext_recovered": False,
                "config_parser_proven": False,
                "runtime_endpoint_constructed": False,
                "runtime_endpoint_to_connect_proven": False,
                "same_socket_send_receive_proven": False,
            },
            "lineage_gap": (
                "concrete_decoder_config_parser_and_network_sink_unproven"
                if opaque_source_use_unique
                else "decoded_config_and_source_to_network_sink_unproven"
            ),
            "export_names_included": False,
            "resource_labels_included": False,
            "raw_addresses_included": False,
            "raw_resource_bytes_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


__all__ = [
    "ExternalCodeRoots",
    "OpaqueWideHexCandidate",
    "OpaqueWideHexInventory",
    "OpaqueWideHexUseInventory",
    "collect_external_code_roots",
    "collect_opaque_wide_hex_candidates",
    "collect_opaque_wide_hex_use_evidence",
    "probe_export_funnel_route",
]
