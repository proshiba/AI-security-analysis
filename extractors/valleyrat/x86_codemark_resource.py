"""x86 codemark shellcodeをPE resourceから実行せず復元する。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from itertools import pairwise
from typing import Any

import pefile

from extractors.valleyrat.nvml_dat import NvmlDatError, parse_codemark_config

MINIMUM_STAGE_SIZE = 512
MAXIMUM_STAGE_SIZE = 4 * 1024 * 1024
MINIMUM_CODE_SIZE = 1_024
MAXIMUM_CODE_SIZE = 1024 * 1024
MINIMUM_INSTRUCTION_COUNT = 128
MAXIMUM_INSTRUCTION_COUNT = 200_000
MAXIMUM_OUTER_SIZE = 64 * 1024 * 1024
MAXIMUM_RESOURCE_LEAVES = 512
MAXIMUM_RESOURCE_DIRECTORY_NODES = 2_048
MAXIMUM_RESOURCE_BYTES_SCANNED = 32 * 1024 * 1024
MAXIMUM_CODEMARK_CANDIDATES = 32
MAXIMUM_CODEMARK_CANDIDATE_BYTES = 16 * 1024 * 1024
MAXIMUM_TOTAL_DISASSEMBLY_INSTRUCTIONS = 400_000
MAXIMUM_EXECUTABLE_SECTION_BYTES = 32 * 1024 * 1024
MAXIMUM_SECTION_COUNT = 96
MAXIMUM_IMPORT_DESCRIPTOR_COUNT = 96
MAXIMUM_IMPORT_COUNT = 8_192
MAXIMUM_RESOURCE_HELPER_SPAN = 128
MAXIMUM_HELPER_TO_PROCESS_DISTANCE = 512
MAXIMUM_RESOURCE_NAME_SETUP = 384
MAXIMUM_RESOURCE_CALL_TAIL = 24
MAXIMUM_LINKED_RESOURCE_NAMES = 32
MAXIMUM_RESOURCE_CALLER_SIZE = 4_096
MAXIMUM_ENTRY_FUNCTION_SPAN = 1_024
MAXIMUM_MAIN_FUNCTION_SPAN = 4_096
MAXIMUM_RESOURCE_HELPER_FUNCTION_SPAN = 512
MAXIMUM_OUTER_REACHABLE_FUNCTIONS = 128
MAXIMUM_OUTER_FUNCTION_INSTRUCTIONS = 16_384
MAXIMUM_OUTER_CFG_INSTRUCTIONS = 200_000
MAXIMUM_PROCESS_ARGUMENT_SCAN = 192
MAXIMUM_PROCESS_DATAFLOW_STATES = 4_096
CODEMARK = b"codemark"

_EXPORT_DIRECTORY_OFFSETS = frozenset({0x18, 0x1C, 0x20, 0x24, 0x3C, 0x78})
_WINSOCK_LITERAL_GROUPS = {
    "winsock_library": (b"ws2_", b"32.d", b"ll"),
    "winsock_startup": (b"WSAS", b"tart", b"up"),
    "name_resolution": (b"geta", b"ddri", b"nfo"),
    "socket_creation": (b"sock", b"et"),
    "port_conversion": (b"hton",),
    "connection": (b"conn", b"ect"),
    "send": (b"send",),
    "receive": (b"recv",),
    "close": (b"clos", b"esoc", b"ket"),
}
_RESOURCE_HELPER_APIS = (
    b"GetModuleHandleW",
    b"FindResourceW",
    b"LoadResource",
    b"SizeofResource",
    b"LockResource",
)
_CREATE_PROCESS_API = b"CreateProcessW"
_EXECUTABLE_SECTION = 0x20000000
_I386_MACHINE = 0x014C
_RESOURCE_NAME_VECTOR_XOR = bytes.fromhex(
    "0f2804240f574424100f294424100f284424600f574424200f29442420"
)
_OUTER_MODRM_OPCODES = frozenset(
    {
        *range(0x04),
        *range(0x08, 0x0C),
        *range(0x10, 0x14),
        *range(0x18, 0x1C),
        *range(0x20, 0x24),
        *range(0x28, 0x2C),
        *range(0x30, 0x34),
        *range(0x38, 0x3C),
        0x62,
        0x63,
        *range(0x84, 0x90),
        *range(0xD0, 0xD4),
        *range(0xD8, 0xE0),
        0xFE,
        0xFF,
    }
)


class X86CodemarkResourceError(ValueError):
    """PE resourceまたはx86 shellcodeの検証に失敗した場合の例外。"""


@dataclass(frozen=True)
class X86CodemarkResourceRecovery:
    """公開要約と非公開の終端stage／configを分離して保持する。"""

    outer_sha256: str
    stage: bytes
    stage_sha256: str
    config: dict[str, Any]
    occurrences: tuple[dict[str, object], ...]
    structural_evidence: dict[str, object]
    resource_leaf_count: int
    unique_resource_locator_count: int
    scanned_resource_bytes: int
    disassembly_instruction_count: int
    outer_loader_evidence: dict[str, object]


@dataclass(frozen=True)
class _HelperOutputLink:
    """resource helper呼出しと出力wstring objectの静的対応。"""

    call_rva: int
    object_stack_offset: int
    output_register: int
    inline_carrier_register: int
    inline_definition_rva: int


def public_recovery_summary(
    recovery: X86CodemarkResourceRecovery,
) -> dict[str, object]:
    """endpoint、resource bytes、code、鍵を含まない要約を返す。"""

    slots = recovery.config["slots"]
    return {
        "status": "validated_x86_codemark_resource_config",
        "outer_sha256": recovery.outer_sha256,
        "stage_sha256": recovery.stage_sha256,
        "stage_size": len(recovery.stage),
        "resource_leaf_count": recovery.resource_leaf_count,
        "unique_resource_locator_count": recovery.unique_resource_locator_count,
        "scanned_resource_bytes": recovery.scanned_resource_bytes,
        "resource_occurrence_count": len(recovery.occurrences),
        "duplicate_resource_count": max(0, len(recovery.occurrences) - 1),
        "unique_stage_count": 1,
        "disassembly_instruction_count": recovery.disassembly_instruction_count,
        "resources": [dict(item) for item in recovery.occurrences],
        "structural_evidence": dict(recovery.structural_evidence),
        "outer_loader_evidence": dict(recovery.outer_loader_evidence),
        "config": {
            "slot_count": len(slots),
            "active_endpoint_count": len(recovery.config["endpoints"]),
            "disabled_slot_count": sum(
                item.get("enabled") is False for item in slots
            ),
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "raw_resource_included": False,
        "raw_resource_identifiers_included": False,
        "raw_code_included": False,
        "raw_key_included": False,
        "sample_executed": False,
        "stage_executed": False,
        "network_contacted": False,
    }


def _modrm_span(
    data: bytes,
    offset: int,
) -> tuple[int, int, int | None] | None:
    """32-bit ModR/M、SIB、displacementだけを有界に読み取る。"""

    if offset >= len(data):
        return None
    modrm = data[offset]
    position = offset + 1
    mode = modrm >> 6
    register_or_memory = modrm & 7
    displacement_size = 0
    if mode != 3 and register_or_memory == 4:
        if position >= len(data):
            return None
        sib = data[position]
        position += 1
        if mode == 0 and sib & 7 == 5:
            displacement_size = 4
    elif mode == 0 and register_or_memory == 5:
        displacement_size = 4
    if mode == 1:
        displacement_size = 1
    elif mode == 2:
        displacement_size = 4
    if position + displacement_size > len(data):
        return None
    displacement: int | None = None
    if displacement_size == 1:
        displacement = data[position]
        if displacement >= 0x80:
            displacement -= 0x100
    elif displacement_size == 4:
        displacement = int.from_bytes(
            data[position : position + 4], "little", signed=True
        )
    return position + displacement_size, modrm, displacement


def _decode_x86_instruction(
    data: bytes,
    offset: int,
) -> tuple[int, int, int | None, int | None, tuple[int, ...], bool] | None:
    """対象stageで必要なx86-32命令だけを決定的に長さ復号する。"""

    position = offset
    operand_size = 4
    fs_prefix = False
    prefix_count = 0
    while position < len(data) and data[position] in {
        0x26,
        0x2E,
        0x36,
        0x3E,
        0x64,
        0x65,
        0x66,
        0x67,
        0xF0,
        0xF2,
        0xF3,
    }:
        prefix = data[position]
        position += 1
        prefix_count += 1
        if prefix_count > 8 or prefix == 0x67:
            return None
        if prefix == 0x64:
            fs_prefix = True
        if prefix == 0x66:
            operand_size = 2
    if position >= len(data):
        return None
    opcode = data[position]
    position += 1
    opcode_key = opcode
    modrm: int | None = None
    displacement: int | None = None
    immediates: tuple[int, ...] = ()

    if opcode == 0x0F:
        if position >= len(data):
            return None
        secondary = data[position]
        position += 1
        opcode_key = 0x0F00 | secondary
        if 0x80 <= secondary <= 0x8F:
            if position + operand_size > len(data):
                return None
            position += operand_size
        elif secondary in {
            0x10,
            0x11,
            0x1F,
            0x40,
            0x41,
            0x42,
            0x43,
            0x44,
            0x45,
            0x46,
            0x47,
            0x48,
            0x49,
            0x4A,
            0x4B,
            0x4C,
            0x4D,
            0x4E,
            0x4F,
            0xB6,
            0xB7,
            0xBE,
            0xBF,
        }:
            parsed = _modrm_span(data, position)
            if parsed is None:
                return None
            position, modrm, displacement = parsed
        else:
            return None
    elif (
        0x40 <= opcode <= 0x5F
        or opcode in {0x90, 0xC3, 0xC9, 0xCB, 0xCC, 0x9C, 0x9D}
    ):
        pass
    elif opcode in {
        0x05,
        0x68,
        0xB8,
        0xB9,
        0xBA,
        0xBB,
        0xBC,
        0xBD,
        0xBE,
        0xBF,
    }:
        if position + operand_size > len(data):
            return None
        immediate = int.from_bytes(data[position : position + operand_size], "little")
        immediates = (immediate,)
        position += operand_size
    elif opcode == 0x6A:
        if position >= len(data):
            return None
        immediates = (data[position],)
        position += 1
    elif 0x70 <= opcode <= 0x7F or opcode in {0xEB, 0xE3}:
        if position >= len(data):
            return None
        position += 1
    elif opcode in {0xE8, 0xE9}:
        if position + operand_size > len(data):
            return None
        position += operand_size
    elif opcode == 0xA1:
        if position + 4 > len(data):
            return None
        immediates = (int.from_bytes(data[position : position + 4], "little"),)
        position += 4
    elif opcode == 0xC2:
        if position + 2 > len(data):
            return None
        position += 2
    elif opcode in {
        0x03,
        0x21,
        0x23,
        0x30,
        0x31,
        0x32,
        0x33,
        0x39,
        0x3B,
        0x84,
        0x85,
        0x89,
        0x8A,
        0x8B,
        0x8D,
        0xFF,
    }:
        parsed = _modrm_span(data, position)
        if parsed is None:
            return None
        position, modrm, displacement = parsed
    elif opcode in {0x80, 0x83, 0xC0, 0xC1, 0xC6}:
        parsed = _modrm_span(data, position)
        if parsed is None:
            return None
        position, modrm, displacement = parsed
        if position >= len(data):
            return None
        immediates = (data[position],)
        position += 1
    elif opcode in {0x81, 0xC7}:
        parsed = _modrm_span(data, position)
        if parsed is None:
            return None
        position, modrm, displacement = parsed
        if position + operand_size > len(data):
            return None
        immediate = int.from_bytes(data[position : position + operand_size], "little")
        immediates = (immediate,)
        position += operand_size
    elif opcode == 0xF7:
        parsed = _modrm_span(data, position)
        if parsed is None:
            return None
        position, modrm, displacement = parsed
        if modrm >> 3 & 7 == 0:
            if position + operand_size > len(data):
                return None
            immediate = int.from_bytes(
                data[position : position + operand_size], "little"
            )
            immediates = (immediate,)
            position += operand_size
    else:
        return None
    if position <= offset or position > len(data) or position - offset > 15:
        return None
    return position, opcode_key, modrm, displacement, immediates, fs_prefix


def _raw_x86_control_transfer(
    data: bytes,
    offset: int,
    decoded: tuple[int, int, int | None, int | None, tuple[int, ...], bool],
) -> tuple[str, int | None]:
    """復号済みraw命令のcontrol種別と相対分岐先を返す。"""

    end, opcode, modrm, _displacement, _immediates, _fs_prefix = decoded
    if opcode in {0xC2, 0xC3, 0xCB, 0xCC}:
        return "terminal", None
    if opcode == 0xFF and modrm is not None:
        operation = modrm >> 3 & 7
        if operation in {4, 5}:
            return "terminal", None
        if operation in {2, 3}:
            return "indirect_call", None
    relative_size = 0
    control = "fallthrough"
    if 0x70 <= opcode <= 0x7F or opcode == 0xE3:
        relative_size = 1
        control = "conditional"
    elif opcode == 0xEB:
        relative_size = 1
        control = "jump"
    elif opcode in {0xE8, 0xE9} or 0x0F80 <= opcode <= 0x0F8F:
        position = offset
        operand_size = 4
        prefix_count = 0
        while position < end and data[position] in {
            0x26,
            0x2E,
            0x36,
            0x3E,
            0x64,
            0x65,
            0x66,
            0xF0,
            0xF2,
            0xF3,
        }:
            if data[position] == 0x66:
                operand_size = 2
            position += 1
            prefix_count += 1
            if prefix_count > 8:
                return "terminal", None
        relative_size = operand_size
        control = (
            "call"
            if opcode == 0xE8
            else "jump"
            if opcode == 0xE9
            else "conditional"
        )
    if relative_size == 0 or end - relative_size < offset:
        return control, None
    relative = int.from_bytes(
        data[end - relative_size : end],
        "little",
        signed=True,
    )
    return control, end + relative


def _reachable_raw_x86_instructions(
    code: bytes,
) -> tuple[
    dict[
        int,
        tuple[int, int, int | None, int | None, tuple[int, ...], bool],
    ],
    dict[int, tuple[int, ...]],
] | None:
    """offset 0から到達するraw x86命令だけを有界CFGとして返す。"""

    if not code:
        return None
    pending = [0]
    instructions: dict[
        int,
        tuple[int, int, int | None, int | None, tuple[int, ...], bool],
    ] = {}
    successors: dict[int, tuple[int, ...]] = {}
    occupied: set[int] = set()
    while pending:
        position = pending.pop()
        while 0 <= position < len(code):
            if position in instructions:
                break
            if position in occupied:
                return None
            decoded = _decode_x86_instruction(code, position)
            if decoded is None:
                return None
            end = decoded[0]
            if len(instructions) >= MAXIMUM_INSTRUCTION_COUNT:
                return None
            if any(index in occupied for index in range(position, end)):
                return None
            for index in range(position, end):
                occupied.add(index)
            instructions[position] = decoded
            control, target = _raw_x86_control_transfer(
                code,
                position,
                decoded,
            )
            next_offsets: list[int] = []
            if control in {"fallthrough", "call", "indirect_call"}:
                if end < len(code):
                    next_offsets.append(end)
                if control == "call" and target is not None and 0 <= target < len(code):
                    next_offsets.append(target)
            elif control == "conditional":
                if end < len(code):
                    next_offsets.append(end)
                if target is None or not 0 <= target < len(code):
                    return None
                next_offsets.append(target)
            elif control == "jump":
                if target is None or not 0 <= target < len(code):
                    return None
                next_offsets.append(target)
            successors[position] = tuple(dict.fromkeys(next_offsets))
            for next_offset in next_offsets[1:]:
                if next_offset not in instructions:
                    pending.append(next_offset)
            if control in {"jump", "terminal"} or not next_offsets:
                break
            position = next_offsets[0]
    return instructions, successors


def _instruction_evidence(data: bytes) -> dict[str, object] | None:
    """codemark前をoffset 0起点CFGで復号し、独立構造を検証する。"""

    if data.count(CODEMARK) != 1:
        return None
    marker_offset = data.find(CODEMARK)
    if not MINIMUM_CODE_SIZE <= marker_offset <= MAXIMUM_CODE_SIZE:
        return None
    code = data[:marker_offset]
    reachable = _reachable_raw_x86_instructions(code)
    if reachable is None:
        return None
    instructions, _successors = reachable
    instruction_count = len(instructions)
    peb_read_count = 0
    ror13_count = 0
    indirect_call_count = 0
    memory_decode_count = 0
    displacements: set[int] = set()
    displacement_addresses: dict[int, list[int]] = {}
    immediates: set[int] = set()
    peb_read_addresses: list[int] = []
    ror13_addresses: list[int] = []
    indirect_call_addresses: list[int] = []
    memory_decode_addresses: list[int] = []
    api_fragments = {
        name: {fragment: False for fragment in fragments}
        for name, fragments in _WINSOCK_LITERAL_GROUPS.items()
    }
    previous_register_calls: dict[int, int] = {}
    close_register_call_pair = False
    decoded_byte_count = 0
    for instruction_address in sorted(instructions):
        decoded = instructions[instruction_address]
        (
            end,
            opcode,
            modrm,
            displacement,
            instruction_immediates,
            fs_prefix,
        ) = decoded
        decoded_byte_count += end - instruction_address
        mode = modrm >> 6 if modrm is not None else 3
        operation = modrm >> 3 & 7 if modrm is not None else -1
        register_or_memory = modrm & 7 if modrm is not None else -1
        if displacement is not None:
            absolute_displacement = abs(displacement)
            if absolute_displacement:
                displacements.add(absolute_displacement)
                addresses = displacement_addresses.get(absolute_displacement)
                if addresses is None:
                    addresses = []
                    displacement_addresses[absolute_displacement] = addresses
                addresses.append(instruction_address)
        for immediate in instruction_immediates:
            immediates.add(immediate & 0xFFFFFFFF)
        if fs_prefix and (
            (opcode == 0xA1 and instruction_immediates == (0x30,))
            or (opcode == 0x8B and mode != 3 and displacement == 0x30)
        ):
            peb_read_count += 1
            peb_read_addresses.append(instruction_address)
        if opcode == 0xC1 and operation == 1 and instruction_immediates == (13,):
            ror13_count += 1
            ror13_addresses.append(instruction_address)
        if opcode in {0xC6, 0xC7} and mode != 3:
            instruction_bytes = code[instruction_address:end]
            for fragments in api_fragments.values():
                for fragment in fragments:
                    if fragment in instruction_bytes:
                        fragments[fragment] = True
        if opcode in {0x30, 0x31} and mode != 3:
            memory_decode_count += 1
            memory_decode_addresses.append(instruction_address)
        if opcode == 0xFF and operation == 2:
            indirect_call_count += 1
            indirect_call_addresses.append(instruction_address)
            if mode == 3:
                previous = previous_register_calls.get(register_or_memory)
                if (
                    previous is not None
                    and instruction_address - previous <= 16
                ):
                    close_register_call_pair = True
                previous_register_calls[register_or_memory] = instruction_address

    coverage = decoded_byte_count / len(code) if code else 0.0
    export_offsets = sorted(_EXPORT_DIRECTORY_OFFSETS & displacements)
    winsock_groups = {
        name: all(fragments.values())
        for name, fragments in api_fragments.items()
    }
    resolver_peb_addresses = [
        address
        for address in peb_read_addresses
        if sum(0 <= ror - address <= 256 for ror in ror13_addresses) >= 2
        and all(
            any(
                0 <= displacement_address - address <= 256
                for displacement_address in displacement_addresses.get(offset, [])
            )
            for offset in _EXPORT_DIRECTORY_OFFSETS
        )
    ]
    decoded_stage_transfer = any(
        call_address > decode_address
        for decode_address in memory_decode_addresses
        for call_address in indirect_call_addresses
    )
    required_immediates = {0x40, 0x1000}
    if not (
        instruction_count >= MINIMUM_INSTRUCTION_COUNT
        and coverage >= 0.98
        and peb_read_count >= 1
        and ror13_count >= 2
        and resolver_peb_addresses
        and len(export_offsets) == len(_EXPORT_DIRECTORY_OFFSETS)
        and all(winsock_groups.values())
        and required_immediates.issubset(immediates)
        and indirect_call_count >= 8
        and memory_decode_count >= 1
        and close_register_call_pair
        and decoded_stage_transfer
    ):
        return None
    return {
        "architecture": "x86",
        "code_size": len(code),
        "instruction_count": instruction_count,
        "instruction_coverage": round(coverage, 6),
        "peb_fs30_read_count": peb_read_count,
        "ror13_count": ror13_count,
        "export_directory_offset_count": len(export_offsets),
        "localized_peb_ror13_export_resolver_present": True,
        "winsock_api_group_count": sum(winsock_groups.values()),
        "winsock_api_groups": winsock_groups,
        "winsock_names_built_by_memory_immediates": True,
        "rwx_allocation_constants_present": True,
        "indirect_call_count": indirect_call_count,
        "memory_decode_present": True,
        "close_register_call_pair_present": True,
        "decoded_stage_indirect_transfer_present": True,
        "codemark_offset": marker_offset,
    }


def analyze_raw_stage(
    data: bytes,
) -> tuple[dict[str, Any], dict[str, object]] | None:
    """x86コード形状と厳密なcodemark configを同時に検証する。"""

    if (
        not isinstance(data, bytes)
        or not MINIMUM_STAGE_SIZE <= len(data) <= MAXIMUM_STAGE_SIZE
    ):
        return None
    if data.startswith((b"MZ", b"PK\x03\x04", bytes.fromhex("d0cf11e0a1b11ae1"))):
        return None
    evidence = _instruction_evidence(data)
    if evidence is None:
        return None
    try:
        config = parse_codemark_config(data)
    except NvmlDatError:
        return None
    if not config.get("endpoints") or not config.get("slots"):
        return None
    return config, evidence


def _identifier(entry: object, label: str) -> str | int:
    """resource識別子を制御文字なしの有界値へ正規化する。"""

    name = getattr(entry, "name", None)
    if name is not None:
        value = str(name)
        if not value or len(value) > 128 or any(
            ord(character) < 0x20 or ord(character) == 0x7F
            for character in value
        ):
            raise X86CodemarkResourceError(f"{label}名が不正です")
        return value
    value = getattr(entry, "id", None)
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 65535:
        raise X86CodemarkResourceError(f"{label} IDが不正です")
    return value


def _bounded_resource_entries(
    directory: object,
    label: str,
    node_count: list[int],
) -> tuple[object, ...]:
    """resource directory nodeを追加前に数え、上限内だけmaterializeする。"""

    try:
        entries = directory.entries
        iterator = iter(entries)
    except (AttributeError, TypeError) as exc:
        raise X86CodemarkResourceError(
            f"{label} directory entriesが不正です"
        ) from exc
    bounded: list[object] = []
    for entry in iterator:
        node_count[0] += 1
        if node_count[0] > MAXIMUM_RESOURCE_DIRECTORY_NODES:
            raise X86CodemarkResourceError(
                "resource directory node件数が上限を超えています"
            )
        bounded.append(entry)
    return tuple(bounded)


def _public_resource_identifier(
    value: object,
    label: str,
) -> dict[str, object]:
    """resource識別子をordinalまたはdomain-separated hashとして公開する。"""

    if isinstance(value, int) and not isinstance(value, bool):
        return {"kind": "ordinal", "value": value}
    text = str(value)
    digest = hashlib.sha256(
        label.encode("ascii") + b"\0" + text.encode("utf-8")
    ).hexdigest()
    return {
        "kind": "name_sha256",
        "sha256": digest,
        "character_count": len(text),
    }


def _public_resource_metadata(
    metadata: dict[str, object],
) -> dict[str, object]:
    """IOCを含み得るresource名を除いた公開locator要約を返す。"""

    return {
        "type": _public_resource_identifier(metadata.get("type"), "type"),
        "name": _public_resource_identifier(metadata.get("name"), "name"),
        "language": _public_resource_identifier(
            metadata.get("language"),
            "language",
        ),
        "size": metadata.get("size"),
        "sha256": metadata.get("sha256"),
        "raw_resource_identifiers_included": False,
    }


def _normalized_import_library(descriptor: object) -> str | None:
    """import descriptorのDLL名をbasename・casefoldした値へ正規化する。"""

    value = getattr(descriptor, "dll", None)
    if isinstance(value, bytes):
        try:
            text = value.decode("ascii", errors="strict")
        except UnicodeError:
            return None
    elif isinstance(value, str):
        text = value
    else:
        return None
    normalized = text.replace("\\", "/").rsplit("/", 1)[-1].strip().casefold()
    return normalized or None


def _required_import_addresses(image: object) -> dict[bytes, int] | None:
    """同一KERNEL32 descriptorから必要なIAT addressを有界に得る。"""

    required = set(_RESOURCE_HELPER_APIS)
    required.add(_CREATE_PROCESS_API)
    import_count = 0
    required_descriptors: list[dict[bytes, int]] = []
    try:
        descriptors = list(image.DIRECTORY_ENTRY_IMPORT)
        if not descriptors or len(descriptors) > MAXIMUM_IMPORT_DESCRIPTOR_COUNT:
            return None
        for descriptor in descriptors:
            imports = list(descriptor.imports)
            descriptor_addresses: dict[bytes, int] = {}
            for imported in imports:
                import_count += 1
                if import_count > MAXIMUM_IMPORT_COUNT:
                    return None
                name = imported.name
                if name not in required:
                    continue
                if _normalized_import_library(descriptor) != "kernel32.dll":
                    return None
                address = int(imported.address)
                if not 0 < address <= 0xFFFFFFFF:
                    return None
                previous = descriptor_addresses.get(name)
                if previous is not None and previous != address:
                    return None
                descriptor_addresses[name] = address
            if descriptor_addresses:
                required_descriptors.append(descriptor_addresses)
    except (AttributeError, OverflowError, TypeError, ValueError):
        return None
    if (
        len(required_descriptors) != 1
        or set(required_descriptors[0]) != required
    ):
        return None
    return required_descriptors[0]


def _bounded_executable_sections(
    data: bytes,
    image: object,
) -> list[tuple[int, bytes]] | None:
    """outer PEの実行可能sectionをfile boundary内だけで返す。"""

    try:
        machine = int(image.FILE_HEADER.Machine)
        sections = list(image.sections)
    except (AttributeError, OverflowError, TypeError, ValueError):
        return None
    if machine != _I386_MACHINE or not sections or len(sections) > MAXIMUM_SECTION_COUNT:
        return None
    executable: list[tuple[int, bytes]] = []
    total_size = 0
    for section in sections:
        try:
            characteristics = int(section.Characteristics)
            raw_offset = int(section.PointerToRawData)
            raw_size = int(section.SizeOfRawData)
            virtual_address = int(section.VirtualAddress)
        except (AttributeError, OverflowError, TypeError, ValueError):
            return None
        if characteristics & _EXECUTABLE_SECTION == 0:
            continue
        if (
            raw_offset < 0
            or raw_size <= 0
            or virtual_address < 0
            or raw_offset + raw_size > len(data)
        ):
            return None
        total_size += raw_size
        if total_size > MAXIMUM_EXECUTABLE_SECTION_BYTES:
            return None
        executable.append(
            (virtual_address, data[raw_offset : raw_offset + raw_size])
        )
    if not executable:
        return None
    return executable


def _decode_outer_x86_instruction(
    data: bytes,
    offset: int,
    section_rva: int,
) -> tuple[int, str, int | None, int | None] | None:
    """outer x86の命令長とcontrol-transferを15 bytes以内で復号する。"""

    start = offset
    position = offset
    operand_size = 4
    address_size_override = False
    prefix_count = 0
    while position < len(data) and data[position] in {
        0x26,
        0x2E,
        0x36,
        0x3E,
        0x64,
        0x65,
        0x66,
        0x67,
        0xF0,
        0xF2,
        0xF3,
    }:
        prefix = data[position]
        position += 1
        prefix_count += 1
        if prefix == 0x66:
            operand_size = 2
        elif prefix == 0x67:
            address_size_override = True
        if prefix_count > 8:
            return None
    # 16-bit ModR/M address形式は意図的に対象外とし、誤った境界を作らない。
    if address_size_override or position >= len(data):
        return None

    opcode = data[position]
    position += 1
    control = "fallthrough"
    target: int | None = None
    iat_target: int | None = None
    modrm: int | None = None
    displacement: int | None = None
    immediate_size = 0

    if opcode == 0x0F:
        if position >= len(data):
            return None
        secondary = data[position]
        position += 1
        if 0x80 <= secondary <= 0x8F:
            immediate_size = operand_size
            control = "conditional"
        elif secondary == 0x0B:
            control = "terminal"
        elif secondary in {
            0x05,
            0x06,
            0x07,
            0x08,
            0x09,
            0x0E,
            0x30,
            0x31,
            0x32,
            0x33,
            0x34,
            0x35,
            0x37,
            0x77,
            0xA0,
            0xA1,
            0xA2,
            0xA8,
            0xA9,
            0xAA,
        } or 0xC8 <= secondary <= 0xCF:
            pass
        elif secondary in {0x38, 0x3A}:
            if position >= len(data):
                return None
            position += 1
            parsed = _modrm_span(data, position)
            if parsed is None:
                return None
            position, modrm, displacement = parsed
            if secondary == 0x3A:
                immediate_size = 1
        else:
            parsed = _modrm_span(data, position)
            if parsed is None:
                return None
            position, modrm, displacement = parsed
            if secondary in {
                0x0F,
                0x70,
                0x71,
                0x72,
                0x73,
                0xA4,
                0xAC,
                0xBA,
                0xC2,
                0xC4,
                0xC5,
                0xC6,
            }:
                immediate_size = 1
    elif 0x70 <= opcode <= 0x7F or 0xE0 <= opcode <= 0xE3:
        immediate_size = 1
        control = "conditional"
    elif opcode == 0xE8:
        immediate_size = operand_size
        control = "call"
    elif opcode in {0xE9, 0xEB}:
        immediate_size = operand_size if opcode == 0xE9 else 1
        control = "jump"
    elif opcode in {0xC2, 0xCA}:
        immediate_size = 2
        control = "terminal"
    elif opcode in {0xC3, 0xCB, 0xCC, 0xCE, 0xCF, 0xF1, 0xF4}:
        control = "terminal"
    elif (
        0x40 <= opcode <= 0x61
        or 0x90 <= opcode <= 0x99
        or 0x9B <= opcode <= 0x9F
        or 0xA4 <= opcode <= 0xA7
        or 0xAA <= opcode <= 0xAF
        or 0xEC <= opcode <= 0xEF
        or opcode == 0xF5
        or 0xF8 <= opcode <= 0xFD
        or opcode
        in {
            0x06,
            0x07,
            0x0E,
            0x16,
            0x17,
            0x1E,
            0x1F,
            0x27,
            0x2F,
            0x37,
            0x3F,
            0x6C,
            0x6D,
            0x6E,
            0x6F,
            0xD6,
            0xD7,
        }
    ):
        pass
    elif 0xB0 <= opcode <= 0xB7:
        immediate_size = 1
    elif 0xB8 <= opcode <= 0xBF or opcode == 0x68:
        immediate_size = operand_size
    elif opcode == 0x6A:
        immediate_size = 1
    elif opcode in {0xA0, 0xA1, 0xA2, 0xA3}:
        immediate_size = 4
    elif opcode in {
        0x04,
        0x0C,
        0x14,
        0x1C,
        0x24,
        0x2C,
        0x34,
        0x3C,
        0xA8,
        0xCD,
        0xD4,
        0xD5,
        0xE4,
        0xE5,
        0xE6,
        0xE7,
    }:
        immediate_size = 1
    elif opcode in {
        0x05,
        0x0D,
        0x15,
        0x1D,
        0x25,
        0x2D,
        0x35,
        0x3D,
        0xA9,
    }:
        immediate_size = operand_size
    elif opcode == 0xC8:
        immediate_size = 3
    elif opcode == 0x9A:
        immediate_size = operand_size + 2
        control = "indirect_call"
    elif opcode == 0xEA:
        immediate_size = operand_size + 2
        control = "terminal"
    elif opcode in _OUTER_MODRM_OPCODES or opcode in {
        0x69,
        0x6B,
        0x80,
        0x81,
        0x82,
        0x83,
        0xC0,
        0xC1,
        0xC4,
        0xC5,
        0xC6,
        0xC7,
        0xF6,
        0xF7,
    }:
        # VEX prefixをLES/LDSとして誤復号しない。
        if (
            opcode in {0xC4, 0xC5}
            and position < len(data)
            and data[position] & 0xC0 == 0xC0
        ):
            return None
        parsed = _modrm_span(data, position)
        if parsed is None:
            return None
        position, modrm, displacement = parsed
        operation = modrm >> 3 & 7
        if opcode in {0x6B, 0x80, 0x82, 0x83, 0xC0, 0xC1, 0xC6}:
            immediate_size = 1
        elif opcode in {0x69, 0x81, 0xC7}:
            immediate_size = operand_size
        elif opcode == 0xF6 and operation in {0, 1}:
            immediate_size = 1
        elif opcode == 0xF7 and operation in {0, 1}:
            immediate_size = operand_size
        if opcode == 0xFF:
            if operation in {2, 3}:
                control = "indirect_call"
                if modrm & 0xC7 == 0x05 and displacement is not None:
                    iat_target = displacement & 0xFFFFFFFF
            elif operation in {4, 5}:
                control = "terminal"
    else:
        return None

    if position + immediate_size > len(data):
        return None
    if control in {"call", "jump", "conditional"}:
        relative = int.from_bytes(
            data[position : position + immediate_size],
            "little",
            signed=True,
        )
        target = section_rva + position + immediate_size + relative
    position += immediate_size
    if position <= start or position - start > 15:
        return None
    return position, control, target, iat_target


def _rva_in_executable_sections(
    sections: list[tuple[int, bytes]],
    rva: int,
) -> bool:
    """RVAが検証済み実行可能section内ならtrueを返す。"""

    return any(start <= rva < start + len(code) for start, code in sections)


def _reachable_outer_function(
    sections: list[tuple[int, bytes]],
    function_rva: int,
    maximum_span: int,
) -> tuple[
    dict[int, tuple[int, str, int | None, int | None]],
    dict[int, tuple[int, ...]],
] | None:
    """命令境界とterminatorを守り、function startから到達するCFGを返す。"""

    section_rva = -1
    code = b""
    start_offset = -1
    end_offset = -1
    for candidate_rva, candidate_code in sections:
        offset = function_rva - candidate_rva
        if 0 <= offset < len(candidate_code):
            section_rva = candidate_rva
            code = candidate_code
            start_offset = offset
            end_offset = min(len(code), offset + maximum_span)
            break
    if start_offset < 0 or end_offset <= start_offset:
        return None

    pending = [function_rva]
    instructions: dict[int, tuple[int, str, int | None, int | None]] = {}
    successors: dict[int, tuple[int, ...]] = {}
    occupied: set[int] = set()
    while pending:
        current_rva = pending.pop()
        while function_rva <= current_rva < section_rva + end_offset:
            if current_rva in instructions:
                break
            if current_rva in occupied:
                return None
            current_offset = current_rva - section_rva
            decoded = _decode_outer_x86_instruction(
                code,
                current_offset,
                section_rva,
            )
            if decoded is None:
                break
            end, control, target, iat_target = decoded
            end_rva = section_rva + end
            if end > end_offset:
                break
            if len(instructions) >= MAXIMUM_OUTER_FUNCTION_INSTRUCTIONS:
                return None
            if any(address in occupied for address in range(current_rva, end_rva)):
                return None
            for address in range(current_rva, end_rva):
                occupied.add(address)
            instructions[current_rva] = (end_rva, control, target, iat_target)

            next_rvas: list[int] = []
            if control in {"fallthrough", "call", "indirect_call"}:
                if end < end_offset:
                    next_rvas.append(end_rva)
            elif control == "conditional":
                if end < end_offset:
                    next_rvas.append(end_rva)
                if target is not None:
                    target_offset = target - section_rva
                    if start_offset <= target_offset < end_offset:
                        next_rvas.append(target)
                    # 共有throw helper等への外向き分岐は、現在functionの
                    # CFGへ混ぜず、fallthrough側だけを継続する。
            elif control == "jump" and target is not None:
                target_offset = target - section_rva
                if start_offset <= target_offset < end_offset:
                    next_rvas.append(target)
            successors[current_rva] = tuple(dict.fromkeys(next_rvas))

            if control == "jump":
                for next_rva in next_rvas:
                    if next_rva not in instructions:
                        pending.append(next_rva)
                break
            for next_rva in next_rvas[1:]:
                if next_rva not in instructions:
                    pending.append(next_rva)
            if control == "terminal" or not next_rvas:
                break
            current_rva = next_rvas[0]

    if not instructions:
        return None
    return instructions, successors


def _cfg_reaches(
    successors: dict[int, tuple[int, ...]],
    start: int,
    target: int,
) -> bool:
    """同一functionの検証済みCFG内でtargetへ到達できるかを有界に調べる。"""

    pending = [start]
    cursor = 0
    visited: set[int] = set()
    while cursor < len(pending):
        current = pending[cursor]
        cursor += 1
        if current == target:
            return True
        if current in visited:
            continue
        visited.add(current)
        if len(visited) > MAXIMUM_OUTER_FUNCTION_INSTRUCTIONS:
            return False
        for successor in successors.get(current, ()):
            if successor not in visited:
                pending.append(successor)
    return False


def _direct_local_targets(
    sections: list[tuple[int, bytes]],
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    *,
    require_frame_prologue: bool = True,
) -> set[int]:
    """到達命令にあるdirect call／tail jump先の通常functionだけを返す。"""

    targets: set[int] = set()
    for _end, control, target, _iat_target in instructions.values():
        if (
            control in {"call", "jump"}
            and target is not None
            and _rva_in_executable_sections(sections, target)
            and (
                not require_frame_prologue
                or _function_prologue_present(sections, target)
            )
        ):
            targets.add(target)
    return targets


def _direct_calls_to(
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    target_rva: int,
) -> set[int]:
    """到達済み命令から指定functionへ向くdirect call siteだけを返す。"""

    return {
        address
        for address, (_end, control, target, _iat_target) in instructions.items()
        if control == "call" and target == target_rva
    }


def _iat_sites_in_function(
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    import_addresses: dict[bytes, int],
) -> dict[bytes, list[int]]:
    """到達済み命令境界にあるIAT indirect callだけをAPI別に返す。"""

    names_by_address = {
        address: name for name, address in import_addresses.items()
    }
    sites = {name: [] for name in import_addresses}
    for address, (_end, control, _target, iat_target) in instructions.items():
        if control != "indirect_call" or iat_target is None:
            continue
        name = names_by_address.get(iat_target)
        if name is not None:
            sites[name].append(address)
    return sites


def _reachable_resource_helper_sequence(
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    successors: dict[int, tuple[int, ...]],
    import_addresses: dict[bytes, int],
) -> tuple[int, ...] | None:
    """同一helperの到達CFGにある一意なresource API列だけを採用する。"""

    sites = _iat_sites_in_function(instructions, import_addresses)
    sequence: list[int] = []
    for name in _RESOURCE_HELPER_APIS:
        current = sites.get(name, [])
        if len(current) != 1:
            return None
        sequence.append(current[0])
    if max(sequence) - min(sequence) > MAXIMUM_RESOURCE_HELPER_SPAN:
        return None
    if any(
        not _cfg_reaches(successors, first, second)
        for first, second in pairwise(sequence)
    ):
        return None
    return tuple(sequence)


def _cfg_dominates(
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    successors: dict[int, tuple[int, ...]],
    dominator: int,
    target: int,
) -> bool:
    """function entry起点CFGでdominatorがtargetを支配するか判定する。"""

    if dominator not in instructions or target not in instructions:
        return False
    entry = min(instructions)
    nodes = set(instructions)
    predecessors = {node: set() for node in nodes}
    for source, targets in successors.items():
        for destination in targets:
            if source in nodes and destination in nodes:
                predecessors[destination].add(source)
    dominators = {
        node: ({entry} if node == entry else set(nodes))
        for node in nodes
    }
    changed = True
    iterations = 0
    while changed:
        changed = False
        iterations += 1
        if iterations > len(nodes):
            return False
        for node in sorted(nodes - {entry}):
            incoming = predecessors[node]
            if not incoming:
                updated = {node}
            else:
                common = set(nodes)
                for predecessor in incoming:
                    common = common & dominators[predecessor]
                updated = common | {node}
            if updated != dominators[node]:
                dominators[node] = updated
                changed = True
    return dominator in dominators[target]


def _binary_resource_type_argument(
    data: bytes,
    image: object,
    value: int,
) -> bool:
    """FindResourceW type引数がordinalまたはUTF-16のBINを指すか確認する。"""

    if value == 10:
        return True
    try:
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
        sections = list(image.sections)
    except (AttributeError, OverflowError, TypeError, ValueError):
        return False
    rva = value - image_base if value >= image_base else value
    if rva < 0:
        return False
    for section in sections:
        try:
            virtual_address = int(section.VirtualAddress)
            raw_offset = int(section.PointerToRawData)
            raw_size = int(section.SizeOfRawData)
        except (AttributeError, OverflowError, TypeError, ValueError):
            return False
        offset = rva - virtual_address
        if (
            0 <= offset
            and offset + 8 <= raw_size
            and raw_offset + offset + 8 <= len(data)
        ):
            return data[raw_offset + offset : raw_offset + offset + 8] == (
                b"B\0I\0N\0\0\0"
            )
    return False


def _pushed_symbol(
    raw: bytes,
    registers: dict[int, str],
) -> tuple[str, object] | None:
    """単一push命令をsymbolic argumentへ変換する。"""

    decoded = _decode_x86_instruction(raw, 0)
    if decoded is None or decoded[0] != len(raw):
        return None
    opcode = decoded[1]
    if 0x50 <= opcode <= 0x57:
        return ("symbol", registers.get(opcode - 0x50, "unknown"))
    if opcode in {0x68, 0x6A} and decoded[4]:
        return ("immediate", decoded[4][0] & 0xFFFFFFFF)
    return None


def _resource_helper_dataflow(
    data: bytes,
    image: object,
    sections: list[tuple[int, bytes]],
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    successors: dict[int, tuple[int, ...]],
    import_addresses: dict[bytes, int],
    sequence: tuple[int, ...],
) -> bool:
    """resource APIの引数・戻り値flowとCFG支配を限定抽象実行で検証する。"""

    if len(sequence) != len(_RESOURCE_HELPER_APIS) or any(
        not _cfg_dominates(instructions, successors, first, second)
        for first, second in pairwise(sequence)
    ):
        return False
    api_by_address = {
        address: name
        for name, address in import_addresses.items()
        if name in _RESOURCE_HELPER_APIS
    }
    expected_sites = dict(zip(sequence, _RESOURCE_HELPER_APIS, strict=True))
    registers: dict[int, str] = {}
    pushes: list[tuple[str, object]] = []
    observed: list[bytes] = []
    for address in sorted(instructions):
        if address > sequence[-1]:
            break
        end, control, _target, iat_target = instructions[address]
        raw = _bytes_at_rva(sections, address, end - address)
        if raw is None:
            return False
        decoded = _decode_x86_instruction(raw, 0)
        if decoded is None or decoded[0] != len(raw):
            return False
        opcode, modrm = decoded[1], decoded[2]
        pushed = _pushed_symbol(raw, registers)
        if pushed is not None:
            pushes.append(pushed)
            continue
        if opcode in {0x89, 0x8B} and modrm is not None:
            mode = modrm >> 6
            register = modrm >> 3 & 7
            register_or_memory = modrm & 7
            if mode == 3:
                destination, source = (
                    (register_or_memory, register)
                    if opcode == 0x89
                    else (register, register_or_memory)
                )
                value = registers.get(source)
                if value is None:
                    registers.pop(destination, None)
                else:
                    registers[destination] = value
            elif (
                opcode == 0x8B
                and _esp_stack_displacement(raw, 0) is not None
                and address < sequence[1]
            ):
                registers[register] = "resource_name_parameter"
            continue
        if control != "indirect_call" or iat_target is None:
            continue
        api_name = api_by_address.get(iat_target)
        if api_name is None:
            pushes.clear()
            registers.pop(0, None)
            continue
        if expected_sites.get(address) != api_name:
            return False
        if api_name == b"GetModuleHandleW":
            if not pushes or pushes[-1] != ("immediate", 0):
                return False
            result_symbol = "module_handle"
        elif api_name == b"FindResourceW":
            if len(pushes) < 3:
                return False
            type_argument, name_argument, module_argument = pushes[-3:]
            if (
                type_argument[0] != "immediate"
                or not isinstance(type_argument[1], int)
                or not _binary_resource_type_argument(
                    data,
                    image,
                    type_argument[1],
                )
                or name_argument != ("symbol", "resource_name_parameter")
                or module_argument != ("symbol", "module_handle")
            ):
                return False
            result_symbol = "resource_info_handle"
        elif api_name == b"LoadResource":
            if pushes[-2:] != [
                ("symbol", "resource_info_handle"),
                ("symbol", "module_handle"),
            ]:
                return False
            result_symbol = "loaded_resource_handle"
        elif api_name == b"SizeofResource":
            if pushes[-2:] != [
                ("symbol", "resource_info_handle"),
                ("symbol", "module_handle"),
            ]:
                return False
            result_symbol = "resource_size"
        elif api_name == b"LockResource":
            if pushes[-1:] != [("symbol", "loaded_resource_handle")]:
                return False
            result_symbol = "resource_pointer"
        else:
            return False
        observed.append(api_name)
        pushes.clear()
        registers[0] = result_symbol
    return tuple(observed) == _RESOURCE_HELPER_APIS


def _esp_stack_displacement(
    data: bytes,
    instruction_offset: int,
) -> int | None:
    """ModR/M operandが32-bit `[esp+disp]`ならdispを返す。"""

    position = instruction_offset
    prefix_count = 0
    while position < len(data) and data[position] in {
        0x26,
        0x2E,
        0x36,
        0x3E,
        0x64,
        0x65,
        0x66,
        0xF0,
        0xF2,
        0xF3,
    }:
        position += 1
        prefix_count += 1
        if prefix_count > 8:
            return None
    if position >= len(data):
        return None
    if data[position] == 0x0F:
        position += 2
    else:
        position += 1
    if position + 1 >= len(data):
        return None
    modrm = data[position]
    mode = modrm >> 6
    if mode == 3 or modrm & 7 != 4 or data[position + 1] != 0x24:
        return None
    displacement_offset = position + 2
    if mode == 0:
        return 0
    if mode == 1 and displacement_offset < len(data):
        displacement = data[displacement_offset]
        return displacement - 0x100 if displacement >= 0x80 else displacement
    if mode == 2 and displacement_offset + 4 <= len(data):
        return int.from_bytes(
            data[displacement_offset : displacement_offset + 4],
            "little",
            signed=True,
        )
    return None


def _constant_stack_before(
    code: bytes,
    start: int,
    end: int,
    initial_registers: dict[int, int],
) -> dict[int, int] | None:
    """直線code片のregister定数と`[esp+disp]` dwordだけを抽象実行する。"""

    registers = initial_registers.copy()
    stack: dict[int, int] = {}
    carry: int | None = None
    position = start
    instruction_count = 0
    while position < end:
        instruction_offset = position
        decoded = _decode_x86_instruction(code, position)
        if decoded is None or decoded[0] > end:
            return None
        position, opcode, modrm, _displacement, immediates, _fs_prefix = decoded
        instruction_count += 1
        if instruction_count > 256:
            return None
        mode = modrm >> 6 if modrm is not None else 3
        operation = modrm >> 3 & 7 if modrm is not None else -1
        register = modrm >> 3 & 7 if modrm is not None else -1
        register_or_memory = modrm & 7 if modrm is not None else -1
        if 0xB8 <= opcode <= 0xBF and immediates:
            registers[opcode - 0xB8] = immediates[0] & 0xFFFFFFFF
        elif opcode == 0x05 and immediates:
            current = registers.get(0)
            if current is None:
                return None
            total = current + immediates[0]
            registers[0] = total & 0xFFFFFFFF
            carry = 1 if total > 0xFFFFFFFF else 0
        elif opcode in {0x81, 0x83} and mode == 3 and immediates:
            current = registers.get(register_or_memory)
            if current is None:
                return None
            supplied = immediates[0]
            if opcode == 0x83 and supplied >= 0x80:
                supplied -= 0x100
            addend = supplied & 0xFFFFFFFF
            if operation == 0:
                total = current + addend
            elif operation == 2 and carry is not None:
                total = current + addend + carry
            else:
                return None
            registers[register_or_memory] = total & 0xFFFFFFFF
            carry = 1 if total > 0xFFFFFFFF else 0
        elif opcode == 0x89 and modrm is not None:
            value = registers.get(register)
            if mode == 3:
                if value is None:
                    registers.pop(register_or_memory, None)
                else:
                    registers[register_or_memory] = value
            else:
                stack_offset = _esp_stack_displacement(code, instruction_offset)
                if stack_offset is not None:
                    if value is None:
                        stack.pop(stack_offset, None)
                    else:
                        stack[stack_offset] = value
        elif opcode == 0x8B and modrm is not None:
            if mode == 3:
                value = registers.get(register_or_memory)
            else:
                stack_offset = _esp_stack_displacement(code, instruction_offset)
                value = stack.get(stack_offset) if stack_offset is not None else None
            if value is None:
                registers.pop(register, None)
            else:
                registers[register] = value
        elif opcode == 0xC7 and modrm is not None and operation == 0 and immediates:
            stack_offset = _esp_stack_displacement(code, instruction_offset)
            if stack_offset is None:
                return None
            stack[stack_offset] = immediates[0] & 0xFFFFFFFF
        else:
            return None
    return stack if position == end else None


def _callee_saved_constant_seeds(
    code: bytes,
    start: int,
    end: int,
    instruction_boundaries: set[int],
) -> dict[int, int]:
    """直前blockから保持されるEBX/ESI/EDIの最後の即値だけをseedする。"""

    registers: dict[int, int] = {}
    for offset in range(start, max(start, end - 4)):
        if offset not in instruction_boundaries:
            continue
        opcode = code[offset]
        if opcode not in {0xBB, 0xBE, 0xBF}:
            continue
        decoded = _decode_x86_instruction(code, offset)
        if (
            decoded is not None
            and decoded[0] == offset + 5
            and decoded[1] == opcode
            and decoded[4]
        ):
            registers[opcode - 0xB8] = decoded[4][0] & 0xFFFFFFFF
    return registers


def _stack_dwords(
    stack: dict[int, int],
    offsets: tuple[int, int, int, int],
) -> bytes | None:
    """4つの既知dwordをlittle-endian 16 bytesへ変換する。"""

    values: list[bytes] = []
    for offset in offsets:
        value = stack.get(offset)
        if value is None:
            return None
        values.append(value.to_bytes(4, "little"))
    return b"".join(values)


def _resource_argument_pointer_present(
    code: bytes,
    call_offset: int,
    instruction_boundaries: set[int],
) -> bool:
    """helper第1引数が復号stack bufferを指すcall tailを確認する。"""

    start = max(0, call_offset - MAXIMUM_RESOURCE_CALL_TAIL)
    for offset in range(start, call_offset):
        if offset not in instruction_boundaries:
            continue
        decoded = _decode_x86_instruction(code, offset)
        if decoded is None:
            continue
        end, opcode, modrm, _displacement, _immediates, _fs = decoded
        if opcode != 0x8D or modrm is None:
            continue
        destination_register = modrm >> 3 & 7
        if _esp_stack_displacement(code, offset) != 0x14:
            continue
        push_pointer = _decode_x86_instruction(code, end)
        if (
            end not in instruction_boundaries
            or push_pointer is None
            or push_pointer[0] != call_offset
            or push_pointer[1] != 0x50 + destination_register
        ):
            continue
        output_pushes = [
            previous
            for previous in instruction_boundaries
            if start <= previous < offset
            and (
                decoded_previous := _decode_x86_instruction(code, previous)
            )
            is not None
            and decoded_previous[0] == offset
            and 0x50 <= decoded_previous[1] <= 0x57
        ]
        if len(output_pushes) == 1:
            return True
    return False


def _resource_name_for_call(
    code: bytes,
    call_offset: int,
    expected_names: set[str],
    instruction_boundaries: set[int],
) -> str | None:
    """call直前のbounded XOR定数からFindResource名を一意に復元する。"""

    if call_offset not in instruction_boundaries or not _resource_argument_pointer_present(
        code,
        call_offset,
        instruction_boundaries,
    ):
        return None
    minimum = max(0, call_offset - MAXIMUM_RESOURCE_NAME_SETUP)
    transform = code.rfind(_RESOURCE_NAME_VECTOR_XOR, minimum, call_offset)
    if transform < 0 or transform not in instruction_boundaries:
        return None
    initial_registers = _callee_saved_constant_seeds(
        code,
        max(0, minimum - MAXIMUM_RESOURCE_NAME_SETUP),
        minimum,
        instruction_boundaries,
    )
    matches: set[str] = set()
    for start in range(minimum, transform):
        if start not in instruction_boundaries:
            continue
        stack = _constant_stack_before(
            code,
            start,
            transform,
            initial_registers,
        )
        if stack is None:
            continue
        left = _stack_dwords(stack, (0x00, 0x04, 0x08, 0x0C))
        right = _stack_dwords(stack, (0x10, 0x14, 0x18, 0x1C))
        second_left = _stack_dwords(stack, (0x60, 0x64, 0x68, 0x6C))
        second_right = _stack_dwords(stack, (0x20, 0x24, 0x28, 0x2C))
        if (
            left is None
            or right is None
            or second_left is None
            or second_right is None
        ):
            continue
        recovered = bytes(
            first ^ second
            for first, second in zip(
                left + second_left,
                right + second_right,
            )
        )
        for name in expected_names:
            encoded = name.encode("utf-16le") + b"\0\0"
            if (
                len(encoded) <= len(recovered)
                and recovered[: len(encoded)] == encoded
                and all(value == 0 for value in recovered[len(encoded) :])
            ):
                matches.add(name)
    if len(matches) != 1:
        return None
    matched = ""
    for name in matches:
        matched = name
    return matched


def _linked_resource_names(
    sections: list[tuple[int, bytes]],
    helper_calls: set[int],
    expected_names: set[str],
    caller_instructions: dict[
        int,
        tuple[int, str, int | None, int | None],
    ],
) -> dict[int, str] | None:
    """各helper callを復号済みresource名へ一対一で結び付ける。"""

    linked: dict[int, str] = {}
    linked_names: set[str] = set()
    for call_rva in sorted(helper_calls):
        matched: str | None = None
        for section_rva, code in sections:
            if section_rva <= call_rva < section_rva + len(code):
                instruction_boundaries = {
                    address - section_rva
                    for address in caller_instructions
                    if section_rva <= address < section_rva + len(code)
                }
                matched = _resource_name_for_call(
                    code,
                    call_rva - section_rva,
                    expected_names,
                    instruction_boundaries,
                )
                break
        if matched is None or matched in linked_names:
            return None
        linked[call_rva] = matched
        linked_names.add(matched)
    if linked_names != expected_names:
        return None
    return linked


def _bytes_at_rva(
    sections: list[tuple[int, bytes]],
    rva: int,
    size: int,
) -> bytes | None:
    """実行可能section内のRVAだけをbytesへ写す。"""

    for section_rva, code in sections:
        offset = rva - section_rva
        if 0 <= offset and offset + size <= len(code):
            return code[offset : offset + size]
    return None


def _instruction_bytes(
    sections: list[tuple[int, bytes]],
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    address: int,
) -> bytes | None:
    """検証済み命令境界の1命令だけを返す。"""

    decoded = instructions.get(address)
    if decoded is None:
        return None
    end = decoded[0]
    if end <= address or end - address > 15:
        return None
    return _bytes_at_rva(sections, address, end - address)


def _opcode_position(raw: bytes) -> int | None:
    """32-bit命令の1-byte opcode位置を返す。"""

    position = 0
    while position < len(raw) and raw[position] in {
        0x26,
        0x2E,
        0x36,
        0x3E,
        0x64,
        0x65,
        0x66,
        0xF0,
        0xF2,
        0xF3,
    }:
        position += 1
        if position > 8:
            return None
    if position >= len(raw) or raw[position] == 0x0F:
        return None
    return position


def _modrm_at(raw: bytes, opcode_position: int) -> int | None:
    """1-byte opcode直後のModR/Mを境界内だけで返す。"""

    position = opcode_position + 1
    if position >= len(raw):
        return None
    return raw[position]


def _push_register(raw: bytes) -> int | None:
    position = _opcode_position(raw)
    if position is None or position + 1 != len(raw):
        return None
    opcode = raw[position]
    return opcode - 0x50 if 0x50 <= opcode <= 0x57 else None


def _pop_register(raw: bytes) -> int | None:
    position = _opcode_position(raw)
    if position is None or position + 1 != len(raw):
        return None
    opcode = raw[position]
    return opcode - 0x58 if 0x58 <= opcode <= 0x5F else None


def _lea_esp_pointer(raw: bytes) -> tuple[int, int] | None:
    """`lea reg,[esp+disp]`を(reg, disp)へ正規化する。"""

    position = _opcode_position(raw)
    if position is None or raw[position] != 0x8D:
        return None
    modrm = _modrm_at(raw, position)
    displacement = _esp_stack_displacement(raw, 0)
    if modrm is None or displacement is None:
        return None
    return modrm >> 3 & 7, displacement


def _mov_register_from_esp(raw: bytes) -> tuple[int, int] | None:
    """`mov reg,[esp+disp]`を(reg, disp)へ正規化する。"""

    position = _opcode_position(raw)
    if position is None or raw[position] != 0x8B:
        return None
    modrm = _modrm_at(raw, position)
    displacement = _esp_stack_displacement(raw, 0)
    if modrm is None or displacement is None:
        return None
    return modrm >> 3 & 7, displacement


def _mov_esp_from_register(raw: bytes) -> tuple[int, int] | None:
    """`mov [esp+disp],reg`を(disp, reg)へ正規化する。"""

    position = _opcode_position(raw)
    if position is None or raw[position] != 0x89:
        return None
    modrm = _modrm_at(raw, position)
    displacement = _esp_stack_displacement(raw, 0)
    if modrm is None or displacement is None:
        return None
    return displacement, modrm >> 3 & 7


def _register_move(raw: bytes) -> tuple[int, int] | None:
    """register間MOVを(destination, source)へ正規化する。"""

    position = _opcode_position(raw)
    if position is None or raw[position] not in {0x89, 0x8B}:
        return None
    modrm = _modrm_at(raw, position)
    if modrm is None or modrm >> 6 != 3:
        return None
    register = modrm >> 3 & 7
    register_or_memory = modrm & 7
    if raw[position] == 0x89:
        return register_or_memory, register
    return register, register_or_memory


def _tested_wstring_object(raw: bytes) -> int | None:
    """`test byte ptr [esp+object],1`のobject offsetを返す。"""

    position = _opcode_position(raw)
    if position is None or raw[position] != 0xF6 or raw[-1:] != b"\x01":
        return None
    modrm = _modrm_at(raw, position)
    displacement = _esp_stack_displacement(raw, 0)
    if (
        modrm is None
        or modrm >> 3 & 7 != 0
        or displacement is None
        or not 0 <= displacement <= 0x10000
    ):
        return None
    return displacement


def _is_zero_branch(raw: bytes) -> bool:
    """short/near JZだけをwstring表現選択のbranchとして許可する。"""

    position = 0
    while position < len(raw) and raw[position] in {
        0x26,
        0x2E,
        0x36,
        0x3E,
        0x64,
        0x65,
        0x66,
        0xF0,
        0xF2,
        0xF3,
    }:
        position += 1
    return (
        position < len(raw)
        and raw[position] == 0x74
        or position + 1 < len(raw)
        and raw[position : position + 2] == b"\x0f\x84"
    )


def _cfg_predecessors(
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    successors: dict[int, tuple[int, ...]],
) -> dict[int, set[int]]:
    predecessors = {address: set() for address in instructions}
    for source, destinations in successors.items():
        for destination in destinations:
            if destination in predecessors:
                predecessors[destination].add(source)
    return predecessors


def _unique_linear_predecessor(
    predecessors: dict[int, set[int]],
    successors: dict[int, tuple[int, ...]],
    address: int,
) -> int | None:
    candidates = predecessors.get(address, set())
    if len(candidates) != 1:
        return None
    previous = next(iter(candidates))
    return previous if successors.get(previous) == (address,) else None


def _linear_path_to(
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    successors: dict[int, tuple[int, ...]],
    start: int,
    target: int,
    *,
    maximum_instructions: int = 8,
) -> tuple[int, ...] | None:
    """単一路だけでtargetへ到達する短い命令列を返す。"""

    current = start
    path: list[int] = []
    while current != target:
        if current not in instructions or current in path:
            return None
        path.append(current)
        if len(path) > maximum_instructions:
            return None
        destinations = successors.get(current, ())
        if len(destinations) != 1:
            return None
        current = destinations[0]
    return tuple(path)


def _helper_output_link(
    sections: list[tuple[int, bytes]],
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    successors: dict[int, tuple[int, ...]],
    call_rva: int,
) -> _HelperOutputLink | None:
    """helper第2引数のwstring short/heap両経路を同一objectへ束縛する。"""

    predecessors = _cfg_predecessors(instructions, successors)
    name_push = _unique_linear_predecessor(predecessors, successors, call_rva)
    if name_push is None:
        return None
    name_lea = _unique_linear_predecessor(predecessors, successors, name_push)
    if name_lea is None:
        return None
    output_push = _unique_linear_predecessor(predecessors, successors, name_lea)
    if output_push is None:
        return None
    name_push_raw = _instruction_bytes(sections, instructions, name_push)
    name_lea_raw = _instruction_bytes(sections, instructions, name_lea)
    output_push_raw = _instruction_bytes(sections, instructions, output_push)
    if name_push_raw is None or name_lea_raw is None or output_push_raw is None:
        return None
    name_register = _push_register(name_push_raw)
    name_pointer = _lea_esp_pointer(name_lea_raw)
    output_register = _push_register(output_push_raw)
    if (
        name_register is None
        or name_pointer != (name_register, 0x14)
        or output_register is None
    ):
        return None

    matches: list[_HelperOutputLink] = []
    for conditional, (_end, control, _target, _iat) in instructions.items():
        if (
            control != "conditional"
            or not output_push - MAXIMUM_RESOURCE_CALL_TAIL <= conditional < output_push
        ):
            continue
        raw = _instruction_bytes(sections, instructions, conditional)
        destinations = successors.get(conditional, ())
        if (
            raw is None
            or not _is_zero_branch(raw)
            or len(destinations) != 2
            or destinations[1] != output_push
        ):
            continue
        heap_path = _linear_path_to(
            instructions,
            successors,
            destinations[0],
            output_push,
            maximum_instructions=3,
        )
        if heap_path is None or len(heap_path) != 1:
            continue
        heap_raw = _instruction_bytes(sections, instructions, heap_path[0])
        if heap_raw is None:
            continue
        heap_load = _mov_register_from_esp(heap_raw)
        if heap_load is None or heap_load[0] != output_register:
            continue

        before_conditional: list[int] = []
        cursor = conditional
        test_address: int | None = None
        object_offset: int | None = None
        for _ in range(5):
            cursor = _unique_linear_predecessor(
                predecessors,
                successors,
                cursor,
            )
            if cursor is None:
                break
            candidate_raw = _instruction_bytes(sections, instructions, cursor)
            if candidate_raw is None:
                break
            tested = _tested_wstring_object(candidate_raw)
            if tested is not None:
                test_address = cursor
                object_offset = tested
                break
            before_conditional.append(cursor)
        if test_address is None or object_offset is None:
            continue
        if heap_load[1] != object_offset + 8:
            continue
        values: dict[int, tuple[str, int]] = {}
        definitions: dict[int, int] = {}
        valid = True
        for address in reversed(before_conditional):
            instruction_raw = _instruction_bytes(sections, instructions, address)
            if instruction_raw is None:
                valid = False
                break
            pointer = _lea_esp_pointer(instruction_raw)
            move = _register_move(instruction_raw)
            if pointer is not None:
                register, displacement = pointer
                if displacement != object_offset + 2:
                    valid = False
                    break
                values[register] = ("inline", object_offset)
                definitions[register] = address
            elif move is not None:
                destination, source = move
                value = values.get(source)
                if value is None:
                    valid = False
                    break
                values[destination] = value
                definitions[destination] = definitions[source]
            else:
                valid = False
                break
        if not valid or values.get(output_register) != ("inline", object_offset):
            continue
        carrier_candidates = [
            (register not in {3, 6, 7}, register, definition)
            for register, value in values.items()
            if value == ("inline", object_offset)
            and (definition := definitions.get(register)) is not None
        ]
        if not carrier_candidates:
            continue
        _volatile, carrier, definition = min(carrier_candidates)
        if not (
            _cfg_dominates(instructions, successors, test_address, conditional)
            and _cfg_dominates(instructions, successors, conditional, output_push)
        ):
            continue
        matches.append(
            _HelperOutputLink(
                call_rva=call_rva,
                object_stack_offset=object_offset,
                output_register=output_register,
                inline_carrier_register=carrier,
                inline_definition_rva=definition,
            )
        )
    if len(matches) != 1:
        return None
    return matches[0]


def _esp_adjustment(raw: bytes) -> int | None:
    """命令によるcaller ESP差分を返す。非stack命令は0。"""

    if _push_register(raw) is not None:
        return -4
    if _pop_register(raw) is not None:
        return 4
    position = _opcode_position(raw)
    if position is None:
        return 0
    opcode = raw[position]
    if opcode in {0x68, 0x6A}:
        return -4
    if opcode not in {0x81, 0x83}:
        return 0
    modrm = _modrm_at(raw, position)
    if modrm is None or modrm >> 6 != 3 or modrm & 7 != 4:
        return 0
    operation = modrm >> 3 & 7
    if operation not in {0, 5}:
        return 0
    immediate_size = 1 if opcode == 0x83 else 4
    if len(raw) < immediate_size:
        return None
    value = int.from_bytes(raw[-immediate_size:], "little", signed=False)
    return value if operation == 0 else -value


def _instruction_writes_register(raw: bytes, register: int) -> bool:
    """caller内で対象GPRを上書きし得る命令を保守的に判定する。"""

    pointer = _lea_esp_pointer(raw)
    if pointer is not None:
        return pointer[0] == register
    memory_load = _mov_register_from_esp(raw)
    if memory_load is not None:
        return memory_load[0] == register
    move = _register_move(raw)
    if move is not None:
        return move[0] == register
    if _mov_esp_from_register(raw) is not None:
        return False
    position = _opcode_position(raw)
    if position is None:
        if raw[:1] == b"\x0f" and len(raw) >= 2:
            secondary = raw[1]
            if secondary in {0x10, 0x11, 0x28, 0x29, 0x57}:
                return False
        return True
    opcode = raw[position]
    if 0xB8 <= opcode <= 0xBF:
        return opcode - 0xB8 == register
    if 0x40 <= opcode <= 0x4F:
        return opcode & 7 == register
    if 0x58 <= opcode <= 0x5F:
        return opcode - 0x58 == register
    if 0x91 <= opcode <= 0x97:
        return register in {0, opcode - 0x90}
    if opcode in {
        *range(0x50, 0x58),
        0x68,
        0x6A,
        *range(0x70, 0x80),
        0x85,
        0x90,
        0xC2,
        0xC3,
        0xC6,
        0xC7,
        0xE8,
        0xE9,
        0xEB,
        0xF6,
    }:
        return False
    modrm = _modrm_at(raw, position)
    if modrm is None:
        return True
    mode = modrm >> 6
    reg_field = modrm >> 3 & 7
    register_or_memory = modrm & 7
    if opcode in {0x8A, 0x8B, 0x8D, 0x03, 0x0B, 0x13, 0x1B, 0x23, 0x2B, 0x33, 0x69, 0x6B}:
        return reg_field == register
    if opcode in {0x88, 0x89, 0x01, 0x09, 0x11, 0x19, 0x21, 0x29, 0x31, 0x81, 0x83, 0xFF}:
        return mode == 3 and register_or_memory == register
    if opcode in {0x39, 0x3B, 0x84, 0xA1, 0xA3, 0xF7}:
        return opcode == 0xA1 and register == 0
    return True


def _reverse_reachable_nodes(
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    successors: dict[int, tuple[int, ...]],
    target: int,
) -> set[int]:
    predecessors = _cfg_predecessors(instructions, successors)
    pending = [target]
    reachable: set[int] = set()
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        reachable.add(current)
        if len(reachable) > MAXIMUM_OUTER_FUNCTION_INSTRUCTIONS:
            return set()
        pending.extend(predecessors.get(current, set()) - reachable)
    return reachable


def _corridor_preserves_register_and_esp(
    sections: list[tuple[int, bytes]],
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    successors: dict[int, tuple[int, ...]],
    start: int,
    target: int,
    register: int,
    *,
    skip_start_write: bool,
) -> bool:
    """startからtargetへ至る全CFG pathでGPRとESP基準が保たれるか確認する。"""

    reaches_target = _reverse_reachable_nodes(instructions, successors, target)
    if start not in reaches_target:
        return False
    pending: list[tuple[int, int]] = [(start, 0)]
    seen: set[tuple[int, int]] = set()
    terminal_deltas: set[int] = set()
    while pending:
        address, delta = pending.pop()
        state = (address, delta)
        if state in seen:
            continue
        seen.add(state)
        if len(seen) > MAXIMUM_PROCESS_DATAFLOW_STATES:
            return False
        if address == target:
            terminal_deltas.add(delta)
            continue
        raw = _instruction_bytes(sections, instructions, address)
        if raw is None:
            return False
        if not (skip_start_write and address == start) and _instruction_writes_register(
            raw,
            register,
        ):
            return False
        adjustment = _esp_adjustment(raw)
        if adjustment is None:
            return False
        next_delta = delta + adjustment
        if not -0x10000 <= next_delta <= 0x10000:
            return False
        destinations = [
            destination
            for destination in successors.get(address, ())
            if destination in reaches_target
        ]
        if not destinations:
            return False
        for destination in destinations:
            pending.append((destination, next_delta))
    return terminal_deltas == {0}


def _callee_preserves_register(
    sections: list[tuple[int, bytes]],
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    successors: dict[int, tuple[int, ...]],
    register: int,
) -> bool:
    """prologue saveと全returnを支配するepilogue restoreを確認する。"""

    if register not in {3, 6, 7} or not instructions:
        return False
    entry = min(instructions)
    prologue_pushes = []
    pop_sites = []
    return_sites = []
    for address in sorted(instructions):
        raw = _instruction_bytes(sections, instructions, address)
        if raw is None:
            return False
        if address - entry <= 16 and _push_register(raw) == register:
            prologue_pushes.append(address)
        if _pop_register(raw) == register:
            pop_sites.append(address)
        position = _opcode_position(raw)
        if position is not None and raw[position] in {0xC2, 0xC3}:
            return_sites.append(address)
    if len(prologue_pushes) != 1 or len(pop_sites) != 1 or not return_sites:
        return False
    saved, restored = prologue_pushes[0], pop_sites[0]
    return _cfg_dominates(instructions, successors, saved, restored) and all(
        _cfg_dominates(instructions, successors, restored, address)
        for address in return_sites
    )


def _process_argument_register(
    sections: list[tuple[int, bytes]],
    instructions: dict[int, tuple[int, str, int | None, int | None]],
    successors: dict[int, tuple[int, ...]],
    process_call: int,
) -> tuple[int, int] | None:
    """CreateProcessWの40-byte引数frameとlpApplicationName registerを返す。"""

    predecessors = _cfg_predecessors(instructions, successors)
    cursor = process_call
    reverse_path: list[int] = []
    sub_rva: int | None = None
    for _ in range(32):
        cursor = _unique_linear_predecessor(predecessors, successors, cursor)
        if cursor is None:
            return None
        raw = _instruction_bytes(sections, instructions, cursor)
        if raw is None:
            return None
        if _esp_adjustment(raw) == -40:
            sub_rva = cursor
            break
        reverse_path.append(cursor)
    if sub_rva is None or process_call - sub_rva > MAXIMUM_PROCESS_ARGUMENT_SCAN:
        return None
    application_writes: list[int] = []
    for address in reversed(reverse_path):
        raw = _instruction_bytes(sections, instructions, address)
        if raw is None or _esp_adjustment(raw) != 0:
            return None
        write = _mov_esp_from_register(raw)
        if write is not None and write[0] == 0:
            application_writes.append(write[1])
            continue
        if _esp_stack_displacement(raw, 0) == 0:
            position = _opcode_position(raw)
            if position is None or raw[position] in {0x88, 0x89, 0xC6, 0xC7}:
                return None
    if len(application_writes) != 1:
        return None
    return sub_rva, application_writes[0]


def _extraction_process_dataflow(
    sections: list[tuple[int, bytes]],
    caller_instructions: dict[int, tuple[int, str, int | None, int | None]],
    caller_successors: dict[int, tuple[int, ...]],
    helper_instructions: dict[int, tuple[int, str, int | None, int | None]],
    helper_successors: dict[int, tuple[int, ...]],
    linked_resource_names: dict[int, str],
    process_call: int,
    terminal_resource_names: set[str],
) -> dict[str, object] | None:
    """helper出力wstringとCreateProcessW第1引数を全経路で照合する。"""

    links: dict[int, _HelperOutputLink] = {}
    for call_rva in linked_resource_names:
        link = _helper_output_link(
            sections,
            caller_instructions,
            caller_successors,
            call_rva,
        )
        if link is None:
            return None
        links[call_rva] = link
    object_offsets = [link.object_stack_offset for link in links.values()]
    if len(set(object_offsets)) != len(object_offsets):
        return None

    process_argument = _process_argument_register(
        sections,
        caller_instructions,
        caller_successors,
        process_call,
    )
    if process_argument is None:
        return None
    sub_rva, application_register = process_argument
    matches: list[tuple[_HelperOutputLink, int]] = []
    for conditional, (_end, control, _target, _iat) in caller_instructions.items():
        if (
            control != "conditional"
            or not process_call - MAXIMUM_PROCESS_ARGUMENT_SCAN
            <= conditional
            < sub_rva
        ):
            continue
        raw = _instruction_bytes(sections, caller_instructions, conditional)
        destinations = caller_successors.get(conditional, ())
        if raw is None or not _is_zero_branch(raw) or len(destinations) != 2:
            continue
        predecessors = _cfg_predecessors(caller_instructions, caller_successors)
        tested_at = _unique_linear_predecessor(
            predecessors,
            caller_successors,
            conditional,
        )
        if tested_at is None:
            continue
        tested_raw = _instruction_bytes(
            sections,
            caller_instructions,
            tested_at,
        )
        if tested_raw is None:
            continue
        object_offset = _tested_wstring_object(tested_raw)
        if object_offset is None:
            continue
        short_join = destinations[1]
        heap_path = _linear_path_to(
            caller_instructions,
            caller_successors,
            destinations[0],
            short_join,
            maximum_instructions=3,
        )
        if heap_path is None or len(heap_path) != 1:
            continue
        heap_raw = _instruction_bytes(
            sections,
            caller_instructions,
            heap_path[0],
        )
        if heap_raw is None or _mov_register_from_esp(heap_raw) != (
            application_register,
            object_offset + 8,
        ):
            continue
        matching_links = [
            link
            for link in links.values()
            if link.object_stack_offset == object_offset
            and link.inline_carrier_register == application_register
            and link.call_rva < conditional
        ]
        if len(matching_links) != 1:
            continue
        link = matching_links[0]
        if not _callee_preserves_register(
            sections,
            helper_instructions,
            helper_successors,
            application_register,
        ):
            continue
        if not (
            _cfg_dominates(
                caller_instructions,
                caller_successors,
                link.call_rva,
                process_call,
            )
            and _cfg_dominates(
                caller_instructions,
                caller_successors,
                tested_at,
                process_call,
            )
            and _corridor_preserves_register_and_esp(
                sections,
                caller_instructions,
                caller_successors,
                link.inline_definition_rva,
                conditional,
                application_register,
                skip_start_write=True,
            )
            and _corridor_preserves_register_and_esp(
                sections,
                caller_instructions,
                caller_successors,
                short_join,
                sub_rva,
                application_register,
                skip_start_write=False,
            )
        ):
            continue
        matches.append((link, object_offset))
    if len(matches) != 1:
        return None
    launched_link, _object_offset = matches[0]
    launched_name = linked_resource_names.get(launched_link.call_rva)
    if launched_name is None:
        return None
    terminal_direct = launched_name in terminal_resource_names
    return {
        "resource_output_argument_dataflow_validated": True,
        "resource_output_object_count": len(links),
        "resource_output_objects_unique": True,
        "create_process_application_argument_frame_validated": True,
        "create_process_application_argument_all_paths_equivalent": True,
        "launched_resource_extraction_destination_to_process_argument_proven": True,
        "launched_resource_count": 1,
        "terminal_resource_is_launched_application": terminal_direct,
        "terminal_resource_to_process_argument_proven": terminal_direct,
    }


def _function_prologue_present(
    sections: list[tuple[int, bytes]],
    rva: int,
) -> bool:
    """x86 frame pointerを作る通常function prologueだけを許容する。"""

    prefix = _bytes_at_rva(sections, rva, 3)
    return prefix in {b"\x55\x89\xe5", b"\x55\x8b\xec"}


def _outer_loader_evidence(
    data: bytes,
    image: object,
    named_binary_resources: set[str],
    candidates: list[tuple[dict[str, object], bytes]],
) -> dict[str, object] | None:
    """候補resourceが抽出・起動経路へ結び付くouterだけを採用する。"""

    if (
        not named_binary_resources
        or len(named_binary_resources) > MAXIMUM_LINKED_RESOURCE_NAMES
    ):
        return None
    candidate_in_named_binary_set = any(
        metadata.get("type") == "BIN"
        and isinstance(metadata.get("name"), str)
        and metadata.get("name") in named_binary_resources
        for metadata, _raw in candidates
    )
    if not candidate_in_named_binary_set:
        return None
    terminal_resource_names = {
        metadata["name"]
        for metadata, _raw in candidates
        if metadata.get("type") == "BIN"
        and isinstance(metadata.get("name"), str)
    }
    if not terminal_resource_names:
        return None
    import_addresses = _required_import_addresses(image)
    sections = _bounded_executable_sections(data, image)
    if import_addresses is None or sections is None:
        return None

    try:
        entrypoint = int(image.OPTIONAL_HEADER.AddressOfEntryPoint)
    except (AttributeError, OverflowError, TypeError, ValueError):
        return None
    if not _rva_in_executable_sections(sections, entrypoint):
        return None

    decoded_cache: dict[
        tuple[int, int],
        tuple[
            dict[int, tuple[int, str, int | None, int | None]],
            dict[int, tuple[int, ...]],
        ]
        | None,
    ] = {}
    total_instruction_count = 0

    def decode_function(
        function_rva: int,
        maximum_span: int,
    ) -> tuple[
        dict[int, tuple[int, str, int | None, int | None]],
        dict[int, tuple[int, ...]],
    ] | None:
        nonlocal total_instruction_count
        key = (function_rva, maximum_span)
        if key in decoded_cache:
            return decoded_cache[key]
        if len(decoded_cache) >= MAXIMUM_OUTER_REACHABLE_FUNCTIONS:
            return None
        decoded = _reachable_outer_function(
            sections,
            function_rva,
            maximum_span,
        )
        decoded_cache[key] = decoded
        if decoded is None:
            return None
        total_instruction_count += len(decoded[0])
        if total_instruction_count > MAXIMUM_OUTER_CFG_INSTRUCTIONS:
            decoded_cache[key] = None
            return None
        return decoded

    entry_decoded = decode_function(entrypoint, MAXIMUM_ENTRY_FUNCTION_SPAN)
    if entry_decoded is None:
        return None

    matches: list[
        tuple[int, int, int, set[int], dict[int, str], int, dict[str, object]]
    ] = []
    main_targets = _direct_local_targets(sections, entry_decoded[0])
    for main_target in sorted(main_targets):
        main_decoded = decode_function(main_target, MAXIMUM_MAIN_FUNCTION_SPAN)
        if main_decoded is None:
            continue
        caller_targets = _direct_local_targets(sections, main_decoded[0])
        for caller_target in sorted(caller_targets):
            caller_decoded = decode_function(
                caller_target,
                MAXIMUM_RESOURCE_CALLER_SIZE,
            )
            if caller_decoded is None:
                continue
            caller_instructions, caller_successors = caller_decoded
            process_sites = _iat_sites_in_function(
                caller_instructions,
                import_addresses,
            ).get(_CREATE_PROCESS_API, [])
            helper_targets = _direct_local_targets(
                sections,
                caller_instructions,
                require_frame_prologue=False,
            )
            for helper_target in sorted(helper_targets):
                helper_decoded = decode_function(
                    helper_target,
                    MAXIMUM_RESOURCE_HELPER_FUNCTION_SPAN,
                )
                if helper_decoded is None:
                    continue
                sequence = _reachable_resource_helper_sequence(
                    helper_decoded[0],
                    helper_decoded[1],
                    import_addresses,
                )
                if sequence is None or not _resource_helper_dataflow(
                    data,
                    image,
                    sections,
                    helper_decoded[0],
                    helper_decoded[1],
                    import_addresses,
                    sequence,
                ):
                    continue
                helper_calls = _direct_calls_to(
                    caller_instructions,
                    helper_target,
                )
                if len(helper_calls) != len(named_binary_resources):
                    continue
                ordered_helper_calls = sorted(helper_calls)
                if any(
                    not _cfg_reaches(caller_successors, first, second)
                    for first, second in pairwise(ordered_helper_calls)
                ):
                    continue
                linked_resource_names = _linked_resource_names(
                    sections,
                    helper_calls,
                    named_binary_resources,
                    caller_instructions,
                )
                if linked_resource_names is None:
                    continue
                last_helper_call = ordered_helper_calls[-1]
                linked_process_calls = [
                    address
                    for address in process_sites
                    if last_helper_call < address
                    <= last_helper_call + MAXIMUM_HELPER_TO_PROCESS_DISTANCE
                    and _cfg_reaches(
                        caller_successors,
                        last_helper_call,
                        address,
                    )
                ]
                if len(linked_process_calls) != 1:
                    continue
                terminal_resource_linked = any(
                    metadata.get("type") == "BIN"
                    and metadata.get("name") in set(linked_resource_names.values())
                    for metadata, _raw in candidates
                )
                if not terminal_resource_linked:
                    continue
                process_dataflow = _extraction_process_dataflow(
                    sections,
                    caller_instructions,
                    caller_successors,
                    helper_decoded[0],
                    helper_decoded[1],
                    linked_resource_names,
                    linked_process_calls[0],
                    terminal_resource_names,
                )
                if process_dataflow is None:
                    continue
                matches.append(
                    (
                        main_target,
                        caller_target,
                        helper_target,
                        helper_calls,
                        linked_resource_names,
                        linked_process_calls[0],
                        process_dataflow,
                    )
                )
    if len(matches) != 1:
        return None
    (
        _main_target,
        _caller_target,
        _helper_target,
        helper_calls,
        linked_resource_names,
        _process_call,
        process_dataflow,
    ) = matches[0]
    terminal_direct = bool(
        process_dataflow.get("terminal_resource_to_process_argument_proven")
    )
    return {
        "architecture": "x86",
        "resource_helper_api_sequence_cfg_linked": True,
        "resource_helper_argument_return_dataflow_validated": True,
        "resource_helper_api_cfg_dominance_validated": True,
        "resource_helper_api_count": len(_RESOURCE_HELPER_APIS),
        "resource_helper_direct_call_count": len(helper_calls),
        "named_binary_resource_count": len(named_binary_resources),
        "helper_call_count_matches_named_binary_resources": True,
        "findresource_name_argument_count": len(linked_resource_names),
        "resource_name_decode_instruction_boundary_linked": True,
        "terminal_resource_name_argument_linked": True,
        "post_extraction_process_launch_cfg_route_present": True,
        "extraction_destination_to_process_argument_proven": terminal_direct,
        "entrypoint_reachable_instruction_boundary_cfg_present": True,
        "loader_route_validated": True,
        "loader_linkage_validated": terminal_direct,
        **process_dataflow,
    }


def _resource_candidates(
    data: bytes,
) -> tuple[
    list[tuple[dict[str, object], bytes]],
    int,
    int,
    int,
    dict[str, object],
]:
    """全resource leafとouter loader linkageを上限内で検証する。"""

    if not data.startswith(b"MZ") or len(data) > MAXIMUM_OUTER_SIZE:
        raise X86CodemarkResourceError("入力は上限内のPEではありません")
    try:
        image = pefile.PE(data=data)
        resource_root = image.DIRECTORY_ENTRY_RESOURCE
    except (
        AttributeError,
        IndexError,
        KeyError,
        pefile.PEFormatError,
        TypeError,
        ValueError,
    ) as exc:
        raise X86CodemarkResourceError("PE resource directoryを解析できません") from exc

    candidates: list[tuple[dict[str, object], bytes]] = []
    leaf_count = 0
    scanned_resource_bytes = 0
    candidate_bytes = 0
    candidate_locators: set[tuple[int, int]] = set()
    locator_cache: dict[tuple[int, int], bytes | None] = {}
    named_binary_resources: set[str] = set()
    resource_node_count = [0]
    try:
        type_entries = _bounded_resource_entries(
            resource_root,
            "resource root",
            resource_node_count,
        )
        for type_entry in type_entries:
            resource_type = _identifier(type_entry, "resource type")
            names = _bounded_resource_entries(
                type_entry.directory,
                "resource type",
                resource_node_count,
            )
            for name_entry in names:
                resource_name = _identifier(name_entry, "resource name")
                if resource_type == "BIN" and isinstance(resource_name, str):
                    named_binary_resources.add(resource_name)
                languages = _bounded_resource_entries(
                    name_entry.directory,
                    "resource name",
                    resource_node_count,
                )
                for language_entry in languages:
                    leaf_count += 1
                    if leaf_count > MAXIMUM_RESOURCE_LEAVES:
                        raise X86CodemarkResourceError(
                            "resource leaf件数が上限を超えています"
                        )
                    language = _identifier(language_entry, "resource language")
                    item = language_entry.data.struct
                    rva, size = int(item.OffsetToData), int(item.Size)
                    if rva < 0 or size < 0:
                        raise X86CodemarkResourceError("resource境界が不正です")
                    if not MINIMUM_STAGE_SIZE <= size <= MAXIMUM_STAGE_SIZE:
                        continue
                    locator = (rva, size)
                    if locator not in locator_cache:
                        scanned_resource_bytes += size
                        if scanned_resource_bytes > MAXIMUM_RESOURCE_BYTES_SCANNED:
                            raise X86CodemarkResourceError(
                                "resource scan bytesが上限を超えています"
                            )
                        raw = image.get_data(rva, size)
                        if not isinstance(raw, bytes) or len(raw) != size:
                            raise X86CodemarkResourceError(
                                "resource bytesが宣言境界と一致しません"
                            )
                        if CODEMARK in raw:
                            locator_cache[locator] = raw
                        else:
                            locator_cache[locator] = None
                            raw = None
                    else:
                        raw = locator_cache[locator]
                    if raw is None:
                        continue
                    if locator not in candidate_locators:
                        candidate_locators.add(locator)
                        candidate_bytes += size
                        if (
                            len(candidate_locators) > MAXIMUM_CODEMARK_CANDIDATES
                            or candidate_bytes > MAXIMUM_CODEMARK_CANDIDATE_BYTES
                        ):
                            raise X86CodemarkResourceError(
                                "codemark resource候補が上限を超えています"
                            )
                    candidates.append(
                        (
                            {
                                "type": resource_type,
                                "name": resource_name,
                                "language": language,
                                "size": size,
                            },
                            raw,
                        )
                    )
        loader_evidence = _outer_loader_evidence(
            data,
            image,
            named_binary_resources,
            candidates,
        )
        if loader_evidence is None:
            raise X86CodemarkResourceError(
                "codemark resourceの抽出・起動linkageを検証できません"
            )
    except X86CodemarkResourceError:
        raise
    except (AttributeError, OverflowError, TypeError, ValueError) as exc:
        raise X86CodemarkResourceError("resource treeまたは境界が不正です") from exc
    return (
        candidates,
        leaf_count,
        len(locator_cache),
        scanned_resource_bytes,
        loader_evidence,
    )


def _config_identity(config: dict[str, Any]) -> tuple[tuple[object, ...], ...]:
    """disabled backupとtransportを含む相反判定用slot identityを返す。"""

    slots = config.get("slots")
    if not isinstance(slots, list) or not slots:
        raise X86CodemarkResourceError("codemark slotがありません")
    identity: list[tuple[object, ...]] = []
    for item in slots:
        if not isinstance(item, dict):
            raise X86CodemarkResourceError("codemark slot形式が不正です")
        identity.append(
            (
                item.get("index"),
                item.get("host"),
                item.get("port"),
                item.get("enabled"),
                item.get("active"),
                item.get("header_enabled"),
                item.get("transport_selector"),
                item.get("transport"),
            )
        )
    return tuple(identity)


def recover_from_pe(data: bytes) -> X86CodemarkResourceRecovery | None:
    """PE resourceから一意なx86 codemark終端だけを静的復元する。"""

    try:
        (
            resources,
            leaf_count,
            unique_resource_locator_count,
            scanned_resource_bytes,
            loader_evidence,
        ) = _resource_candidates(data)
    except X86CodemarkResourceError:
        return None
    if not resources:
        return None

    by_stage: dict[
        str,
        tuple[bytes, dict[str, Any], dict[str, object], list[dict[str, object]]],
    ] = {}
    identities: set[tuple[tuple[object, ...], ...]] = set()
    total_disassembly_instructions = 0
    for metadata, raw in resources:
        digest = hashlib.sha256(raw).hexdigest()
        previous = by_stage.get(digest)
        if previous is not None:
            if previous[0] != raw:
                return None
            previous[3].append(
                _public_resource_metadata({**metadata, "sha256": digest})
            )
            continue
        analyzed = analyze_raw_stage(raw)
        # 強い候補と弱い／破損codemarkを混在させたouterは採用しない。
        if analyzed is None:
            return None
        config, evidence = analyzed
        instruction_count = evidence.get("instruction_count")
        if isinstance(instruction_count, bool) or not isinstance(
            instruction_count, int
        ):
            return None
        total_disassembly_instructions += instruction_count
        if (
            total_disassembly_instructions
            > MAXIMUM_TOTAL_DISASSEMBLY_INSTRUCTIONS
        ):
            return None
        try:
            identities.add(_config_identity(config))
        except X86CodemarkResourceError:
            return None
        metadata = _public_resource_metadata({**metadata, "sha256": digest})
        by_stage[digest] = (raw, config, evidence, [metadata])

    # 同一stageの複製だけをdedupeする。異なるstageや相反configはfail closed。
    if len(identities) != 1 or len(by_stage) != 1:
        return None
    stage_sha256 = ""
    stage = b""
    config: dict[str, Any] = {}
    evidence: dict[str, object] = {}
    occurrences: list[dict[str, object]] = []
    for digest, recovered in by_stage.items():
        stage_sha256 = digest
        stage, config, evidence, occurrences = recovered
    occurrences.sort(
        key=lambda item: (
            str(item["type"]),
            str(item["name"]),
            str(item["language"]),
        )
    )
    return X86CodemarkResourceRecovery(
        outer_sha256=hashlib.sha256(data).hexdigest(),
        stage=stage,
        stage_sha256=stage_sha256,
        config=config,
        occurrences=tuple(occurrences),
        structural_evidence=evidence,
        resource_leaf_count=leaf_count,
        unique_resource_locator_count=unique_resource_locator_count,
        scanned_resource_bytes=scanned_resource_bytes,
        disassembly_instruction_count=total_disassembly_instructions,
        outer_loader_evidence=loader_evidence,
    )


def probe_resource_config(data: bytes) -> dict[str, object]:
    """detector向けに秘密値なしのx86 resource終端証拠だけを返す。"""

    if not isinstance(data, bytes):
        return {
            "matched": False,
            "supports_family_attribution": False,
            "static_config_recovered": False,
            "evidence": {},
            "config": {},
            "sample_executed": False,
            "network_contacted": False,
        }
    recovery = recover_from_pe(data)
    if recovery is None:
        return {
            "matched": False,
            "supports_family_attribution": False,
            "static_config_recovered": False,
            "evidence": {},
            "config": {},
            "sample_executed": False,
            "network_contacted": False,
        }
    return {
        "matched": True,
        "family": None,
        "variant": "x86_codemark_resource_terminal",
        "supports_family_attribution": False,
        "attribution_scope": "component_handler_route",
        "terminal_family_confirmed": False,
        "static_config_recovered": True,
        "evidence": public_recovery_summary(recovery),
        "config": {
            "endpoint_count": len(recovery.config["endpoints"]),
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


__all__ = [
    "X86CodemarkResourceRecovery",
    "analyze_raw_stage",
    "probe_resource_config",
    "public_recovery_summary",
    "recover_from_pe",
]
