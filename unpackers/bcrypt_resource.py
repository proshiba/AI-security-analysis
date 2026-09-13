"""BCryptを使うPE resourceローダーを実行せず、厳格に静的復元する。"""

from __future__ import annotations

import hashlib
import math
import struct
import zlib
from dataclasses import dataclass

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs, CsError
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_EAX,
    X86_REG_ECX,
    X86_REG_EDX,
)
from Cryptodome.Cipher import AES

MAX_INPUT_SIZE = 64 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 16 * 1024 * 1024
MAX_EXECUTABLE_SCAN_BYTES = MAX_INPUT_SIZE
MAX_EXECUTABLE_SECTIONS = 96
MAX_INSTRUCTIONS = 250_000
MAX_RESOURCE_ENTRIES = 512
MAX_RESOURCE_SIZE = 64 * 1024 * 1024
MAX_RESOURCE_TOTAL_SIZE = 256 * 1024 * 1024
MAX_RECIPES = 16
MAX_DECRYPT_ATTEMPTS = 256
MAX_RECOVERED_ARTIFACTS = 32
MAX_RECOVERED_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_KDF_ITERATIONS = 1_000_000
MAX_SECRET_SIZE = 4096
MAX_DECOMPRESSED_SIZE = 256 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200.0
MAX_CALL_SPAN = 0x800
MAX_ARGUMENT_INSTRUCTIONS = 24
ANCHOR_WINDOW_BEFORE = 0x400
ANCHOR_WINDOW_AFTER = 0x700
MAX_PREFLIGHT_PE_HEADER_OFFSET = 1024 * 1024
MAX_PREFLIGHT_SECTIONS = 96
MAX_PREFLIGHT_IMPORT_DESCRIPTORS = 256
MAX_PREFLIGHT_IMPORT_THUNKS = 4096
MAX_PREFLIGHT_IMPORT_NAME_SIZE = 256
MAX_PREFLIGHT_RESOURCE_DEPTH = 8
MAX_PREFLIGHT_CALL_MARKERS = 250_000
MAX_IMPORT_DESCRIPTORS = 256
MAX_IMPORT_THUNKS = 4096
MAX_DERIVE_IAT_ADDRESSES = 16

_REQUIRED_BCRYPT_APIS = frozenset(
    {
        "BCryptDecrypt",
        "BCryptDeriveKeyPBKDF2",
        "BCryptGenerateSymmetricKey",
        "BCryptOpenAlgorithmProvider",
        "BCryptSetProperty",
    }
)
_REQUIRED_RESOURCE_APIS = frozenset({"LockResource", "SizeofResource"})
_CALL_ARGUMENT_COUNTS = {
    "BCryptOpenAlgorithmProvider": 4,
    "BCryptDeriveKeyPBKDF2": 10,
    "BCryptSetProperty": 5,
    "BCryptGenerateSymmetricKey": 7,
    "BCryptDecrypt": 10,
}


@dataclass(frozen=True)
class StaticArgument:
    """x86 pushから復元した、値を公開しない引数表現。"""

    kind: str
    value: int | None = None
    register: int | None = None
    base_register: int | None = None
    displacement: int | None = None


@dataclass(frozen=True)
class CallEvidence:
    """import callと直前のstdcall引数。"""

    name: str
    index: int
    address: int
    arguments: tuple[StaticArgument, ...]


@dataclass(frozen=True)
class ResourceLayout:
    """resource先頭IV・後続ciphertextのデータフロー証跡。"""

    size_call: int
    lock_call: int
    resource_register: int
    size_register: int


@dataclass(frozen=True)
class BcryptRecipe:
    """静的に確定した復号recipe。秘密値はpublic reportへ含めない。"""

    password: bytes
    salt: bytes
    iterations: int
    key_size: int
    decrypt_flags: int
    call_addresses: tuple[tuple[str, int], ...]
    layout: ResourceLayout


@dataclass(frozen=True)
class ResourceCandidate:
    """PE resource directoryから境界検証済みで読んだblob。"""

    ordinal: int
    blob: bytes


@dataclass(frozen=True)
class _PreflightSection:
    """大容量入力の先行判定で使う、file-backed section境界。"""

    virtual_address: int
    virtual_size: int
    raw_offset: int
    raw_size: int
    executable: bool


@dataclass(frozen=True)
class _PreflightPe:
    """全入力をparseせずに検証したPE32の必要最小構造。"""

    image_base: int
    import_rva: int
    import_size: int
    resource_rva: int
    resource_size: int
    sections: tuple[_PreflightSection, ...]


@dataclass(frozen=True)
class _PreflightResult:
    """大容量入力の三値判定。"""

    status: str
    reason: str
    required_imports_present: bool = False
    resource_candidate_present: bool = False
    pbkdf2_call_anchor_present: bool = False
    executable_bytes_examined: int = 0


class _ImportScanLimit(RuntimeError):
    """通常経路のimport inventoryが固定走査上限を超えた。"""


def _u32(value: int) -> int:
    return value & 0xFFFFFFFF


def _read_u16(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 2 > len(data):
        return None
    return int(struct.unpack_from("<H", data, offset)[0])


def _read_u32(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    return int(struct.unpack_from("<I", data, offset)[0])


def _preflight_not_candidate(reason: str, **evidence: object) -> _PreflightResult:
    return _PreflightResult("not_candidate", reason, **evidence)


def _preflight_indeterminate(reason: str, **evidence: object) -> _PreflightResult:
    return _PreflightResult("indeterminate", reason, **evidence)


def _parse_preflight_pe(
    data: bytes,
) -> tuple[_PreflightPe | None, _PreflightResult | None]:
    """大容量入力から固定位置のPE32 metadataだけを有界に読む。"""

    if len(data) < 0x40 or data[:2] != b"MZ":
        return None, _preflight_not_candidate("dos_header_missing")
    pe_offset = _read_u32(data, 0x3C)
    if pe_offset is None or pe_offset + 24 > len(data):
        return None, _preflight_not_candidate("pe_header_invalid")
    if pe_offset > MAX_PREFLIGHT_PE_HEADER_OFFSET:
        return None, _preflight_indeterminate("pe_header_offset_limit")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None, _preflight_not_candidate("pe_signature_missing")

    machine = _read_u16(data, pe_offset + 4)
    section_count = _read_u16(data, pe_offset + 6)
    optional_size = _read_u16(data, pe_offset + 20)
    if machine != 0x14C:
        return None, _preflight_not_candidate("unsupported_machine")
    if section_count is None or section_count == 0 or optional_size is None:
        return None, _preflight_not_candidate("coff_header_invalid")
    if section_count > MAX_PREFLIGHT_SECTIONS:
        return None, _preflight_indeterminate("section_count_limit")

    optional_offset = pe_offset + 24
    optional_end = optional_offset + optional_size
    if optional_end > len(data) or optional_size < 120:
        return None, _preflight_not_candidate("optional_header_invalid")
    if _read_u16(data, optional_offset) != 0x10B:
        return None, _preflight_not_candidate("unsupported_optional_header")
    image_base = _read_u32(data, optional_offset + 28)
    directory_count = _read_u32(data, optional_offset + 92)
    if image_base is None or directory_count is None or directory_count < 3:
        return None, _preflight_not_candidate("data_directories_missing")
    import_rva = _read_u32(data, optional_offset + 104)
    import_size = _read_u32(data, optional_offset + 108)
    resource_rva = _read_u32(data, optional_offset + 112)
    resource_size = _read_u32(data, optional_offset + 116)
    if None in {import_rva, import_size, resource_rva, resource_size}:
        return None, _preflight_not_candidate("data_directories_invalid")
    assert import_rva is not None
    assert import_size is not None
    assert resource_rva is not None
    assert resource_size is not None
    if import_rva == 0 or import_size < 20:
        return None, _preflight_not_candidate("import_directory_missing")
    if resource_rva == 0 or resource_size < 16:
        return None, _preflight_not_candidate("resource_directory_missing")

    section_table = optional_end
    if section_table + section_count * 40 > len(data):
        return None, _preflight_not_candidate("section_table_invalid")
    sections: list[_PreflightSection] = []
    for index in range(section_count):
        offset = section_table + index * 40
        virtual_size = _read_u32(data, offset + 8)
        virtual_address = _read_u32(data, offset + 12)
        raw_size = _read_u32(data, offset + 16)
        raw_offset = _read_u32(data, offset + 20)
        characteristics = _read_u32(data, offset + 36)
        if None in {
            virtual_size,
            virtual_address,
            raw_size,
            raw_offset,
            characteristics,
        }:
            return None, _preflight_not_candidate("section_table_invalid")
        assert virtual_size is not None
        assert virtual_address is not None
        assert raw_size is not None
        assert raw_offset is not None
        assert characteristics is not None
        sections.append(
            _PreflightSection(
                virtual_address,
                virtual_size,
                raw_offset,
                raw_size,
                bool(characteristics & 0x20000000),
            )
        )
    return (
        _PreflightPe(
            image_base,
            import_rva,
            import_size,
            resource_rva,
            resource_size,
            tuple(sections),
        ),
        None,
    )


def _preflight_rva_offset(
    pe: _PreflightPe,
    data: bytes,
    rva: int,
    size: int,
) -> int | None:
    if rva < 0 or size < 0:
        return None
    for section in pe.sections:
        delta = rva - section.virtual_address
        if delta < 0 or delta + size > section.raw_size:
            continue
        offset = section.raw_offset + delta
        if offset < 0 or offset + size > len(data):
            return None
        return offset
    return None


def _preflight_import_name(data: bytes, offset: int) -> str | None:
    start = offset + 2
    if start < 0 or start >= len(data):
        return None
    stop = min(len(data), start + MAX_PREFLIGHT_IMPORT_NAME_SIZE)
    terminator = data.find(b"\0", start, stop)
    if terminator < 0:
        return None
    try:
        return data[start:terminator].decode("ascii")
    except UnicodeDecodeError:
        return None


def _preflight_imports(
    pe: _PreflightPe,
    data: bytes,
) -> tuple[_PreflightResult | None, tuple[int, ...]]:
    """必須import名とPBKDF2のIAT slotをbounded walkで確認する。"""

    required = _REQUIRED_BCRYPT_APIS | _REQUIRED_RESOURCE_APIS
    names: set[str] = set()
    derive_iat_addresses: list[int] = []
    descriptor_limit = min(
        pe.import_size // 20,
        MAX_PREFLIGHT_IMPORT_DESCRIPTORS,
    )
    saw_terminator = False
    thunk_count = 0
    for descriptor_index in range(descriptor_limit):
        descriptor_rva = pe.import_rva + descriptor_index * 20
        descriptor_offset = _preflight_rva_offset(pe, data, descriptor_rva, 20)
        if descriptor_offset is None:
            return _preflight_indeterminate("import_directory_unmapped"), ()
        descriptor = struct.unpack_from("<IIIII", data, descriptor_offset)
        if not any(descriptor):
            saw_terminator = True
            break
        original_thunk = int(descriptor[0])
        first_thunk = int(descriptor[4])
        name_thunk = original_thunk or first_thunk
        if name_thunk == 0 or first_thunk == 0:
            continue
        descriptor_complete = False
        for thunk_index in range(MAX_PREFLIGHT_IMPORT_THUNKS - thunk_count):
            thunk_offset = _preflight_rva_offset(
                pe,
                data,
                name_thunk + thunk_index * 4,
                4,
            )
            if thunk_offset is None:
                return _preflight_indeterminate("import_thunk_unmapped"), ()
            thunk_value = _read_u32(data, thunk_offset)
            if thunk_value is None:
                return _preflight_indeterminate("import_thunk_invalid"), ()
            thunk_count += 1
            if thunk_value == 0:
                descriptor_complete = True
                break
            if thunk_value & 0x80000000:
                continue
            name_offset = _preflight_rva_offset(pe, data, thunk_value, 3)
            if name_offset is None:
                return _preflight_indeterminate("import_name_unmapped"), ()
            name = _preflight_import_name(data, name_offset)
            if name is None:
                continue
            names.add(name)
            if name == "BCryptDeriveKeyPBKDF2":
                derive_iat_addresses.append(
                    _u32(pe.image_base + first_thunk + thunk_index * 4)
                )
                if len(derive_iat_addresses) > MAX_RECIPES:
                    return _preflight_indeterminate("pbkdf2_iat_count_limit"), ()
            if required <= names and derive_iat_addresses:
                return None, tuple(derive_iat_addresses)
        if not descriptor_complete:
            return _preflight_indeterminate("import_thunk_count_limit"), ()
    if not saw_terminator and pe.import_size // 20 > descriptor_limit:
        return _preflight_indeterminate("import_descriptor_count_limit"), ()
    return _preflight_not_candidate("required_imports_missing"), ()


def _preflight_resource_candidate(
    pe: _PreflightPe,
    data: bytes,
) -> _PreflightResult | None:
    """AES-CBC blobになり得るresource leafがあるかmetadataだけで確かめる。"""

    queue: list[tuple[int, int]] = [(0, 0)]
    seen: set[int] = set()
    metadata_count = 0
    malformed_branch = False
    limited_branch: str | None = None
    while queue:
        relative, depth = queue.pop()
        if relative in seen:
            continue
        seen.add(relative)
        if depth > MAX_PREFLIGHT_RESOURCE_DEPTH:
            limited_branch = "resource_depth_limit"
            continue
        if relative < 0 or relative + 16 > pe.resource_size:
            malformed_branch = True
            continue
        directory_offset = _preflight_rva_offset(
            pe,
            data,
            pe.resource_rva + relative,
            16,
        )
        if directory_offset is None:
            malformed_branch = True
            continue
        named_count = _read_u16(data, directory_offset + 12)
        id_count = _read_u16(data, directory_offset + 14)
        if named_count is None or id_count is None:
            malformed_branch = True
            continue
        entry_count = named_count + id_count
        metadata_count += entry_count
        if metadata_count > MAX_RESOURCE_ENTRIES:
            return _preflight_indeterminate(
                "resource_entry_count_limit",
                required_imports_present=True,
            )
        entries_relative = relative + 16
        if entries_relative + entry_count * 8 > pe.resource_size:
            malformed_branch = True
            continue
        entries_offset = _preflight_rva_offset(
            pe,
            data,
            pe.resource_rva + entries_relative,
            entry_count * 8,
        )
        if entries_offset is None:
            malformed_branch = True
            continue
        for entry_index in range(entry_count):
            child = _read_u32(data, entries_offset + entry_index * 8 + 4)
            if child is None:
                malformed_branch = True
                continue
            child_relative = child & 0x7FFFFFFF
            if child & 0x80000000:
                queue.append((child_relative, depth + 1))
                continue
            if child_relative + 16 > pe.resource_size:
                malformed_branch = True
                continue
            data_entry_offset = _preflight_rva_offset(
                pe,
                data,
                pe.resource_rva + child_relative,
                16,
            )
            if data_entry_offset is None:
                malformed_branch = True
                continue
            blob_rva = _read_u32(data, data_entry_offset)
            blob_size = _read_u32(data, data_entry_offset + 4)
            if blob_rva is None or blob_size is None:
                malformed_branch = True
                continue
            if blob_size > MAX_RESOURCE_SIZE:
                limited_branch = "resource_size_limit"
                continue
            if (
                blob_size < AES.block_size * 2
                or (blob_size - AES.block_size) % AES.block_size
            ):
                continue
            if _preflight_rva_offset(pe, data, blob_rva, blob_size) is not None:
                return None
            malformed_branch = True
    if limited_branch is not None:
        return _preflight_indeterminate(
            limited_branch,
            required_imports_present=True,
        )
    if malformed_branch:
        return _preflight_indeterminate(
            "resource_directory_unmapped",
            required_imports_present=True,
        )
    return _preflight_not_candidate(
        "resource_candidate_missing",
        required_imports_present=True,
    )


def _preflight_pbkdf2_anchor(
    pe: _PreflightPe,
    data: bytes,
    derive_iat_addresses: tuple[int, ...],
) -> _PreflightResult:
    """実行section内のdirect callまたはimport thunk callだけを有界に探す。"""

    ranges: list[tuple[_PreflightSection, int, int]] = []
    examined = 0
    complete = True
    for section in pe.sections:
        if not section.executable or section.raw_size <= 0:
            continue
        if section.raw_offset < 0 or section.raw_offset >= len(data):
            complete = False
            continue
        available = min(section.raw_size, len(data) - section.raw_offset)
        if available < section.raw_size:
            complete = False
        remaining = MAX_EXECUTABLE_BYTES - examined
        if remaining <= 0:
            complete = False
            break
        selected = min(available, remaining)
        if selected < available:
            complete = False
        start = section.raw_offset
        stop = start + selected
        ranges.append((section, start, stop))
        examined += selected

    thunk_addresses: set[int] = set()
    marker_count = 0
    for section, start, stop in ranges:
        for iat_address in derive_iat_addresses:
            direct = b"\xff\x15" + struct.pack("<I", _u32(iat_address))
            if data.find(direct, start, stop) >= 0:
                return _PreflightResult(
                    "candidate",
                    "required_anchors_present",
                    True,
                    True,
                    True,
                    examined,
                )
            thunk = b"\xff\x25" + struct.pack("<I", _u32(iat_address))
            position = start
            while (found := data.find(thunk, position, stop)) >= 0:
                marker_count += 1
                if marker_count > MAX_PREFLIGHT_CALL_MARKERS:
                    return _preflight_indeterminate(
                        "call_marker_count_limit",
                        required_imports_present=True,
                        resource_candidate_present=True,
                        executable_bytes_examined=examined,
                    )
                thunk_addresses.add(
                    _u32(
                        pe.image_base
                        + section.virtual_address
                        + found
                        - section.raw_offset
                    )
                )
                position = found + 1
    if thunk_addresses:
        for section, start, stop in ranges:
            position = start
            while (found := data.find(b"\xe8", position, stop)) >= 0:
                marker_count += 1
                if marker_count > MAX_PREFLIGHT_CALL_MARKERS:
                    return _preflight_indeterminate(
                        "call_marker_count_limit",
                        required_imports_present=True,
                        resource_candidate_present=True,
                        executable_bytes_examined=examined,
                    )
                relative = _read_u32(data, found + 1) if found + 5 <= stop else None
                if relative is not None:
                    signed_relative = struct.unpack("<i", struct.pack("<I", relative))[
                        0
                    ]
                    instruction_rva = (
                        section.virtual_address + found - section.raw_offset
                    )
                    target = _u32(pe.image_base + instruction_rva + 5 + signed_relative)
                    if target in thunk_addresses:
                        return _PreflightResult(
                            "candidate",
                            "required_anchors_present",
                            True,
                            True,
                            True,
                            examined,
                        )
                position = found + 1
    if not complete:
        return _preflight_indeterminate(
            "executable_scan_limit",
            required_imports_present=True,
            resource_candidate_present=True,
            executable_bytes_examined=examined,
        )
    return _preflight_not_candidate(
        "pbkdf2_call_anchor_missing",
        required_imports_present=True,
        resource_candidate_present=True,
        executable_bytes_examined=examined,
    )


def _large_input_preflight(data: bytes) -> _PreflightResult:
    """大容量PEをcopyせず、必要条件だけでBcrypt route適合性を判定する。"""

    pe, header_result = _parse_preflight_pe(data)
    if header_result is not None:
        return header_result
    assert pe is not None
    import_result, derive_iat_addresses = _preflight_imports(pe, data)
    if import_result is not None:
        return import_result
    resource_result = _preflight_resource_candidate(pe, data)
    if resource_result is not None:
        return resource_result
    return _preflight_pbkdf2_anchor(pe, data, derive_iat_addresses)


def _public_large_input_preflight(result: _PreflightResult) -> dict[str, object]:
    return {
        "status": result.status,
        "reason": result.reason,
        "required_imports_present": result.required_imports_present,
        "resource_candidate_present": result.resource_candidate_present,
        "pbkdf2_call_anchor_present": result.pbkdf2_call_anchor_present,
        "executable_bytes_examined": result.executable_bytes_examined,
        "whole_input_copied": False,
        "sample_executed": False,
    }


def _immediate(argument: StaticArgument) -> int | None:
    return argument.value if argument.kind == "immediate" else None


def _mapped_slice(
    pe: pefile.PE,
    data: bytes,
    address: int,
    size: int,
) -> bytes | None:
    """zero-fillやheaderへ逸脱しないfile-backed VAだけを読む。"""

    if size < 0 or size > MAX_RESOURCE_TOTAL_SIZE:
        return None
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    rva = address - image_base
    if rva < 0:
        return None
    for section in pe.sections:
        start = int(section.VirtualAddress)
        raw_size = int(section.SizeOfRawData)
        if rva < start or rva + size > start + raw_size:
            continue
        offset = int(section.PointerToRawData) + (rva - start)
        if offset < 0 or offset + size > len(data):
            return None
        return data[offset : offset + size]
    return None


def _read_utf16_literal(
    pe: pefile.PE,
    data: bytes,
    argument: StaticArgument,
    expected: str,
) -> bool:
    address = _immediate(argument)
    if address is None:
        return False
    encoded = (expected + "\0").encode("utf-16le")
    return _mapped_slice(pe, data, address, len(encoded)) == encoded


def _import_map(pe: pefile.PE) -> dict[int, str]:
    descriptors = getattr(pe, "DIRECTORY_ENTRY_IMPORT", ())
    try:
        descriptor_count = len(descriptors)
    except TypeError as exc:
        raise _ImportScanLimit from exc
    if descriptor_count > MAX_IMPORT_DESCRIPTORS:
        raise _ImportScanLimit

    # 名前を1件も読む前に総thunk数を確定する。これにより上限超過時に
    # descriptor順へ依存した部分prefixを後段へ渡さない。
    descriptor_imports: list[object] = []
    thunk_count = 0
    for descriptor in descriptors:
        items = getattr(descriptor, "imports", ())
        try:
            item_count = len(items)
        except TypeError as exc:
            raise _ImportScanLimit from exc
        if item_count > MAX_IMPORT_THUNKS - thunk_count:
            raise _ImportScanLimit
        thunk_count += item_count
        descriptor_imports.append(items)

    imports: dict[int, str] = {}
    derive_iat_count = 0
    for items in descriptor_imports:
        for item in items:
            if item.name is None:
                continue
            try:
                name = item.name.decode("ascii")
            except UnicodeDecodeError:
                continue
            if name == "BCryptDeriveKeyPBKDF2":
                derive_iat_count += 1
                if derive_iat_count > MAX_DERIVE_IAT_ADDRESSES:
                    raise _ImportScanLimit
            imports[_u32(int(item.address))] = name
    return imports


def _call_target(instruction: object, thunks: dict[int, str]) -> int | str | None:
    if instruction.mnemonic != "call" or not instruction.operands:
        return None
    operand = instruction.operands[0]
    if operand.type == X86_OP_MEM and operand.mem.base == 0 and operand.mem.index == 0:
        return _u32(int(operand.mem.disp))
    if operand.type == X86_OP_IMM:
        return thunks.get(_u32(int(operand.imm)))
    return None


def _resolve_register_argument(
    instructions: list[object],
    push_index: int,
    register: int,
) -> StaticArgument:
    push_address = int(instructions[push_index].address)
    zero_lower = max(0, push_index - 64)
    for index in range(push_index - 1, zero_lower - 1, -1):
        instruction = instructions[index]
        if instruction.mnemonic in {"jmp", "ret", "retn"}:
            break
        if instruction.mnemonic == "call" and register in {
            X86_REG_EAX,
            X86_REG_ECX,
            X86_REG_EDX,
        }:
            break
        if instruction.mnemonic in {"jne", "jnz"} and instruction.operands:
            target = instruction.operands[0]
            prior = instructions[index - 1] if index > zero_lower else None
            if (
                target.type == X86_OP_IMM
                and _u32(int(target.imm)) > _u32(push_address)
                and prior is not None
                and prior.mnemonic == "test"
                and len(prior.operands) >= 2
                and prior.operands[0].type == X86_OP_REG
                and prior.operands[1].type == X86_OP_REG
                and prior.operands[0].reg == register
                and prior.operands[1].reg == register
            ):
                return StaticArgument("immediate", value=0)
        try:
            _, written_registers = instruction.regs_access()
        except (CsError, AttributeError):
            written_registers = ()
        if register in written_registers:
            if (
                instruction.mnemonic == "xor"
                and len(instruction.operands) >= 2
                and instruction.operands[0].type == X86_OP_REG
                and instruction.operands[0].reg == register
                and instruction.operands[1].type == X86_OP_REG
                and instruction.operands[1].reg == register
            ):
                return StaticArgument("immediate", value=0)
            break

    lower = max(0, push_index - 12)
    for index in range(push_index - 1, lower - 1, -1):
        instruction = instructions[index]
        if instruction.mnemonic in {"call", "ret", "retn"}:
            break
        if instruction.mnemonic.startswith("j"):
            break
        if not instruction.operands or instruction.operands[0].type != X86_OP_REG:
            continue
        if instruction.operands[0].reg != register:
            continue
        if instruction.mnemonic == "mov" and len(instruction.operands) >= 2:
            source = instruction.operands[1]
            if source.type == X86_OP_IMM:
                return StaticArgument("immediate", value=_u32(int(source.imm)))
        if instruction.mnemonic == "lea" and len(instruction.operands) >= 2:
            source = instruction.operands[1]
            if source.type == X86_OP_MEM and source.mem.index == 0:
                if source.mem.base == 0:
                    return StaticArgument("immediate", value=_u32(int(source.mem.disp)))
                return StaticArgument(
                    "address_expression",
                    register=register,
                    base_register=int(source.mem.base),
                    displacement=int(source.mem.disp),
                )
        break
    return StaticArgument("register", register=register)


def _push_argument(
    instructions: list[object], push_index: int
) -> StaticArgument | None:
    instruction = instructions[push_index]
    if instruction.mnemonic != "push" or len(instruction.operands) != 1:
        return None
    operand = instruction.operands[0]
    if operand.type == X86_OP_IMM:
        return StaticArgument("immediate", value=_u32(int(operand.imm)))
    if operand.type == X86_OP_REG:
        return _resolve_register_argument(instructions, push_index, int(operand.reg))
    if operand.type == X86_OP_MEM:
        return StaticArgument(
            "memory",
            base_register=int(operand.mem.base),
            displacement=int(operand.mem.disp),
        )
    return None


def _collect_push_arguments(
    instructions: list[object], call_index: int, count: int
) -> tuple[StaticArgument, ...]:
    """直前basic blockのpushを、callee引数順に返す。"""

    arguments: list[StaticArgument] = []
    lower = max(0, call_index - MAX_ARGUMENT_INSTRUCTIONS)
    last_address = int(instructions[call_index].address)
    for index in range(call_index - 1, lower - 1, -1):
        instruction = instructions[index]
        end = int(instruction.address) + int(instruction.size)
        if last_address - end > 32:
            break
        last_address = int(instruction.address)
        if instruction.mnemonic in {"call", "ret", "retn"}:
            break
        if instruction.mnemonic.startswith("j"):
            break
        argument = _push_argument(instructions, index)
        if argument is None:
            continue
        arguments.append(argument)
        if len(arguments) == count:
            break
    return tuple(arguments)


def _anchored_ranges(
    section_data: bytes,
    section_address: int,
    derive_iat_addresses: tuple[int, ...],
) -> list[tuple[int, int]]:
    """PBKDF2 import callを生byteで固定し、周辺関数だけを選ぶ。"""

    if len(derive_iat_addresses) > MAX_DERIVE_IAT_ADDRESSES:
        raise _ImportScanLimit

    anchors: set[int] = set()
    thunk_addresses: set[int] = set()
    for iat_address in derive_iat_addresses:
        direct = b"\xff\x15" + struct.pack("<I", _u32(iat_address))
        thunk = b"\xff\x25" + struct.pack("<I", _u32(iat_address))
        start = 0
        while (found := section_data.find(direct, start)) >= 0:
            anchors.add(found)
            start = found + 1
        start = 0
        while (found := section_data.find(thunk, start)) >= 0:
            thunk_addresses.add(_u32(section_address + found))
            start = found + 1
    if thunk_addresses:
        for offset in range(max(0, len(section_data) - 4)):
            if section_data[offset] != 0xE8:
                continue
            relative = struct.unpack_from("<i", section_data, offset + 1)[0]
            target = _u32(section_address + offset + 5 + relative)
            if target in thunk_addresses:
                anchors.add(offset)

    ranges: list[tuple[int, int]] = []
    prologues = (b"\x55\x8b\xec", b"\x55\x89\xe5")
    for anchor in sorted(anchors):
        lower = max(0, anchor - ANCHOR_WINDOW_BEFORE)
        starts = [section_data.rfind(item, lower, anchor + 1) for item in prologues]
        prologue = max(starts)
        start = prologue if prologue >= 0 else lower
        stop = min(len(section_data), anchor + ANCHOR_WINDOW_AFTER)
        if ranges and start <= ranges[-1][1]:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], stop))
        else:
            ranges.append((start, stop))
    return ranges


def _disassemble(
    pe: pefile.PE,
    data: bytes,
    derive_iat_addresses: tuple[int, ...],
) -> tuple[list[object], str | None]:
    # IAT件数とsection byte数の直積探索を始める前に拒否する。
    if len(derive_iat_addresses) > MAX_DERIVE_IAT_ADDRESSES:
        return [], "import_scan_limit"
    if len(pe.sections) > MAX_EXECUTABLE_SECTIONS:
        return [], "executable_scan_limit"

    scan_sections: list[tuple[int, int, int]] = []
    scanned_raw_bytes = 0
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    for section in pe.sections:
        if not (int(section.Characteristics) & 0x20000000):
            continue
        offset = int(section.PointerToRawData)
        size = min(int(section.SizeOfRawData), max(0, len(data) - offset))
        if offset < 0 or size <= 0:
            continue
        if size > MAX_EXECUTABLE_SCAN_BYTES - scanned_raw_bytes:
            return [], "executable_scan_limit"
        scanned_raw_bytes += size
        scan_sections.append(
            (offset, size, image_base + int(section.VirtualAddress))
        )

    executable: list[tuple[int, bytes]] = []
    total = 0
    for offset, size, section_address in scan_sections:
        section_data = data[offset : offset + size]
        ranges = _anchored_ranges(section_data, section_address, derive_iat_addresses)
        for start, stop in ranges:
            selected = section_data[start:stop]
            total += len(selected)
            if total > MAX_EXECUTABLE_BYTES:
                return [], "executable_bytes_limit"
            executable.append((section_address + start, selected))
    if not executable:
        return [], "pbkdf2_call_anchor_not_found"
    engine = Cs(CS_ARCH_X86, CS_MODE_32)
    engine.detail = True
    engine.skipdata = True
    instructions: list[object] = []
    try:
        for address, blob in executable:
            remaining = MAX_INSTRUCTIONS - len(instructions)
            if remaining <= 0:
                return [], "instruction_limit"
            instructions.extend(engine.disasm(blob, address, count=remaining + 1))
            if len(instructions) > MAX_INSTRUCTIONS:
                return [], "instruction_limit"
    except (CsError, ValueError):
        return [], "disassembly_failed"
    instructions.sort(key=lambda item: int(item.address))
    return instructions, None


def _call_evidence(
    instructions: list[object], imports: dict[int, str]
) -> list[CallEvidence]:
    thunks: dict[int, str] = {}
    for instruction in instructions:
        if instruction.mnemonic != "jmp" or not instruction.operands:
            continue
        operand = instruction.operands[0]
        if (
            operand.type == X86_OP_MEM
            and operand.mem.base == 0
            and operand.mem.index == 0
        ):
            name = imports.get(_u32(int(operand.mem.disp)))
            if name:
                thunks[_u32(int(instruction.address))] = name

    calls: list[CallEvidence] = []
    for index, instruction in enumerate(instructions):
        target = _call_target(instruction, thunks)
        name = imports.get(target) if isinstance(target, int) else target
        if name is None:
            continue
        count = _CALL_ARGUMENT_COUNTS.get(name, 0)
        arguments = _collect_push_arguments(instructions, index, count) if count else ()
        calls.append(CallEvidence(name, index, int(instruction.address), arguments))
    return calls


def _register_loaded_from_eax(
    instructions: list[object], start: int, stop: int
) -> int | None:
    for instruction in instructions[start + 1 : stop]:
        if instruction.mnemonic != "mov" or len(instruction.operands) < 2:
            continue
        destination, source = instruction.operands[:2]
        if (
            destination.type == X86_OP_REG
            and source.type == X86_OP_REG
            and source.reg == X86_REG_EAX
        ):
            return int(destination.reg)
    return None


def _has_subtract_16(
    instructions: list[object], start: int, stop: int, register: int
) -> bool:
    for instruction in instructions[start:stop]:
        if len(instruction.operands) < 2:
            continue
        destination, source = instruction.operands[:2]
        if destination.type != X86_OP_REG or destination.reg != register:
            continue
        if source.type != X86_OP_IMM:
            continue
        value = _u32(int(source.imm))
        if instruction.mnemonic == "sub" and value == 16:
            return True
        if instruction.mnemonic == "add" and value == 0xFFFFFFF0:
            return True
    return False


def _resource_layout(
    instructions: list[object],
    calls: list[CallEvidence],
    open_call: CallEvidence,
    decrypt_call: CallEvidence,
) -> ResourceLayout | None:
    prior = [
        call
        for call in calls
        if call.address < open_call.address
        and open_call.address - call.address <= 0x200
    ]
    size_calls = [call for call in prior if call.name == "SizeofResource"]
    lock_calls = [call for call in prior if call.name == "LockResource"]
    if not size_calls or not lock_calls:
        return None
    size_call = size_calls[-1]
    lock_call = next(
        (
            call
            for call in lock_calls
            if size_call.address < call.address < open_call.address
        ),
        None,
    )
    if lock_call is None:
        return None
    size_register = _register_loaded_from_eax(
        instructions, size_call.index, lock_call.index
    )
    resource_register = _register_loaded_from_eax(
        instructions, lock_call.index, open_call.index
    )
    if size_register is None or resource_register is None:
        return None
    if not _has_subtract_16(
        instructions, size_call.index, decrypt_call.index, size_register
    ):
        return None
    if len(decrypt_call.arguments) != 10:
        return None
    input_pointer = decrypt_call.arguments[1]
    input_size = decrypt_call.arguments[2]
    iv_pointer = decrypt_call.arguments[4]
    if not (
        input_pointer.kind == "address_expression"
        and input_pointer.base_register == resource_register
        and input_pointer.displacement == 16
        and input_size.kind == "register"
        and input_size.register == size_register
        and iv_pointer.kind == "address_expression"
    ):
        return None

    loaded_xmm: int | None = None
    iv_stack: tuple[int, int] | None = None
    for instruction in instructions[lock_call.index : open_call.index + 1]:
        if instruction.mnemonic not in {"movaps", "movdqu", "movups"}:
            continue
        if len(instruction.operands) < 2:
            continue
        destination, source = instruction.operands[:2]
        if (
            destination.type == X86_OP_REG
            and source.type == X86_OP_MEM
            and source.mem.base == resource_register
            and source.mem.index == 0
            and source.mem.disp == 0
        ):
            loaded_xmm = int(destination.reg)
            continue
        if (
            loaded_xmm is not None
            and destination.type == X86_OP_MEM
            and source.type == X86_OP_REG
            and source.reg == loaded_xmm
            and destination.mem.index == 0
        ):
            iv_stack = (int(destination.mem.base), int(destination.mem.disp))
    if iv_stack is None:
        return None
    if (iv_pointer.base_register, iv_pointer.displacement) != iv_stack:
        return None
    return ResourceLayout(
        size_call=size_call.address,
        lock_call=lock_call.address,
        resource_register=resource_register,
        size_register=size_register,
    )


def _next_call(
    calls: list[CallEvidence],
    name: str,
    after: CallEvidence,
    before_address: int,
) -> CallEvidence | None:
    return next(
        (
            call
            for call in calls
            if call.name == name and after.address < call.address < before_address
        ),
        None,
    )


def _recipe_from_derive(
    pe: pefile.PE,
    data: bytes,
    instructions: list[object],
    calls: list[CallEvidence],
    derive: CallEvidence,
) -> BcryptRecipe | None:
    opens_before = [
        call
        for call in calls
        if call.name == "BCryptOpenAlgorithmProvider"
        and 0 < derive.address - call.address <= MAX_CALL_SPAN
        and len(call.arguments) == 4
        and _read_utf16_literal(pe, data, call.arguments[1], "SHA256")
    ]
    if not opens_before:
        return None
    sha_open = opens_before[-1]
    end = sha_open.address + MAX_CALL_SPAN
    aes_open = next(
        (
            call
            for call in calls
            if call.name == "BCryptOpenAlgorithmProvider"
            and derive.address < call.address < end
            and len(call.arguments) == 4
            and _read_utf16_literal(pe, data, call.arguments[1], "AES")
        ),
        None,
    )
    if aes_open is None:
        return None
    set_property = _next_call(calls, "BCryptSetProperty", aes_open, end)
    generate = (
        _next_call(calls, "BCryptGenerateSymmetricKey", set_property, end)
        if set_property
        else None
    )
    decrypt = _next_call(calls, "BCryptDecrypt", generate, end) if generate else None
    if set_property is None or generate is None or decrypt is None:
        return None
    if not (
        len(derive.arguments) == 10
        and len(set_property.arguments) == 5
        and len(generate.arguments) == 7
        and len(decrypt.arguments) == 10
    ):
        return None
    if not (
        _read_utf16_literal(pe, data, set_property.arguments[1], "ChainingMode")
        and _read_utf16_literal(pe, data, set_property.arguments[2], "ChainingModeCBC")
    ):
        return None

    password_address = _immediate(derive.arguments[1])
    password_size = _immediate(derive.arguments[2])
    salt_address = _immediate(derive.arguments[3])
    salt_size = _immediate(derive.arguments[4])
    iterations_low = _immediate(derive.arguments[5])
    iterations_high = _immediate(derive.arguments[6])
    key_size = _immediate(derive.arguments[8])
    derive_flags = _immediate(derive.arguments[9])
    property_size = _immediate(set_property.arguments[3])
    property_flags = _immediate(set_property.arguments[4])
    generated_key_size = _immediate(generate.arguments[5])
    generate_flags = _immediate(generate.arguments[6])
    iv_size = _immediate(decrypt.arguments[5])
    decrypt_flags = _immediate(decrypt.arguments[9])
    sha_flags = _immediate(sha_open.arguments[3])
    aes_flags = _immediate(aes_open.arguments[3])
    if None in {
        password_address,
        password_size,
        salt_address,
        salt_size,
        iterations_low,
        iterations_high,
        key_size,
        derive_flags,
        property_size,
        property_flags,
        generated_key_size,
        generate_flags,
        iv_size,
        decrypt_flags,
        sha_flags,
        aes_flags,
    }:
        return None
    assert password_address is not None
    assert password_size is not None
    assert salt_address is not None
    assert salt_size is not None
    assert iterations_low is not None
    assert iterations_high is not None
    assert key_size is not None
    assert generated_key_size is not None
    assert decrypt_flags is not None
    if not (
        1 <= password_size <= MAX_SECRET_SIZE
        and 1 <= salt_size <= MAX_SECRET_SIZE
        and iterations_high == 0
        and 1 <= iterations_low <= MAX_KDF_ITERATIONS
        and key_size in {16, 24, 32}
        and generated_key_size == key_size
        and derive_flags == 0
        and property_size == len("ChainingModeCBC\0".encode("utf-16le"))
        and property_flags == 0
        and generate_flags == 0
        and iv_size == AES.block_size
        and decrypt_flags in {0, 1}
        and sha_flags is not None
        and sha_flags & 8 == 8
        and aes_flags == 0
    ):
        return None
    password = _mapped_slice(pe, data, password_address, password_size)
    salt = _mapped_slice(pe, data, salt_address, salt_size)
    if password is None or salt is None or not any(password) or not any(salt):
        return None
    layout = _resource_layout(instructions, calls, sha_open, decrypt)
    if layout is None:
        return None
    sequence = (sha_open, derive, aes_open, set_property, generate, decrypt)
    return BcryptRecipe(
        password=password,
        salt=salt,
        iterations=iterations_low,
        key_size=key_size,
        decrypt_flags=decrypt_flags,
        call_addresses=tuple((call.name, call.address) for call in sequence),
        layout=layout,
    )


def _recover_recipes(
    pe: pefile.PE,
    data: bytes,
    instructions: list[object],
    imports: dict[int, str] | None = None,
) -> tuple[list[BcryptRecipe], dict[str, object]]:
    if imports is None:
        try:
            imports = _import_map(pe)
        except _ImportScanLimit:
            return [], {
                "status": "import_scan_limit",
                "candidate_set_complete": False,
            }
    names = set(imports.values())
    missing_bcrypt = sorted(_REQUIRED_BCRYPT_APIS - names)
    missing_resource = sorted(_REQUIRED_RESOURCE_APIS - names)
    if missing_bcrypt or missing_resource:
        return [], {
            "status": "required_imports_missing",
            "missing_bcrypt_api_count": len(missing_bcrypt),
            "missing_resource_api_count": len(missing_resource),
        }
    calls = _call_evidence(instructions, imports)
    recipes: list[BcryptRecipe] = []
    seen: set[tuple[int, int, int, bytes, bytes]] = set()
    derives = [call for call in calls if call.name == "BCryptDeriveKeyPBKDF2"]
    # 上限を超えた集合から先頭だけを選ぶと、call順序によって採否が変わり、
    # 未評価recipeと競合するartifactを誤って確定し得る。集合全体を不完全とし、
    # 秘密値の読出しや復号を開始する前にfail-closedにする。
    if len(derives) > MAX_RECIPES:
        return [], {
            "status": "recipe_scan_limit",
            "import_call_count": len(calls),
            "pbkdf2_call_count": len(derives),
            "recipe_count": 0,
            "recipe_scan_truncated": True,
            "candidate_set_complete": False,
        }
    for derive in derives:
        recipe = _recipe_from_derive(pe, data, instructions, calls, derive)
        if recipe is None:
            continue
        identity = (
            recipe.iterations,
            recipe.key_size,
            recipe.decrypt_flags,
            recipe.password,
            recipe.salt,
        )
        if identity in seen:
            continue
        seen.add(identity)
        recipes.append(recipe)
    return recipes, {
        "status": "recipe_recovered" if recipes else "call_chain_not_proven",
        "import_call_count": len(calls),
        "pbkdf2_call_count": len(derives),
        "recipe_count": len(recipes),
        "recipe_scan_truncated": False,
        "candidate_set_complete": True,
    }


def _entropy(blob: bytes) -> float:
    if not blob:
        return 0.0
    counts = [0] * 256
    for value in blob:
        counts[value] += 1
    length = len(blob)
    return -sum(
        (count / length) * math.log2(count / length) for count in counts if count
    )


def _resource_candidates(
    pe: pefile.PE, data: bytes
) -> tuple[list[ResourceCandidate], dict[str, object]]:
    root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if root is None:
        return [], {"status": "resource_directory_missing", "entry_count": 0}
    candidates: list[ResourceCandidate] = []
    metadata_count = 0
    total_size = 0
    blocked_count = 0

    def walk(directory: object) -> bool:
        nonlocal metadata_count, total_size, blocked_count
        for entry in getattr(directory, "entries", ()):
            metadata_count += 1
            if metadata_count > MAX_RESOURCE_ENTRIES:
                return False
            child = getattr(entry, "directory", None)
            if child is not None:
                if not walk(child):
                    return False
                continue
            data_entry = getattr(entry, "data", None)
            structure = getattr(data_entry, "struct", None)
            if structure is None:
                blocked_count += 1
                continue
            size = int(structure.Size)
            rva = int(structure.OffsetToData)
            if size < AES.block_size * 2 or size > MAX_RESOURCE_SIZE:
                blocked_count += 1
                continue
            total_size += size
            if total_size > MAX_RESOURCE_TOTAL_SIZE:
                return False
            blob = _mapped_slice(
                pe, data, int(pe.OPTIONAL_HEADER.ImageBase) + rva, size
            )
            if blob is None or (len(blob) - AES.block_size) % AES.block_size:
                blocked_count += 1
                continue
            if _entropy(blob[: min(len(blob), 1024 * 1024)]) < 6.0:
                continue
            candidates.append(ResourceCandidate(len(candidates), blob))
        return True

    complete = walk(root)
    return (
        candidates if complete else [],
        {
            "status": "candidates_recovered"
            if complete and candidates
            else "no_candidate"
            if complete
            else "resource_limits_exceeded",
            "metadata_entry_count": metadata_count,
            "candidate_count": len(candidates) if complete else 0,
            "blocked_entry_count": blocked_count,
            "total_declared_size": total_size,
            "inventory_complete": complete,
        },
    )


def _unpad_pkcs7(blob: bytes) -> bytes | None:
    if not blob:
        return None
    amount = blob[-1]
    if not 1 <= amount <= AES.block_size or len(blob) < amount:
        return None
    if blob[-amount:] != bytes([amount]) * amount:
        return None
    return blob[:-amount]


def _bounded_zlib(blob: bytes) -> tuple[bytes | None, str]:
    if len(blob) < 2 or blob[0] != 0x78:
        return None, "not_zlib"
    allowed = min(
        MAX_DECOMPRESSED_SIZE,
        math.floor(len(blob) * MAX_COMPRESSION_RATIO),
    )
    limit_reason = (
        "compression_ratio_limit"
        if allowed < MAX_DECOMPRESSED_SIZE
        else "decompressed_size_limit"
    )
    decoder = zlib.decompressobj()
    try:
        output = decoder.decompress(blob, allowed + 1)
    except zlib.error:
        return None, "zlib_invalid"
    if len(output) > allowed or decoder.unconsumed_tail:
        return None, limit_reason
    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        return None, "zlib_incomplete_or_trailing"
    return output, "zlib"


def _is_complete_pe(blob: bytes) -> bool:
    if not blob.startswith(b"MZ") or len(blob) > MAX_DECOMPRESSED_SIZE:
        return False
    try:
        parsed = pefile.PE(data=blob, fast_load=True)
    except (pefile.PEFormatError, ValueError):
        return False
    return bool(parsed.sections)


def _decrypt_resource(
    recipe: BcryptRecipe,
    resource: bytes,
    derived_key: bytes | None = None,
) -> tuple[bytes | None, str]:
    if (
        len(resource) <= AES.block_size
        or (len(resource) - AES.block_size) % AES.block_size
    ):
        return None, "ciphertext_alignment_invalid"
    key = derived_key or hashlib.pbkdf2_hmac(
        "sha256",
        recipe.password,
        recipe.salt,
        recipe.iterations,
        dklen=recipe.key_size,
    )
    if len(key) != recipe.key_size:
        return None, "derived_key_length_invalid"
    plaintext = AES.new(key, AES.MODE_CBC, resource[: AES.block_size]).decrypt(
        resource[AES.block_size :]
    )
    unpadded = _unpad_pkcs7(plaintext)
    if unpadded is None:
        return None, "pkcs7_invalid"
    inflated, status = _bounded_zlib(unpadded)
    if inflated is not None:
        return inflated, status
    if _is_complete_pe(unpadded):
        return unpadded, "direct_pe"
    return None, status if status != "not_zlib" else "payload_type_unproven"


def _public_recipe(recipe: BcryptRecipe, image_base: int) -> dict[str, object]:
    return {
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": recipe.iterations,
        "password_length": len(recipe.password),
        "salt_length": len(recipe.salt),
        "derived_key_length": recipe.key_size,
        "cipher": "AES",
        "mode": "CBC",
        "iv_length": AES.block_size,
        "resource_layout": "iv_prefix_then_ciphertext",
        "decrypt_flags": recipe.decrypt_flags,
        "call_sequence": [name for name, _ in recipe.call_addresses],
        "call_rvas": [
            hex(address - image_base) for _, address in recipe.call_addresses
        ],
        "resource_api_rvas": {
            "SizeofResource": hex(recipe.layout.size_call - image_base),
            "LockResource": hex(recipe.layout.lock_call - image_base),
        },
        "secret_values_included": False,
    }


def recover_bcrypt_resource(
    data: bytes,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """BCrypt resource loaderを認定し、復号済み子だけを返す。"""

    base_report: dict[str, object] = {
        "schema_version": 1,
        "status": "profile_not_matched",
        "candidate": False,
        "sample_executed": False,
        "network_contacted": False,
        "raw_secrets_included": False,
        "terminal_promotion_eligible": False,
        "route_only_reasons": [
            "recovered_layer_requires_downstream_family_and_config_validation"
        ],
    }
    if len(data) > MAX_INPUT_SIZE:
        preflight = _large_input_preflight(data)
        public_preflight = _public_large_input_preflight(preflight)
        if preflight.status == "not_candidate":
            return {
                **base_report,
                "large_input_preflight": public_preflight,
            }, []
        if preflight.status == "candidate":
            return {
                **base_report,
                "status": "input_size_limit",
                "candidate": True,
                "large_input_preflight": public_preflight,
            }, []
        return {
            **base_report,
            "status": "large_input_preflight_limit",
            "large_input_preflight": public_preflight,
        }, []
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except (pefile.PEFormatError, ValueError):
        return base_report, []
    if int(pe.FILE_HEADER.Machine) != 0x14C or int(pe.OPTIONAL_HEADER.Magic) != 0x10B:
        return base_report, []
    try:
        imports = _import_map(pe)
    except _ImportScanLimit:
        return {
            **base_report,
            "status": "import_scan_limit",
            "candidate_set_complete": False,
            "recovery_attempts_complete": False,
            "recovered_artifact_set_complete": False,
            "recipe_analysis": {
                "status": "import_scan_limit",
                "candidate_set_complete": False,
            },
        }, []
    import_names = set(imports.values())
    missing_bcrypt = sorted(_REQUIRED_BCRYPT_APIS - import_names)
    missing_resource = sorted(_REQUIRED_RESOURCE_APIS - import_names)
    if missing_bcrypt or missing_resource:
        return {
            **base_report,
            "recipe_analysis": {
                "status": "required_imports_missing",
                "missing_bcrypt_api_count": len(missing_bcrypt),
                "missing_resource_api_count": len(missing_resource),
            },
        }, []
    derive_iat_addresses = tuple(
        address for address, name in imports.items() if name == "BCryptDeriveKeyPBKDF2"
    )
    instructions, disassembly_error = _disassemble(pe, data, derive_iat_addresses)
    if disassembly_error:
        return {
            **base_report,
            "status": disassembly_error,
            "candidate": True,
        }, []
    recipes, recipe_report = _recover_recipes(pe, data, instructions, imports)
    if (
        recipe_report.get("recipe_scan_truncated") is True
        or recipe_report.get("candidate_set_complete", True) is False
    ):
        return {
            **base_report,
            "status": "recipe_scan_limit",
            "candidate": True,
            "candidate_set_complete": False,
            "recovery_attempts_complete": False,
            "recovered_artifact_set_complete": False,
            "recipe_analysis": recipe_report,
        }, []
    if not recipes:
        return {
            **base_report,
            "recipe_analysis": recipe_report,
        }, []
    resources, resource_report = _resource_candidates(pe, data)
    image_base = int(pe.OPTIONAL_HEADER.ImageBase)
    public_recipes = [_public_recipe(item, image_base) for item in recipes]
    if resource_report.get("inventory_complete", True) is False:
        return {
            **base_report,
            "status": str(resource_report.get("status", "resource_limits_exceeded")),
            "candidate": True,
            "candidate_set_complete": False,
            "recovery_attempts_complete": False,
            "recovered_artifact_set_complete": False,
            "recipe_analysis": recipe_report,
            "recipes": public_recipes,
            "resource_analysis": resource_report,
        }, []
    if not resources:
        candidate_set_complete = (
            recipe_report.get("candidate_set_complete", True) is not False
            and resource_report.get("inventory_complete", True) is not False
        )
        return {
            **base_report,
            "status": str(resource_report["status"]),
            "candidate": True,
            "candidate_set_complete": candidate_set_complete,
            "recovery_attempts_complete": candidate_set_complete,
            "recovered_artifact_set_complete": candidate_set_complete,
            "recipe_analysis": recipe_report,
            "recipes": public_recipes,
            "resource_analysis": resource_report,
        }, []

    candidate_attempt_count = len(recipes) * len(resources)
    if candidate_attempt_count > MAX_DECRYPT_ATTEMPTS:
        return {
            **base_report,
            "status": "decrypt_attempt_limit",
            "candidate": True,
            "candidate_set_complete": False,
            "recovery_attempts_complete": False,
            "recovered_artifact_set_complete": False,
            "recipe_analysis": recipe_report,
            "recipes": public_recipes,
            "resource_analysis": resource_report,
            "candidate_attempt_count": candidate_attempt_count,
            "attempt_count": 0,
            "recovered_artifact_count": 0,
            "recovered_artifact_total_size": 0,
            "recovered_transform_counts": {},
            "failure_counts": {},
        }, []

    artifacts: list[tuple[str, bytes]] = []
    seen: set[str] = set()
    failure_counts: dict[str, int] = {}
    transform_counts: dict[str, int] = {}
    attempt_count = 0
    recovered_artifact_total_size = 0

    def recovery_limit_report(status: str) -> dict[str, object]:
        return {
            **base_report,
            "status": status,
            "candidate": True,
            "candidate_set_complete": False,
            "recovery_attempts_complete": False,
            "recovered_artifact_set_complete": False,
            "recipe_analysis": recipe_report,
            "recipes": public_recipes,
            "resource_analysis": resource_report,
            "candidate_attempt_count": candidate_attempt_count,
            "attempt_count": attempt_count,
            "recovered_artifact_count": 0,
            "recovered_artifact_total_size": 0,
            "recovered_transform_counts": {},
            "failure_counts": dict(sorted(failure_counts.items())),
        }

    for recipe in recipes:
        derived_key = hashlib.pbkdf2_hmac(
            "sha256",
            recipe.password,
            recipe.salt,
            recipe.iterations,
            dklen=recipe.key_size,
        )
        for resource in resources:
            attempt_count += 1
            recovered, transform = _decrypt_resource(recipe, resource.blob, derived_key)
            if recovered is None:
                failure_counts[transform] = failure_counts.get(transform, 0) + 1
                continue
            digest = hashlib.sha256(recovered).hexdigest()
            if digest in seen:
                continue
            if len(artifacts) >= MAX_RECOVERED_ARTIFACTS:
                return recovery_limit_report("recovered_artifact_count_limit"), []
            if (
                len(recovered)
                > MAX_RECOVERED_ARTIFACT_BYTES - recovered_artifact_total_size
            ):
                return recovery_limit_report(
                    "recovered_artifact_total_size_limit"
                ), []
            seen.add(digest)
            transform_counts[transform] = transform_counts.get(transform, 0) + 1
            label = (
                "bcrypt-resource-zlib"
                if transform == "zlib"
                else "bcrypt-resource-decrypted-pe"
            )
            artifacts.append((label, recovered))
            recovered_artifact_total_size += len(recovered)
    return {
        **base_report,
        "status": "artifacts_recovered"
        if artifacts
        else "profile_matched_recovery_failed",
        "candidate": True,
        "candidate_set_complete": True,
        "recovery_attempts_complete": True,
        "recovered_artifact_set_complete": True,
        "recipe_analysis": recipe_report,
        "recipes": public_recipes,
        "resource_analysis": resource_report,
        "candidate_attempt_count": candidate_attempt_count,
        "attempt_count": attempt_count,
        "recovered_artifact_count": len(artifacts),
        "recovered_artifact_total_size": recovered_artifact_total_size,
        "recovered_transform_counts": dict(sorted(transform_counts.items())),
        "failure_counts": dict(sorted(failure_counts.items())),
    }, artifacts


__all__ = [
    "BcryptRecipe",
    "CallEvidence",
    "ResourceCandidate",
    "ResourceLayout",
    "StaticArgument",
    "recover_bcrypt_resource",
]
