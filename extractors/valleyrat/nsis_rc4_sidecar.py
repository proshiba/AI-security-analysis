"""NSIS展開後のXOR／ZipCrypto／RC4多段chainを静的に復元する。

このmoduleはNSIS自体を起動または展開しない。上限付きの共通container処理が
取得した同一bundle内のfile bytesを受け取り、loader codeから復元した値だけで
次の3段を結ぶ。

1. code参照された可変長keyによる反復XOR PE
2. decoded loaderが参照するZipCrypto archiveと、全member CRCを満たすpassword
3. side-load DLLが参照するRC4 key、KSA／PRGA、暗号化sidecar PE

hash、file名、key、C2値をroute条件へ固定しない。終端では既存の厳格な
vvaS reversed-config parser／Winsock data-flow probeを再利用し、全段が一意に
成立した場合だけValleyRAT終端へ昇格する。公開観測にはkey、password、raw
config、payload bytesを含めない。
"""

from __future__ import annotations

import hashlib
import io
import re
import struct
import zipfile
import zlib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import PurePosixPath

import pefile
from capstone import CS_ARCH_X86, CS_GRP_JUMP, CS_MODE_64, Cs
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_RIP,
)

MAXIMUM_COMPONENT_COUNT = 64
MAXIMUM_COMPONENT_SIZE = 384 * 1024 * 1024
MAXIMUM_TOTAL_SIZE = 512 * 1024 * 1024
MAXIMUM_NORMALIZED_PE_SIZE = 16 * 1024 * 1024
MAXIMUM_ZERO_OVERLAY_SIZE = 320 * 1024 * 1024
MAXIMUM_ARCHIVE_SIZE = 32 * 1024 * 1024
MAXIMUM_ARCHIVE_MEMBERS = 32
MAXIMUM_ARCHIVE_MEMBER_SIZE = 32 * 1024 * 1024
MAXIMUM_ARCHIVE_TOTAL_SIZE = 64 * 1024 * 1024
MAXIMUM_STRING_COUNT = 16_384
MAXIMUM_INSTRUCTION_COUNT = 250_000
MAXIMUM_KEY_SIZE = 32
MAXIMUM_XOR_PROOF_SPAN = 0x1000
MAXIMUM_REFERENCES_PER_VALUE = 32
MAXIMUM_XOR_KEY_CANDIDATES = 64
MAXIMUM_XOR_REFERENCE_ATTEMPTS = 256
MAXIMUM_XOR_DECODE_ATTEMPTS = 32
MAXIMUM_ARCHIVE_PASSWORD_CANDIDATES = 64
MAXIMUM_ARCHIVE_CANDIDATES = 64
MAXIMUM_ARCHIVE_PASSWORD_ATTEMPTS = 64
MAXIMUM_RC4_KEY_CANDIDATES = 64
MAXIMUM_RC4_REFERENCE_ATTEMPTS = 256
MAXIMUM_RC4_DECODE_ATTEMPTS = 32
MAXIMUM_STAGE_TRANSFORM_BYTES = 128 * 1024 * 1024
MAXIMUM_PE_VIEW_COUNT = 8
MAXIMUM_AGGREGATE_PE_INSTRUCTIONS = 500_000
MAXIMUM_AGGREGATE_PE_REFERENCES = 250_000
MAXIMUM_AGGREGATE_PE_STRINGS = 32_768
MAXIMUM_ARCHIVE_COMPRESSION_RATIO = 128

_EXECUTABLE = 0x20000000
_ASCII = re.compile(rb"[\x20-\x7e]{4,64}\x00")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){4,64}\x00\x00")


@dataclass(frozen=True)
class NsisRc4SidecarLineage:
    """公開可能な証明要約と、後段専用の復元bytes。"""

    observation: dict[str, object]
    terminal_component: bytes
    recovered_components: tuple[bytes, ...]


@dataclass(frozen=True)
class _PeExtent:
    extent: int
    trailing_size: int
    trailing_sha256: str | None = None


@dataclass(frozen=True)
class _StringRecord:
    text: str
    encoding: str
    address: int


@dataclass(frozen=True)
class _Reference:
    address: int
    target: int


@dataclass(frozen=True)
class _PeView:
    data: bytes
    image: pefile.PE
    image_base: int
    strings: tuple[_StringRecord, ...]
    references: tuple[_Reference, ...]
    instructions: tuple[object, ...]
    function_ranges: tuple[tuple[int, int], ...]
    omitted_zero_overlay_size: int


@dataclass(frozen=True)
class _DecodedStage:
    controller: bytes
    source: bytes
    decoded: bytes
    extent: _PeExtent
    proof: str


@dataclass(frozen=True)
class _ArchiveStage:
    controller: bytes
    archive: bytes
    members: tuple[tuple[str, bytes, int], ...]
    proof: str


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bounded_components(components: Mapping[str, bytes]) -> dict[str, bytes] | None:
    if not isinstance(components, Mapping) or not 1 <= len(components) <= MAXIMUM_COMPONENT_COUNT:
        return None
    normalized: dict[str, bytes] = {}
    total = 0
    for raw_name, raw_data in components.items():
        if not isinstance(raw_name, str) or not raw_name or not isinstance(raw_data, bytes):
            return None
        name = raw_name.replace("\\", "/")
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or not path.name:
            return None
        if len(raw_data) > MAXIMUM_COMPONENT_SIZE:
            return None
        total += len(raw_data)
        if total > MAXIMUM_TOTAL_SIZE or name.casefold() in {key.casefold() for key in normalized}:
            return None
        normalized[name] = raw_data
    return normalized


def _manual_pe_extent(data: bytes) -> _PeExtent | None:
    if len(data) < 0x100 or data[:2] != b"MZ":
        return None
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset > min(len(data) - 24, 1024 * 1024):
        return None
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        return None
    section_count = struct.unpack_from("<H", data, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
    if not 1 <= section_count <= 96 or not 0x60 <= optional_size <= 0x400:
        return None
    optional = pe_offset + 24
    section_table = optional + optional_size
    if section_table + section_count * 40 > len(data):
        return None
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in {0x10B, 0x20B}:
        return None
    extent = section_table + section_count * 40
    for index in range(section_count):
        entry = section_table + index * 40
        raw_size, raw_offset = struct.unpack_from("<II", data, entry + 16)
        if raw_offset > len(data) or raw_size > len(data) - raw_offset:
            return None
        extent = max(extent, raw_offset + raw_size)
    header_size_offset = optional + 60
    if header_size_offset + 4 <= section_table:
        header_size = struct.unpack_from("<I", data, header_size_offset)[0]
        if header_size > len(data):
            return None
        extent = max(extent, header_size)
    directory_count_offset = optional + (108 if magic == 0x20B else 92)
    directory_offset = optional + (112 if magic == 0x20B else 96)
    if directory_count_offset + 4 <= section_table:
        directory_count = struct.unpack_from("<I", data, directory_count_offset)[0]
        if directory_count > 4 and directory_offset + 5 * 8 <= section_table:
            certificate_offset, certificate_size = struct.unpack_from(
                "<II", data, directory_offset + 4 * 8
            )
            if certificate_size:
                if certificate_offset > len(data) or certificate_size > len(data) - certificate_offset:
                    return None
                extent = max(extent, certificate_offset + certificate_size)
    if extent > len(data) or extent > MAXIMUM_NORMALIZED_PE_SIZE:
        return None
    return _PeExtent(extent=extent, trailing_size=len(data) - extent)


def _all_zero(data: bytes, offset: int) -> bool:
    view = memoryview(data)
    for start in range(offset, len(data), 1024 * 1024):
        if any(view[start : min(len(data), start + 1024 * 1024)]):
            return False
    return True


def _normalize_source_pe(data: bytes) -> tuple[bytes, _PeExtent] | None:
    extent = _manual_pe_extent(data)
    if extent is None:
        return None
    if extent.trailing_size and (
        extent.trailing_size > MAXIMUM_ZERO_OVERLAY_SIZE
        or not _all_zero(data, extent.extent)
    ):
        return None
    return data[: extent.extent], extent


def _validated_decoded_pe(data: bytes) -> tuple[bytes, _PeExtent] | None:
    extent = _manual_pe_extent(data)
    if extent is None:
        return None
    trailing_sha256 = None
    if extent.trailing_size:
        # BuilderがPE file extentの後ろへ小さい暗号化paddingを残すvariantを
        # 許容する。省いたbyte列は公開せず、sizeとhashで境界を固定する。
        if extent.trailing_size > 0x1000:
            return None
        trailing_sha256 = _sha256(data[extent.extent :])
        extent = _PeExtent(
            extent=extent.extent,
            trailing_size=extent.trailing_size,
            trailing_sha256=trailing_sha256,
        )
    return data[: extent.extent], extent


def _scan_strings(data: bytes, image: pefile.PE) -> tuple[_StringRecord, ...]:
    records: list[_StringRecord] = []
    seen: set[tuple[str, str, int]] = set()
    for encoding, pattern, terminator_size in (
        ("ascii", _ASCII, 1),
        ("utf-16le", _UTF16, 2),
    ):
        for match in pattern.finditer(data):
            raw = match.group(0)[:-terminator_size]
            try:
                text = raw.decode(encoding)
                rva = image.get_rva_from_offset(match.start())
            except (UnicodeDecodeError, pefile.PEFormatError, TypeError, ValueError):
                continue
            record = (text, encoding, image.OPTIONAL_HEADER.ImageBase + rva)
            if record in seen:
                continue
            seen.add(record)
            records.append(_StringRecord(*record))
            if len(records) > MAXIMUM_STRING_COUNT:
                return ()
    return tuple(records)


def _load_pe_view(data: bytes) -> _PeView | None:
    normalized = _normalize_source_pe(data)
    if normalized is None:
        return None
    pe_data, extent = normalized
    try:
        image = pefile.PE(data=pe_data, fast_load=False)
    except (OSError, pefile.PEFormatError, TypeError, ValueError):
        return None
    if image.FILE_HEADER.Machine != 0x8664:
        return None
    image_base = image.OPTIONAL_HEADER.ImageBase
    strings = _scan_strings(pe_data, image)
    if not strings:
        return None
    instructions: list[object] = []
    references: list[_Reference] = []
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    for section in image.sections:
        if not section.Characteristics & _EXECUTABLE:
            continue
        for instruction in disassembler.disasm(
            section.get_data(), image_base + section.VirtualAddress
        ):
            instructions.append(instruction)
            if len(instructions) > MAXIMUM_INSTRUCTION_COUNT:
                return None
            for operand in instruction.operands:
                if operand.type == X86_OP_MEM and operand.mem.base == X86_REG_RIP:
                    references.append(
                        _Reference(
                            instruction.address,
                            instruction.address + instruction.size + operand.mem.disp,
                        )
                    )
    function_ranges: list[tuple[int, int]] = []
    for entry in getattr(image, "DIRECTORY_ENTRY_EXCEPTION", ()):
        begin = int(entry.struct.BeginAddress)
        end = int(entry.struct.EndAddress)
        if begin < end:
            function_ranges.append((image_base + begin, image_base + end))
    return _PeView(
        data=pe_data,
        image=image,
        image_base=image_base,
        strings=strings,
        references=tuple(references),
        instructions=tuple(instructions),
        function_ranges=tuple(sorted(set(function_ranges))),
        omitted_zero_overlay_size=extent.trailing_size,
    )


def _refs_by_target(view: _PeView) -> dict[int, tuple[int, ...]]:
    grouped: dict[int, list[int]] = {}
    for reference in view.references:
        grouped.setdefault(reference.target, []).append(reference.address)
    return {target: tuple(sorted(set(values))) for target, values in grouped.items()}


def _component_basename(name: str) -> str:
    return PurePosixPath(name.replace("\\", "/")).name.casefold()


def _function_range(view: _PeView, address: int) -> tuple[int, int] | None:
    matches = [item for item in view.function_ranges if item[0] <= address < item[1]]
    return matches[0] if len(matches) == 1 else None


def _instructions_between(view: _PeView, start: int, end: int) -> tuple[object, ...]:
    return tuple(item for item in view.instructions if start <= item.address < end)


def _backward_branch(instruction: object) -> bool:
    return bool(
        instruction.group(CS_GRP_JUMP)
        and instruction.operands
        and instruction.operands[0].type == X86_OP_IMM
        and instruction.operands[0].imm < instruction.address
    )


def _canonical_register(instruction: object, register: int) -> str:
    name = str(instruction.reg_name(register)).casefold()
    aliases = {
        "al": "rax", "ah": "rax", "ax": "rax", "eax": "rax",
        "bl": "rbx", "bh": "rbx", "bx": "rbx", "ebx": "rbx",
        "cl": "rcx", "ch": "rcx", "cx": "rcx", "ecx": "rcx",
        "dl": "rdx", "dh": "rdx", "dx": "rdx", "edx": "rdx",
        "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
    }
    if name in aliases:
        return aliases[name]
    if name.startswith("r") and name.endswith(("b", "w", "d")) and name[1:-1].isdigit():
        return name[:-1]
    return name


def _immediate_register_assignments(instructions: tuple[object, ...], value: int) -> set[str]:
    registers: set[str] = set()
    for instruction in instructions:
        if instruction.mnemonic != "mov" or len(instruction.operands) != 2:
            continue
        destination, source = instruction.operands
        if destination.type == X86_OP_REG and source.type == X86_OP_IMM and source.imm == value:
            registers.add(_canonical_register(instruction, destination.reg))
    return registers


def _xor_loader_grammar(
    view: _PeView,
    *,
    filename_reference: int,
    key_reference: int,
    key_size: int,
) -> bool:
    low = min(filename_reference, key_reference)
    high = max(filename_reference, key_reference)
    if high - low > MAXIMUM_XOR_PROOF_SPAN:
        return False
    instructions = _instructions_between(view, max(view.image_base, low - 0x80), high + 0x180)
    if not instructions or any(item.mnemonic == "ret" for item in instructions):
        return False
    key_registers = _immediate_register_assignments(instructions, key_size)
    if not key_registers:
        return False
    modulo = any(
        item.mnemonic in {"div", "idiv"}
        and item.operands
        and item.operands[0].type == X86_OP_REG
        and _canonical_register(item, item.operands[0].reg) in key_registers
        for item in instructions
    )
    xor_memory = any(
        item.mnemonic == "xor"
        and any(operand.type == X86_OP_MEM for operand in item.operands)
        for item in instructions
    )
    return modulo and xor_memory and any(_backward_branch(item) for item in instructions)


def _repeating_xor(data: bytes, key: bytes) -> bytes:
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def _recover_xor_stage(components: Mapping[str, bytes]) -> _DecodedStage | None:
    candidates: list[_DecodedStage] = []
    reference_attempts = 0
    decode_attempts = 0
    transformed_bytes = 0
    pe_view_count = 0
    aggregate_instruction_count = 0
    aggregate_reference_count = 0
    aggregate_string_count = 0
    for _loader_name, loader_data in components.items():
        view = _load_pe_view(loader_data)
        if view is None:
            continue
        pe_view_count += 1
        aggregate_instruction_count += len(view.instructions)
        aggregate_reference_count += len(view.references)
        aggregate_string_count += len(view.strings)
        if (
            pe_view_count > MAXIMUM_PE_VIEW_COUNT
            or aggregate_instruction_count > MAXIMUM_AGGREGATE_PE_INSTRUCTIONS
            or aggregate_reference_count > MAXIMUM_AGGREGATE_PE_REFERENCES
            or aggregate_string_count > MAXIMUM_AGGREGATE_PE_STRINGS
        ):
            return None
        references = _refs_by_target(view)
        referenced = [item for item in view.strings if item.address in references]
        keys = [
            item
            for item in referenced
            if item.encoding == "ascii"
            and 4 <= len(item.text.encode("ascii")) <= MAXIMUM_KEY_SIZE
            and all(character.isalnum() or character in "_-" for character in item.text)
        ]
        if len(keys) > MAXIMUM_XOR_KEY_CANDIDATES:
            return None
        for component_name, ciphertext in components.items():
            if ciphertext.startswith(b"MZ") or len(ciphertext) > MAXIMUM_NORMALIZED_PE_SIZE:
                continue
            basename = _component_basename(component_name)
            filenames = [
                item
                for item in referenced
                if item.encoding == "utf-16le" and item.text.casefold() == basename
            ]
            if len(filenames) > MAXIMUM_XOR_KEY_CANDIDATES:
                return None
            for filename in filenames:
                for key in keys:
                    filename_refs = references[filename.address]
                    key_refs = references[key.address]
                    if (
                        len(filename_refs) > MAXIMUM_REFERENCES_PER_VALUE
                        or len(key_refs) > MAXIMUM_REFERENCES_PER_VALUE
                    ):
                        return None
                    grammar_proven = False
                    for filename_ref in filename_refs:
                        for key_ref in key_refs:
                            reference_attempts += 1
                            if reference_attempts > MAXIMUM_XOR_REFERENCE_ATTEMPTS:
                                return None
                            if _xor_loader_grammar(
                                view,
                                filename_reference=filename_ref,
                                key_reference=key_ref,
                                key_size=len(key.text.encode("ascii")),
                            ):
                                grammar_proven = True
                                break
                        if grammar_proven:
                            break
                    if not grammar_proven:
                        continue
                    decode_attempts += 1
                    transformed_bytes += len(ciphertext)
                    if (
                        decode_attempts > MAXIMUM_XOR_DECODE_ATTEMPTS
                        or transformed_bytes > MAXIMUM_STAGE_TRANSFORM_BYTES
                    ):
                        return None
                    decoded = _repeating_xor(ciphertext, key.text.encode("ascii"))
                    validated = _validated_decoded_pe(decoded)
                    if validated is None:
                        continue
                    child, extent = validated
                    candidates.append(
                        _DecodedStage(
                            controller=loader_data,
                            source=ciphertext,
                            decoded=child,
                            extent=extent,
                            proof="direct_key_reference_modulo_xor_loop_and_valid_pe",
                        )
                    )
    unique = {
        (_sha256(item.controller), _sha256(item.source), _sha256(item.decoded)): item
        for item in candidates
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _zip_declared_uncompressed_size(archive: bytes) -> int | None:
    """ZipCrypto候補を展開する前に宣言sizeと圧縮率を検証する。"""

    if len(archive) > MAXIMUM_ARCHIVE_SIZE:
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as container:
            infos = [item for item in container.infolist() if not item.is_dir()]
            if not 1 <= len(infos) <= MAXIMUM_ARCHIVE_MEMBERS:
                return None
            if not any(item.flag_bits & 1 for item in infos):
                return None
            total = 0
            for info in infos:
                path = PurePosixPath(info.filename.replace("\\", "/"))
                if path.is_absolute() or ".." in path.parts or not path.name:
                    return None
                if info.file_size > MAXIMUM_ARCHIVE_MEMBER_SIZE:
                    return None
                if info.file_size and (
                    info.compress_size <= 0
                    or info.file_size
                    > info.compress_size * MAXIMUM_ARCHIVE_COMPRESSION_RATIO
                ):
                    return None
                total += info.file_size
                if total > MAXIMUM_ARCHIVE_TOTAL_SIZE:
                    return None
    except (OSError, ValueError, zipfile.BadZipFile):
        return None
    return total


def _safe_zip_members(archive: bytes, password: bytes) -> tuple[tuple[str, bytes, int], ...] | None:
    if _zip_declared_uncompressed_size(archive) is None:
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(archive)) as container:
            infos = [item for item in container.infolist() if not item.is_dir()]
            output: list[tuple[str, bytes, int]] = []
            for info in infos:
                path = PurePosixPath(info.filename.replace("\\", "/"))
                value = container.read(info, pwd=password)
                crc = zlib.crc32(value) & 0xFFFFFFFF
                if len(value) != info.file_size or crc != info.CRC:
                    return None
                output.append((str(path), value, crc))
    except (KeyError, NotImplementedError, RuntimeError, ValueError, zipfile.BadZipFile):
        return None
    return tuple(output)


def _recover_archive_stage(
    controller: bytes,
    components: Mapping[str, bytes],
) -> _ArchiveStage | None:
    view = _load_pe_view(controller)
    if view is None:
        return None
    references = _refs_by_target(view)
    referenced = [item for item in view.strings if item.address in references]
    archive_strings_by_name: dict[str, list[_StringRecord]] = {}
    for item in referenced:
        folded = item.text.casefold()
        if folded.endswith(".zip"):
            existing = archive_strings_by_name.get(folded)
            if existing is None:
                archive_strings_by_name[folded] = [item]
            else:
                existing.append(item)
    archives: list[tuple[str, bytes, _StringRecord]] = []
    for name, data in components.items():
        for item in archive_strings_by_name.get(_component_basename(name), ()):
            archives.append((name, data, item))
            if len(archives) > MAXIMUM_ARCHIVE_CANDIDATES:
                return None
    passwords = [
        item
        for item in referenced
        if 4 <= len(item.text.encode("utf-8")) <= MAXIMUM_KEY_SIZE
        and not item.text.casefold().endswith((".zip", ".exe", ".dll", ".dat"))
    ]
    if len(passwords) > MAXIMUM_ARCHIVE_PASSWORD_CANDIDATES:
        return None
    candidates: list[_ArchiveStage] = []
    attempts = 0
    transformed_bytes = 0
    for _name, archive, archive_string in archives:
        declared_uncompressed_size = _zip_declared_uncompressed_size(archive)
        if declared_uncompressed_size is None:
            continue
        archive_refs = references[archive_string.address]
        if len(archive_refs) > MAXIMUM_REFERENCES_PER_VALUE:
            return None
        for password in passwords:
            password_refs = references[password.address]
            if len(password_refs) > MAXIMUM_REFERENCES_PER_VALUE:
                return None
            if not any(abs(left - right) <= MAXIMUM_XOR_PROOF_SPAN for left in archive_refs for right in password_refs):
                continue
            attempts += 1
            transformed_bytes += declared_uncompressed_size
            if (
                attempts > MAXIMUM_ARCHIVE_PASSWORD_ATTEMPTS
                or transformed_bytes > MAXIMUM_STAGE_TRANSFORM_BYTES
            ):
                return None
            members = _safe_zip_members(archive, password.text.encode("utf-8"))
            if members is None:
                continue
            candidates.append(
                _ArchiveStage(
                    controller=controller,
                    archive=archive,
                    members=members,
                    proof="direct_password_reference_and_all_member_crc_validation",
                )
            )
    unique = {
        (_sha256(item.archive), tuple(_sha256(value) for _name, value, _crc in item.members)): item
        for item in candidates
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _direct_call_targets(instructions: tuple[object, ...]) -> tuple[int, ...]:
    return tuple(
        int(item.operands[0].imm)
        for item in instructions
        if item.mnemonic == "call"
        and item.operands
        and item.operands[0].type == X86_OP_IMM
    )


def _function_instructions(view: _PeView, address: int) -> tuple[object, ...]:
    bounds = _function_range(view, address)
    if bounds is None or bounds[1] - bounds[0] > 0x1000:
        return ()
    return _instructions_between(view, *bounds)


def _immediate_count(instructions: tuple[object, ...], mnemonic: str, value: int) -> int:
    return sum(
        1
        for item in instructions
        if item.mnemonic == mnemonic
        and any(operand.type == X86_OP_IMM and operand.imm == value for operand in item.operands)
    )


def _is_rc4_ksa(instructions: tuple[object, ...]) -> bool:
    return bool(
        instructions
        and _immediate_count(instructions, "cmp", 0x100) >= 2
        and _immediate_count(instructions, "and", 0xFF) >= 1
        and any(item.mnemonic in {"div", "idiv"} for item in instructions)
        and sum(_backward_branch(item) for item in instructions) >= 2
    )


def _is_rc4_prga(instructions: tuple[object, ...]) -> bool:
    memory_xor = any(
        item.mnemonic == "xor"
        and any(operand.type == X86_OP_MEM for operand in item.operands)
        for item in instructions
    )
    byte_store = any(
        item.mnemonic == "mov"
        and item.operands
        and item.operands[0].type == X86_OP_MEM
        and getattr(item.operands[0], "size", 0) == 1
        for item in instructions
    )
    return bool(
        instructions
        and _immediate_count(instructions, "and", 0xFF) >= 3
        and memory_xor
        and byte_store
        and any(_backward_branch(item) for item in instructions)
    )


def _rc4(data: bytes, key: bytes) -> bytes:
    state = list(range(256))
    index = 0
    for offset in range(256):
        index = (index + state[offset] + key[offset % len(key)]) & 0xFF
        state[offset], state[index] = state[index], state[offset]
    left = 0
    right = 0
    output = bytearray(len(data))
    for offset, value in enumerate(data):
        left = (left + 1) & 0xFF
        right = (right + state[left]) & 0xFF
        state[left], state[right] = state[right], state[left]
        output[offset] = value ^ state[(state[left] + state[right]) & 0xFF]
    return bytes(output)


def _recover_rc4_stage(members: tuple[tuple[str, bytes, int], ...]) -> _DecodedStage | None:
    mapping = {name: data for name, data, _crc in members}
    candidates: list[_DecodedStage] = []
    reference_attempts = 0
    decode_attempts = 0
    transformed_bytes = 0
    pe_view_count = 0
    aggregate_instruction_count = 0
    aggregate_reference_count = 0
    aggregate_string_count = 0
    for loader_data in mapping.values():
        view = _load_pe_view(loader_data)
        if view is None:
            continue
        pe_view_count += 1
        aggregate_instruction_count += len(view.instructions)
        aggregate_reference_count += len(view.references)
        aggregate_string_count += len(view.strings)
        if (
            pe_view_count > MAXIMUM_PE_VIEW_COUNT
            or aggregate_instruction_count > MAXIMUM_AGGREGATE_PE_INSTRUCTIONS
            or aggregate_reference_count > MAXIMUM_AGGREGATE_PE_REFERENCES
            or aggregate_string_count > MAXIMUM_AGGREGATE_PE_STRINGS
        ):
            return None
        references = _refs_by_target(view)
        referenced = [item for item in view.strings if item.address in references]
        keys = [
            item
            for item in referenced
            if 4 <= len(item.text.encode("utf-8")) <= MAXIMUM_KEY_SIZE
            and not item.text.casefold().endswith((".exe", ".dll", ".dat", ".zip"))
            and all(character.isalnum() or character in "_-" for character in item.text)
        ]
        if len(keys) > MAXIMUM_RC4_KEY_CANDIDATES:
            return None
        for source_name, source in mapping.items():
            if source.startswith(b"MZ") or len(source) > MAXIMUM_NORMALIZED_PE_SIZE:
                continue
            source_strings = [
                item for item in referenced if item.text.casefold() == _component_basename(source_name)
            ]
            if len(source_strings) > MAXIMUM_RC4_KEY_CANDIDATES:
                return None
            for source_string in source_strings:
                for key in keys:
                    source_refs = references[source_string.address]
                    key_refs = references[key.address]
                    if (
                        len(source_refs) > MAXIMUM_REFERENCES_PER_VALUE
                        or len(key_refs) > MAXIMUM_REFERENCES_PER_VALUE
                    ):
                        return None
                    reference_attempts += len(source_refs) + len(key_refs)
                    if reference_attempts > MAXIMUM_RC4_REFERENCE_ATTEMPTS:
                        return None
                    shared_ranges = {
                        _function_range(view, address)
                        for address in source_refs
                    } & {
                        _function_range(view, address) for address in key_refs
                    }
                    shared_ranges.discard(None)
                    if len(shared_ranges) != 1:
                        continue
                    root_instructions = _instructions_between(view, *next(iter(shared_ranges)))
                    targets = _direct_call_targets(root_instructions)
                    ksa_targets = [target for target in targets if _is_rc4_ksa(_function_instructions(view, target))]
                    prga_targets = [target for target in targets if _is_rc4_prga(_function_instructions(view, target))]
                    if len(set(ksa_targets)) != 1 or len(set(prga_targets)) != 1:
                        continue
                    decode_attempts += 1
                    transformed_bytes += len(source)
                    if (
                        decode_attempts > MAXIMUM_RC4_DECODE_ATTEMPTS
                        or transformed_bytes > MAXIMUM_STAGE_TRANSFORM_BYTES
                    ):
                        return None
                    decoded = _rc4(source, key.text.encode("utf-8"))
                    validated = _validated_decoded_pe(decoded)
                    if validated is None:
                        continue
                    child, extent = validated
                    candidates.append(
                        _DecodedStage(
                            controller=loader_data,
                            source=source,
                            decoded=child,
                            extent=extent,
                            proof="direct_key_reference_unique_rc4_ksa_prga_and_valid_pe",
                        )
                    )
    unique = {
        (_sha256(item.controller), _sha256(item.source), _sha256(item.decoded)): item
        for item in candidates
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def _terminal_proof(data: bytes) -> dict[str, object] | None:
    # 循環importを避け、終端に到達した時だけ既存の厳格probeを読み込む。
    from extractors.valleyrat.extractor import probe_vvas_config

    result = probe_vvas_config(data, input_format="pe")
    evidence = result.get("evidence")
    config = result.get("config")
    format_evidence = evidence.get("format_corroboration") if isinstance(evidence, dict) else None
    endpoint_count = config.get("endpoint_count") if isinstance(config, dict) else None
    if not (
        result.get("matched") is True
        and result.get("family") == "valleyrat"
        and result.get("variant") == "vvas_reversed_config_terminal"
        and result.get("supports_family_attribution") is True
        and result.get("terminal_family_confirmed") is True
        and result.get("static_config_recovered") is True
        and isinstance(endpoint_count, int)
        and not isinstance(endpoint_count, bool)
        and 1 <= endpoint_count <= 3
        and isinstance(format_evidence, dict)
        and format_evidence.get("matched") is True
    ):
        return None
    return {
        "family": "valleyrat",
        "variant": "vvas_reversed_config_terminal",
        "endpoint_count": endpoint_count,
        "config_to_connect_send_receive": True,
        "terminal_family_confirmed": True,
        "raw_config_included": False,
        "raw_network_values_included": False,
    }


def _stage_record(kind: str, stage: _DecodedStage) -> dict[str, object]:
    record: dict[str, object] = {
        "kind": kind,
        "controller_sha256": _sha256(stage.controller),
        "parent_sha256": _sha256(stage.source),
        "child_sha256": _sha256(stage.decoded),
        "parent_size": len(stage.source),
        "child_size": len(stage.decoded),
        "validated_pe_extent": stage.extent.extent,
        "trailing_plaintext_bytes_omitted": stage.extent.trailing_size,
        "proof": stage.proof,
        "raw_key_included": False,
        "raw_payload_included": False,
    }
    if stage.extent.trailing_sha256 is not None:
        record["trailing_plaintext_sha256"] = stage.extent.trailing_sha256
    return record


def analyze_nsis_rc4_sidecar_bundle(
    components: Mapping[str, bytes],
) -> NsisRc4SidecarLineage | None:
    """展開済み同一bundleから一意なValleyRAT終端chainだけを返す。"""

    bounded = _bounded_components(components)
    if bounded is None:
        return None
    xor_stage = _recover_xor_stage(bounded)
    if xor_stage is None:
        return None
    archive_stage = _recover_archive_stage(xor_stage.decoded, bounded)
    if archive_stage is None:
        return None
    rc4_stage = _recover_rc4_stage(archive_stage.members)
    if rc4_stage is None:
        return None
    terminal = _terminal_proof(rc4_stage.decoded)
    if terminal is None:
        return None
    archive_record = {
        "kind": "code_referenced_zipcrypto_archive",
        "controller_sha256": _sha256(archive_stage.controller),
        "parent_sha256": _sha256(archive_stage.archive),
        "parent_size": len(archive_stage.archive),
        "member_count": len(archive_stage.members),
        "members": [
            {
                "sha256": _sha256(value),
                "size": len(value),
                "crc32": f"{crc:08x}",
            }
            for _name, value, crc in archive_stage.members
        ],
        "proof": archive_stage.proof,
        "raw_password_included": False,
        "raw_payload_included": False,
    }
    observation: dict[str, object] = {
        "schema_version": 1,
        "status": "validated_nsis_xor_zipcrypto_rc4_to_vvas_terminal",
        "matched": True,
        "stages": [
            _stage_record("code_referenced_repeating_xor_pe", xor_stage),
            archive_record,
            _stage_record("code_referenced_rc4_sidecar_pe", rc4_stage),
        ],
        "terminal": terminal,
        "supports_family_attribution": True,
        "terminal_family_confirmed": True,
        "terminal_network_lineage_proven": True,
        "hash_or_filename_rule_used": False,
        "external_label_used": False,
        "raw_key_included": False,
        "raw_password_included": False,
        "raw_config_included": False,
        "raw_payload_included": False,
        "sample_executed": False,
        "network_contacted": False,
    }
    recovered = [xor_stage.decoded]
    recovered.extend(value for _name, value, _crc in archive_stage.members)
    return NsisRc4SidecarLineage(
        observation=observation,
        terminal_component=rc4_stage.decoded,
        recovered_components=tuple(recovered),
    )


__all__ = [
    "NsisRc4SidecarLineage",
    "analyze_nsis_rc4_sidecar_bundle",
]
