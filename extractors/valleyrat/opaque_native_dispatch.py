"""x64 opaque pointer dispatchを有界に復元するfamily-neutral probe。

このprobeは、実行時にXORされるfunction pointer slotと短いcontrol bytecodeを
組み合わせるnative dispatcherを静的に可視化する。dispatcherの存在だけでは
ValleyRAT、設定、C2、または通信到達性を証明しない。値やaddressは公開結果へ
含めず、terminal network lineageが別途閉じない限り必ずfail-closedにする。
"""

from __future__ import annotations

import struct
from collections import Counter, deque
from dataclasses import dataclass

import pefile
from capstone import CS_ARCH_X86, CS_GRP_JUMP, CS_GRP_RET, CS_MODE_64, Cs
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_RCX,
    X86_REG_RIP,
)

MAXIMUM_SAMPLE_SIZE = 64 * 1024 * 1024
MAXIMUM_SECTION_COUNT = 96
MAXIMUM_DESCRIPTOR_SCAN_BYTES = 8 * 1024 * 1024
MAXIMUM_DESCRIPTOR_COUNT = 8_192
MAXIMUM_CONTROL_LENGTH = 64
MAXIMUM_DISASSEMBLY_BYTES = 16 * 1024 * 1024
MAXIMUM_INSTRUCTION_COUNT = 250_000
MAXIMUM_IMPORT_DESCRIPTORS = 512
MAXIMUM_IMPORT_COUNT = 8_192

_DESCRIPTOR_SIZE = 56
_CONTROL_XOR_CONSTANT = 0x9E3779B97F4A7C15
_CONTROL_OPCODES = frozenset({0x00, 0x10, 0x20, 0x40, 0xFF})
_NETWORK_LIBRARIES = frozenset(
    {
        "dnsapi.dll",
        "urlmon.dll",
        "winhttp.dll",
        "wininet.dll",
        "ws2_32.dll",
        "wsock32.dll",
    }
)
_NETWORK_APIS = frozenset(
    {
        "connect",
        "dnsquery_a",
        "dnsquery_w",
        "getaddrinfo",
        "gethostbyname",
        "internetconnecta",
        "internetconnectw",
        "internetopena",
        "internetopenw",
        "recv",
        "send",
        "socket",
        "urldownloadtofilea",
        "urldownloadtofilew",
        "winhttpconnect",
        "winhttpopen",
        "wsastartup",
    }
)


@dataclass(frozen=True)
class _Section:
    address: int
    raw_start: int
    raw_size: int
    executable: bool

    @property
    def raw_end(self) -> int:
        return self.raw_start + self.raw_size

    def contains_address(self, address: int) -> bool:
        return self.address <= address < self.address + self.raw_size

    def offset(self, address: int) -> int:
        return self.raw_start + address - self.address


@dataclass(frozen=True)
class _Descriptor:
    address: int
    target: int


def decode_control_bytecode(ciphertext: bytes, key: int) -> bytes | None:
    """最大64 byteのdispatcher control bytecodeを復号・検証する。"""

    if not 1 <= len(ciphertext) <= MAXIMUM_CONTROL_LENGTH:
        return None
    key_bytes = (key ^ _CONTROL_XOR_CONSTANT).to_bytes(8, "little")
    plaintext = bytes(
        value ^ ((key_bytes[index & 7] + 27 * index - 0x5B) & 0xFF)
        for index, value in enumerate(ciphertext)
    )
    if any(value not in _CONTROL_OPCODES for value in plaintext):
        return None
    if plaintext[-1] != 0xFF or plaintext.count(0xFF) != 1:
        return None
    if plaintext.count(0x40) != 1:
        return None
    if plaintext.count(0x10) + plaintext.count(0x20) != 1:
        return None
    return plaintext


def _empty_result(status: str, missing: list[str]) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": status,
        "matched": False,
        "profile": "x64_opaque_pointer_dispatch",
        "static_analysis_route_recovered": False,
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "static_config_recovered": False,
        "network_lineage_proven": False,
        "evidence": {
            "architecture": "unknown",
            "opaque_dispatch": {
                "descriptor_count": 0,
                "referenced_descriptor_count": 0,
                "unique_target_count": 0,
                "resolver_candidate_count": 0,
                "dominant_resolver_reference_count": 0,
                "candidate_set_complete": False,
                "candidate_set_truncated": False,
                "scan_budget_exhausted": False,
            },
            "direct_import_surface": {
                "network_library_count": 0,
                "network_api_count": 0,
                "import_inventory_complete": False,
            },
            "embedded_pe_count": 0,
        },
        "missing_proof_codes": missing,
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_config_included": False,
            "raw_payload_published": False,
        },
    }


def _build_sections(
    image: pefile.PE,
    data_size: int,
) -> tuple[list[_Section], bool]:
    raw_sections = list(getattr(image, "sections", ()))
    if not 1 <= len(raw_sections) <= MAXIMUM_SECTION_COUNT:
        return [], False
    base = int(image.OPTIONAL_HEADER.ImageBase)
    sections: list[_Section] = []
    for raw in raw_sections:
        raw_start = int(raw.PointerToRawData)
        raw_size = int(raw.SizeOfRawData)
        if raw_start < 0 or raw_size < 0 or raw_start + raw_size > data_size:
            return [], False
        if raw_size == 0:
            continue
        sections.append(
            _Section(
                address=base + int(raw.VirtualAddress),
                raw_start=raw_start,
                raw_size=raw_size,
                executable=bool(int(raw.Characteristics) & 0x20000000),
            )
        )
    return sections, bool(sections)


def _section_for_address(
    sections: list[_Section],
    address: int,
) -> _Section | None:
    return next(
        (section for section in sections if section.contains_address(address)),
        None,
    )


def _parse_descriptor_at(
    data: bytes,
    offset: int,
    address: int,
    sections: list[_Section],
) -> _Descriptor | None:
    if offset < 0 or offset + _DESCRIPTOR_SIZE > len(data):
        return None
    (
        initializer,
        next_descriptor,
        target,
        key,
        control_address,
        control_length,
        guard,
    ) = struct.unpack_from("<7Q", data, offset)
    initializer_section = _section_for_address(sections, initializer)
    target_section = _section_for_address(sections, target)
    control_section = _section_for_address(sections, control_address)
    if initializer_section is None or not initializer_section.executable:
        return None
    if target_section is None or not target_section.executable:
        return None
    if next_descriptor:
        next_section = _section_for_address(sections, next_descriptor)
        if next_section is None or next_section.executable:
            return None
    if control_section is None or control_section.executable:
        return None
    if not 1 <= control_length <= MAXIMUM_CONTROL_LENGTH:
        return None
    if key == 0 or guard == 0 or guard > 0xFFFFFFFF:
        return None
    control_offset = control_section.offset(control_address)
    control_end = control_offset + int(control_length)
    if control_offset < 0 or control_end > len(data):
        return None
    if decode_control_bytecode(data[control_offset:control_end], key) is None:
        return None
    return _Descriptor(address=address, target=target)


def _scan_descriptors(
    data: bytes,
    sections: list[_Section],
) -> tuple[list[_Descriptor], bool, bool]:
    candidates: list[_Descriptor] = []
    scanned = 0
    for section in sections:
        if section.executable:
            continue
        if scanned + section.raw_size > MAXIMUM_DESCRIPTOR_SCAN_BYTES:
            return candidates, False, True
        scanned += section.raw_size
        first = section.raw_start + ((-section.address) & 7)
        stop = section.raw_end - _DESCRIPTOR_SIZE + 1
        for offset in range(first, max(first, stop), 8):
            address = section.address + offset - section.raw_start
            candidate = _parse_descriptor_at(data, offset, address, sections)
            if candidate is None:
                continue
            candidates.append(candidate)
            if len(candidates) > MAXIMUM_DESCRIPTOR_COUNT:
                return candidates[:MAXIMUM_DESCRIPTOR_COUNT], False, True
    return candidates, True, False


def _recover_dispatch_references(
    data: bytes,
    sections: list[_Section],
    descriptors: list[_Descriptor],
) -> tuple[set[int], Counter[int], bool]:
    descriptor_addresses = {item.address for item in descriptors}
    referenced: set[int] = set()
    resolvers: Counter[int] = Counter()
    decoded_bytes = 0
    instruction_count = 0
    decoder = Cs(CS_ARCH_X86, CS_MODE_64)
    decoder.detail = True
    decoder.skipdata = True
    for section in sections:
        if not section.executable:
            continue
        decoded_bytes += section.raw_size
        if decoded_bytes > MAXIMUM_DISASSEMBLY_BYTES:
            return referenced, resolvers, False
        pending: deque[tuple[int, int]] = deque()
        code = data[section.raw_start : section.raw_end]
        for instruction in decoder.disasm(code, section.address):
            instruction_count += 1
            if instruction_count > MAXIMUM_INSTRUCTION_COUNT:
                return referenced, resolvers, False
            if instruction.id == 0:
                pending.clear()
                continue
            pending = deque(
                (address, age + 1)
                for address, age in pending
                if age + 1 <= 8
            )
            operands = instruction.operands
            if (
                instruction.mnemonic == "lea"
                and len(operands) == 2
                and operands[0].type == X86_OP_REG
                and operands[0].reg == X86_REG_RCX
                and operands[1].type == X86_OP_MEM
                and operands[1].mem.base == X86_REG_RIP
            ):
                address = (
                    instruction.address
                    + instruction.size
                    + operands[1].mem.disp
                )
                if address in descriptor_addresses:
                    pending.append((address, 0))
            if (
                instruction.mnemonic == "call"
                and operands
                and operands[0].type == X86_OP_IMM
            ):
                call_target = int(operands[0].imm)
                for descriptor_address, _age in pending:
                    referenced.add(descriptor_address)
                    resolvers[call_target] += 1
                pending.clear()
            if instruction.group(CS_GRP_JUMP) or instruction.group(CS_GRP_RET):
                pending.clear()
    return referenced, resolvers, True


def _import_surface(image: pefile.PE) -> tuple[int, int, bool]:
    descriptors = list(getattr(image, "DIRECTORY_ENTRY_IMPORT", ()))
    if len(descriptors) > MAXIMUM_IMPORT_DESCRIPTORS:
        return 0, 0, False
    library_matches = 0
    api_matches = 0
    import_count = 0
    for descriptor in descriptors:
        try:
            library = bytes(descriptor.dll).decode("ascii", errors="strict").casefold()
            imported = list(descriptor.imports)
        except (AttributeError, TypeError, UnicodeDecodeError):
            return 0, 0, False
        import_count += len(imported)
        if import_count > MAXIMUM_IMPORT_COUNT:
            return 0, 0, False
        if library in _NETWORK_LIBRARIES:
            library_matches += 1
        for item in imported:
            raw_name = getattr(item, "name", None)
            if not isinstance(raw_name, bytes):
                continue
            try:
                name = raw_name.decode("ascii", errors="strict").casefold()
            except UnicodeDecodeError:
                return 0, 0, False
            if name in _NETWORK_APIS:
                api_matches += 1
    return library_matches, api_matches, True


def _embedded_pe_count(data: bytes) -> int:
    count = 0
    cursor = 1
    for _ in range(4_096):
        offset = data.find(b"MZ", cursor)
        if offset < 0:
            break
        cursor = offset + 2
        if offset + 0x40 > len(data):
            continue
        pe_offset = struct.unpack_from("<I", data, offset + 0x3C)[0]
        if pe_offset > 1024 * 1024:
            continue
        signature = offset + pe_offset
        if signature + 4 <= len(data) and data[signature : signature + 4] == b"PE\0\0":
            count += 1
    return count


def probe_opaque_native_dispatch(data: bytes) -> dict[str, object]:
    """opaque dispatcherを診断する。family/configの確定には使用しない。"""

    if len(data) > MAXIMUM_SAMPLE_SIZE:
        return _empty_result("budget_exceeded", ["sample_size_budget_exceeded"])
    if len(data) < 0x100 or data[:2] != b"MZ":
        return _empty_result("not_detected", ["valid_x64_pe_missing"])
    try:
        image = pefile.PE(data=data, fast_load=False)
        machine = int(image.FILE_HEADER.Machine)
        magic = int(image.OPTIONAL_HEADER.Magic)
    except (AttributeError, OSError, OverflowError, TypeError, ValueError, pefile.PEFormatError):
        return _empty_result("not_detected", ["valid_x64_pe_missing"])
    if machine != 0x8664 or magic != 0x20B:
        return _empty_result("not_detected", ["x64_pe_required"])
    sections, sections_complete = _build_sections(image, len(data))
    if not sections_complete:
        return _empty_result("assessment_rejected", ["file_backed_sections_invalid"])
    descriptors, candidates_complete, scan_exhausted = _scan_descriptors(data, sections)
    referenced, resolvers, disassembly_complete = _recover_dispatch_references(
        data,
        sections,
        descriptors,
    )
    network_libraries, network_apis, imports_complete = _import_surface(image)
    unique_targets = len({item.target for item in descriptors})
    dominant_references = resolvers.most_common(1)[0][1] if resolvers else 0
    resolver_reference_total = sum(resolvers.values())
    dominant_ratio = (
        dominant_references / resolver_reference_total
        if resolver_reference_total
        else 0.0
    )
    route_recovered = bool(
        candidates_complete
        and disassembly_complete
        and len(descriptors) >= 64
        and len(referenced) >= 32
        and unique_targets >= 16
        and dominant_references >= 32
        and dominant_ratio >= 0.8
    )
    status = (
        "opaque_native_dispatch_recovered"
        if route_recovered
        else "assessment_rejected"
    )
    missing = [
        "terminal_family_lineage_missing",
        "config_source_decoder_parser_lineage_missing",
        "connect_send_receive_lineage_missing",
    ]
    if network_libraries == 0 and network_apis == 0:
        missing.append("direct_network_import_surface_missing")
    if _embedded_pe_count(data) == 0:
        missing.append("embedded_pe_source_missing")
    return {
        "schema_version": 1,
        "status": status,
        "matched": route_recovered,
        "profile": "x64_opaque_pointer_dispatch",
        "static_analysis_route_recovered": route_recovered,
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "static_config_recovered": False,
        "network_lineage_proven": False,
        "evidence": {
            "architecture": "x86_64",
            "opaque_dispatch": {
                "descriptor_count": len(descriptors),
                "referenced_descriptor_count": len(referenced),
                "unique_target_count": unique_targets,
                "resolver_candidate_count": len(resolvers),
                "dominant_resolver_reference_count": dominant_references,
                "candidate_set_complete": candidates_complete,
                "candidate_set_truncated": scan_exhausted,
                "scan_budget_exhausted": scan_exhausted
                or not disassembly_complete,
            },
            "direct_import_surface": {
                "network_library_count": network_libraries,
                "network_api_count": network_apis,
                "import_inventory_complete": imports_complete,
            },
            "embedded_pe_count": _embedded_pe_count(data),
        },
        "missing_proof_codes": missing,
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_config_included": False,
            "raw_payload_published": False,
        },
    }


__all__ = ["decode_control_bytecode", "probe_opaque_native_dispatch"]
