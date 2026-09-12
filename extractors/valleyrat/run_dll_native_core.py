"""``run`` export型native loaderから固定幅設定を静的に復元する。

このmoduleは検体を実行せず、外部通信も行わない。既知componentで確認した
PE構造、3件の固定幅UTF-16LE record、実行sectionから各fieldへの参照が
すべて一致する場合だけ設定候補を返す。さらに共通native data-flow coreで
run exportからnetwork sinkまでを評価し、証明が閉じない場合は欠落code付きの
route-only結果に留める。
"""

from __future__ import annotations

import ipaddress
import re
import struct
from dataclasses import dataclass

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, Cs, CsError
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_REG_INVALID

from extractors.native_dataflow import NativeSource, analyze_x86_pe_dataflow
from extractors.valleyrat.run_dll_native_terminal import (
    analyze_run_dll_terminal_lineage,
)

MINIMUM_SAMPLE_SIZE = 350 * 1024
MAXIMUM_SAMPLE_SIZE = 450 * 1024
HOST_FIELD_SIZE = 510
PORT_FIELD_SIZE = 60
RECORD_FIELD_SIZE = HOST_FIELD_SIZE + PORT_FIELD_SIZE
MAXIMUM_SECTION_COUNT = 5
MAXIMUM_IMPORT_COUNT = 4_096
MAXIMUM_CONFIG_CANDIDATES = 2

PROFILE_SECTION_NAMES = (".text", ".rdata", ".data", ".fptable", ".reloc")
PROFILE_IMPORT_LIBRARIES = {
    "advapi32",
    "bcrypt",
    "dxgi",
    "gdi32",
    "gdiplus",
    "kernel32",
    "ole32",
    "oleaut32",
    "shlwapi",
    "user32",
    "winmm",
    "ws2_32",
}
PROFILE_REQUIRED_APIS = {
    "BCryptOpenAlgorithmProvider",
    "CreateRemoteThread",
    "GetThreadContext",
    "SetThreadContext",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "connect",
    "recv",
    "send",
    "socket",
}

_DOMAIN_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_HOST_START_BYTES = frozenset(
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)


@dataclass(frozen=True)
class _SectionView:
    """境界検証済みPE sectionの最小view。"""

    name: str
    raw_start: int
    raw_end: int
    virtual_address: int
    executable: bool


@dataclass(frozen=True)
class _ConfigRecord:
    """内部検証にoffsetを保持する固定幅設定record。"""

    host: str
    port: int
    selector: int
    host_offset: int
    port_offset: int
    selector_offset: int


def _empty_probe(status: str = "not_matched") -> dict[str, object]:
    """部分一致を昇格しない固定shapeを返す。"""

    return {
        "matched": False,
        "family": None,
        "variant": None,
        "supports_family_attribution": False,
        "static_config_recovered": False,
        "candidate_config_recovered": False,
        "terminal_family_confirmed": False,
        "evidence": {"status": status},
        "config": {},
        "sample_executed": False,
        "network_contacted": False,
    }


def _directory_size(image: pefile.PE, index: int) -> int | None:
    """任意header値を例外やbool混入なしで取得する。"""

    try:
        directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[index]
        size = directory.Size
    except (AttributeError, IndexError, TypeError, ValueError, OverflowError):
        return None
    if type(size) is not int or size < 0:
        return None
    return size


def _section_views(image: pefile.PE, data_size: int) -> list[_SectionView] | None:
    """exact section列とraw範囲を検証する。"""

    try:
        sections = list(image.sections)
        declared_count = image.FILE_HEADER.NumberOfSections
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if (
        type(declared_count) is not int
        or declared_count != len(sections)
        or len(sections) != MAXIMUM_SECTION_COUNT
    ):
        return None
    views: list[_SectionView] = []
    prior_end = 0
    for section in sections:
        try:
            name = bytes(section.Name).rstrip(b"\x00").decode("ascii", errors="strict")
            raw_start = section.PointerToRawData
            raw_size = section.SizeOfRawData
            virtual_address = section.VirtualAddress
            characteristics = section.Characteristics
        except (AttributeError, UnicodeError, TypeError, ValueError, OverflowError):
            return None
        if any(
            type(value) is not int
            for value in (raw_start, raw_size, virtual_address, characteristics)
        ):
            return None
        raw_end = raw_start + raw_size
        if (
            raw_start < 0
            or raw_size < 0
            or raw_end < raw_start
            or raw_end > data_size
            or raw_start < prior_end
            or virtual_address < 0
        ):
            return None
        views.append(
            _SectionView(
                name=name,
                raw_start=raw_start,
                raw_end=raw_end,
                virtual_address=virtual_address,
                executable=bool(characteristics & 0x20000000),
            )
        )
        prior_end = raw_end
    if tuple(view.name for view in views) != PROFILE_SECTION_NAMES:
        return None
    if [view.name for view in views if view.executable] != [".text"]:
        return None
    if any(view.raw_end <= view.raw_start for view in views if view.name != ".fptable"):
        return None
    return views


def _decode_library(value: object) -> str | None:
    if not isinstance(value, bytes) or not 1 <= len(value) <= 128:
        return None
    try:
        name = value.decode("ascii", errors="strict").casefold()
    except UnicodeError:
        return None
    return name.removesuffix(".dll")


def _imports(image: pefile.PE) -> tuple[set[str], set[str]] | None:
    """ordinalや壊れたdescriptorを許容せずimport集合を返す。"""

    try:
        descriptors = list(image.DIRECTORY_ENTRY_IMPORT)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    libraries: set[str] = set()
    apis: set[str] = set()
    import_count = 0
    for descriptor in descriptors:
        try:
            raw_library = descriptor.dll
        except AttributeError:
            return None
        library = _decode_library(raw_library)
        if library is None or library in libraries:
            return None
        libraries.add(library)
        try:
            imports = list(descriptor.imports)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if not imports:
            return None
        for imported in imports:
            import_count += 1
            if import_count > MAXIMUM_IMPORT_COUNT:
                return None
            try:
                raw_name = imported.name
            except AttributeError:
                return None
            if not isinstance(raw_name, bytes) or not 1 <= len(raw_name) <= 128:
                return None
            try:
                name = raw_name.decode("ascii", errors="strict")
            except UnicodeError:
                return None
            if not name or any(ord(character) < 0x20 for character in name):
                return None
            apis.add(name)
    return libraries, apis


def _export_address(image: pefile.PE, executable: _SectionView) -> int | None:
    """唯一の非forwarded ``run`` exportのVAを返す。"""

    try:
        symbols = list(image.DIRECTORY_ENTRY_EXPORT.symbols)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if len(symbols) != 1:
        return None
    symbol = symbols[0]
    try:
        name = symbol.name
        address = symbol.address
    except AttributeError:
        return None
    forwarder = symbol.forwarder if hasattr(symbol, "forwarder") else None
    if name != b"run" or forwarder is not None:
        return None
    try:
        image_base = image.OPTIONAL_HEADER.ImageBase
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if not (
        type(address) is int
        and type(image_base) is int
        and executable.virtual_address
        <= address
        < executable.virtual_address + (executable.raw_end - executable.raw_start)
        and 0 <= image_base + address <= 0xFFFFFFFF
    ):
        return None
    return image_base + address


def _native_sources(
    image: pefile.PE,
    records: tuple[_ConfigRecord, _ConfigRecord, _ConfigRecord],
) -> tuple[NativeSource, ...] | None:
    """configの値を公開せず、9 fieldのVA範囲と役割だけを構成する。"""

    try:
        image_base = image.OPTIONAL_HEADER.ImageBase
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if type(image_base) is not int or not 0 <= image_base <= 0xFFFFFFFF:
        return None
    result: list[NativeSource] = []
    for slot, record in enumerate(records, start=1):
        for field, offset, size, kind in (
            ("host", record.host_offset, HOST_FIELD_SIZE, "host"),
            ("port", record.port_offset, PORT_FIELD_SIZE, "port"),
            ("selector", record.selector_offset, 4, "selector"),
        ):
            rva = _mapped_rva(image, offset)
            if rva is None or image_base + rva > 0xFFFFFFFF:
                return None
            result.append(
                NativeSource(
                    name=f"slot_{slot}_{field}",
                    address=image_base + rva,
                    size=size,
                    kind=kind,
                )
            )
    return tuple(result)


def _terminal_protocol_contract(data: bytes) -> dict[str, object]:
    """文字列の存在を終端証明と誤認せず、serializer未証明を明示する。"""

    frame_marker_candidate = any(
        marker in data
        for marker in (
            b"CA00",
            b"CA01",
            "CA00".encode("utf-16le"),
            "CA01".encode("utf-16le"),
        )
    )
    return {
        "proven": False,
        "status": "serializer_producer_consumer_lineage_unproven",
        "frame_marker_candidate_present": frame_marker_candidate,
        "literal_marker_alone_is_terminal_proof": False,
        "raw_frame_included": False,
    }


def _decode_zero_padded_utf16(data: bytes, start: int, width: int) -> str | None:
    """固定幅fieldをNUL終端とzero paddingまで含めて検証する。"""

    if start < 0 or width <= 0 or width % 2 or start + width > len(data):
        return None
    characters: list[str] = []
    terminated_at: int | None = None
    for relative in range(0, width, 2):
        unit = struct.unpack_from("<H", data, start + relative)[0]
        if unit == 0:
            terminated_at = relative
            break
        if not 0x20 <= unit <= 0x7E:
            return None
        characters.append(chr(unit))
    if terminated_at is None or not characters:
        return None
    if any(data[start + terminated_at : start + width]):
        return None
    return "".join(characters)


def _normalize_external_host(value: str) -> str | None:
    """global IPv4または厳格なASCII domainだけを主C2候補として扱う。"""

    host = value.rstrip(".").casefold()
    if not host or len(host) > 253:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split(".")
        if (
            len(labels) < 2
            or any(_DOMAIN_LABEL.fullmatch(label) is None for label in labels)
            or labels[-1].isdigit()
        ):
            return None
        return host
    if address.version != 4 or not address.is_global:
        return None
    return str(address)


def _normalize_loopback_host(value: str) -> str | None:
    """IPv4/IPv6 loopbackだけをplaceholder hostとして正規化する。"""

    host = value.rstrip(".").casefold()
    if not host or len(host) > 253:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if not address.is_loopback:
        return None
    return str(address)


def _mapped_rva(image: pefile.PE, offset: int) -> int | None:
    try:
        value = image.get_rva_from_offset(offset)
    except (AttributeError, TypeError, ValueError, OverflowError, pefile.PEFormatError):
        return None
    return value if type(value) is int and value >= 0 else None


def _mapped_offset(image: pefile.PE, rva: int) -> int | None:
    try:
        value = image.get_offset_from_rva(rva)
    except (AttributeError, TypeError, ValueError, OverflowError, pefile.PEFormatError):
        return None
    return value if type(value) is int and value >= 0 else None


def _read_record(
    data: bytes,
    image: pefile.PE,
    section: _SectionView,
    start: int,
) -> tuple[_ConfigRecord, int] | None:
    """1件のhost/port/aligned selector recordを読む。"""

    port_offset = start + HOST_FIELD_SIZE
    host = _decode_zero_padded_utf16(data, start, HOST_FIELD_SIZE)
    port_text = _decode_zero_padded_utf16(data, port_offset, PORT_FIELD_SIZE)
    start_rva = _mapped_rva(image, start)
    if host is None or port_text is None or start_rva is None:
        return None
    selector_rva = (start_rva + RECORD_FIELD_SIZE + 3) & ~3
    selector_offset = _mapped_offset(image, selector_rva)
    next_offset = _mapped_offset(image, selector_rva + 4)
    if (
        selector_offset is None
        or next_offset is None
        or selector_offset < port_offset + PORT_FIELD_SIZE
        or selector_offset + 4 > section.raw_end
        or any(ord(character) > 0x7F for character in port_text)
        or not port_text.isdigit()
    ):
        return None
    port = int(port_text)
    selector = struct.unpack_from("<I", data, selector_offset)[0]
    if not 1 <= port <= 65535 or selector not in {0, 1}:
        return None
    return (
        _ConfigRecord(
            host=host,
            port=port,
            selector=selector,
            host_offset=start,
            port_offset=port_offset,
            selector_offset=selector_offset,
        ),
        next_offset,
    )


def _referenced_operand(
    disassembler: Cs,
    code: bytes,
    code_address: int,
    packed_offset: int,
    target: int,
) -> bool:
    """packed VAを覆うx86 instruction operandがtargetそのものか検証する。"""

    search_start = max(0, packed_offset - 15)
    for instruction_start in range(search_start, packed_offset + 1):
        chunk = code[instruction_start : min(len(code), instruction_start + 15)]
        try:
            instructions = list(
                disassembler.disasm(
                    chunk,
                    code_address + instruction_start,
                    count=1,
                )
            )
        except CsError:
            continue
        if not instructions:
            continue
        instruction = instructions[0]
        instruction_end = instruction_start + instruction.size
        if not (
            instruction_start <= packed_offset and packed_offset + 4 <= instruction_end
        ):
            continue
        for operand in instruction.operands:
            if operand.type == X86_OP_IMM and (operand.imm & 0xFFFFFFFF) == target:
                return True
            if (
                operand.type == X86_OP_MEM
                and operand.mem.base == X86_REG_INVALID
                and operand.mem.index == X86_REG_INVALID
                and (operand.mem.disp & 0xFFFFFFFF) == target
            ):
                return True
    return False


def _code_reference_counts(
    data: bytes,
    image: pefile.PE,
    executable: _SectionView,
    offsets: tuple[int, ...],
) -> dict[int, int] | None:
    """全config field addressが実行sectionのoperandで参照されることを確認する。"""

    try:
        image_base = image.OPTIONAL_HEADER.ImageBase
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if type(image_base) is not int or not 0 <= image_base <= 0xFFFFFFFF:
        return None
    try:
        disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
        disassembler.detail = True
    except CsError:
        return None
    code = data[executable.raw_start : executable.raw_end]
    code_address = image_base + executable.virtual_address
    counts: dict[int, int] = {}
    for offset in offsets:
        rva = _mapped_rva(image, offset)
        if rva is None:
            return None
        target = image_base + rva
        if not 0 <= target <= 0xFFFFFFFF:
            return None
        packed = struct.pack("<I", target)
        count = 0
        position = code.find(packed)
        while position >= 0:
            if _referenced_operand(
                disassembler,
                code,
                code_address,
                position,
                target,
            ):
                count += 1
            position = code.find(packed, position + 1)
        if count < 1:
            return None
        counts[target] = count
    return counts if len(counts) == len(offsets) else None


def _config_candidates(
    data: bytes,
    image: pefile.PE,
    data_section: _SectionView,
    executable: _SectionView,
) -> list[tuple[tuple[_ConfigRecord, _ConfigRecord, _ConfigRecord], dict[int, int]]]:
    """一意な3-record configと9個のcode-referenceを探索する。"""

    results: list[
        tuple[tuple[_ConfigRecord, _ConfigRecord, _ConfigRecord], dict[int, int]]
    ] = []
    minimum_size = RECORD_FIELD_SIZE * 3 + 12
    final_start = data_section.raw_end - minimum_size
    if final_start < data_section.raw_start:
        return results
    for start in range(data_section.raw_start, final_start + 1):
        if (
            start + 1 >= len(data)
            or data[start] not in _HOST_START_BYTES
            or data[start + 1] != 0
        ):
            continue
        start_rva = _mapped_rva(image, start)
        if start_rva is None:
            continue
        try:
            image_base = image.OPTIONAL_HEADER.ImageBase
        except AttributeError:
            return []
        if type(image_base) is not int or (image_base + start_rva) % 2:
            continue
        parsed: list[_ConfigRecord] = []
        next_start = start
        for _index in range(3):
            value = _read_record(data, image, data_section, next_start)
            if value is None:
                break
            record, next_start = value
            parsed.append(record)
        if len(parsed) != 3:
            continue
        first, second, fallback = parsed
        normalized_primary = _normalize_external_host(first.host)
        normalized_duplicate = _normalize_external_host(second.host)
        normalized_fallback = _normalize_loopback_host(fallback.host)
        if (
            normalized_primary is None
            or normalized_duplicate != normalized_primary
            or first.port != second.port
            or first.selector != second.selector
            or normalized_fallback is None
        ):
            continue
        offsets = tuple(
            offset
            for record in parsed
            for offset in (
                record.host_offset,
                record.port_offset,
                record.selector_offset,
            )
        )
        references = _code_reference_counts(
            data,
            image,
            executable,
            offsets,
        )
        if references is None:
            continue
        normalized_first = _ConfigRecord(
            host=normalized_primary,
            port=first.port,
            selector=first.selector,
            host_offset=first.host_offset,
            port_offset=first.port_offset,
            selector_offset=first.selector_offset,
        )
        normalized_second = _ConfigRecord(
            host=normalized_primary,
            port=second.port,
            selector=second.selector,
            host_offset=second.host_offset,
            port_offset=second.port_offset,
            selector_offset=second.selector_offset,
        )
        normalized_placeholder = _ConfigRecord(
            host=normalized_fallback,
            port=fallback.port,
            selector=fallback.selector,
            host_offset=fallback.host_offset,
            port_offset=fallback.port_offset,
            selector_offset=fallback.selector_offset,
        )
        results.append(
            (
                (normalized_first, normalized_second, normalized_placeholder),
                references,
            )
        )
        if len(results) >= MAXIMUM_CONFIG_CANDIDATES:
            break
    return results


def _public_slot(record: _ConfigRecord, slot: int, role: str) -> dict[str, object]:
    return {
        "slot": slot,
        "host": record.host,
        "port": record.port,
        "transport_selector": record.selector,
        "transport": "tcp" if record.selector == 1 else "udp",
        "role": role,
    }


def probe_run_dll_native_core_config(data: bytes) -> dict[str, object]:
    """厳格なPE＋data-reference契約からroute-only C2設定を返す。"""

    if (
        not isinstance(data, bytes)
        or not MINIMUM_SAMPLE_SIZE <= len(data) <= MAXIMUM_SAMPLE_SIZE
        or not data.startswith(b"MZ")
    ):
        return _empty_probe()
    try:
        image = pefile.PE(data=data, fast_load=False)
    except (pefile.PEFormatError, TypeError, ValueError, OverflowError):
        return _empty_probe("invalid_pe")
    try:
        try:
            machine = image.FILE_HEADER.Machine
            characteristics = image.FILE_HEADER.Characteristics
            magic = image.OPTIONAL_HEADER.Magic
            subsystem = image.OPTIONAL_HEADER.Subsystem
        except (
            AttributeError,
            TypeError,
            ValueError,
            OverflowError,
            pefile.PEFormatError,
        ):
            return _empty_probe("invalid_pe_headers")
        if (
            machine != 0x14C
            or type(characteristics) is not int
            or not characteristics & 0x2000
            or magic != 0x10B
            or subsystem != 2
            or _directory_size(image, 2) != 0
            or _directory_size(image, 4) != 0
            or _directory_size(image, 14) != 0
        ):
            return _empty_probe("profile_mismatch")
        try:
            overlay_start = image.get_overlay_data_start_offset()
        except (
            AttributeError,
            TypeError,
            ValueError,
            OverflowError,
            pefile.PEFormatError,
        ):
            return _empty_probe("overlay_state_unavailable")
        if overlay_start is not None:
            return _empty_probe("overlay_rejected")
        sections = _section_views(image, len(data))
        if sections is None:
            return _empty_probe("section_contract_rejected")
        executable = sections[0]
        data_section = sections[2]
        run_export = _export_address(image, executable)
        if run_export is None:
            return _empty_probe("export_contract_rejected")
        imported = _imports(image)
        if imported is None:
            return _empty_probe("import_contract_rejected")
        libraries, apis = imported
        if libraries != PROFILE_IMPORT_LIBRARIES or not PROFILE_REQUIRED_APIS.issubset(
            apis
        ):
            return _empty_probe("import_profile_mismatch")
        candidates = _config_candidates(data, image, data_section, executable)
        if len(candidates) != 1:
            return _empty_probe("ambiguous_or_missing_static_triplet")
        records, references = candidates[0]
        first, second, _fallback = records
        sources = _native_sources(image, records)
        if sources is None:
            return _empty_probe("native_source_mapping_failed")
        native_flow = analyze_x86_pe_dataflow(
            data,
            image,
            roots=(run_export,),
            sources=sources,
            require_callback=True,
        )
        terminal_lineage = analyze_run_dll_terminal_lineage(
            data,
            image,
            run_export=run_export,
            sources=sources,
            selector_values=tuple(record.selector for record in records),
        )
        terminal_family_confirmed = bool(
            terminal_lineage["terminal_family_lineage_proven"] is True
        )
        protocol_proven = bool(
            terminal_lineage["proof"]["framed_send_receive"] is True
            and terminal_lineage["proof"]["registration_serializer"] is True
        )
        missing_proof_codes = list(terminal_lineage["missing_proof_codes"])
        if not terminal_family_confirmed:
            missing_proof_codes.extend(
                code
                for code in native_flow["missing_proof_codes"]
                if code not in missing_proof_codes
            )
        if not protocol_proven:
            missing_proof_codes.append("run_dll_terminal_protocol_serializer_unproven")
        terminal_protocol_contract = {
            "proven": protocol_proven,
            "status": (
                "validated_serializer_producer_consumer_lineage"
                if protocol_proven
                else "serializer_producer_consumer_lineage_unproven"
            ),
            "frame_marker_candidate_present": (
                terminal_lineage["protocol"]["marker"] is not None
            ),
            "literal_marker_alone_is_terminal_proof": False,
            "raw_frame_included": False,
        }
        endpoint = f"{first.host}:{first.port}"
        slots = [
            _public_slot(first, 1, "primary"),
            _public_slot(second, 2, "primary"),
        ]
        evidence = {
            "status": (
                "validated_terminal_family_config"
                if terminal_family_confirmed
                else "validated_static_config_route_candidate"
            ),
            "profile": "run_dll_native_core",
            "sample_size": len(data),
            "section_count": len(sections),
            "import_library_count": len(libraries),
            "import_api_count": len(apis),
            "configuration_record_count": 3,
            "unique_configuration_count": 1,
            "duplicate_primary_slot_count": 2,
            "external_endpoint_count": 1,
            "loopback_placeholder_slot_count": 1,
            "loopback_placeholder_values_included": False,
            "validated_code_reference_target_count": len(references),
            "validated_code_reference_count": sum(references.values()),
            "native_dataflow": native_flow,
            "run_dll_terminal_lineage": terminal_lineage,
            "terminal_protocol_contract": terminal_protocol_contract,
            "missing_proof_codes": missing_proof_codes,
            "raw_config_included": False,
            "raw_payload_included": False,
        }
        return {
            "matched": True,
            "family": "valleyrat" if terminal_family_confirmed else None,
            "variant": (
                "run_dll_native_terminal_config"
                if terminal_family_confirmed
                else "run_dll_native_core_static_triplet_candidate"
            ),
            "supports_family_attribution": terminal_family_confirmed,
            "attribution_scope": (
                "terminal_payload"
                if terminal_family_confirmed
                else "component_handler_route"
            ),
            "terminal_family_confirmed": terminal_family_confirmed,
            "family_attribution_basis": (
                "run_export_config_to_same_socket_network_and_terminal_protocol"
                if terminal_family_confirmed
                else "strict_run_export_native_core_pe_and_unique_referenced_static_triplet"
            ),
            "classification_confidence": (
                "confirmed_static_terminal_lineage"
                if terminal_family_confirmed
                else "high_structural_static_config_candidate"
            ),
            "decoded_config_recovered": False,
            "static_config_recovered": True,
            "candidate_config_recovered": not terminal_family_confirmed,
            "endpoints": [endpoint],
            "slots": slots,
            "excluded_placeholder_defaults": [],
            "evidence": evidence,
            "config": {
                "endpoint_count": 1,
                "record_count": 3,
                "raw_config_included": False,
                "raw_network_values_included": False,
            },
            "sample_executed": False,
            "network_contacted": False,
        }
    finally:
        # data=で構築したin-memory viewだけを保持し、file handleは開かない。
        del image


__all__ = [
    "MAXIMUM_SAMPLE_SIZE",
    "MINIMUM_SAMPLE_SIZE",
    "PROFILE_IMPORT_LIBRARIES",
    "PROFILE_REQUIRED_APIS",
    "PROFILE_SECTION_NAMES",
    "probe_run_dll_native_core_config",
]
