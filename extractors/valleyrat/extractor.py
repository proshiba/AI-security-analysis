"""レビュー済みValleyRAT campaign variantから設定指標を静的に抽出する。"""

from __future__ import annotations

import hashlib
import re
import struct
from collections import deque
from dataclasses import dataclass
from pathlib import PurePosixPath
from urllib.parse import urlsplit, urlunsplit

import pefile
from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs, CsError
from capstone.x86 import (
    X86_OP_IMM,
    X86_OP_MEM,
    X86_OP_REG,
    X86_REG_EBP,
    X86_REG_ESP,
    X86_REG_INVALID,
    X86_REG_RIP,
)

from extractors.common import (
    build_result,
    endpoint_candidates,
    ipv4_candidates,
    sha256_bytes,
    url_candidates,
)
from extractors.stealer_common import infrastructure_urls
from extractors.valleyrat.ca01_sideload import (
    public_recovery_summary as public_ca01_recovery_summary,
)
from extractors.valleyrat.ca01_sideload import (
    recover_config as recover_ca01_config,
)
from extractors.valleyrat.ca01_sideload import (
    validate_recovery_contract as validate_ca01_recovery_contract,
)
from extractors.valleyrat.export_funnel import (
    collect_external_code_roots,
    probe_export_funnel_route,
)
from extractors.valleyrat.n520 import (
    N520ConfigError,
)
from extractors.valleyrat.n520 import (
    public_recovery_summary as public_n520_recovery_summary,
)
from extractors.valleyrat.n520 import (
    recover_config as recover_n520_config,
)
from extractors.valleyrat.n520 import (
    structural_evidence as n520_structural_evidence,
)
from extractors.valleyrat.nvml_dat import (
    NvmlDatError,
    looks_like_nvml_dat,
    normalize_host,
    parse_codemark_config,
    parse_endpoint,
    public_recovery_summary,
    recover_nvml_dat,
    render_authority,
    render_endpoint,
)
from extractors.valleyrat.native_loader_lineage import (
    analyze_native_loader_lineage,
)
from extractors.valleyrat.run_dll_native_core import (
    probe_run_dll_native_core_config,
)
from extractors.valleyrat.silverfox_loader_lineage import (
    analyze_silverfox_loader_lineage,
)
from extractors.valleyrat.wide_pipe_config import (
    public_recovery_summary as public_wide_pipe_recovery_summary,
)
from extractors.valleyrat.wide_pipe_config import (
    recover_config as recover_wide_pipe_config,
)
from extractors.valleyrat.x86_codemark_resource import (
    analyze_raw_stage as analyze_x86_codemark_stage,
)
from extractors.valleyrat.x86_codemark_resource import (
    probe_resource_config as probe_x86_codemark_resource_config,
)
from extractors.valleyrat.x86_codemark_resource import (
    public_recovery_summary as public_x86_codemark_recovery_summary,
)
from extractors.valleyrat.x86_codemark_resource import (
    recover_from_pe as recover_x86_codemark_resource,
)
from extractors.valleyrat.zip_sideload_shellcode import (
    public_raw_shellcode_summary,
    recover_raw_vvas_shellcode,
)
from unpackers.bin101_nibble_rc4 import (
    looks_like_bin101_profile,
    recover_bin101_payload,
)
from unpackers.bin101_nibble_rc4 import (
    public_recovery_summary as public_bin101_recovery_summary,
)
from unpackers.onyx_qt_loader import (
    matches_onyx_qt_profile,
    recover_onyx_qt_payload,
    recover_onyx_terminal_config,
)

HANDLER_CONTRACT = {
    "input_formats": ["pe", "data"],
    "minimum_evidence_score": 30_000,
}

MAXIMUM_INPUT_SIZE = 64 * 1024 * 1024
MAXIMUM_STRING_COUNT = 100_000
MAXIMUM_STRING_LENGTH = 8_192
MAXIMUM_STRING_CHARACTERS = 4 * 1024 * 1024
MAXIMUM_VVAS_XOR_INPUT_SIZE = 8 * 1024 * 1024
MAXIMUM_VVAS_XOR_CANDIDATES = 4
# 大容量の低entropy mapped data sectionも、全体文字列列挙を行わずに
# 走査できるよう、PE probeは共有extractor上限まで受け付ける。実際に
# marker走査するbyte数は、下記の独立したsection/total上限でさらに絞る。
MAXIMUM_VVAS_PROBE_INPUT_SIZE = MAXIMUM_INPUT_SIZE
MAXIMUM_VVAS_PE_GLOBAL_STRING_SCAN_INPUT_SIZE = 16 * 1024 * 1024
MAXIMUM_PE_IMPORT_DESCRIPTORS = 1_024
MAXIMUM_PE_IMPORTS = 65_536
MAXIMUM_PE_IMPORT_NAME_LENGTH = 128
MAXIMUM_VVAS_PE_SECTIONS = 96
MAXIMUM_VVAS_EXECUTABLE_BYTES = 8 * 1024 * 1024
MAXIMUM_VVAS_CONFIG_LOCATIONS = 32
MAXIMUM_VVAS_MAPPED_SCAN_SECTIONS = 96
MAXIMUM_VVAS_MAPPED_SCAN_SECTION_BYTES = 40 * 1024 * 1024
MAXIMUM_VVAS_MAPPED_SCAN_TOTAL_BYTES = 48 * 1024 * 1024
MAXIMUM_VVAS_MAPPED_SCAN_CHUNK_BYTES = 256 * 1024
MAXIMUM_VVAS_MAPPED_SCAN_HITS = 64
MAXIMUM_VVAS_MAPPED_CANDIDATE_CHARACTERS = 8_192
MAXIMUM_VVAS_REACHABLE_FUNCTIONS = 2_048
MAXIMUM_VVAS_FUNCTION_INSTRUCTIONS = 16_384
MAXIMUM_VVAS_REACHABLE_INSTRUCTIONS = 200_000
MAXIMUM_VVAS_CALL_GRAPH_DEPTH = 64
MAXIMUM_VVAS_CALL_GRAPH_EDGES = 32_768
MAXIMUM_VVAS_PENDING_FUNCTIONS = 2_048
MAXIMUM_VVAS_COMPONENT_EDGES = 16_384
MAXIMUM_VVAS_NETWORK_PATH_STATES = 262_144
MAXIMUM_VVAS_NETWORK_CHAIN_STATES = 65_536
MAXIMUM_VVAS_DIRECT_CALLS_PER_FUNCTION = 2_048
MAXIMUM_VVAS_DATA_REFERENCES_PER_FUNCTION = 4_096
MAXIMUM_VVAS_VTABLE_ENTRIES = 32
MAXIMUM_VVAS_VTABLES_PER_FUNCTION = 64
MAXIMUM_VVAS_CREATE_THREAD_CALLS_PER_FUNCTION = 64
MAXIMUM_VVAS_CALLBACK_LOOKBACK_INSTRUCTIONS = 24
MAXIMUM_XOR_B1_URLS = 16
MINIMUM_CODEMARK_RAW_STAGE_SIZE = 512
MAXIMUM_CODEMARK_RAW_STAGE_SIZE = 4 * 1024 * 1024
VVAS_MARKER = b"odaktomk"
XOR_B1_KEY = 0xB1
_XOR_B1_TRANSLATION = bytes(value ^ XOR_B1_KEY for value in range(256))

_ASCII = re.compile(rb"[\x20-\x7e]{4,}")
_WIDE = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_XOR_B1_WININET_MARKER = re.compile(
    rb"(?:wininet\.dll|w\x00i\x00n\x00i\x00n\x00e\x00t\x00\.\x00d\x00l\x00l\x00)",
    re.IGNORECASE,
)
_VVAS_FIELD = re.compile(r"(?:^|\|)([pot][123]):([^|]{0,255})(?=\||$)", re.IGNORECASE)
_SENSITIVE_URL_PATH = re.compile(
    r"(?i)(?:^|/)(?:access[_-]?token|token|secret|password|passwd|"
    r"api[_-]?key|auth(?:orization)?)(?:[=/:_-]|$)"
)
_OPAQUE_URL_SEGMENT = re.compile(r"[A-Za-z0-9_-]{32,}(?:\.[A-Za-z0-9]{1,10})?\Z")

REVIEWED_PDFCORE8_ROTATED_VARIANTS = {
    "8136a9b1252e0d8c293c6c99444b371f3f7dc9fccbf351597a0aec029fe92a96": "pdfcore8_rotated_resource_proxy_component_20260813",
}


@dataclass(frozen=True)
class _VvasPeSection:
    """静的data-flowで利用する、検証済みPE sectionの有界view。"""

    name: str
    virtual_start: int
    virtual_end: int
    raw_start: int
    raw_end: int
    executable: bool
    resource: bool


@dataclass(frozen=True)
class _VvasMappedConfigCandidate:
    """marker-first走査で完全に検証したmapped設定候補。"""

    value: str
    raw_start: int
    raw_end: int
    configuration_identity: str
    encoding: str


@dataclass
class _VvasFunctionSummary:
    """1個のdirect-call function rootから得た非公開の到達性要約。"""

    start: int
    instruction_count: int
    direct_calls: set[int]
    direct_call_counts: dict[int, int]
    direct_call_first_sites: dict[int, int]
    direct_call_sites: dict[int, tuple[int, ...]]
    callback_targets: set[int]
    callback_sites: dict[int, int]
    callback_call_sites: dict[int, tuple[int, ...]]
    vtable_targets: set[int]
    vtable_target_sites: dict[int, tuple[int, ...]]
    api_names: set[str]
    api_calls: set[tuple[str, int]]
    api_call_sites: tuple[tuple[int, str, int], ...]
    cfg_successors: dict[int, tuple[int, ...]]
    instructions: dict[int, object]
    return_sites: tuple[int, ...]
    config_reference_count: int
    repeated_direct_call_count: int
    utf16_reverse_loop: bool


def _safe_source_name(name: str) -> str:
    """呼出元が渡したpathからbasenameだけを公開する。"""

    value = str(name).replace("\\", "/")
    basename = PurePosixPath(value).name[:255]
    return (
        "".join(character for character in basename if ord(character) >= 0x20)
        or "sample"
    )


def _bounded_strings(data: bytes) -> tuple[list[str], dict[str, object]]:
    """件数・単体長・総文字数を上限付きでASCII／UTF-16LE抽出する。

    上限到達を空振りと区別できるよう、走査完了状態も返す。設定の一意性を
    判定するcallerは ``truncated`` が真なら候補を採用してはならない。
    """

    values: list[str] = []
    seen: set[str] = set()
    characters = 0
    truncation_reasons: set[str] = set()

    def scan_evidence() -> dict[str, object]:
        return {
            "completed": not truncation_reasons,
            "truncated": bool(truncation_reasons),
            "truncation_reasons": sorted(truncation_reasons),
            "string_count": len(values),
            "character_count": characters,
            "maximum_string_count": MAXIMUM_STRING_COUNT,
            "maximum_string_length": MAXIMUM_STRING_LENGTH,
            "maximum_string_characters": MAXIMUM_STRING_CHARACTERS,
        }

    patterns = ((_ASCII, "ascii"), (_WIDE, "utf-16le"))
    for pattern, encoding in patterns:
        for match in pattern.finditer(data):
            if len(values) >= MAXIMUM_STRING_COUNT:
                truncation_reasons.add("maximum_string_count")
                return values, scan_evidence()
            raw = match.group()
            if len(raw) > MAXIMUM_STRING_LENGTH * (2 if encoding == "utf-16le" else 1):
                truncation_reasons.add("maximum_string_length")
                raw = raw[
                    : MAXIMUM_STRING_LENGTH * (2 if encoding == "utf-16le" else 1)
                ]
            try:
                value = raw.decode(encoding, errors="strict")
            except UnicodeError:
                continue
            if value in seen:
                continue
            if characters + len(value) > MAXIMUM_STRING_CHARACTERS:
                truncation_reasons.add("maximum_string_characters")
                return values, scan_evidence()
            seen.add(value)
            values.append(value)
            characters += len(value)
    return values, scan_evidence()


def _vvas_string_scan_not_attempted(reason: str) -> dict[str, object]:
    """PEの厳格なmarker-first経路で省略した全文字列走査を記録する。"""

    return {
        "status": "not_attempted",
        "completed": False,
        "skipped": True,
        "skip_reason": reason,
        "truncated": False,
        "truncation_reasons": [],
        "string_count": 0,
        "character_count": 0,
        "maximum_string_count": MAXIMUM_STRING_COUNT,
        "maximum_string_length": MAXIMUM_STRING_LENGTH,
        "maximum_string_characters": MAXIMUM_STRING_CHARACTERS,
    }


def _public_urls(strings: list[str]) -> list[str]:
    """資格情報、query、fragment、秘密値らしいpathを除いたURLだけを返す。"""

    results: set[str] = set()
    candidates = set(infrastructure_urls(strings))
    for value in url_candidates(strings):
        try:
            if ":" in (urlsplit(value).hostname or ""):
                candidates.add(value)
        except ValueError:
            continue
    for value in candidates:
        try:
            parsed = urlsplit(value)
            host = normalize_host(parsed.hostname or "")
            port = parsed.port
        except ValueError:
            continue
        if host is None:
            continue
        if port is not None and not 1 <= port <= 65535:
            continue
        authority = render_authority(host, port)
        if authority is None:
            continue
        sensitive_path = (
            "%" in parsed.path
            or _SENSITIVE_URL_PATH.search(parsed.path) is not None
            or any(
                _OPAQUE_URL_SEGMENT.fullmatch(segment) is not None
                for segment in parsed.path.split("/")
            )
        )
        path = "/[REDACTED]" if sensitive_path else parsed.path[:512]
        results.add(urlunsplit((parsed.scheme.casefold(), authority, path, "", "")))
    return sorted(results)


def identify_variant(strings: list[str]) -> str:
    """すべてのbuildを同一視せず、設定表現からvariantを識別する。"""
    lower = "\n".join(strings).lower()
    if "odaktomk" in lower or all(
        item in lower for item in ("vvas.bin", "loggercollector.dll")
    ):
        return "dll_sideload_vvas_bundle"
    if "config.enc" in lower or "n520" in lower:
        return "single_pe_n520_managed"
    if "silverfox" in lower:
        return "silverfox_related"
    if all(
        item in lower
        for item in ("myappdomainmanager", "initializenewdomain", "enumuilanguagesa")
    ):
        return "appdomainmanager_pixel_loader"
    nvml_markers = ("nvml.dat", "nvml.dll", "runtimebroker.exe")
    nvml_loader_apis = ("queueuserapc", "virtualalloc", "virtualprotect", "readfile")
    if (
        all(item in lower for item in nvml_markers)
        and sum(item in lower for item in nvml_loader_apis) >= 3
    ):
        # raw ISO/IMGとcompact proxy DLLの両方で成立するhash非依存構造。
        # filename共存だけではなく、APC・memory保護・DAT読込みAPIを要求する。
        return "nvml_compact_dat_iso_bundle"
    winos_stage_markers = (
        "ipdatespecial",
        "sedebugprivilege",
        "192.168.1.200",
        "remark",
    )
    if all(item in lower for item in winos_stage_markers):
        return "pdfcore8_winos_recovered_stage"
    return "unresolved_variant"


def _parse_vvas_reversed_value(
    value: str,
) -> (
    tuple[dict[str, str], tuple[tuple[int, str, int, int], ...], dict[str, int]] | None
):
    """反転設定のp/o/t slotを完全に検証し、外部endpointだけを返す。

    t は有効／無効flagではなく、観測済みbuildでは 0 がUDP系、
    1 がTCP系を選ぶtransport selectorである。したがって t=0 の
    endpointも設定identityへ含めて公開対象とする。一方、空のbackup slotは
    p と o がともに空で、対応する t が明示される場合だけ許容する。
    """

    folded = value.casefold()
    if len(value) > MAXIMUM_STRING_LENGTH or ":1p" not in folded or ":1o" not in folded:
        return None
    fields: dict[str, str] = {}
    for match in _VVAS_FIELD.finditer(value[::-1]):
        key, raw = match.group(1).casefold(), match.group(2).strip()
        previous = fields.get(key)
        if previous is not None and previous != raw:
            return None
        fields[key] = raw
    if not {"p1", "o1"}.issubset(fields):
        return None
    endpoints: dict[str, str] = {}
    slot_identity: list[tuple[int, str, int, int]] = []
    excluded_placeholder_slots = 0
    empty_backup_slots = 0
    explicit_transport_selectors = 0
    implicit_transport_selectors = 0
    tcp_transport_slots = 0
    udp_transport_slots = 0
    has_transport_selectors = any(f"t{index}" in fields for index in (1, 2, 3))
    for index in (1, 2, 3):
        host_key, port_key, transport_key = f"p{index}", f"o{index}", f"t{index}"
        if (host_key in fields) != (port_key in fields):
            return None
        if has_transport_selectors and (
            (transport_key in fields) != (host_key in fields)
        ):
            return None
        if host_key not in fields:
            continue
        raw_transport = fields.get(transport_key)
        if raw_transport is not None and raw_transport not in {"0", "1"}:
            return None
        transport = int(raw_transport) if raw_transport is not None else -1
        explicit_transport_selectors += int(raw_transport is not None)
        implicit_transport_selectors += int(raw_transport is None)
        tcp_transport_slots += int(transport == 1)
        udp_transport_slots += int(transport == 0)

        raw_host, raw_port = fields[host_key], fields[port_key]
        if not raw_host and not raw_port:
            if raw_transport is None:
                return None
            empty_backup_slots += 1
            slot_identity.append((index, "", 0, transport))
            continue
        if not raw_host or not raw_port:
            return None
        host, port = normalize_host(raw_host), raw_port
        if host is None or not port.isdigit() or not 1 <= int(port) <= 65535:
            return None
        slot_identity.append((index, host, int(port), transport))
        if host in {"127.0.0.1", "0.0.0.0", "::1"}:
            excluded_placeholder_slots += 1
            continue
        endpoint = render_endpoint(host, int(port))
        if endpoint is None:
            return None
        endpoints[f"endpoint_{index}"] = endpoint
    if not endpoints:
        return None
    return (
        endpoints,
        tuple(slot_identity),
        {
            "configured_slot_count": len(slot_identity),
            # 旧schemaとの互換性のため残す。tはenabled flagではないので常に0。
            "disabled_slot_count": 0,
            "excluded_placeholder_slot_count": excluded_placeholder_slots,
            "explicit_enable_flag_count": 0,
            "implicit_enable_flag_count": 0,
            "empty_backup_slot_count": empty_backup_slots,
            "explicit_transport_selector_count": explicit_transport_selectors,
            "implicit_transport_selector_count": implicit_transport_selectors,
            "tcp_transport_slot_count": tcp_transport_slots,
            "udp_transport_slot_count": udp_transport_slots,
        },
    )


def _decode_vvas_reversed_config(
    strings: list[str],
) -> tuple[dict[str, str], dict[str, object]]:
    """全候補を評価し、一意なvvaS endpoint集合だけを採用する。"""

    candidates: dict[tuple[tuple[int, str, int, int], ...], dict[str, str]] = {}
    candidate_count = 0
    excluded_placeholder_slot_count = 0
    disabled_slot_count = 0
    configured_slot_count = 0
    explicit_enable_flag_count = 0
    implicit_enable_flag_count = 0
    empty_backup_slot_count = 0
    explicit_transport_selector_count = 0
    implicit_transport_selector_count = 0
    tcp_transport_slot_count = 0
    udp_transport_slot_count = 0
    for value in strings[:MAXIMUM_STRING_COUNT]:
        parsed = _parse_vvas_reversed_value(value)
        if parsed is None:
            continue
        endpoints, identity, slot_evidence = parsed
        candidate_count += 1
        excluded_placeholder_slot_count += slot_evidence[
            "excluded_placeholder_slot_count"
        ]
        disabled_slot_count += slot_evidence["disabled_slot_count"]
        configured_slot_count += slot_evidence["configured_slot_count"]
        explicit_enable_flag_count += slot_evidence["explicit_enable_flag_count"]
        implicit_enable_flag_count += slot_evidence["implicit_enable_flag_count"]
        empty_backup_slot_count += slot_evidence["empty_backup_slot_count"]
        explicit_transport_selector_count += slot_evidence[
            "explicit_transport_selector_count"
        ]
        implicit_transport_selector_count += slot_evidence[
            "implicit_transport_selector_count"
        ]
        tcp_transport_slot_count += slot_evidence["tcp_transport_slot_count"]
        udp_transport_slot_count += slot_evidence["udp_transport_slot_count"]
        candidates[identity] = endpoints
    if not candidates:
        return {}, {
            "status": "not_found",
            "candidate_count": 0,
            "unique_configuration_count": 0,
            "excluded_placeholder_slot_count": 0,
            "disabled_slot_count": 0,
            "configured_slot_count": 0,
            "explicit_enable_flag_count": 0,
            "implicit_enable_flag_count": 0,
            "empty_backup_slot_count": 0,
            "explicit_transport_selector_count": 0,
            "implicit_transport_selector_count": 0,
            "tcp_transport_slot_count": 0,
            "udp_transport_slot_count": 0,
            "endpoint_slots": [],
        }
    if len(candidates) != 1:
        return {}, {
            "status": "ambiguous_rejected",
            "candidate_count": candidate_count,
            "unique_configuration_count": len(candidates),
            "excluded_placeholder_slot_count": excluded_placeholder_slot_count,
            "disabled_slot_count": disabled_slot_count,
            "configured_slot_count": configured_slot_count,
            "explicit_enable_flag_count": explicit_enable_flag_count,
            "implicit_enable_flag_count": implicit_enable_flag_count,
            "empty_backup_slot_count": empty_backup_slot_count,
            "explicit_transport_selector_count": explicit_transport_selector_count,
            "implicit_transport_selector_count": implicit_transport_selector_count,
            "tcp_transport_slot_count": tcp_transport_slot_count,
            "udp_transport_slot_count": udp_transport_slot_count,
            "endpoint_slots": [],
        }
    identity, endpoints = next(iter(candidates.items()))
    endpoint_slots = [
        {
            "slot": index,
            "endpoint": endpoints[f"endpoint_{index}"],
            "transport": {0: "udp", 1: "tcp"}.get(transport, "unknown"),
        }
        for index, _host, _port, transport in identity
        if f"endpoint_{index}" in endpoints
    ]
    return endpoints, {
        "status": "decoded_unique",
        "candidate_count": candidate_count,
        "unique_configuration_count": 1,
        "excluded_placeholder_slot_count": excluded_placeholder_slot_count,
        "disabled_slot_count": disabled_slot_count,
        "configured_slot_count": configured_slot_count,
        "explicit_enable_flag_count": explicit_enable_flag_count,
        "implicit_enable_flag_count": implicit_enable_flag_count,
        "empty_backup_slot_count": empty_backup_slot_count,
        "explicit_transport_selector_count": explicit_transport_selector_count,
        "implicit_transport_selector_count": implicit_transport_selector_count,
        "tcp_transport_slot_count": tcp_transport_slot_count,
        "udp_transport_slot_count": udp_transport_slot_count,
        "endpoint_slots": endpoint_slots,
        "configuration_identity_sha256": _vvas_configuration_identity(identity),
    }


def _vvas_configuration_identity(
    identity: tuple[tuple[int, str, int, int], ...],
) -> str:
    """生のhostを公開せず、完全なslot構成の安定identityを返す。"""

    serialized = "\n".join(
        f"{index}|{host}|{port}|{transport}"
        for index, host, port, transport in identity
    ).encode("utf-8")
    return hashlib.sha256(serialized).hexdigest()


def decode_vvas_reversed_config(strings: list[str]) -> dict[str, str]:
    """一意に検証できたvvaS反転key/value設定だけを返す。"""

    decoded, _evidence = _decode_vvas_reversed_config(strings)
    return decoded


def _vvas_pe_import_evidence(data: bytes) -> dict[str, object]:
    """PE import tableからvvaS terminalのWinsock利用を有界に補強する。"""

    if len(data) > MAXIMUM_VVAS_PROBE_INPUT_SIZE or not data.startswith(b"MZ"):
        return {"matched": False}
    try:
        image = pefile.PE(data=data, fast_load=False)
    except (pefile.PEFormatError, ValueError, OverflowError):
        return {"matched": False}
    try:
        entries = list(image.DIRECTORY_ENTRY_IMPORT)
    except AttributeError:
        return {"matched": False}
    if not entries or len(entries) > MAXIMUM_PE_IMPORT_DESCRIPTORS:
        return {"matched": False}
    winsock_descriptors: list[set[str]] = []
    import_count = 0
    for entry in entries:
        try:
            raw_library = entry.dll
            entry_imports = list(entry.imports)
        except AttributeError:
            return {"matched": False}
        if (
            not isinstance(raw_library, bytes)
            or len(raw_library) > MAXIMUM_PE_IMPORT_NAME_LENGTH
        ):
            return {"matched": False}
        try:
            library = raw_library.decode("ascii", errors="strict").casefold()
        except UnicodeError:
            return {"matched": False}
        import_count += len(entry_imports)
        if import_count > MAXIMUM_PE_IMPORTS:
            return {"matched": False}
        descriptor_imports: set[str] = set()
        for item in entry_imports:
            try:
                raw_name = item.name
            except AttributeError:
                return {"matched": False}
            if raw_name is None:
                continue
            if (
                not isinstance(raw_name, bytes)
                or len(raw_name) > MAXIMUM_PE_IMPORT_NAME_LENGTH
            ):
                return {"matched": False}
            try:
                normalized_name = raw_name.decode("ascii", errors="strict").casefold()
            except UnicodeError:
                return {"matched": False}
            if library == "ws2_32.dll":
                descriptor_imports.add(normalized_name)
        if library == "ws2_32.dll":
            winsock_descriptors.append(descriptor_imports)

    def required_groups(imports: set[str]) -> dict[str, bool]:
        return {
            "ws2_32_library": True,
            "winsock_initialization": "wsastartup" in imports,
            "socket_creation": bool({"socket", "wsasocketa", "wsasocketw"} & imports),
            "connection": bool({"connect", "wsaconnect"} & imports),
            "send": bool({"send", "wsasend"} & imports),
            "receive": bool({"recv", "wsarecv"} & imports),
        }

    validated = [
        (imports, required_groups(imports))
        for imports in winsock_descriptors
        if all(required_groups(imports).values())
    ]
    selected_imports, groups = (
        validated[0]
        if len(validated) == 1
        else (
            set(),
            {
                "ws2_32_library": bool(winsock_descriptors),
                "winsock_initialization": False,
                "socket_creation": False,
                "connection": False,
                "send": False,
                "receive": False,
            },
        )
    )
    return {
        "matched": len(validated) == 1,
        "import_descriptor_count": len(entries),
        "import_count": import_count,
        "winsock_descriptor_count": len(winsock_descriptors),
        "validated_winsock_descriptor_count": len(validated),
        "winsock_descriptor_import_count": len(selected_imports),
        "required_groups": groups,
        "raw_import_names_included": False,
    }


def _vvas_pe_sections(
    image: pefile.PE,
    data: bytes,
) -> tuple[list[_VvasPeSection], int, int] | None:
    """重複のないfile-backed PE sectionとentrypointを有界に検証する。"""

    try:
        raw_sections = list(image.sections)
        image_base = int(image.OPTIONAL_HEADER.ImageBase)
        entrypoint = image_base + int(image.OPTIONAL_HEADER.AddressOfEntryPoint)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return None
    if not raw_sections or len(raw_sections) > MAXIMUM_VVAS_PE_SECTIONS:
        return None

    resource_start = 0
    resource_end = 0
    try:
        resource_directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[2]
        resource_start = image_base + int(resource_directory.VirtualAddress)
        resource_size = int(resource_directory.Size)
        if resource_size > 0:
            resource_end = resource_start + resource_size
    except (AttributeError, IndexError, TypeError, ValueError, OverflowError):
        resource_start = resource_end = 0

    sections: list[_VvasPeSection] = []
    executable_bytes = 0
    for raw_section in raw_sections:
        try:
            raw_name = raw_section.Name
            virtual_address = int(raw_section.VirtualAddress)
            virtual_size = int(raw_section.Misc_VirtualSize)
            raw_start = int(raw_section.PointerToRawData)
            raw_size = int(raw_section.SizeOfRawData)
            characteristics = int(raw_section.Characteristics)
        except (AttributeError, TypeError, ValueError, OverflowError):
            return None
        if (
            not isinstance(raw_name, bytes)
            or virtual_address < 0
            or virtual_size < 0
            or raw_start < 0
            or raw_size < 0
        ):
            return None
        mapped_size = min(raw_size, virtual_size or raw_size)
        if mapped_size <= 0:
            continue
        raw_end = raw_start + mapped_size
        virtual_start = image_base + virtual_address
        virtual_end = virtual_start + mapped_size
        if raw_end > len(data) or virtual_end <= virtual_start:
            return None
        name = raw_name.rstrip(b"\0").decode("ascii", errors="replace").casefold()
        executable = bool(characteristics & 0x20000000)
        overlaps_resource = (
            resource_end > resource_start
            and virtual_start < resource_end
            and resource_start < virtual_end
        )
        resource = name == ".rsrc" or overlaps_resource
        if executable:
            executable_bytes += mapped_size
            if executable_bytes > MAXIMUM_VVAS_EXECUTABLE_BYTES:
                return None
        sections.append(
            _VvasPeSection(
                name=name,
                virtual_start=virtual_start,
                virtual_end=virtual_end,
                raw_start=raw_start,
                raw_end=raw_end,
                executable=executable,
                resource=resource,
            )
        )

    if not sections:
        return None
    for index, section in enumerate(sections):
        for other in sections[index + 1 :]:
            raw_overlap = (
                section.raw_start < other.raw_end and other.raw_start < section.raw_end
            )
            virtual_overlap = (
                section.virtual_start < other.virtual_end
                and other.virtual_start < section.virtual_end
            )
            if raw_overlap or virtual_overlap:
                return None
    if not any(
        section.executable and section.virtual_start <= entrypoint < section.virtual_end
        for section in sections
    ):
        return None
    return sections, image_base, entrypoint


def _vvas_mapped_candidate_window(
    data: bytes,
    section: _VvasPeSection,
    marker_offset: int,
    encoding: str,
) -> tuple[str | None, int, int, bool]:
    """markerを含む1文字列だけをsection境界内で有界に復元する。"""

    if encoding == "ascii":
        marker_size = 3
        maximum_bytes = MAXIMUM_VVAS_MAPPED_CANDIDATE_CHARACTERS

        def is_character(offset: int) -> bool:
            return 0x20 <= data[offset] <= 0x7E

        start = marker_offset
        while start > section.raw_start and is_character(start - 1):
            if marker_offset - start >= maximum_bytes:
                return None, marker_offset, marker_offset + marker_size, True
            start -= 1
        end = marker_offset + marker_size
        while end < section.raw_end and is_character(end):
            if end - start >= maximum_bytes:
                return None, start, end, True
            end += 1
        if end - start > maximum_bytes:
            return None, start, end, True
        try:
            return data[start:end].decode("ascii", errors="strict"), start, end, False
        except UnicodeError:
            return None, start, end, False

    if encoding != "utf-16le":
        return None, marker_offset, marker_offset, False
    marker_size = 6
    maximum_bytes = MAXIMUM_VVAS_MAPPED_CANDIDATE_CHARACTERS * 2
    start = marker_offset
    while start - 2 >= section.raw_start:
        if data[start - 2 : start] == b"\0\0":
            break
        if marker_offset - start >= maximum_bytes:
            return None, marker_offset, marker_offset + marker_size, True
        start -= 2
    end = marker_offset + marker_size
    while end + 2 <= section.raw_end:
        if data[end : end + 2] == b"\0\0":
            break
        if end - start >= maximum_bytes:
            return None, start, end, True
        end += 2
    if end - start > maximum_bytes:
        return None, start, end, True
    try:
        return data[start:end].decode("utf-16le", errors="strict"), start, end, False
    except UnicodeError:
        return None, start, end, False


def _vvas_mapped_config_candidates(
    data: bytes,
) -> tuple[tuple[_VvasMappedConfigCandidate, ...], dict[str, object]]:
    """mapped PE sectionをmarker-firstで完全走査し、反転設定だけを返す。

    全sectionを走査できない場合は、それ以前に得た候補をすべて破棄する。
    raw文字列やendpointは公開evidenceへ含めない。
    """

    maximums = {
        "maximum_input_size": MAXIMUM_VVAS_PROBE_INPUT_SIZE,
        "maximum_section_count": MAXIMUM_VVAS_MAPPED_SCAN_SECTIONS,
        "maximum_section_bytes": MAXIMUM_VVAS_MAPPED_SCAN_SECTION_BYTES,
        "maximum_total_bytes": MAXIMUM_VVAS_MAPPED_SCAN_TOTAL_BYTES,
        "maximum_chunk_bytes": MAXIMUM_VVAS_MAPPED_SCAN_CHUNK_BYTES,
        "maximum_marker_hits": MAXIMUM_VVAS_MAPPED_SCAN_HITS,
        "maximum_candidate_count": MAXIMUM_VVAS_CONFIG_LOCATIONS,
        "maximum_candidate_characters": MAXIMUM_VVAS_MAPPED_CANDIDATE_CHARACTERS,
    }

    def evidence(
        status: str,
        *,
        complete: bool,
        section_count: int = 0,
        total_bytes: int = 0,
        scanned_bytes: int = 0,
        marker_hit_count: int = 0,
        candidate_count: int = 0,
        unique_configuration_count: int = 0,
        rejected_marker_hit_count: int = 0,
        marker_scan_passes: int = 0,
        truncation_reasons: tuple[str, ...] = (),
    ) -> dict[str, object]:
        return {
            "status": status,
            "completed": complete,
            "candidate_set_complete": complete,
            "truncated": bool(truncation_reasons),
            "truncation_reasons": list(truncation_reasons),
            "section_scope": "all_nonoverlapping_file_backed_mapped_sections",
            "section_count": section_count,
            "total_section_bytes": total_bytes,
            "scanned_byte_count": scanned_bytes,
            "marker_scan_passes": marker_scan_passes,
            "marker_encoding_count": 2,
            "marker_hit_count": marker_hit_count,
            "rejected_marker_hit_count": rejected_marker_hit_count,
            "candidate_count": candidate_count,
            "unique_configuration_count": unique_configuration_count,
            **maximums,
            "raw_config_included": False,
            "raw_network_values_included": False,
        }

    if not isinstance(data, bytes) or not data.startswith(b"MZ"):
        return (), evidence("invalid_pe_input", complete=False)
    if len(data) > MAXIMUM_VVAS_PROBE_INPUT_SIZE:
        return (), evidence(
            "input_size_limit_rejected",
            complete=False,
            truncation_reasons=("maximum_input_size",),
        )
    if any(
        limit < 1
        for limit in (
            MAXIMUM_VVAS_MAPPED_SCAN_SECTIONS,
            MAXIMUM_VVAS_MAPPED_SCAN_SECTION_BYTES,
            MAXIMUM_VVAS_MAPPED_SCAN_TOTAL_BYTES,
            MAXIMUM_VVAS_MAPPED_SCAN_CHUNK_BYTES,
            MAXIMUM_VVAS_MAPPED_SCAN_HITS,
            MAXIMUM_VVAS_CONFIG_LOCATIONS,
            MAXIMUM_VVAS_MAPPED_CANDIDATE_CHARACTERS,
        )
    ):
        return (), evidence(
            "invalid_scan_limits",
            complete=False,
            truncation_reasons=("invalid_scan_limits",),
        )
    try:
        # marker走査に必要なのはsection tableとresource directory範囲だけであり、
        # import/resource tree全体の eager parseは不要。後段lineageは候補成立後に
        # 別途fast_load=Falseで解析する。
        image = pefile.PE(data=data, fast_load=True)
    except (pefile.PEFormatError, ValueError, OverflowError):
        return (), evidence("invalid_pe_structure", complete=False)
    section_result = _vvas_pe_sections(image, data)
    if section_result is None:
        return (), evidence("invalid_pe_sections", complete=False)
    sections, _image_base, _entrypoint = section_result
    section_count = len(sections)
    if section_count > MAXIMUM_VVAS_MAPPED_SCAN_SECTIONS:
        return (), evidence(
            "section_count_limit_rejected",
            complete=False,
            section_count=section_count,
            truncation_reasons=("maximum_section_count",),
        )
    section_sizes = [section.raw_end - section.raw_start for section in sections]
    total_bytes = sum(section_sizes)
    if any(size > MAXIMUM_VVAS_MAPPED_SCAN_SECTION_BYTES for size in section_sizes):
        return (), evidence(
            "section_byte_limit_rejected",
            complete=False,
            section_count=section_count,
            total_bytes=total_bytes,
            truncation_reasons=("maximum_section_bytes",),
        )
    if total_bytes > MAXIMUM_VVAS_MAPPED_SCAN_TOTAL_BYTES:
        return (), evidence(
            "total_byte_limit_rejected",
            complete=False,
            section_count=section_count,
            total_bytes=total_bytes,
            truncation_reasons=("maximum_total_bytes",),
        )

    markers = (
        (b":1p", "ascii"),
        (b":1P", "ascii"),
        (b":\x001\x00p\x00", "utf-16le"),
        (b":\x001\x00P\x00", "utf-16le"),
    )
    carry_size = max(len(marker) for marker, _encoding in markers) - 1
    hits: set[tuple[int, str, int]] = set()
    scanned_bytes = 0
    for section_index, section in enumerate(sections):
        cursor = section.raw_start
        carry = b""
        while cursor < section.raw_end:
            chunk_end = min(
                cursor + MAXIMUM_VVAS_MAPPED_SCAN_CHUNK_BYTES,
                section.raw_end,
            )
            chunk = carry + data[cursor:chunk_end]
            chunk_base = cursor - len(carry)
            for marker, encoding in markers:
                search_from = 0
                while True:
                    relative = chunk.find(marker, search_from)
                    if relative < 0:
                        break
                    offset = chunk_base + relative
                    if (
                        section.raw_start <= offset
                        and offset + len(marker) <= section.raw_end
                    ):
                        hits.add((offset, encoding, section_index))
                        if len(hits) > MAXIMUM_VVAS_MAPPED_SCAN_HITS:
                            return (), evidence(
                                "marker_hit_limit_rejected",
                                complete=False,
                                section_count=section_count,
                                total_bytes=total_bytes,
                                scanned_bytes=scanned_bytes + chunk_end - cursor,
                                marker_hit_count=len(hits),
                                marker_scan_passes=1,
                                truncation_reasons=("maximum_marker_hits",),
                            )
                    search_from = relative + 1
            scanned_bytes += chunk_end - cursor
            carry = chunk[-carry_size:] if chunk_end < section.raw_end else b""
            cursor = chunk_end

    candidates: list[_VvasMappedConfigCandidate] = []
    candidate_spans: set[tuple[int, int, str]] = set()
    rejected_hits = 0
    for marker_offset, encoding, section_index in sorted(hits):
        value, raw_start, raw_end, window_limit = _vvas_mapped_candidate_window(
            data,
            sections[section_index],
            marker_offset,
            encoding,
        )
        if window_limit:
            return (), evidence(
                "candidate_window_limit_rejected",
                complete=False,
                section_count=section_count,
                total_bytes=total_bytes,
                scanned_bytes=scanned_bytes,
                marker_hit_count=len(hits),
                rejected_marker_hit_count=rejected_hits + 1,
                marker_scan_passes=1,
                truncation_reasons=("maximum_candidate_characters",),
            )
        if value is None:
            rejected_hits += 1
            continue
        # mapped PEではNUL等で区切られた文字列全体が設定そのものであることを
        # 要求する。printable prefix/suffixやsection端で切れた部分設定から、
        # 内部のfield substringだけを採用しない。
        if not value.startswith("|") or not value.endswith("|"):
            rejected_hits += 1
            continue
        parsed = _parse_vvas_reversed_value(value)
        if parsed is None:
            rejected_hits += 1
            continue
        _endpoints, identity, _slot_evidence = parsed
        identity_hash = _vvas_configuration_identity(identity)
        span = (raw_start, raw_end, identity_hash)
        if span in candidate_spans:
            continue
        candidate_spans.add(span)
        candidates.append(
            _VvasMappedConfigCandidate(
                value=value,
                raw_start=raw_start,
                raw_end=raw_end,
                configuration_identity=identity_hash,
                encoding=encoding,
            )
        )
        if len(candidates) > MAXIMUM_VVAS_CONFIG_LOCATIONS:
            return (), evidence(
                "candidate_count_limit_rejected",
                complete=False,
                section_count=section_count,
                total_bytes=total_bytes,
                scanned_bytes=scanned_bytes,
                marker_hit_count=len(hits),
                candidate_count=len(candidates),
                rejected_marker_hit_count=rejected_hits,
                marker_scan_passes=1,
                truncation_reasons=("maximum_candidate_count",),
            )

    unique_configuration_count = len(
        {candidate.configuration_identity for candidate in candidates}
    )
    return tuple(candidates), evidence(
        "complete_candidates" if candidates else "complete_no_candidates",
        complete=True,
        section_count=section_count,
        total_bytes=total_bytes,
        scanned_bytes=scanned_bytes,
        marker_hit_count=len(hits),
        candidate_count=len(candidates),
        unique_configuration_count=unique_configuration_count,
        rejected_marker_hit_count=rejected_hits,
        marker_scan_passes=1,
    )


def _decode_vvas_mapped_pe_config(
    data: bytes,
) -> tuple[
    dict[str, str],
    dict[str, object],
    tuple[_VvasMappedConfigCandidate, ...],
]:
    """完全走査済みmapped候補だけを既存slot grammarへ渡す。"""

    candidates, scan = _vvas_mapped_config_candidates(data)
    if scan["candidate_set_complete"] is not True:
        return (
            {},
            {
                "status": "mapped_config_scan_incomplete_rejected",
                "mapped_config_scan": scan,
            },
            (),
        )
    decoded, recovery = _decode_vvas_reversed_config(
        [candidate.value for candidate in candidates]
    )
    recovery["mapped_config_scan"] = scan
    return decoded, recovery, candidates


def _vvas_config_locations(
    data: bytes,
    sections: list[_VvasPeSection],
    configuration_identity: str,
    *,
    allow_resource: bool = False,
    mapped_candidates: tuple[_VvasMappedConfigCandidate, ...] | None = None,
) -> list[tuple[int, int]] | None:
    """一意configと同じidentityを持つ許可済みmapped位置だけを返す。"""

    locations: set[tuple[int, int]] = set()
    if mapped_candidates is not None:
        for candidate in mapped_candidates:
            if candidate.configuration_identity != configuration_identity:
                continue
            # 現在検証しているparserはUTF-16LEの16-bit反転loopである。
            # ASCII候補を同じVAで参照していても、このlineageへ昇格しない。
            if candidate.encoding != "utf-16le":
                continue
            containing = [
                section
                for section in sections
                if section.raw_start <= candidate.raw_start
                and candidate.raw_end <= section.raw_end
            ]
            if len(containing) != 1:
                return None
            section = containing[0]
            if section.resource and not allow_resource:
                continue
            virtual_start = (
                section.virtual_start + candidate.raw_start - section.raw_start
            )
            locations.add(
                (virtual_start, virtual_start + candidate.raw_end - candidate.raw_start)
            )
        return sorted(locations)

    candidate_count = 0
    for pattern, encoding in ((_ASCII, "ascii"), (_WIDE, "utf-16le")):
        for match in pattern.finditer(data):
            raw = match.group()
            if len(raw) > MAXIMUM_STRING_LENGTH * (2 if encoding == "utf-16le" else 1):
                continue
            try:
                value = raw.decode(encoding, errors="strict")
            except UnicodeError:
                continue
            parsed = _parse_vvas_reversed_value(value)
            if parsed is None:
                continue
            candidate_count += 1
            if candidate_count > MAXIMUM_VVAS_CONFIG_LOCATIONS:
                return None
            _endpoints, identity, _evidence = parsed
            if _vvas_configuration_identity(identity) != configuration_identity:
                continue
            containing = [
                section
                for section in sections
                if (allow_resource or not section.resource)
                and section.raw_start <= match.start()
                and match.end() <= section.raw_end
            ]
            if len(containing) != 1:
                continue
            section = containing[0]
            raw_start, raw_end = match.start(), match.end()
            if encoding == "utf-16le":
                # ASCIIだけの正規表現は、日本語等を含む同じUTF-16LE bufferの
                # 中間から一致し得る。codeが参照する先頭までNUL境界内を戻す。
                while (
                    raw_start - 2 >= section.raw_start
                    and data[raw_start - 2 : raw_start] != b"\0\0"
                    and raw_end - (raw_start - 2) <= MAXIMUM_STRING_LENGTH * 2
                ):
                    raw_start -= 2
                while (
                    raw_end + 2 <= section.raw_end
                    and data[raw_end : raw_end + 2] != b"\0\0"
                    and raw_end + 2 - raw_start <= MAXIMUM_STRING_LENGTH * 2
                ):
                    raw_end += 2
                try:
                    expanded = data[raw_start:raw_end].decode(
                        "utf-16le", errors="strict"
                    )
                except UnicodeError:
                    continue
                expanded_parsed = _parse_vvas_reversed_value(expanded)
                if (
                    expanded_parsed is None
                    or _vvas_configuration_identity(expanded_parsed[1])
                    != configuration_identity
                ):
                    continue
            virtual_start = section.virtual_start + raw_start - section.raw_start
            virtual_length = raw_end - raw_start
            locations.add((virtual_start, virtual_start + virtual_length))
    return sorted(locations)


def _vvas_import_address_map(
    image: pefile.PE,
) -> tuple[dict[int, tuple[str, int]], int] | None:
    """import thunkを名称・descriptorへ対応付け、単一WS2群を選ぶ。"""

    try:
        entries = list(image.DIRECTORY_ENTRY_IMPORT)
    except AttributeError:
        return None
    if not entries or len(entries) > MAXIMUM_PE_IMPORT_DESCRIPTORS:
        return None
    result: dict[int, tuple[str, int]] = {}
    descriptor_imports: dict[int, tuple[str, set[str]]] = {}
    import_count = 0
    for descriptor_index, entry in enumerate(entries):
        try:
            raw_library = entry.dll
            items = list(entry.imports)
        except AttributeError:
            return None
        if (
            not isinstance(raw_library, bytes)
            or len(raw_library) > MAXIMUM_PE_IMPORT_NAME_LENGTH
        ):
            return None
        try:
            library = raw_library.decode("ascii", errors="strict").casefold()
        except UnicodeError:
            return None
        import_count += len(items)
        if import_count > MAXIMUM_PE_IMPORTS:
            return None
        names: set[str] = set()
        for item in items:
            try:
                raw_name = item.name
                address = int(item.address)
            except (AttributeError, TypeError, ValueError, OverflowError):
                return None
            if raw_name is None:
                continue
            if (
                not isinstance(raw_name, bytes)
                or len(raw_name) > MAXIMUM_PE_IMPORT_NAME_LENGTH
                or address <= 0
            ):
                return None
            try:
                name = raw_name.decode("ascii", errors="strict").casefold()
            except UnicodeError:
                return None
            names.add(name)
            previous = result.get(address)
            current = (name, descriptor_index)
            if previous is not None and previous != current:
                return None
            result[address] = current
        descriptor_imports[descriptor_index] = (library, names)
    validated_ws2 = [
        descriptor_index
        for descriptor_index, (library, names) in descriptor_imports.items()
        if library == "ws2_32.dll" and all(_vvas_network_groups(names).values())
    ]
    if len(validated_ws2) != 1:
        return None
    return result, validated_ws2[0]


def _vvas_section_for_address(
    address: int,
    sections: list[_VvasPeSection],
    *,
    executable: bool | None = None,
) -> _VvasPeSection | None:
    """検証済みsectionからVAを一意に解決する。"""

    matches = [
        section
        for section in sections
        if section.virtual_start <= address < section.virtual_end
        and (executable is None or section.executable is executable)
    ]
    return matches[0] if len(matches) == 1 else None


def _vvas_read_pointer(
    data: bytes,
    sections: list[_VvasPeSection],
    address: int,
    pointer_size: int,
) -> int | None:
    """file-backed section内のpointerを境界検証して読む。"""

    section = _vvas_section_for_address(address, sections)
    if section is None or address + pointer_size > section.virtual_end:
        return None
    raw_offset = section.raw_start + address - section.virtual_start
    if raw_offset + pointer_size > section.raw_end:
        return None
    return int.from_bytes(data[raw_offset : raw_offset + pointer_size], "little")


def _vvas_vtable_targets(
    data: bytes,
    sections: list[_VvasPeSection],
    address: int,
    pointer_size: int,
) -> set[int] | None:
    """非実行・非resource sectionの連続function pointerだけをvtableとする。"""

    source = _vvas_section_for_address(address, sections, executable=False)
    if source is None or source.resource:
        return set()
    targets: list[int] = []
    for index in range(MAXIMUM_VVAS_VTABLE_ENTRIES + 1):
        target = _vvas_read_pointer(
            data,
            sections,
            address + index * pointer_size,
            pointer_size,
        )
        if (
            target is None
            or _vvas_section_for_address(target, sections, executable=True) is None
        ):
            break
        targets.append(target)
    if len(targets) > MAXIMUM_VVAS_VTABLE_ENTRIES:
        return None
    return set(targets) if len(targets) >= 3 else set()


def _vvas_operand_address(
    instruction: object, operand: object, pointer_size: int
) -> int | None:
    """x86/x64 operandから静的に確定する絶対VAだけを返す。"""

    if operand.type == X86_OP_IMM:
        mask = (1 << (pointer_size * 8)) - 1
        return int(operand.imm) & mask
    if operand.type != X86_OP_MEM:
        return None
    displacement = int(operand.mem.disp)
    if pointer_size == 8 and operand.mem.base == X86_REG_RIP:
        return int(instruction.address + instruction.size + displacement)
    if operand.mem.base == X86_REG_INVALID and operand.mem.index == X86_REG_INVALID:
        mask = (1 << (pointer_size * 8)) - 1
        return displacement & mask
    return None


def _vvas_decode_instruction(
    data: bytes,
    sections: list[_VvasPeSection],
    disassembler: Cs,
    address: int,
) -> object | None:
    """file-backed executable sectionの1命令だけをdecodeする。"""

    section = _vvas_section_for_address(address, sections, executable=True)
    if section is None:
        return None
    raw_offset = section.raw_start + address - section.virtual_start
    maximum = min(section.raw_end - raw_offset, 15)
    if maximum <= 0:
        return None
    try:
        decoded = list(
            disassembler.disasm(
                data[raw_offset : raw_offset + maximum],
                address,
                1,
            )
        )
    except CsError:
        return None
    return decoded[0] if decoded else None


def _vvas_constant_zero_branch(
    instruction: object,
    previous: object | None,
) -> bool | None:
    """直前の自己演算でZFが確定するje/jneだけを静的に枝刈りする。"""

    if previous is None or int(previous.address + previous.size) != instruction.address:
        return None
    previous_operands = list(previous.operands)
    if (
        previous.mnemonic not in {"cmp", "sub", "xor"}
        or len(previous_operands) < 2
        or previous_operands[0].type != X86_OP_REG
        or previous_operands[1].type != X86_OP_REG
        or previous_operands[0].reg != previous_operands[1].reg
    ):
        return None
    if instruction.mnemonic in {"je", "jz"}:
        return True
    if instruction.mnemonic in {"jne", "jnz"}:
        return False
    return None


def _vvas_utf16_reverse_loop(instructions: dict[int, object]) -> bool:
    """NUL走査後に両端の16-bit値を交換する内部reverse loopを検証する。"""

    word_reads = 0
    word_writes = 0
    two_byte_pointer_steps = 0
    backward_conditional_branches = 0
    for instruction in instructions.values():
        operands = list(instruction.operands)
        if instruction.mnemonic == "mov" and len(operands) >= 2:
            word_writes += int(
                operands[0].type == X86_OP_MEM and getattr(operands[0], "size", 0) == 2
            )
            word_reads += int(
                operands[1].type == X86_OP_MEM and getattr(operands[1], "size", 0) == 2
            )
        elif instruction.mnemonic == "movzx" and len(operands) >= 2:
            word_reads += int(
                operands[1].type == X86_OP_MEM and getattr(operands[1], "size", 0) == 2
            )
        elif instruction.mnemonic in {"cmp", "test"}:
            word_reads += sum(
                operand.type == X86_OP_MEM and getattr(operand, "size", 0) == 2
                for operand in operands
            )
        if (
            instruction.mnemonic in {"add", "sub"}
            and len(operands) >= 2
            and operands[0].type == X86_OP_REG
            and operands[1].type == X86_OP_IMM
            and abs(int(operands[1].imm)) == 2
        ):
            two_byte_pointer_steps += 1
        if (
            instruction.mnemonic.startswith("j")
            and instruction.mnemonic != "jmp"
            and operands
            and operands[0].type == X86_OP_IMM
            and int(operands[0].imm) < int(instruction.address)
        ):
            backward_conditional_branches += 1
    return (
        word_reads >= 3
        and word_writes >= 2
        and two_byte_pointer_steps >= 2
        and backward_conditional_branches >= 2
    )


def _vvas_x86_push_arguments(
    instructions: dict[int, object],
    cfg_successors: dict[int, tuple[int, ...]],
    callsite: int,
) -> tuple[int | None, ...]:
    """x86 call直前の6個のpushを安全な非stack命令越しに復元する。"""

    ordered = sorted(instructions)
    ending_at = {
        address + int(instructions[address].size): address for address in ordered
    }
    if len(ending_at) != len(ordered):
        return ()
    current = callsite
    pushed: list[int | None] = []
    for _index in range(MAXIMUM_VVAS_CALLBACK_LOOKBACK_INSTRUCTIONS):
        address = ending_at.get(current)
        if address is None or callsite - address > 96:
            break
        instruction = instructions[address]
        if current not in cfg_successors.get(address, ()):
            break
        operands = list(instruction.operands)
        if instruction.mnemonic == "push" and len(operands) == 1:
            pushed.append(_vvas_operand_address(instruction, operands[0], 4))
            if len(pushed) == 6:
                return tuple(pushed)
        elif instruction.mnemonic in {"mov", "lea"}:
            if (
                operands
                and operands[0].type == X86_OP_REG
                and operands[0].reg == X86_REG_ESP
            ):
                break
        else:
            break
        current = address
    return ()


def _vvas_function_summary(
    data: bytes,
    sections: list[_VvasPeSection],
    disassembler: Cs,
    start: int,
    pointer_size: int,
    import_addresses: dict[int, tuple[str, int]],
    config_locations: list[tuple[int, int]],
) -> _VvasFunctionSummary | None:
    """1 rootのintraprocedural CFGを有界に歩き、call/data参照を要約する。"""

    pending: deque[tuple[int, int | None]] = deque([(start, None)])
    queued: set[int] = {start}
    visited: set[int] = set()
    instructions: dict[int, object] = {}
    cfg_successors: dict[int, tuple[int, ...]] = {}
    direct_call_counts: dict[int, int] = {}
    direct_call_first_sites: dict[int, int] = {}
    direct_call_sites: dict[int, set[int]] = {}
    api_calls: list[tuple[int, str, int]] = []
    vtable_references: dict[int, set[int]] = {}
    config_reference_count = 0

    while pending:
        address, predecessor = pending.popleft()
        queued.discard(address)
        if address in visited:
            continue
        if len(visited) >= MAXIMUM_VVAS_FUNCTION_INSTRUCTIONS:
            return None
        instruction = _vvas_decode_instruction(data, sections, disassembler, address)
        if instruction is None:
            continue
        visited.add(address)
        instructions[address] = instruction
        operands = list(instruction.operands)
        operand_addresses = [
            candidate
            for operand in operands
            if (candidate := _vvas_operand_address(instruction, operand, pointer_size))
            is not None
        ]
        if any(
            location_start <= candidate < location_end
            for candidate in operand_addresses
            for location_start, location_end in config_locations
        ):
            config_reference_count += 1
        if (
            instruction.mnemonic == "mov"
            and len(operands) >= 2
            and operands[0].type == X86_OP_MEM
            and operands[1].type == X86_OP_IMM
        ):
            vtable_address = _vvas_operand_address(
                instruction, operands[1], pointer_size
            )
            if vtable_address is not None:
                reference_sites = vtable_references.get(vtable_address)
                if reference_sites is None:
                    reference_sites = set()
                    vtable_references[vtable_address] = reference_sites
                reference_sites.add(address)
            if len(vtable_references) > MAXIMUM_VVAS_DATA_REFERENCES_PER_FUNCTION:
                return None

        direct_target = (
            operand_addresses[0]
            if operands and operands[0].type == X86_OP_IMM and operand_addresses
            else None
        )
        import_target = (
            _vvas_operand_address(instruction, operands[0], pointer_size)
            if operands
            and operands[0].type == X86_OP_MEM
            and instruction.mnemonic in {"call", "jmp"}
            else None
        )
        if import_target in import_addresses:
            name, descriptor_index = import_addresses[import_target]
            api_calls.append((address, name, descriptor_index))

        next_address = int(instruction.address + instruction.size)
        next_addresses: list[int] = []

        def enqueue(candidate: int) -> bool:
            next_addresses.append(candidate)
            if candidate in visited or candidate in queued:
                return True
            if len(pending) >= MAXIMUM_VVAS_FUNCTION_INSTRUCTIONS:
                return False
            pending.append((candidate, address))
            queued.add(candidate)
            return True

        if instruction.mnemonic == "call":
            if (
                direct_target is not None
                and _vvas_section_for_address(direct_target, sections, executable=True)
                is not None
            ):
                direct_call_counts[direct_target] = (
                    direct_call_counts.get(direct_target, 0) + 1
                )
                if direct_target not in direct_call_first_sites:
                    direct_call_first_sites[direct_target] = address
                callsites = direct_call_sites.get(direct_target)
                if callsites is None:
                    callsites = set()
                    direct_call_sites[direct_target] = callsites
                callsites.add(address)
                if len(direct_call_counts) > MAXIMUM_VVAS_DIRECT_CALLS_PER_FUNCTION:
                    return None
            if not enqueue(next_address):
                return None
            cfg_successors[address] = tuple(dict.fromkeys(next_addresses))
            continue
        if instruction.mnemonic == "jmp":
            if direct_target is not None and not enqueue(direct_target):
                return None
            cfg_successors[address] = tuple(dict.fromkeys(next_addresses))
            continue
        if instruction.mnemonic.startswith(("ret", "iret")) or instruction.mnemonic in {
            "int3",
            "ud2",
        }:
            cfg_successors[address] = ()
            continue
        if instruction.mnemonic.startswith("j") or instruction.mnemonic.startswith(
            "loop"
        ):
            previous = (
                instructions.get(predecessor) if predecessor is not None else None
            )
            constant_target = _vvas_constant_zero_branch(instruction, previous)
            if (
                direct_target is not None
                and constant_target is not False
                and not enqueue(direct_target)
            ):
                return None
            if constant_target is not True and not enqueue(next_address):
                return None
            cfg_successors[address] = tuple(dict.fromkeys(next_addresses))
            continue
        if not enqueue(next_address):
            return None
        cfg_successors[address] = tuple(dict.fromkeys(next_addresses))

    callback_targets: set[int] = set()
    callback_sites: dict[int, int] = {}
    callback_call_sites: dict[int, set[int]] = {}
    create_thread_callsites = [
        callsite
        for callsite, name, _descriptor_index in api_calls
        if name == "createthread"
    ]
    if len(create_thread_callsites) > MAXIMUM_VVAS_CREATE_THREAD_CALLS_PER_FUNCTION:
        return None
    ordered_addresses = sorted(instructions)
    for previous_address, address in zip(ordered_addresses, ordered_addresses[1:]):
        if address < previous_address + int(instructions[previous_address].size):
            return None
    if pointer_size == 4:
        for callsite in create_thread_callsites:
            pushed_values = _vvas_x86_push_arguments(
                instructions,
                cfg_successors,
                callsite,
            )
            if len(pushed_values) != 6:
                continue
            target = pushed_values[2]
            if (
                target is None
                or _vvas_section_for_address(target, sections, executable=True) is None
            ):
                continue
            callback_targets.add(target)
            if target not in callback_sites:
                callback_sites[target] = callsite
            callsites = callback_call_sites.get(target)
            if callsites is None:
                callsites = set()
                callback_call_sites[target] = callsites
            callsites.add(callsite)

    vtable_targets: set[int] = set()
    vtable_target_sites: dict[int, set[int]] = {}
    vtable_count = 0
    for address, reference_sites in vtable_references.items():
        targets = _vvas_vtable_targets(data, sections, address, pointer_size)
        if targets is None:
            return None
        if not targets:
            continue
        vtable_count += 1
        if vtable_count > MAXIMUM_VVAS_VTABLES_PER_FUNCTION:
            return None
        vtable_targets.update(targets)
        for target in targets:
            sites = vtable_target_sites.get(target)
            if sites is None:
                sites = set()
                vtable_target_sites[target] = sites
            sites.update(reference_sites)

    filtered_successors = {
        address: tuple(target for target in targets if target in instructions)
        for address, targets in cfg_successors.items()
    }

    return _VvasFunctionSummary(
        start=start,
        instruction_count=len(visited),
        direct_calls=set(direct_call_counts),
        direct_call_counts=dict(direct_call_counts),
        direct_call_first_sites=direct_call_first_sites,
        direct_call_sites={
            target: tuple(sorted(sites)) for target, sites in direct_call_sites.items()
        },
        callback_targets=callback_targets,
        callback_sites=callback_sites,
        callback_call_sites={
            target: tuple(sorted(sites))
            for target, sites in callback_call_sites.items()
        },
        vtable_targets=vtable_targets,
        vtable_target_sites={
            target: tuple(sorted(sites))
            for target, sites in vtable_target_sites.items()
        },
        api_names={name for _address, name, _descriptor_index in api_calls},
        api_calls={
            (name, descriptor_index) for _address, name, descriptor_index in api_calls
        },
        api_call_sites=tuple(sorted(api_calls)),
        cfg_successors=filtered_successors,
        instructions=instructions,
        return_sites=tuple(
            sorted(
                address
                for address, instruction in instructions.items()
                if instruction.mnemonic.startswith(("ret", "iret"))
            )
        ),
        config_reference_count=config_reference_count,
        repeated_direct_call_count=max(direct_call_counts.values(), default=0),
        utf16_reverse_loop=_vvas_utf16_reverse_loop(instructions),
    )


def _vvas_network_groups(names: set[str]) -> dict[str, bool]:
    """到達可能callsiteのWinsock群を公開可能なbooleanへ正規化する。"""

    return {
        "winsock_initialization": "wsastartup" in names,
        "socket_creation": bool({"socket", "wsasocketa", "wsasocketw"} & names),
        "connection": bool({"connect", "wsaconnect"} & names),
        "send": bool({"send", "wsasend"} & names),
        "receive": bool({"recv", "wsarecv"} & names),
    }


_VVAS_REQUIRED_NETWORK_GROUPS = (
    "winsock_initialization",
    "socket_creation",
    "connection",
    "send",
)
_VVAS_NETWORK_GROUP_BITS = {
    name: 1 << index for index, name in enumerate(_VVAS_REQUIRED_NETWORK_GROUPS)
}
_VVAS_REQUIRED_NETWORK_MASK = sum(_VVAS_NETWORK_GROUP_BITS.values())


def _vvas_network_api_mask(name: str) -> int:
    """Winsock API名を高確度化に必要な機能bitへ変換する。"""

    groups = _vvas_network_groups({name})
    return sum(bit for group, bit in _VVAS_NETWORK_GROUP_BITS.items() if groups[group])


def _vvas_cfg_reaches(
    summary: _VvasFunctionSummary,
    source: int,
    target: int,
) -> bool:
    """同一functionの実在CFG edgeだけでsourceからtargetへ到達できるか返す。"""

    if source not in summary.cfg_successors or target not in summary.cfg_successors:
        return False
    pending: deque[int] = deque([source])
    queued: set[int] = {source}
    seen: set[int] = set()
    while pending:
        current = pending.popleft()
        queued.discard(current)
        if current == target:
            return True
        if current in seen:
            continue
        seen.add(current)
        if len(seen) > MAXIMUM_VVAS_FUNCTION_INSTRUCTIONS:
            return False
        for successor in summary.cfg_successors.get(current, ()):
            if successor in seen or successor in queued:
                continue
            pending.append(successor)
            queued.add(successor)
    return False


def _vvas_cfg_network_masks(
    summary: _VvasFunctionSummary,
    descriptor_index: int,
    callee_return_masks: dict[int, set[int]] | None = None,
) -> tuple[dict[int, set[int]], set[int], set[int]] | None:
    """単一CFG/call-return pathごとのWinsock機能maskを有界に列挙する。"""

    if summary.start not in summary.cfg_successors:
        return None
    api_masks: dict[int, int] = {}
    for address, name, current_descriptor in summary.api_call_sites:
        if current_descriptor != descriptor_index:
            continue
        mask = _vvas_network_api_mask(name)
        if mask:
            api_masks[address] = api_masks.get(address, 0) | mask
    direct_targets_by_address: dict[int, set[int]] = {}
    for target, callsites in summary.direct_call_sites.items():
        for callsite in callsites:
            targets = direct_targets_by_address.get(callsite)
            if targets is None:
                targets = set()
                direct_targets_by_address[callsite] = targets
            targets.add(target)

    pending: deque[tuple[int, int]] = deque([(summary.start, 0)])
    queued: set[tuple[int, int]] = {(summary.start, 0)}
    seen: set[tuple[int, int]] = set()
    masks_by_address: dict[int, set[int]] = {}
    all_masks: set[int] = set()
    while pending:
        address, incoming_mask = pending.popleft()
        queued.discard((address, incoming_mask))
        state = (address, incoming_mask)
        if state in seen:
            continue
        if len(seen) >= MAXIMUM_VVAS_NETWORK_PATH_STATES:
            return None
        seen.add(state)
        outgoing_masks = {incoming_mask | api_masks.get(address, 0)}
        for target in direct_targets_by_address.get(address, set()):
            target_masks = (
                callee_return_masks.get(target, set())
                if callee_return_masks is not None
                else set()
            )
            choices = set(target_masks)
            choices.add(0)
            outgoing_masks = {
                current_mask | target_mask
                for current_mask in outgoing_masks
                for target_mask in choices
            }
        address_masks = masks_by_address.get(address)
        if address_masks is None:
            address_masks = set()
            masks_by_address[address] = address_masks
        address_masks.update(outgoing_masks)
        all_masks.update(outgoing_masks)
        for outgoing_mask in outgoing_masks:
            for successor in summary.cfg_successors.get(address, ()):
                next_state = (successor, outgoing_mask)
                if next_state in seen or next_state in queued:
                    continue
                if len(seen) + len(pending) >= MAXIMUM_VVAS_NETWORK_PATH_STATES:
                    return None
                pending.append(next_state)
                queued.add(next_state)
    return_masks = {
        mask
        for address in summary.return_sites
        for mask in masks_by_address.get(address, set())
    }
    return masks_by_address, all_masks, return_masks


def _vvas_direct_return_masks(
    summaries: dict[int, _VvasFunctionSummary],
    descriptor_index: int,
    component_functions: set[int],
) -> dict[int, set[int]] | None:
    """direct callの戻りを含む単一path maskを有界fixed pointで解く。"""

    result = {function_start: set() for function_start in component_functions}
    reverse_callers: dict[int, set[int]] = {}
    for caller in component_functions:
        summary = summaries.get(caller)
        if summary is None:
            return None
        for target in summary.direct_calls & component_functions:
            callers = reverse_callers.get(target)
            if callers is None:
                callers = set()
                reverse_callers[target] = callers
            callers.add(caller)

    pending: deque[int] = deque(sorted(component_functions))
    queued: set[int] = set(component_functions)
    solve_count = 0
    while pending:
        current = pending.popleft()
        queued.discard(current)
        if solve_count >= MAXIMUM_VVAS_NETWORK_CHAIN_STATES:
            return None
        solve_count += 1
        summary = summaries.get(current)
        if summary is None:
            return None
        recovered = _vvas_cfg_network_masks(
            summary,
            descriptor_index,
            result,
        )
        if recovered is None:
            return None
        _masks_by_address, _all_masks, return_masks = recovered
        new_masks = return_masks - result[current]
        if not new_masks:
            continue
        result[current].update(new_masks)
        for caller in reverse_callers.get(current, set()):
            if caller in queued:
                continue
            if len(pending) >= MAXIMUM_VVAS_NETWORK_CHAIN_STATES:
                return None
            pending.append(caller)
            queued.add(caller)
    return result


def _vvas_network_chain_proof(
    summaries: dict[int, _VvasFunctionSummary],
    callback_start: int,
    descriptor_index: int,
    component_functions: set[int],
) -> dict[str, object]:
    """単一CFG/call-return pathとvtable chain上のWinsock群を証明する。"""

    if callback_start not in component_functions:
        return {"matched": False, "analysis_complete": False}
    direct_return_masks = _vvas_direct_return_masks(
        summaries,
        descriptor_index,
        component_functions,
    )
    if direct_return_masks is None:
        return {"matched": False, "analysis_complete": False}
    path_cache: dict[
        int,
        tuple[dict[int, set[int]], set[int], set[int]],
    ] = {}

    def path_masks(
        function_start: int,
    ) -> tuple[dict[int, set[int]], set[int], set[int]] | None:
        cached = path_cache.get(function_start)
        if cached is not None:
            return cached
        summary = summaries.get(function_start)
        if summary is None:
            return None
        recovered = _vvas_cfg_network_masks(
            summary,
            descriptor_index,
            direct_return_masks,
        )
        if recovered is not None:
            path_cache[function_start] = recovered
        return recovered

    pending: deque[tuple[int, int, bool, int]] = deque([(callback_start, 0, False, 1)])
    queued: set[tuple[int, int, bool]] = {(callback_start, 0, False)}
    seen: set[tuple[int, int, bool]] = set()
    while pending:
        current, incoming_mask, used_vtable, chain_length = pending.popleft()
        state = (current, incoming_mask, used_vtable)
        queued.discard(state)
        if state in seen:
            continue
        if len(seen) >= MAXIMUM_VVAS_NETWORK_CHAIN_STATES:
            return {"matched": False, "analysis_complete": False}
        seen.add(state)
        summary = summaries.get(current)
        recovered = path_masks(current)
        if summary is None or recovered is None:
            return {"matched": False, "analysis_complete": False}
        masks_by_address, all_masks, _return_masks = recovered
        for local_mask in all_masks:
            combined_mask = incoming_mask | local_mask
            if (
                used_vtable
                and combined_mask & _VVAS_REQUIRED_NETWORK_MASK
                == _VVAS_REQUIRED_NETWORK_MASK
            ):
                return {
                    "matched": True,
                    "analysis_complete": True,
                    "single_reachable_chain": True,
                    "vtable_transition_observed": True,
                    "chain_function_count": chain_length,
                    "network_groups": {
                        group: bool(combined_mask & bit)
                        for group, bit in _VVAS_NETWORK_GROUP_BITS.items()
                    },
                    "raw_addresses_included": False,
                }

        def enqueue_transition(
            target: int,
            combined_mask: int,
            next_used_vtable: bool,
        ) -> bool:
            next_state = (target, combined_mask, next_used_vtable)
            if next_state in seen or next_state in queued:
                return True
            if len(seen) + len(pending) >= MAXIMUM_VVAS_NETWORK_CHAIN_STATES:
                return False
            pending.append((target, combined_mask, next_used_vtable, chain_length + 1))
            queued.add(next_state)
            return True

        for target, callsites in summary.direct_call_sites.items():
            if target not in component_functions:
                continue
            callsite_masks = {
                mask
                for callsite in callsites
                for mask in masks_by_address.get(callsite, set())
            }
            for local_mask in callsite_masks:
                if not enqueue_transition(
                    target,
                    incoming_mask | local_mask,
                    used_vtable,
                ):
                    return {"matched": False, "analysis_complete": False}
        for target in summary.vtable_targets:
            if target not in component_functions:
                continue
            for local_mask in all_masks:
                if not enqueue_transition(
                    target,
                    incoming_mask | local_mask,
                    True,
                ):
                    return {"matched": False, "analysis_complete": False}
    return {"matched": False, "analysis_complete": True}


def _vvas_parser_paths(
    summaries: dict[int, _VvasFunctionSummary],
) -> dict[int, tuple[set[int], set[int]]]:
    """設定参照を内包する1段wrapperまで含めてparser lineageを返す。

    config文字列の直接参照、UTF-16反転、3回以上のfield parser呼出しは、
    同一functionまたはその直下callee群だけで揃う必要がある。単にcall graph
    全体で観測したsignalを合算しない。
    """

    parser_paths: dict[int, tuple[set[int], set[int]]] = {}
    for root in summaries.values():
        component = [root]
        if not root.callback_targets:
            component.extend(
                child
                for target in root.direct_calls
                if (child := summaries.get(target)) is not None
                and child.config_reference_count > 0
            )
        if not any(item.config_reference_count > 0 for item in component):
            continue
        reverse_targets = {
            target
            for item in component
            for target in item.direct_calls
            if (target_summary := summaries.get(target)) is not None
            and target_summary.utf16_reverse_loop
        }
        field_parser_targets = {
            target
            for item in component
            for target, count in item.direct_call_counts.items()
            if count >= 3
            and target not in reverse_targets
            and summaries.get(target) is not None
        }
        if reverse_targets and field_parser_targets:
            parser_paths[root.start] = (reverse_targets, field_parser_targets)
    nested = {
        target
        for root in parser_paths
        for target in summaries[root].direct_calls
        if target in parser_paths
    }
    return {
        root: evidence for root, evidence in parser_paths.items() if root not in nested
    }


def _vvas_thread_wrapper_callback_parameter(
    summaries: dict[int, _VvasFunctionSummary],
    wrapper_start: int,
) -> int | None:
    """静的thread wrapperが保存・trampoline実行するcallback引数を返す。"""

    wrapper = summaries.get(wrapper_start)
    if wrapper is None:
        return None
    create_calls = [
        callsite
        for callsite, name, _descriptor in wrapper.api_call_sites
        if name == "createthread"
    ]
    if len(create_calls) != 1:
        return None
    create_call = create_calls[0]
    create_args = _vvas_x86_push_arguments(
        wrapper.instructions,
        wrapper.cfg_successors,
        create_call,
    )
    if len(create_args) != 6:
        return None
    trampoline = create_args[2]
    if trampoline is None or trampoline not in wrapper.callback_targets:
        return None

    stores: set[tuple[int, int]] = set()
    for address, instruction in wrapper.instructions.items():
        if address >= create_call or instruction.mnemonic != "mov":
            continue
        operands = list(instruction.operands)
        if (
            len(operands) != 2
            or operands[0].type != X86_OP_REG
            or operands[1].type != X86_OP_MEM
            or operands[1].mem.base != X86_REG_EBP
            or operands[1].mem.index != X86_REG_INVALID
        ):
            continue
        argument_offset = int(operands[1].mem.disp)
        if not 8 <= argument_offset <= 0x40 or (argument_offset - 8) % 4:
            continue
        register = int(operands[0].reg)
        for later_address, later in wrapper.instructions.items():
            if not address < later_address < create_call or later.mnemonic != "mov":
                continue
            later_operands = list(later.operands)
            if (
                len(later_operands) == 2
                and later_operands[0].type == X86_OP_MEM
                and later_operands[0].mem.base != X86_REG_INVALID
                and later_operands[0].mem.index == X86_REG_INVALID
                and later_operands[1].type == X86_OP_REG
                and later_operands[1].reg == register
                and 0 < int(later_operands[0].mem.disp) <= 0x400
            ):
                stores.add(
                    ((argument_offset - 8) // 4, int(later_operands[0].mem.disp))
                )

    validated: set[int] = set()
    for argument_index, field_offset in stores:
        pending: list[tuple[int, int]] = [(trampoline, 0)]
        pending_index = 0
        seen: set[int] = set()
        indirect_call = False
        while pending_index < len(pending):
            current, depth = pending[pending_index]
            pending_index += 1
            if current in seen or depth > 2:
                continue
            seen.add(current)
            summary = summaries.get(current)
            if summary is None:
                continue
            for instruction in summary.instructions.values():
                operands = list(instruction.operands)
                if (
                    instruction.mnemonic == "call"
                    and len(operands) == 1
                    and operands[0].type == X86_OP_MEM
                    and operands[0].mem.base != X86_REG_INVALID
                    and operands[0].mem.index == X86_REG_INVALID
                    and int(operands[0].mem.disp) == field_offset
                ):
                    indirect_call = True
                    break
            if indirect_call:
                break
            pending.extend((target, depth + 1) for target in summary.direct_calls)
        if indirect_call:
            validated.add(argument_index)
    return next(iter(validated)) if len(validated) == 1 else None


def _vvas_object_worker_network_proof(
    data: bytes,
    sections: list[_VvasPeSection],
    disassembler: Cs,
    import_addresses: dict[int, tuple[str, int]],
    summaries: dict[int, _VvasFunctionSummary],
    callback_start: int,
    descriptor_index: int,
    component_functions: set[int],
) -> dict[str, object]:
    """同一object vtableと静的thread wrapper上の送受信lineageを証明する。"""

    if callback_start not in component_functions:
        return {"matched": False, "analysis_complete": False}
    wrappers = {
        start: parameter
        for start in summaries
        if (parameter := _vvas_thread_wrapper_callback_parameter(summaries, start))
        is not None
    }
    if not wrappers:
        return {"matched": False, "analysis_complete": True}

    def ws_names(summary: _VvasFunctionSummary) -> set[str]:
        return {
            name
            for name, descriptor in summary.api_calls
            if descriptor == descriptor_index
        }

    receive_callbacks: set[int] = set()
    send_callbacks: set[int] = set()

    def callback_network_names(callback: int) -> set[str] | None:
        """wrapper callbackとその2段direct calleeのWinsock群を返す。"""

        pending: list[tuple[int, int]] = [(callback, 0)]
        pending_index = 0
        seen: set[int] = set()
        names: set[str] = set()
        while pending_index < len(pending):
            current, depth = pending[pending_index]
            pending_index += 1
            if current in seen or depth > 2:
                continue
            if len(seen) >= 64:
                return None
            seen.add(current)
            summary = summaries.get(current)
            if summary is None:
                summary = _vvas_function_summary(
                    data,
                    sections,
                    disassembler,
                    current,
                    4,
                    import_addresses,
                    [],
                )
            if summary is None:
                return None
            names.update(ws_names(summary))
            pending.extend((target, depth + 1) for target in summary.direct_calls)
        return names

    for constructor_start in component_functions:
        constructor = summaries.get(constructor_start)
        if constructor is None or "wsastartup" not in ws_names(constructor):
            continue
        target_groups: dict[tuple[int, ...], set[int]] = {}
        for target, sites in constructor.vtable_target_sites.items():
            if target in component_functions:
                site_identity = tuple(sites)
                targets = target_groups.get(site_identity)
                if targets is None:
                    targets = set()
                    target_groups[site_identity] = targets
                targets.add(target)
        for targets in target_groups.values():
            connection_targets = {
                target
                for target in targets
                if all(
                    _vvas_network_groups(ws_names(summaries[target]))[group]
                    for group in ("socket_creation", "connection")
                )
            }
            if not connection_targets:
                continue
            for source in connection_targets:
                summary = summaries[source]
                for wrapper_start in summary.direct_calls & wrappers.keys():
                    argument_index = wrappers[wrapper_start]
                    for callsite in summary.direct_call_sites.get(wrapper_start, ()):
                        arguments = _vvas_x86_push_arguments(
                            summary.instructions,
                            summary.cfg_successors,
                            callsite,
                        )
                        if argument_index >= len(arguments):
                            continue
                        callback = arguments[argument_index]
                        if (
                            callback is None
                            or _vvas_section_for_address(
                                callback,
                                sections,
                                executable=True,
                            )
                            is None
                        ):
                            continue
                        names = callback_network_names(callback)
                        if names is None:
                            return {"matched": False, "analysis_complete": False}
                        groups = _vvas_network_groups(names)
                        if groups["receive"]:
                            receive_callbacks.add(callback)
                        if groups["send"]:
                            send_callbacks.add(callback)
            if receive_callbacks and send_callbacks:
                return {
                    "matched": True,
                    "analysis_complete": True,
                    "single_reachable_chain": False,
                    "object_vtable_worker_lineage": True,
                    "thread_wrapper_callback_lineage": True,
                    "chain_function_count": len(component_functions),
                    "receive_callback_count": len(receive_callbacks),
                    "send_callback_count": len(send_callbacks),
                    "network_groups": {
                        "winsock_initialization": True,
                        "socket_creation": True,
                        "connection": True,
                        "send": True,
                        "receive": True,
                    },
                    "raw_addresses_included": False,
                }
    return {"matched": False, "analysis_complete": True}


def _vvas_reachable_functions(
    summaries: dict[int, _VvasFunctionSummary],
    roots: tuple[int, ...],
) -> set[int]:
    """root別のdirect/callback/vtable到達集合を有界に復元する。"""

    pending = list(roots)
    pending_index = 0
    queued = set(roots)
    seen: set[int] = set()
    while pending_index < len(pending):
        current = pending[pending_index]
        pending_index += 1
        if current in seen:
            continue
        if len(seen) >= MAXIMUM_VVAS_REACHABLE_FUNCTIONS:
            return set()
        summary = summaries.get(current)
        if summary is None:
            return set()
        seen.add(current)
        targets = (
            summary.direct_calls | summary.callback_targets | summary.vtable_targets
        )
        for target in targets:
            if target in summaries and target not in seen and target not in queued:
                pending.append(target)
                queued.add(target)
    return seen


def _vvas_resource_source_reaches_parser(
    launcher: _VvasFunctionSummary,
    parser_site: int,
) -> bool:
    """同一launcher CFGでresource取得API列がparser callへ達するか検証する。"""

    groups = {
        "find": {
            "findresourcea",
            "findresourcew",
            "findresourceexa",
            "findresourceexw",
        },
        "load": {"loadresource"},
        "lock": {"lockresource"},
        "size": {"sizeofresource"},
    }
    sites = {
        group: [
            address
            for address, name, _descriptor in launcher.api_call_sites
            if name in names
        ]
        for group, names in groups.items()
    }
    if any(not values for values in sites.values()):
        return False
    for find_site in sites["find"]:
        reachable_loads = [
            site
            for site in sites["load"]
            if _vvas_cfg_reaches(launcher, find_site, site)
        ]
        reachable_sizes = [
            site
            for site in sites["size"]
            if _vvas_cfg_reaches(launcher, find_site, site)
            and _vvas_cfg_reaches(launcher, site, parser_site)
        ]
        for load_site in reachable_loads:
            if (
                any(
                    _vvas_cfg_reaches(launcher, load_site, lock_site)
                    and _vvas_cfg_reaches(launcher, lock_site, parser_site)
                    for lock_site in sites["lock"]
                )
                and reachable_sizes
            ):
                return True
    return False


def _vvas_pe_structure_evidence(
    data: bytes,
    configuration_identity: str,
    *,
    use_external_roots: bool = False,
    allow_resource_config: bool = False,
    mapped_candidates: tuple[_VvasMappedConfigCandidate, ...] | None = None,
) -> dict[str, object]:
    """mapped configと選択root到達可能なparser／network pathを検証する。"""

    unmatched: dict[str, object] = {"matched": False}
    if len(data) > MAXIMUM_VVAS_PROBE_INPUT_SIZE or not data.startswith(b"MZ"):
        return unmatched
    import_evidence = _vvas_pe_import_evidence(data)
    if import_evidence.get("matched") is not True:
        return unmatched
    try:
        image = pefile.PE(data=data, fast_load=False)
    except (pefile.PEFormatError, ValueError, OverflowError):
        return unmatched
    section_result = _vvas_pe_sections(image, data)
    if section_result is None:
        return unmatched
    sections, _image_base, entrypoint = section_result
    try:
        machine = int(image.FILE_HEADER.Machine)
    except (AttributeError, TypeError, ValueError, OverflowError):
        return unmatched
    if machine == 0x14C:
        mode, pointer_size, architecture = CS_MODE_32, 4, "x86"
    elif machine == 0x8664:
        mode, pointer_size, architecture = CS_MODE_64, 8, "x64"
    else:
        return unmatched
    config_locations = _vvas_config_locations(
        data,
        sections,
        configuration_identity,
        allow_resource=allow_resource_config,
        mapped_candidates=mapped_candidates,
    )
    if not config_locations:
        return unmatched
    location_kinds = {
        "resource" if section.resource else "mapped_data"
        for location_start, location_end in config_locations
        for section in sections
        if section.virtual_start <= location_start
        and location_end <= section.virtual_end
    }
    if len(location_kinds) != 1:
        return unmatched
    resource_config = location_kinds == {"resource"}
    if resource_config and not allow_resource_config:
        return unmatched
    external = collect_external_code_roots(image, data)
    if use_external_roots:
        if external is None or not external.export_funnel or not external.roots:
            return unmatched
        analysis_roots = external.roots
    else:
        analysis_roots = (entrypoint,)
    import_map = _vvas_import_address_map(image)
    if import_map is None:
        return unmatched
    import_addresses, validated_ws2_descriptor = import_map
    try:
        disassembler = Cs(CS_ARCH_X86, mode)
        disassembler.detail = True
    except CsError:
        return unmatched

    if MAXIMUM_VVAS_PENDING_FUNCTIONS < 1:
        return unmatched
    pending: deque[tuple[int, int]] = deque((root, 0) for root in analysis_roots)
    queued: set[int] = set(analysis_roots)
    seen_functions: set[int] = set()
    summaries: dict[int, _VvasFunctionSummary] = {}
    total_instructions = 0
    call_graph_edge_count = 0
    while pending:
        start, depth = pending.popleft()
        queued.discard(start)
        if start in seen_functions:
            continue
        if (
            depth > MAXIMUM_VVAS_CALL_GRAPH_DEPTH
            or len(seen_functions) >= MAXIMUM_VVAS_REACHABLE_FUNCTIONS
        ):
            return unmatched
        seen_functions.add(start)
        summary = _vvas_function_summary(
            data,
            sections,
            disassembler,
            start,
            pointer_size,
            import_addresses,
            config_locations,
        )
        if summary is None:
            return unmatched
        summaries[start] = summary
        total_instructions += summary.instruction_count
        if total_instructions > MAXIMUM_VVAS_REACHABLE_INSTRUCTIONS:
            return unmatched
        relation_edge_count = (
            len(summary.direct_calls)
            + len(summary.callback_targets)
            + len(summary.vtable_targets)
        )
        if (
            relation_edge_count > MAXIMUM_VVAS_CALL_GRAPH_EDGES
            or call_graph_edge_count
            > MAXIMUM_VVAS_CALL_GRAPH_EDGES - relation_edge_count
        ):
            return unmatched
        call_graph_edge_count += relation_edge_count
        targets = (
            summary.direct_calls | summary.callback_targets | summary.vtable_targets
        )
        for target in sorted(targets):
            if target in seen_functions or target in queued:
                continue
            if (
                depth >= MAXIMUM_VVAS_CALL_GRAPH_DEPTH
                or len(pending) >= MAXIMUM_VVAS_PENDING_FUNCTIONS
            ):
                return unmatched
            pending.append((target, depth + 1))
            queued.add(target)

    parser_paths = _vvas_parser_paths(summaries)
    external_reachable = (
        _vvas_reachable_functions(summaries, analysis_roots)
        if use_external_roots
        else set(summaries)
    )
    if not external_reachable:
        return unmatched

    reachable_api_names = {
        name
        for summary in summaries.values()
        for name, descriptor_index in summary.api_calls
        if descriptor_index == validated_ws2_descriptor
    }
    reachable_groups = _vvas_network_groups(reachable_api_names)

    validated_paths: set[tuple[int, int, int]] = set()
    network_components: set[tuple[int, ...]] = set()
    component_cache: dict[int, set[int]] = {}
    network_proof_cache: dict[int, dict[str, object]] = {}
    component_edge_count = 0
    resource_source_path_count = 0

    def component_for(callback_start: int) -> set[int] | None:
        nonlocal component_edge_count
        cached = component_cache.get(callback_start)
        if cached is not None:
            return cached
        component_pending: deque[int] = deque([callback_start])
        component_queued: set[int] = {callback_start}
        component_seen: set[int] = set()
        while component_pending:
            current = component_pending.popleft()
            component_queued.discard(current)
            if current in component_seen:
                continue
            component = summaries.get(current)
            if component is None:
                return None
            component_seen.add(current)
            relation_edge_count = len(component.direct_calls) + len(
                component.vtable_targets
            )
            if (
                relation_edge_count > MAXIMUM_VVAS_COMPONENT_EDGES
                or component_edge_count
                > MAXIMUM_VVAS_COMPONENT_EDGES - relation_edge_count
            ):
                return None
            component_edge_count += relation_edge_count
            targets = component.direct_calls | component.vtable_targets
            for target in sorted(targets):
                if target in component_seen or target in component_queued:
                    continue
                component_pending.append(target)
                component_queued.add(target)
        component_cache[callback_start] = component_seen
        return component_seen

    for launcher in summaries.values():
        if launcher.start not in external_reachable:
            continue
        launcher_parsers = launcher.direct_calls & parser_paths.keys()
        if not launcher_parsers or not launcher.callback_targets:
            continue
        for parser_start in launcher_parsers:
            parser_sites = launcher.direct_call_sites.get(parser_start, ())
            for callback_start in launcher.callback_targets:
                callback_sites = launcher.callback_call_sites.get(
                    callback_start,
                    (),
                )
                for parser_site in parser_sites:
                    if resource_config and not _vvas_resource_source_reaches_parser(
                        launcher,
                        parser_site,
                    ):
                        continue
                    valid_callback_sites = [
                        callback_site
                        for callback_site in callback_sites
                        if parser_site != callback_site
                        and _vvas_cfg_reaches(
                            launcher,
                            parser_site,
                            callback_site,
                        )
                    ]
                    if not valid_callback_sites:
                        continue
                    component_seen = component_for(callback_start)
                    if component_seen is None:
                        return unmatched
                    proof = network_proof_cache.get(callback_start)
                    if proof is None:
                        proof = _vvas_network_chain_proof(
                            summaries,
                            callback_start,
                            validated_ws2_descriptor,
                            component_seen,
                        )
                        if proof.get("matched") is not True:
                            proof = _vvas_object_worker_network_proof(
                                data,
                                sections,
                                disassembler,
                                import_addresses,
                                summaries,
                                callback_start,
                                validated_ws2_descriptor,
                                component_seen,
                            )
                        network_proof_cache[callback_start] = proof
                    if proof.get("analysis_complete") is not True:
                        return unmatched
                    if proof.get("matched") is not True:
                        continue
                    if resource_config:
                        resource_source_path_count += 1
                    for callback_site in valid_callback_sites:
                        validated_paths.add(
                            (launcher.start, parser_start, callback_start)
                        )
                    network_components.add(tuple(sorted(component_seen)))

    validated_network_proofs = [
        proof for proof in network_proof_cache.values() if proof.get("matched") is True
    ]

    required_groups = {
        "mapped_configuration_source": bool(config_locations),
        "resource_source_to_parser": (
            not resource_config or resource_source_path_count > 0
        ),
        "selected_root_to_launcher": bool(validated_paths),
        "reachable_config_reference": bool(parser_paths),
        "reachable_parser_reverse_path": bool(parser_paths),
        "launcher_parser_before_callback": bool(validated_paths),
        "launcher_parser_to_callback_cfg_path": bool(validated_paths),
        "reachable_vtable_network_path": bool(network_components),
        "same_descriptor_winsock_cluster": bool(validated_paths),
        "single_reachable_winsock_chain": bool(validated_network_proofs),
    }
    matched = all(required_groups.values())
    if not matched:
        return unmatched
    return {
        "matched": True,
        "architecture": architecture,
        "root_strategy": ("export_tls" if use_external_roots else "entrypoint"),
        "external_cfg_root_count": (len(analysis_roots) if use_external_roots else 0),
        "export_root_count": (
            len(external.export_roots)
            if use_external_roots and external is not None
            else 0
        ),
        "tls_callback_root_count": (
            len(external.tls_roots)
            if use_external_roots and external is not None
            else 0
        ),
        "configuration_storage": ("resource" if resource_config else "mapped_data"),
        "resource_source_parser_path_count": resource_source_path_count,
        "mapped_config_location_count": len(config_locations),
        "reachable_function_count": len(summaries),
        "reachable_instruction_count": total_instructions,
        "reachable_call_graph_edge_count": call_graph_edge_count,
        "reachable_component_edge_count": component_edge_count,
        "reachable_config_reference_count": sum(
            summary.config_reference_count for summary in summaries.values()
        ),
        "reachable_parser_path_count": len(parser_paths),
        "validated_parser_callback_network_path_count": len(validated_paths),
        "reachable_callback_edge_count": sum(
            len(summary.callback_targets) for summary in summaries.values()
        ),
        "reachable_vtable_edge_count": sum(
            len(summary.vtable_targets) for summary in summaries.values()
        ),
        "reachable_network_component_count": len(network_components),
        "reachable_network_groups": reachable_groups,
        "validated_network_chain_count": len(validated_network_proofs),
        "validated_network_chain_max_function_count": max(
            (
                int(proof.get("chain_function_count", 0))
                for proof in validated_network_proofs
            ),
            default=0,
        ),
        "validated_network_chain_groups": (
            validated_network_proofs[0].get("network_groups", {})
            if validated_network_proofs
            else {}
        ),
        "validated_object_worker_lineage_count": sum(
            proof.get("object_vtable_worker_lineage") is True
            for proof in validated_network_proofs
        ),
        "validated_receive_callback_count": sum(
            int(proof.get("receive_callback_count", 0))
            for proof in validated_network_proofs
        ),
        "validated_send_callback_count": sum(
            int(proof.get("send_callback_count", 0))
            for proof in validated_network_proofs
        ),
        "required_groups": required_groups,
        "import_corroboration": import_evidence,
        "raw_addresses_included": False,
        "raw_config_included": False,
        "raw_network_values_included": False,
    }


def _vvas_terminal_structure_evidence(
    data: bytes,
    configuration_identity: str,
    *,
    mapped_candidates: tuple[_VvasMappedConfigCandidate, ...] | None = None,
) -> dict[str, object]:
    """既存entrypoint経路の後にexport/TLS経路をfail-closedで試す。"""

    entrypoint = _vvas_pe_structure_evidence(
        data,
        configuration_identity,
        mapped_candidates=mapped_candidates,
    )
    if entrypoint.get("matched") is True:
        return entrypoint
    return _vvas_pe_structure_evidence(
        data,
        configuration_identity,
        use_external_roots=True,
        allow_resource_config=True,
        mapped_candidates=mapped_candidates,
    )


def probe_vvas_config(data: bytes, *, input_format: str) -> dict[str, object]:
    """一意な反転設定とformat別の構造補強が揃う場合だけfamily帰属を許可する。

    PEは同一WS2_32 descriptorのAPI群だけでなく、mapped設定、実行section
    からの参照、entrypointまたはexport/TLS rootからparser／reverse／network
    componentへの有界到達性を要求する。resource内設定ではさらに同一launcher
    CFG上のresource取得API列を要求する。endpointやraw設定自体はdetector向け
    probeへ含めない。
    """

    unmatched: dict[str, object] = {
        "matched": False,
        "family": None,
        "variant": None,
        "supports_family_attribution": False,
        "static_config_recovered": False,
        "evidence": {},
        "config": {},
        "sample_executed": False,
        "network_contacted": False,
    }
    if (
        not isinstance(data, bytes)
        or input_format not in {"pe", "data"}
    ):
        return unmatched
    if len(data) > MAXIMUM_VVAS_PROBE_INPUT_SIZE:
        if input_format != "pe":
            return unmatched
        _decoded, recovery, _candidates = _decode_vvas_mapped_pe_config(data)
        limited = dict(unmatched)
        limited["analysis_limits"] = {
            "mapped_config_scan": recovery["mapped_config_scan"]
        }
        return limited
    mapped_candidates: tuple[_VvasMappedConfigCandidate, ...] = ()
    if input_format == "pe":
        decoded, decode_evidence, mapped_candidates = (
            _decode_vvas_mapped_pe_config(data)
        )
        mapped_scan = decode_evidence.get("mapped_config_scan", {})
        if (
            isinstance(mapped_scan, dict)
            and mapped_scan.get("candidate_set_complete") is not True
        ):
            limited = dict(unmatched)
            limited["analysis_limits"] = {"mapped_config_scan": mapped_scan}
            return limited
    else:
        strings, string_scan = _bounded_strings(data)
        if string_scan["truncated"] is True:
            limited = dict(unmatched)
            limited["analysis_limits"] = {"string_scan": string_scan}
            return limited
        decoded, decode_evidence = _decode_vvas_reversed_config(strings)
    if not decoded or decode_evidence["status"] != "decoded_unique":
        if input_format != "pe":
            return unmatched
        completed = dict(unmatched)
        completed["analysis_coverage"] = {
            "mapped_config_scan": decode_evidence["mapped_config_scan"],
            "decode_status": decode_evidence["status"],
            "terminal_lineage_matched": False,
        }
        return completed
    if input_format == "pe":
        identity = decode_evidence.get("configuration_identity_sha256")
        if not isinstance(identity, str):
            return unmatched
        format_evidence = _vvas_terminal_structure_evidence(
            data,
            identity,
            mapped_candidates=mapped_candidates,
        )
        attribution_basis = (
            "unique_vvas_config_and_export_tls_resource_parser_network_dataflow"
            if format_evidence.get("root_strategy") == "export_tls"
            else "unique_vvas_config_and_mapped_reachable_parser_network_dataflow"
        )
    else:
        marker_count = data.count(VVAS_MARKER)
        format_evidence = {
            "matched": marker_count == 1,
            "marker": VVAS_MARKER.decode("ascii"),
            "marker_occurrence_count": marker_count,
        }
        attribution_basis = "unique_vvas_config_and_plaintext_odaktomk_marker"
    if format_evidence.get("matched") is not True:
        if input_format != "pe":
            return unmatched
        unlinked = dict(unmatched)
        unlinked["analysis_coverage"] = {
            "mapped_config_scan": decode_evidence["mapped_config_scan"],
            "decode_status": decode_evidence["status"],
            "terminal_lineage_matched": False,
        }
        return unlinked
    supports_attribution = input_format == "pe"
    return {
        "matched": True,
        "family": "valleyrat" if supports_attribution else None,
        "variant": (
            "vvas_reversed_config_terminal"
            if supports_attribution
            else "vvas_reversed_config_candidate"
        ),
        "supports_family_attribution": supports_attribution,
        "attribution_scope": (
            "validated_terminal_component_structure"
            if supports_attribution
            else "component_handler_route"
        ),
        "terminal_family_confirmed": supports_attribution,
        "family_attribution_basis": attribution_basis,
        "classification_confidence": (
            "high_structural_decoded_config"
            if supports_attribution
            else "medium_candidate_decoded_config"
        ),
        "static_config_recovered": supports_attribution,
        "candidate_config_recovered": not supports_attribution,
        "evidence": {
            "vvas_reversed_config": {
                "candidate_count": decode_evidence["candidate_count"],
                "unique_configuration_count": 1,
                "endpoint_count": len(decoded),
                "excluded_placeholder_slot_count": decode_evidence[
                    "excluded_placeholder_slot_count"
                ],
                "disabled_slot_count": decode_evidence["disabled_slot_count"],
                "configured_slot_count": decode_evidence["configured_slot_count"],
                "explicit_enable_flag_count": decode_evidence[
                    "explicit_enable_flag_count"
                ],
                "implicit_enable_flag_count": decode_evidence[
                    "implicit_enable_flag_count"
                ],
                "empty_backup_slot_count": decode_evidence["empty_backup_slot_count"],
                "explicit_transport_selector_count": decode_evidence[
                    "explicit_transport_selector_count"
                ],
                "implicit_transport_selector_count": decode_evidence[
                    "implicit_transport_selector_count"
                ],
                "tcp_transport_slot_count": decode_evidence["tcp_transport_slot_count"],
                "udp_transport_slot_count": decode_evidence["udp_transport_slot_count"],
                **(
                    {"mapped_config_scan": decode_evidence["mapped_config_scan"]}
                    if input_format == "pe"
                    else {}
                ),
                "raw_config_included": False,
            },
            "format_corroboration": format_evidence,
        },
        "config": {
            "endpoint_count": len(decoded),
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def _xor_marker_candidate_keys(data: bytes, marker: bytes) -> tuple[list[int], int]:
    """既知markerとのbyte差から候補鍵を1回の有界走査で導出する。"""

    if not marker:
        return [], 0
    scan_count = max(0, len(data) - len(marker) + 1)
    if not scan_count:
        return [], scan_count
    keys: set[int] = set()
    first = marker[0]
    marker_size = len(marker)
    for offset in range(scan_count):
        key = data[offset] ^ first
        if key == 0 or key in keys:
            continue
        for index in range(1, marker_size):
            if data[offset + index] ^ key != marker[index]:
                break
        else:
            keys.add(key)
    return sorted(keys), scan_count


def _recover_xor_vvas(
    data: bytes,
) -> tuple[bytes | None, dict[str, str], dict[str, object]]:
    """単一byte XORされたvvaSをmarkerと設定の同時一致で静的復元する。"""

    if len(data) > MAXIMUM_VVAS_XOR_INPUT_SIZE:
        return (
            None,
            {},
            {
                "status": "not_attempted_size_limit",
                "maximum_input_size": MAXIMUM_VVAS_XOR_INPUT_SIZE,
                "marker_scan_passes": 0,
                "marker_scan_byte_count": 0,
                "raw_key_included": False,
                "raw_payload_included": False,
            },
        )
    candidate_keys, marker_scan_byte_count = _xor_marker_candidate_keys(
        data, VVAS_MARKER
    )
    if not candidate_keys:
        return (
            None,
            {},
            {
                "status": "not_found",
                "candidate_key_count": 0,
                "marker_scan_passes": 1,
                "marker_scan_byte_count": marker_scan_byte_count,
                "raw_key_included": False,
                "raw_payload_included": False,
            },
        )
    if len(candidate_keys) > MAXIMUM_VVAS_XOR_CANDIDATES:
        return (
            None,
            {},
            {
                "status": "candidate_limit_rejected",
                "candidate_key_count": len(candidate_keys),
                "maximum_candidate_keys": MAXIMUM_VVAS_XOR_CANDIDATES,
                "marker_scan_passes": 1,
                "marker_scan_byte_count": marker_scan_byte_count,
                "raw_key_included": False,
                "raw_payload_included": False,
            },
        )
    recoveries: dict[str, tuple[bytes, dict[str, str], dict[str, object]]] = {}
    for key in candidate_keys:
        plaintext = bytes(value ^ key for value in data)
        if plaintext.count(VVAS_MARKER) != 1:
            continue
        strings, string_scan = _bounded_strings(plaintext)
        if string_scan["truncated"] is True:
            return (
                None,
                {},
                {
                    "status": "string_scan_truncated_rejected",
                    "candidate_key_count": len(candidate_keys),
                    "marker_scan_passes": 1,
                    "marker_scan_byte_count": marker_scan_byte_count,
                    "string_scan": string_scan,
                    "raw_key_included": False,
                    "raw_payload_included": False,
                },
            )
        decoded, evidence = _decode_vvas_reversed_config(strings)
        if decoded and evidence["status"] == "decoded_unique":
            identity = evidence.get("configuration_identity_sha256")
            if isinstance(identity, str):
                recoveries[identity] = (plaintext, decoded, evidence)
    if len(recoveries) != 1:
        return (
            None,
            {},
            {
                "status": "ambiguous_or_invalid_rejected",
                "candidate_key_count": len(candidate_keys),
                "validated_configuration_count": len(recoveries),
                "marker_scan_passes": 1,
                "marker_scan_byte_count": marker_scan_byte_count,
                "raw_key_included": False,
                "raw_payload_included": False,
            },
        )
    plaintext, decoded, config_evidence = next(iter(recoveries.values()))
    return (
        plaintext,
        decoded,
        {
            "status": "decoded_unique",
            "transform": "single_byte_xor",
            "source_size": len(data),
            "recovered_size": len(plaintext),
            "recovered_sha256": hashlib.sha256(plaintext).hexdigest(),
            "marker": VVAS_MARKER.decode("ascii"),
            "marker_occurrence_count": 1,
            "candidate_key_count": len(candidate_keys),
            "configured_slot_count": config_evidence["configured_slot_count"],
            "disabled_slot_count": config_evidence["disabled_slot_count"],
            "excluded_placeholder_slot_count": config_evidence[
                "excluded_placeholder_slot_count"
            ],
            "configuration_identity_sha256": config_evidence[
                "configuration_identity_sha256"
            ],
            "endpoint_slots": config_evidence["endpoint_slots"],
            "marker_scan_passes": 1,
            "marker_scan_byte_count": marker_scan_byte_count,
            "raw_key_included": False,
            "raw_payload_included": False,
        },
    )


def _empty_static_probe() -> dict[str, object]:
    """構造未一致をfamily情報なしの固定shapeで返す。"""

    return {
        "matched": False,
        "family": None,
        "variant": None,
        "supports_family_attribution": False,
        "static_config_recovered": False,
        "static_stage_locator_recovered": False,
        "evidence": {},
        "config": {},
        "sample_executed": False,
        "network_contacted": False,
    }


def probe_xor_vvas_config(data: bytes) -> dict[str, object]:
    """単一byte XOR設定をfamily未確定の後続解析候補として要約する。"""

    if not isinstance(data, bytes) or data.startswith(
        (b"MZ", b"PK\x03\x04", bytes.fromhex("d0cf11e0a1b11ae1"))
    ):
        return _empty_static_probe()
    _plaintext, decoded, recovery = _recover_xor_vvas(data)
    if not decoded or recovery.get("status") != "decoded_unique":
        return _empty_static_probe()
    return {
        "matched": True,
        "family": None,
        "variant": "single_byte_xor_vvas_candidate",
        "supports_family_attribution": False,
        "attribution_scope": "component_handler_route",
        "terminal_family_confirmed": False,
        "family_attribution_basis": (
            "single_byte_xor_unique_odaktomk_and_vvas_slot_structure"
        ),
        "classification_confidence": "medium_candidate_decoded_config",
        "static_config_recovered": False,
        "candidate_config_recovered": True,
        "static_stage_locator_recovered": False,
        "evidence": {
            "single_byte_xor_vvas": {
                key: recovery[key]
                for key in (
                    "status",
                    "transform",
                    "source_size",
                    "recovered_size",
                    "recovered_sha256",
                    "marker",
                    "marker_occurrence_count",
                    "candidate_key_count",
                    "configured_slot_count",
                    "disabled_slot_count",
                    "excluded_placeholder_slot_count",
                    "configuration_identity_sha256",
                    "raw_key_included",
                    "raw_payload_included",
                )
            }
        },
        "config": {
            "endpoint_count": len(decoded),
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def probe_codemark_terminal_config(
    data: bytes,
    *,
    trusted_static_recovery: bool = False,
) -> dict[str, object]:
    """raw x86／x64 code形状とcodemark設定を検証しprovenanceを分離する。"""

    if not isinstance(trusted_static_recovery, bool) or not isinstance(data, bytes):
        return _empty_static_probe()
    if (
        not MINIMUM_CODEMARK_RAW_STAGE_SIZE
        <= len(data)
        <= MAXIMUM_CODEMARK_RAW_STAGE_SIZE
    ):
        return _empty_static_probe()
    if data.startswith((b"MZ", b"PK\x03\x04", bytes.fromhex("d0cf11e0a1b11ae1"))):
        return _empty_static_probe()
    if data.count(b"codemark") != 1:
        return _empty_static_probe()
    x86 = analyze_x86_codemark_stage(data)
    if x86 is not None:
        config, raw_code_evidence = x86
        raw_code_key = "raw_x86_shellcode"
    else:
        code_probe = data[: min(1024, len(data))]
        peb_walk = re.search(
            rb"\x65\x48\x8b[\x04\x0c\x14\x1c\x24\x2c\x34\x3c]\x25\x60\x00\x00\x00",
            code_probe,
        )
        control_transfer_count = sum(
            code_probe.count(bytes((opcode,))) for opcode in (0xE8, 0xE9, 0xEB, 0xC3)
        )
        control_transfer_count += sum(
            code_probe.count(bytes((0x0F, opcode))) for opcode in range(0x80, 0x90)
        )
        if peb_walk is None or control_transfer_count < 4:
            return _empty_static_probe()
        try:
            config = parse_codemark_config(data)
        except NvmlDatError:
            return _empty_static_probe()
        raw_code_key = "raw_x64_shellcode"
        raw_code_evidence = {
            "bounded_code_probe_size": len(code_probe),
            "control_transfer_opcode_count": control_transfer_count,
            "peb_walk_machine_pattern_present": True,
            "codemark_offset": data.find(b"codemark"),
            "container_header_present": False,
        }
    return {
        "matched": True,
        "family": "valleyrat" if trusted_static_recovery else None,
        "variant": "winos_codemark_recovered_stage",
        "supports_family_attribution": trusted_static_recovery,
        "attribution_scope": (
            "validated_terminal_component_structure"
            if trusted_static_recovery
            else "component_handler_route"
        ),
        "terminal_family_confirmed": trusted_static_recovery,
        "static_config_recovered": True,
        "static_stage_locator_recovered": False,
        "evidence": {
            raw_code_key: raw_code_evidence,
            "codemark_config": {
                "slot_count": len(config["slots"]),
                "active_endpoint_count": len(config["endpoints"]),
                "disabled_slot_count": sum(
                    item.get("enabled") is False for item in config["slots"]
                ),
                "raw_config_included": False,
                "raw_network_values_included": False,
            },
            "trusted_static_recovery": trusted_static_recovery,
        },
        "config": {
            "endpoint_count": len(config["endpoints"]),
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def _extract_bin101(data: bytes, name: str) -> dict | None:
    """BIN/101外層から復元・検証したcodemark終端設定だけを返す。"""

    if not looks_like_bin101_profile(data):
        return None
    recovery = recover_bin101_payload(data)
    if recovery is None:
        return None
    payload_digest = sha256_bytes(recovery.payload)
    if (
        recovery.input_sha256 != sha256_bytes(data)
        or recovery.payload_sha256 != payload_digest
    ):
        return None

    probe = probe_codemark_terminal_config(
        recovery.payload,
        trusted_static_recovery=True,
    )
    if (
        probe.get("matched") is not True
        or probe.get("family") != "valleyrat"
        or probe.get("supports_family_attribution") is not True
        or probe.get("terminal_family_confirmed") is not True
        or probe.get("static_config_recovered") is not True
        or probe.get("attribution_scope") != "validated_terminal_component_structure"
    ):
        return None
    probe_config = probe.get("config")
    if not isinstance(probe_config, dict):
        return None
    try:
        codemark = parse_codemark_config(recovery.payload)
    except NvmlDatError:
        return None
    raw_endpoints = codemark.get("endpoints")
    raw_slots = codemark.get("slots")
    if not isinstance(raw_endpoints, list) or not isinstance(raw_slots, list):
        return None
    endpoints = list(raw_endpoints)
    if (
        not endpoints
        or any(not isinstance(endpoint, str) for endpoint in endpoints)
        or len(set(endpoints)) != len(endpoints)
        or probe_config.get("endpoint_count") != len(endpoints)
    ):
        return None

    result = build_result(
        "valleyrat",
        data,
        {
            "variant": "bin101_nibble_rc4_loader_terminal",
            "decoded_config_recovered": True,
            "static_config_recovered": True,
            "candidate_config_recovered": False,
            "terminal_family_confirmed": True,
            "attribution_scope": "validated_terminal_component_structure",
            "family_attribution_basis": (
                "strict_bin101_resource_transform_x64_code_and_codemark_config"
            ),
            "c2_liveness_confirmed": False,
            "source_name": _safe_source_name(name),
            "endpoints": endpoints,
            "ipv4": ipv4_candidates(endpoints),
            "urls": [],
            "bin101_nibble_rc4": public_bin101_recovery_summary(recovery),
            "codemark_stage": codemark,
            "codemark_terminal_probe": probe,
        },
        [
            {
                "kind": "network.endpoint",
                "value": endpoint,
                "role": "static_config_c2",
                "confidence": "confirmed_static_config",
                "source": "validated_bin101_recovered_codemark",
            }
            for endpoint in endpoints
        ],
        [
            "AMD64 PEの一意なBIN/101 resource、状態依存nibble変換、RC4、x64命令構造を静的に検証しました。",
            "同じ復元payloadについてcodemark marker、slot境界、host、port、transport設定を独立に再検証しました。",
            "この経路では終端ValleyRAT構造と設定を確認し、現在のC2稼働状態や所有者は確認していません。",
            "復元payloadは実行せず、外部通信も行っていません。",
        ],
    )
    result["terminal_payload"] = {
        "role": "terminal_payload",
        "name": f"{payload_digest}.bin",
        "data": recovery.payload,
    }
    return result


def _extract_n520(data: bytes, name: str) -> dict | None:
    """独立したmanaged構造とAES復号を検証できたN520設定だけを返す。"""

    structural = n520_structural_evidence(data)
    if structural.get("matched") is not True:
        return None
    try:
        recovery = recover_n520_config(data)
    except N520ConfigError:
        return None
    endpoints = list(recovery.endpoints)
    urls = list(recovery.urls)
    findings = [
        {
            "kind": "network.endpoint",
            "value": endpoint,
            "role": "configuration_distribution_endpoint",
            "confidence": "confirmed_static_config",
            "source": "validated_n520_managed_aes_config",
        }
        for endpoint in endpoints
    ]
    findings += [
        {
            "kind": "network.url",
            "value": url,
            "role": "configuration_distribution",
            "confidence": "confirmed_static_config",
            "source": "validated_n520_managed_aes_config",
        }
        for url in urls
    ]
    return build_result(
        "valleyrat",
        data,
        {
            "variant": "single_pe_n520_managed",
            "decoded_config_recovered": True,
            "static_config_recovered": True,
            "candidate_config_recovered": False,
            "terminal_family_confirmed": True,
            "attribution_scope": "validated_terminal_component_structure",
            "family_attribution_basis": (
                "managed_cil_key_decryptor_reader_dataflow_and_unique_aes_config"
            ),
            "c2_liveness_confirmed": False,
            "source_name": _safe_source_name(name),
            "endpoints": endpoints,
            "ipv4": ipv4_candidates(endpoints),
            "urls": urls,
            "n520": public_n520_recovery_summary(recovery),
            "final_c2_inherited_from_configuration_distribution": False,
        },
        findings,
        [
            "名前非依存のCIL鍵初期化・復号・reader data-flowとAES-CBC／PKCS#7を静的に検証しました。",
            "復号値のうち公開可能なURL／endpointだけを要約し、生鍵、暗号文、任意plaintextは公開しません。",
            "取得先は設定配布インフラとして記録し、runtimeで取得される最終C2へは継承しません。",
            "検体実行と外部通信は行っていません。",
        ],
    )


def _extract_ca01_sideload(data: bytes, name: str) -> dict | None:
    """CA01 x64外層と同一lineageで検証した3-slot設定を返す。"""

    recovery = recover_ca01_config(data)
    if recovery is None or not validate_ca01_recovery_contract(recovery):
        return None
    public_summary = public_ca01_recovery_summary(recovery)
    reviewed_exact = public_summary.get("reviewed_exact_outer_sha256") is True
    outer_profile = public_summary.get("outer_profile")
    cef_profile = outer_profile == "cef_alias_export_beginthreadex"
    attribution_scope = (
        ("reviewed_exact_cef_alias_loader_linked_config_and_memory_stage_consumer")
        if cef_profile
        else "reviewed_exact_loader_linked_config_and_memory_stage_consumer"
    )
    family_attribution_basis = (
        (
            "reviewed_exact_sha256_and_cef_alias_export_to_"
            "beginthreadex_callback_double_base64_three_slot_consumer_lineage"
        )
        if cef_profile
        else "reviewed_exact_sha256_and_vulkan_export_to_thread_callback_"
        "double_base64_three_slot_consumer_lineage"
    )
    if not reviewed_exact:
        attribution_scope = "component_handler_route"
        family_attribution_basis = "ca01_structure_without_reviewed_terminal_identity"
    raw_endpoints = recovery.config.get("endpoints")
    raw_slots = recovery.config.get("slots")
    if not isinstance(raw_endpoints, list) or not isinstance(raw_slots, list):
        return None

    endpoints: list[str] = []
    for item in raw_endpoints:
        if not isinstance(item, dict):
            return None
        host = item.get("host")
        port = item.get("port")
        if not isinstance(host, str) or type(port) is not int:
            return None
        endpoint = render_endpoint(host, port)
        if endpoint is None:
            return None
        if endpoint not in endpoints:
            endpoints.append(endpoint)
    if not endpoints:
        return None

    slots: list[dict[str, object]] = []
    for item in raw_slots:
        if not isinstance(item, dict):
            return None
        index = item.get("index")
        host = item.get("host")
        port = item.get("port")
        transport = item.get("transport")
        selector = item.get("transport_selector")
        role = item.get("role")
        if (
            type(index) is not int
            or not 1 <= index <= 3
            or not isinstance(host, str)
            or type(port) is not int
            or not isinstance(transport, str)
            or transport not in {"tcp", "udp"}
            or type(selector) is not int
            or selector not in {0, 1}
            or not isinstance(role, str)
            or role not in {"primary", "primary_duplicate", "alternate"}
            or item.get("enabled") is not True
        ):
            return None
        endpoint = render_endpoint(host, port)
        if endpoint is None:
            return None
        slots.append(
            {
                "slot": index,
                "endpoint": endpoint,
                "transport": transport,
                "transport_selector": selector,
                "role": role,
                "enabled": True,
            }
        )
    if (
        len(slots) != 3
        or [item["slot"] for item in slots] != [1, 2, 3]
        or [item["role"] for item in slots]
        != ["primary", "primary_duplicate", "alternate"]
        or slots[0]["endpoint"] != slots[1]["endpoint"]
        or slots[0]["endpoint"] == slots[2]["endpoint"]
        or len({item["transport_selector"] for item in slots}) != 1
        or any(
            item["transport"] != ("tcp" if item["transport_selector"] == 1 else "udp")
            for item in slots
        )
        or endpoints != list(dict.fromkeys(str(item["endpoint"]) for item in slots))
    ):
        return None

    return build_result(
        "valleyrat",
        data,
        {
            "variant": "ca01_x64_double_base64_sideload_terminal",
            "decoded_config_recovered": True,
            "static_config_recovered": True,
            "candidate_config_recovered": False,
            "terminal_family_confirmed": reviewed_exact,
            "attribution_scope": attribution_scope,
            "family_attribution_basis": family_attribution_basis,
            "classification_confidence": (
                "high_structural_decoded_config"
                if reviewed_exact
                else "medium_structural_config_route"
            ),
            "c2_liveness_confirmed": False,
            "source_name": _safe_source_name(name),
            "outer_profile": outer_profile,
            "endpoints": endpoints,
            "ipv4": ipv4_candidates(endpoints),
            "urls": [],
            "decoded_ca01_slots": slots,
            "ca01": public_summary,
        },
        [
            {
                "kind": "network.endpoint",
                "value": endpoint,
                "role": "static_config_c2",
                "confidence": "confirmed_static_config",
                "source": "validated_ca01_loader_linked_config",
            }
            for endpoint in endpoints
        ],
        [
            (
                "CEF alias exportから_beginthreadex callback、二重Base64設定、"
                "3-slot builder、memory-stage consumerまでを同一の有界CFG "
                "lineageで検証しました。"
                if cef_profile
                else "Vulkan exportからthread callback、二重Base64設定、3-slot "
                "builder、memory-stage consumerまでを同一の有界CFG lineageで"
                "検証しました。"
            ),
            "endpoint、port、transport selectorは静的defaultです。現在の稼働状態と所有者は確認していません。",
            "復元後のmemory stage自体は復号していないため、network APIへの直接到達性は未確認です。",
            "生のBase64 token、内部label、内部address、設定identityは公開しません。検体実行と外部通信も行っていません。",
        ],
    )


def _x86_pe_header_valid(data: bytes) -> bool:
    """x86 PEのDOS／NT header境界だけを副作用なく検証する。"""

    if len(data) < 0x40 or not data.startswith(b"MZ"):
        return False
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset < 0x40 or pe_offset > len(data) - 24:
        return False
    return (
        data[pe_offset : pe_offset + 4] == b"PE\0\0"
        and struct.unpack_from("<H", data, pe_offset + 4)[0] == 0x14C
    )


def _extract_xor_b1_downloader(data: bytes, name: str) -> dict | None:
    """x86 PE内のXOR 0xB1文字列群から次段取得URLだけを復元する。"""

    if len(data) > MAXIMUM_VVAS_XOR_INPUT_SIZE or not _x86_pe_header_valid(data):
        return None
    # C実装のtranslateで全byteを一度だけ変換し、後段が必須とする
    # WinINet marker不在なら高コストの全文文字列列挙を開始しない。
    decoded_view = data.translate(_XOR_B1_TRANSLATION)
    if _XOR_B1_WININET_MARKER.search(decoded_view) is None:
        return None
    strings, string_scan = _bounded_strings(decoded_view)
    if string_scan["truncated"] is True:
        return None
    lower = "\n".join(strings).casefold()
    marker_groups = {
        "wininet_library": "wininet.dll" in lower,
        "dynamic_api_resolution": "getprocaddress" in lower,
        "module_resolution": any(
            item in lower
            for item in (
                "getmodulehandlea",
                "getmodulehandlew",
                "loadlibrarya",
                "loadlibraryw",
            )
        ),
        "internet_session": any(
            item in lower for item in ("internetopena", "internetopenw")
        ),
        "internet_url_open": any(
            item in lower for item in ("internetopenurla", "internetopenurlw")
        ),
        "internet_read": "internetreadfile" in lower,
        "veh_registration": "addvectoredexceptionhandler" in lower,
        "memory_allocation": "virtualalloc" in lower,
    }
    if not all(marker_groups.values()):
        return None
    urls = [
        url
        for url in _public_urls(strings)
        if urlsplit(url).scheme in {"http", "https"}
        and urlsplit(url).path.casefold().endswith((".bin", ".dat", ".dll", ".exe"))
    ]
    if not urls or len(urls) > MAXIMUM_XOR_B1_URLS:
        return None
    decoded_sha256 = hashlib.sha256(decoded_view).hexdigest()
    findings = [
        {
            "kind": "network.url",
            "value": url,
            "role": "next_stage_download",
            "confidence": "confirmed_static_stage_locator",
            "source": "x86_pe_single_byte_xor_wininet_api_cluster",
        }
        for url in urls
    ]
    return build_result(
        "valleyrat",
        data,
        {
            "variant": "x86_single_byte_xor_wininet_next_stage_loader",
            "decoded_config_recovered": False,
            "static_config_recovered": False,
            "static_stage_locator_recovered": True,
            "c2_liveness_confirmed": False,
            "source_name": _safe_source_name(name),
            "endpoints": [],
            "ipv4": [],
            "urls": urls,
            "next_stage_download": {
                "status": "decoded_static_url",
                "transform": "single_byte_xor",
                "key_size": 1,
                "raw_key_included": False,
                "x86_pe_header_validated": True,
                "api_marker_groups": marker_groups,
                "decoded_view_sha256": decoded_sha256,
                "decoded_view_published": False,
                "raw_payload_included": False,
            },
            "final_c2_inherited_from_next_stage_url": False,
            "terminal_family_attribution": "unresolved",
        },
        findings,
        [
            "x86 PE境界、単一byte XOR、WinINet library、動的API解決、module解決をURLと相関しました。",
            "復元URLは次段取得先であり、ValleyRAT終端C2としては扱いません。",
            "復号viewと取得payloadは公開せず、検体実行と外部通信も行っていません。",
        ],
    )


def probe_xor_b1_downloader(data: bytes) -> dict[str, object]:
    """XOR-B1 WinINet loaderを次段候補routeとしてだけ要約する。"""

    if not isinstance(data, bytes):
        return _empty_static_probe()
    extracted = _extract_xor_b1_downloader(data, "sample")
    if extracted is None:
        return _empty_static_probe()
    config = extracted.get("config")
    if not isinstance(config, dict):
        return _empty_static_probe()
    locator = config.get("next_stage_download")
    urls = config.get("urls")
    if not isinstance(locator, dict) or not isinstance(urls, list) or not urls:
        return _empty_static_probe()
    return {
        "matched": True,
        "family": None,
        "variant": "x86_single_byte_xor_wininet_next_stage_loader",
        "supports_family_attribution": False,
        "attribution_scope": "component_handler_route",
        "terminal_family_confirmed": False,
        "static_config_recovered": False,
        "static_stage_locator_recovered": True,
        "evidence": {
            "single_byte_xor_stage_locator": {
                "transform": locator.get("transform"),
                "key_size": locator.get("key_size"),
                "raw_key_included": False,
                "x86_pe_header_validated": locator.get("x86_pe_header_validated"),
                "api_marker_groups": locator.get("api_marker_groups"),
                "decoded_view_sha256": locator.get("decoded_view_sha256"),
                "stage_url_count": len(urls),
                "decoded_view_published": False,
                "raw_stage_url_included": False,
                "raw_payload_included": False,
            }
        },
        "config": {
            "stage_url_count": len(urls),
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def _extract_x86_codemark_resource(data: bytes, name: str) -> dict | None:
    """PE resourceから検証済みx86 codemark終端と設定を復元する。"""

    recovery = recover_x86_codemark_resource(data)
    if recovery is None:
        return None
    endpoints = list(recovery.config["endpoints"])
    result = build_result(
        "valleyrat",
        data,
        {
            "variant": "x86_codemark_resource_terminal",
            "decoded_config_recovered": True,
            "static_config_recovered": True,
            "candidate_config_recovered": True,
            "c2_liveness_confirmed": False,
            "source_name": _safe_source_name(name),
            "endpoints": endpoints,
            "ipv4": ipv4_candidates(endpoints),
            "urls": [],
            "x86_codemark_resource": public_x86_codemark_recovery_summary(recovery),
            "terminal_family_confirmed": False,
            "attribution_scope": "component_handler_route",
            "family_attribution_basis": (
                "component_handler_route_only_unproven_extraction_destination_process_argument"
            ),
        },
        [
            {
                "kind": "network.endpoint",
                "value": endpoint,
                "role": "static_config_c2",
                "confidence": "confirmed_static_config",
                "source": "validated_x86_codemark_resource",
            }
            for endpoint in endpoints
        ],
        [
            "外層PEの全resource directory nodeを上限付きで列挙し、同一stageの重複だけを統合しました。resource helper内の引数・戻り値flowと後続process起動routeを静的に検証しています。",
            "抽出先pathとCreateProcessW引数の全経路同値性は未証明のため、family帰属ではなくroute-onlyです。",
            "x86命令被覆、PEB参照、ROR13 export resolver、Winsock構造、制御移譲を検証しました。",
            "codemarkと全slotを境界検証し、複数の異なるstageまたは相反設定は拒否します。",
            "現在の稼働状態と所有者は未確認で、検体実行と外部通信は行っていません。",
        ],
    )
    result["terminal_payload"] = {
        "role": "terminal_payload",
        "name": f"{recovery.stage_sha256}.bin",
        "data": recovery.stage,
    }
    return result


def _extract_codemark_stage(data: bytes, name: str) -> dict | None:
    """検証済みraw x86／x64 stageから一意なcodemark C2 slotを回収する。"""

    probe = probe_codemark_terminal_config(data)
    if probe.get("matched") is not True:
        return None
    try:
        codemark = parse_codemark_config(data)
    except NvmlDatError:
        return None
    endpoints = list(codemark["endpoints"])
    evidence = probe.get("evidence", {})
    architecture = (
        "x86"
        if isinstance(evidence, dict) and "raw_x86_shellcode" in evidence
        else "x64"
    )
    return build_result(
        "valleyrat",
        data,
        {
            "variant": "winos_codemark_recovered_stage",
            "decoded_config_recovered": True,
            "static_config_recovered": True,
            "candidate_config_recovered": True,
            "terminal_family_confirmed": False,
            "attribution_scope": "component_handler_route",
            "c2_liveness_confirmed": False,
            "source_name": _safe_source_name(name),
            "endpoints": endpoints,
            "ipv4": ipv4_candidates(endpoints),
            "urls": [],
            "codemark_stage": codemark,
            "codemark_terminal_probe": probe,
            "family_attribution_basis": (
                "component_handler_route_only_raw_stage"
                if architecture == "x86"
                else "validated_raw_x64_shellcode_and_codemark_structure"
            ),
        },
        [
            {
                "kind": "network.endpoint",
                "value": endpoint,
                "role": "static_config_c2",
                "confidence": "confirmed_static_config",
                "source": "validated_codemark_stage",
            }
            for endpoint in endpoints
        ],
        [
            f"raw {architecture}命令構造とcodemarkの一意性を検証しました。",
            "codemark header、host長、NUL終端、port、固定header enabled flagを境界検証しました。",
            "末尾3-slot設定はUTF-16LE全文反転後の先頭2 slotがactiveなheaderのhost／portと一致する場合だけ追加し、t=0をUDP、t=1をTCPとして分離します。",
            "raw stage単体は外層の静的復元provenanceを欠くため、family帰属ではなくroute-onlyです。",
            "現在の稼働状態と所有者は未確認で、検体実行と外部通信は行っていません。",
        ],
    )


def _extract_raw_vvas_transport_shellcode(data: bytes, name: str) -> dict | None:
    """外層provenanceのないraw vvaS transport shellcodeを候補として復元する。"""

    recovery = recover_raw_vvas_shellcode(data)
    if recovery is None:
        return None
    endpoints = list(recovery.endpoints)
    return build_result(
        "valleyrat",
        data,
        {
            "variant": "raw_vvas_codemark_transport_candidate",
            "decoded_config_recovered": True,
            "static_config_recovered": True,
            "candidate_config_recovered": True,
            "terminal_family_confirmed": False,
            "attribution_scope": "component_handler_route",
            "family_attribution_basis": (
                "validated_raw_x86_transport_and_correlated_vvas_config_without_outer_lineage"
            ),
            "c2_liveness_confirmed": False,
            "source_name": _safe_source_name(name),
            "endpoints": endpoints,
            "ipv4": ipv4_candidates(endpoints),
            "urls": [],
            "raw_vvas_transport_shellcode": public_raw_shellcode_summary(recovery),
        },
        [
            {
                "kind": "network.endpoint",
                "value": endpoint,
                "role": "static_config_c2",
                "confidence": "confirmed_static_config",
                "source": "validated_raw_vvas_transport_shellcode",
            }
            for endpoint in endpoints
        ],
        [
            "raw x86 shellcodeのPEB resolver、Winsock構築、socket引数、check-in、受信stage用memory sinkを有界CFGで静的に検証しました。",
            "codemark headerと末尾の全文反転UTF-16LE 3-slot設定を相関し、ゼロ埋めportは数値同値の場合だけ受理します。",
            "portを欠く重複backupはheader側もport 0の場合だけ不完全slotとして除外し、loopback既定slotもC2へ昇格しません。",
            "raw stage単体ではZIPからのsource／transform／sink provenanceがないため、family帰属はroute-onlyです。",
            "検体とpayloadは実行せず、外部通信も行っていません。",
        ],
    )


def _extract_onyx_terminal(data: bytes, name: str) -> dict | None:
    """外層3変換と4反復slotをすべて検証できたOnyx設定だけを返す。"""

    if not matches_onyx_qt_profile(data):
        return None
    recovery = recover_onyx_qt_payload(data)
    if recovery is None:
        return None
    terminal = recover_onyx_terminal_config(recovery.payload)
    if terminal is None:
        return None

    endpoint = f"{terminal.host}:{terminal.port}"
    result = build_result(
        "valleyrat",
        data,
        {
            "variant": "onyx_qt_loader_terminal_component",
            "decoded_vvas": {},
            "decoded_onyx": {"endpoint_1": endpoint},
            "static_config_recovered": True,
            "c2_liveness_confirmed": False,
            "source_name": _safe_source_name(name),
            "endpoints": [endpoint],
            "ipv4": ipv4_candidates([terminal.host]),
            "urls": [],
            "onyx_qt_loader": {
                "outer_recovery_status": "shellcode_recovered",
                "terminal_component": "onyx_terminal_stage",
                "terminal_component_status": "confirmed_static",
                "terminal_family_attribution": "unresolved",
                "payload_size": len(recovery.payload),
                "payload_sha256": recovery.payload_sha256,
                "config_size": terminal.config_size,
                "config_sha256": terminal.config_sha256,
                "repeated_slot_count": terminal.repeated_slot_count,
                "raw_key_included": False,
                "raw_config_included": False,
                "raw_payload_included": False,
            },
        },
        [
            {
                "kind": "network.endpoint",
                "value": endpoint,
                "role": "static_config_c2",
                "confidence": "confirmed_static_config",
                "source": "onyx_terminal_repeated_slots",
            }
        ],
        [
            "Onyx terminal componentは静的に確証しましたが、独立malware familyの範囲は未確定です。",
            "providerのValleyRAT／SilverFox labelは終端family帰属の根拠に使用しません。",
            "endpointの現在の稼働状態と所有者は確認していません。",
        ],
    )
    result["terminal_payload"] = {
        "role": "terminal_payload",
        "name": f"{recovery.payload_sha256}.bin",
        "data": recovery.payload,
    }
    return result


def _reviewed_pdfcore8_result(data: bytes, name: str) -> dict | None:
    """exact SHAで確認済みのrotated PDFCore8 chainを非終端証拠として返す。"""

    digest = sha256_bytes(data)
    variant = REVIEWED_PDFCORE8_ROTATED_VARIANTS.get(digest)
    if variant is None:
        return None
    return build_result(
        "valleyrat",
        data,
        {
            "variant": variant,
            "reviewed_hash": True,
            "matched_patterns": [
                "reviewed_exact_sha256",
                "pdfcore8_rotated_resource_lineage",
            ],
            "static_config_recovered": False,
            "c2_liveness_confirmed": False,
            "final_rat_confirmed": False,
            "terminal_family_attribution": "pdfcore8_winos_lineage_correlated_terminal_unrecovered",
            "source_name": _safe_source_name(name),
            "endpoints": [],
            "ipv4": [],
            "urls": [],
            "raw_resource_published": False,
        },
        [],
        [
            "exact SHAとresource／proxy構造は確認済みですが、保護された現行terminal、設定、C2 endpointは未回収です。",
            "旧PDFCore8検体のendpointを現行buildへ継承しません。",
        ],
    )


def _extract_wide_pipe_config(data: bytes, name: str) -> dict | None:
    """UTF-16LE pipe設定とWinos bootstrapの静的系譜を評価する。"""

    recovery = recover_wide_pipe_config(data)
    if recovery is None:
        return None
    terminal = recovery.terminal_family_confirmed
    endpoints = list(recovery.endpoints)
    slots = [
        {
            "slot": slot.index,
            "endpoint": slot.endpoint,
            "transport": "tcp" if slot.transport == 1 else "udp",
            "transport_selector": slot.transport,
            "enabled": True,
        }
        for slot in recovery.slots
        if slot.endpoint is not None
    ]
    findings = [
        {
            "kind": "network.endpoint",
            "value": endpoint,
            "role": "static_config_c2" if terminal else "static_config_c2_candidate",
            "confidence": (
                "confirmed_static_config" if terminal else "decoded_candidate_config"
            ),
            "source": (
                "validated_wide_pipe_winos_bootstrap_lineage"
                if terminal
                else "wide_pipe_plaintext_config_candidate"
            ),
        }
        for endpoint in endpoints
    ]
    return build_result(
        "valleyrat",
        data,
        {
            "variant": (
                "winos_plaintext_pipe_bootstrap_terminal"
                if terminal
                else "winos_plaintext_pipe_config_candidate"
            ),
            "decoded_config_recovered": True,
            "static_config_recovered": terminal,
            "candidate_config_recovered": not terminal,
            "terminal_family_confirmed": terminal,
            "attribution_scope": (
                "validated_winos_bootstrap_component"
                if terminal
                else "component_handler_route"
            ),
            "family_attribution_basis": (
                "unique_pipe_config_parser_runtime_globals_tcp_vtable_winos_frame_dispatcher"
                if terminal
                else "unique_plaintext_pipe_config_without_complete_network_lineage"
            ),
            "classification_confidence": (
                "high_structural_decoded_config"
                if terminal
                else "medium_candidate_decoded_config"
            ),
            "c2_liveness_confirmed": False,
            "source_name": _safe_source_name(name),
            "endpoints": endpoints,
            "ipv4": ipv4_candidates(endpoints),
            "urls": [],
            "slots": slots,
            "wide_pipe_config": public_wide_pipe_recovery_summary(recovery),
        },
        findings,
        [
            (
                "一意なUTF-16LE pipe設定、全field tagのparser参照、実行時endpoint global、"
                "workerからTCP vtableの同一socket fieldを使うconnect／send／recvまでを"
                "静的に検証しました。"
                if terminal
                else "一意なUTF-16LE pipe設定を復元しましたが、parserから実行時global、"
                "network sink、protocol dispatcherまでの完全な系譜は証明できないため"
                "候補としてのみ記録します。"
            ),
            (
                "4-byte長、10-byte header、header由来XOR、初期command 0x0004、"
                "受信dispatcher markerを同一bootstrap内で検証しました。"
                if terminal
                else "不足するnetworkまたはprotocol証拠があるため、ValleyRAT familyへは"
                "昇格していません。"
            ),
            "loopback placeholderはC2候補から除外しました。現在の稼働状態と所有者は確認していません。",
            "検体実行と外部通信は行っていません。",
        ],
    )


def _extract_run_dll_native_core(
    data: bytes,
    name: str,
) -> dict | None:
    """run export型native DLLの設定を、終端とroute-onlyを分離して返す。"""

    run_dll_config = probe_run_dll_native_core_config(data)
    if run_dll_config.get("matched") is not True:
        return None
    endpoints = list(run_dll_config["endpoints"])
    terminal_family_confirmed = bool(
        run_dll_config.get("terminal_family_confirmed") is True
    )
    findings = [
        {
            "kind": "network.endpoint",
            "value": endpoint,
            "role": "static_config_c2",
            "confidence": "confirmed_static_config",
            "source": "validated_run_export_static_config",
        }
        for endpoint in endpoints
    ]
    return build_result(
        "valleyrat",
        data,
        {
            "variant": run_dll_config["variant"],
            "decoded_config_recovered": False,
            "static_config_recovered": True,
            "candidate_config_recovered": not terminal_family_confirmed,
            "terminal_family_confirmed": terminal_family_confirmed,
            "supports_family_attribution": terminal_family_confirmed,
            "attribution_scope": run_dll_config["attribution_scope"],
            "family_attribution_basis": run_dll_config[
                "family_attribution_basis"
            ],
            "c2_liveness_confirmed": False,
            "source_name": _safe_source_name(name),
            "endpoints": endpoints,
            "ipv4": ipv4_candidates(endpoints),
            "urls": [],
            "slots": list(run_dll_config["slots"]),
            "excluded_placeholder_defaults": list(
                run_dll_config["excluded_placeholder_defaults"]
            ),
            "run_dll_native_core": dict(run_dll_config["evidence"]),
        },
        findings,
        [
            "run export型native DLLの厳格なPE profile、固定幅3-record設定、全9 fieldへの実行code参照を静的に検証しました。",
            "重複する主設定は1 endpointへ縮約し、第三recordのIPv4/IPv6 loopback placeholderは値を公開せずC2候補から除外しました。",
            (
                "run exportから同一socketのnetwork sinkおよび終端protocolまでの静的系譜を検証しました。"
                if terminal_family_confirmed
                else "未証明のnetworkまたはserializer系譜があるため、終端family確定には昇格していません。"
            ),
            "検体実行と外部通信は行っていません。",
        ],
    )


def _attach_final_payloads(
    result: dict,
    payloads: tuple[dict[str, object], ...],
) -> None:
    """既存payloadとloader follow-onをdigest一意に統合する。"""

    combined: list[dict[str, object]] = []
    existing = result.pop("final_payload", None)
    if isinstance(existing, dict):
        combined.append(existing)
    existing_many = result.pop("final_payloads", None)
    if isinstance(existing_many, list):
        combined.extend(item for item in existing_many if isinstance(item, dict))
    combined.extend(payloads)

    unique: dict[bytes, dict[str, object]] = {}
    for payload in combined:
        raw = payload.get("data")
        if (
            payload.get("role") != "final_payload"
            or not isinstance(payload.get("name"), str)
            or not payload.get("name")
            or not isinstance(raw, bytes)
            or not raw
        ):
            continue
        unique.setdefault(hashlib.sha256(raw).digest(), payload)
    retained = list(unique.values())
    if len(retained) == 1:
        result["final_payload"] = retained[0]
    elif retained:
        result["final_payloads"] = retained


def _extract_native_loader_lineage(
    data: bytes,
    name: str,
) -> tuple[
    dict | None,
    dict[str, object],
    tuple[dict[str, object], ...],
]:
    """native loaderを静的に辿り、確定終端、route観測、follow-onを返す。"""

    native = analyze_native_loader_lineage(data)
    observations: dict[str, object] = {}
    if native is not None:
        native_observation = dict(native.observation)
        terminal = native_observation.get("terminal")
        confirmed = bool(
            isinstance(native.terminal_component, bytes)
            and native.terminal_component
            and native_observation.get("supports_family_attribution") is True
            and native_observation.get("terminal_family_confirmed") is True
            and native_observation.get("terminal_network_lineage_proven") is True
            and native_observation.get("terminal_protocol_lineage_proven") is True
            and isinstance(terminal, dict)
            and terminal.get("static_config_recovered") is True
            and terminal.get("candidate_only") is False
        )
        if confirmed:
            endpoint_count = terminal.get("endpoint_count")
            terminal_result = extract(
                native.terminal_component,
                f"{_safe_source_name(name)}::validated-terminal",
            )
            terminal_config = terminal_result.get("config")
            endpoints = (
                terminal_config.get("endpoints")
                if isinstance(terminal_config, dict)
                else None
            )
            if (
                terminal_result.get("family") != "valleyrat"
                or not isinstance(terminal_config, dict)
                or terminal_config.get("static_config_recovered") is not True
                or terminal_config.get("terminal_family_confirmed") is not True
                or type(endpoint_count) is not int
                or not isinstance(endpoints, list)
                or len(endpoints) != endpoint_count
                or any(not isinstance(endpoint, str) or not endpoint for endpoint in endpoints)
            ):
                raise RuntimeError(
                    "native loader終端とshared extractor結果の契約が一致しません"
                )
            result = dict(terminal_result)
            result["sample_sha256"] = sha256_bytes(data)
            result["config"] = {
                **terminal_config,
                "variant": "native_loader_valleyrat_terminal_lineage",
                "terminal_component_variant": terminal_config.get("variant"),
                "source_name": _safe_source_name(name),
                "supports_family_attribution": True,
                "terminal_network_lineage_proven": True,
                "terminal_protocol_lineage_proven": True,
                "native_loader_lineage": native_observation,
            }
            limitations = list(result.get("limitations") or [])
            limitations.insert(
                0,
                "native loaderの全復元辺と終端config/network/protocolを静的に検証しました。",
            )
            result["limitations"] = limitations
            result["terminal_payload"] = {
                "role": "terminal_payload",
                "name": "validated-native-loader-terminal.bin",
                "data": native.terminal_component,
            }
            return result, {}, ()
        observations["native_loader_lineage"] = native_observation
        if (
            native_observation.get("supports_family_attribution") is False
            and native_observation.get("terminal_family_confirmed") is False
            and native_observation.get("follow_on_candidate_set_complete") is True
            and native_observation.get("raw_payload_included") is False
            and native_observation.get("sample_executed") is False
            and native_observation.get("network_contacted") is False
        ):
            native_follow_ons = [
                {
                    "role": "final_payload",
                    "name": f"{sha256_bytes(component)}.bin",
                    "data": component,
                }
                for component in native.recovered_components
                if isinstance(component, bytes) and component
            ]
        else:
            native_follow_ons = []
    else:
        native_follow_ons = []

    follow_ons = native_follow_ons
    silverfox = analyze_silverfox_loader_lineage(data)
    if silverfox is not None:
        silverfox_observation = dict(silverfox.observation)
        observations["silverfox_loader_lineage"] = silverfox_observation
        component = silverfox.recovered_component
        if (
            isinstance(component, bytes)
            and component
            and silverfox_observation.get("status")
            == "validated_silverfox_style_infection_loader_lineage"
            and silverfox_observation.get("matched") is True
            and silverfox_observation.get("supports_family_attribution") is False
            and silverfox_observation.get("terminal_family_confirmed") is False
            and silverfox_observation.get("terminal_network_lineage_proven") is False
            and silverfox_observation.get("terminal_protocol_lineage_proven") is False
            and silverfox_observation.get("candidate_only") is True
            and silverfox_observation.get("raw_payload_included") is False
            and silverfox_observation.get("sample_executed") is False
            and silverfox_observation.get("network_contacted") is False
        ):
            follow_ons.append(
                {
                    "role": "final_payload",
                    "name": f"{sha256_bytes(component)}.bin",
                    "data": component,
                }
            )
    return None, observations, tuple(follow_ons)


def extract(data: bytes, name: str = "sample") -> dict:
    """endpointへ接続せず、ValleyRAT関連の静的設定候補を返す。"""
    safe_name = _safe_source_name(name)
    if len(data) > MAXIMUM_INPUT_SIZE:
        return build_result(
            "valleyrat",
            data,
            {
                "variant": "unresolved_variant",
                "recovery_status": "not_attempted_input_size_limit",
                "maximum_input_size": MAXIMUM_INPUT_SIZE,
                "decoded_config_recovered": False,
                "static_config_recovered": False,
                "c2_liveness_confirmed": False,
                "source_name": safe_name,
                "endpoints": [],
                "ipv4": [],
                "urls": [],
            },
            [],
            [
                "入力がValleyRAT抽出器の64 MiB上限を超えたため、設定復元を開始していません。",
                "検体実行と外部通信は行っていません。",
            ],
        )
    reviewed_pdfcore8 = _reviewed_pdfcore8_result(data, name)
    if reviewed_pdfcore8 is not None:
        return reviewed_pdfcore8
    ca01 = _extract_ca01_sideload(data, name)
    if ca01 is not None:
        return ca01
    onyx = _extract_onyx_terminal(data, name)
    if onyx is not None:
        return onyx
    run_dll = _extract_run_dll_native_core(data, name)
    if run_dll is not None:
        return run_dll
    x86_codemark_resource = _extract_x86_codemark_resource(data, name)
    if x86_codemark_resource is not None:
        return x86_codemark_resource
    bin101 = _extract_bin101(data, name)
    if bin101 is not None:
        return bin101
    codemark_stage = _extract_codemark_stage(data, name)
    if codemark_stage is not None:
        return codemark_stage
    raw_vvas_transport = _extract_raw_vvas_transport_shellcode(data, name)
    if raw_vvas_transport is not None:
        return raw_vvas_transport
    n520 = _extract_n520(data, name)
    if n520 is not None:
        return n520
    xor_b1_downloader = _extract_xor_b1_downloader(data, name)
    if xor_b1_downloader is not None:
        return xor_b1_downloader
    wide_pipe = _extract_wide_pipe_config(data, name)
    if wide_pipe is not None:
        return wide_pipe
    (
        native_terminal,
        native_loader_observations,
        loader_follow_ons,
    ) = _extract_native_loader_lineage(
        data,
        name,
    )
    if native_terminal is not None:
        return native_terminal
    mapped_candidates: tuple[_VvasMappedConfigCandidate, ...] = ()
    mapped_decoded: dict[str, str] = {}
    mapped_recovery: dict[str, object] = {}
    if data.startswith(b"MZ"):
        mapped_decoded, mapped_recovery, mapped_candidates = (
            _decode_vvas_mapped_pe_config(data)
        )
    if not mapped_candidates:
        export_funnel_route = probe_export_funnel_route(data)
        if export_funnel_route.get("matched") is True:
            result = build_result(
                "valleyrat",
                data,
                {
                    "variant": export_funnel_route["variant"],
                    "decoded_config_recovered": False,
                    "static_config_recovered": False,
                    "candidate_config_recovered": False,
                    "encoded_config_candidate_observed": (
                        export_funnel_route.get("encoded_config_candidate_observed")
                        is True
                    ),
                    "recovery_status": export_funnel_route.get(
                        "recovery_status", "not_recovered"
                    ),
                    "terminal_family_confirmed": False,
                    "terminal_network_lineage_proven": False,
                    "supports_family_attribution": False,
                    "attribution_scope": "component_handler_route",
                    "c2_liveness_confirmed": False,
                    "source_name": safe_name,
                    "endpoints": [],
                    "ipv4": [],
                    "urls": [],
                    "export_funnel_native_route": export_funnel_route,
                },
                [],
                [
                    "名称に依存せず、複数exportの単一code root収束、resource処理、Winsock call群を静的に確認しました。",
                    "書込み可能・非実行sectionの高entropy UTF-16LE hexは暗号化設定候補としてのみinventory化し、raw値は出力していません。",
                    "復号、設定parser、実行時endpoint、connect、同一socketのsend／recv系譜が閉じないため、設定復元またはValleyRAT family確定へ昇格していません。",
                    "検体実行と外部通信は行っていません。",
                ],
            )
            _attach_final_payloads(result, loader_follow_ons)
            return result
    mapped_scan = mapped_recovery.get("mapped_config_scan")
    mapped_scan_incomplete = bool(
        isinstance(mapped_scan, dict)
        and mapped_scan.get("candidate_set_complete") is not True
    )
    if data.startswith(b"MZ") and mapped_candidates:
        # 候補の一意性とcode lineageはmapped候補だけで評価できる。ここで
        # 全PE文字列を再走査すると、大容量printable sectionの巨大matchを
        # 一時割当してmarker-first化の目的を失うため、明示的に省略する。
        strings = []
        string_scan = _vvas_string_scan_not_attempted(
            "mapped_vvas_candidates_available"
        )
    elif data.startswith(b"MZ") and mapped_scan_incomplete:
        # 未完了のmapped候補集合を全体文字列scanのprefixで補完しない。
        strings = []
        string_scan = _vvas_string_scan_not_attempted(
            "mapped_config_scan_incomplete"
        )
    elif (
        data.startswith(b"MZ")
        and len(data) > MAXIMUM_VVAS_PE_GLOBAL_STRING_SCAN_INPUT_SIZE
    ):
        # markerがない大容量PEでも、generic variant推測のためだけに全文字列を
        # 列挙しない。family/configは未解決のまま保持する。
        strings = []
        string_scan = _vvas_string_scan_not_attempted(
            "large_pe_marker_first_only"
        )
    else:
        strings, string_scan = _bounded_strings(data)
    nvml_recovery = None
    if looks_like_nvml_dat(data):
        try:
            nvml_recovery = recover_nvml_dat(data)
        except NvmlDatError:
            # trailer長だけが偶然一致したdataをValleyRATへ昇格しない。
            nvml_recovery = None
    variant = (
        "nvml_compact_dat_winos_stage"
        if nvml_recovery is not None
        else identify_variant(strings)
    )
    if variant == "unresolved_variant":
        if "silverfox_loader_lineage" in native_loader_observations:
            variant = "silverfox_style_infection_loader"
        elif "native_loader_lineage" in native_loader_observations:
            variant = "native_loader_candidate"
    if data.startswith(b"MZ"):
        # PEではmapped sectionの完全なmarker-first走査だけを設定候補源にする。
        # 全体文字列scanが上限へ達しても、そのpartial prefixへfallbackしない。
        decoded = mapped_decoded
        vvas_recovery = mapped_recovery
    elif string_scan["truncated"] is True:
        decoded = {}
        vvas_recovery = {
            "status": "string_scan_truncated_rejected",
            "string_scan": string_scan,
        }
    else:
        decoded, vvas_recovery = _decode_vvas_reversed_config(strings)
    static_config_confirmed = False
    candidate_config_recovered = False
    if decoded and nvml_recovery is None:
        if data.startswith(b"MZ"):
            identity = vvas_recovery.get("configuration_identity_sha256")
            format_corroboration = (
                _vvas_terminal_structure_evidence(
                    data,
                    identity,
                    mapped_candidates=mapped_candidates,
                )
                if isinstance(identity, str)
                else {"matched": False}
            )
            validated_variant = "vvas_reversed_config_terminal"
        else:
            marker_count = data.count(VVAS_MARKER)
            format_corroboration = {
                "matched": marker_count == 1,
                "marker": VVAS_MARKER.decode("ascii"),
                "marker_occurrence_count": marker_count,
            }
            validated_variant = "vvas_reversed_config_candidate"
        if format_corroboration.get("matched") is True:
            variant = validated_variant
            vvas_recovery["format_corroboration"] = format_corroboration
            static_config_confirmed = data.startswith(b"MZ")
            candidate_config_recovered = not static_config_confirmed
        elif data.startswith(b"MZ"):
            # PE内に一意な設定があっても、mapped section・code reference・
            # entrypoint到達性を証明できなければfamily/configを確定しない。
            variant = "vvas_reversed_config_pe_candidate"
            vvas_recovery["format_corroboration"] = {"matched": False}
            candidate_config_recovered = True
        else:
            decoded = {}
            variant = "unresolved_variant"
            vvas_recovery = {
                "status": "structural_corroboration_rejected",
                "candidate_count": vvas_recovery["candidate_count"],
                "unique_configuration_count": vvas_recovery[
                    "unique_configuration_count"
                ],
                "excluded_placeholder_slot_count": vvas_recovery[
                    "excluded_placeholder_slot_count"
                ],
                "format_corroboration": {},
            }
    xor_plaintext = None
    if (
        not decoded
        and nvml_recovery is None
        and string_scan["truncated"] is not True
        and not data.startswith(
            (
                b"MZ",
                b"PK\x03\x04",
                bytes.fromhex("d0cf11e0a1b11ae1"),
                b"7z\xbc\xaf\x27\x1c",
                b"Rar!\x1a\x07",
            )
        )
    ):
        xor_plaintext, decoded, vvas_recovery = _recover_xor_vvas(data)
        if decoded:
            variant = "single_byte_xor_vvas_candidate"
            candidate_config_recovered = True
            strings, string_scan = _bounded_strings(xor_plaintext or b"")
    if nvml_recovery is not None:
        decoded = {
            f"endpoint_{index}": endpoint
            for index, endpoint in enumerate(
                nvml_recovery.codemark_config["endpoints"], start=1
            )
        }
        vvas_recovery = {
            "status": "not_applicable_nvml_dat",
            "raw_key_included": False,
            "raw_payload_included": False,
        }
        static_config_confirmed = True
        candidate_config_recovered = False
    endpoints, urls = endpoint_candidates(strings), _public_urls(strings)
    if not decoded and (
        variant == "unresolved_variant" or native_loader_observations
    ):
        endpoints = []
        urls = []
    if variant == "pdfcore8_winos_recovered_stage" and not decoded:
        # 復元stageに残るRFC1918の既定slotは実運用C2ではない。外層または
        # 実行時更新から注入されたglobal endpointだけを別証跡で公開する。
        endpoints = []
        urls = []
    if decoded:
        endpoints = sorted(set(decoded.values()))
    ips = (
        ipv4_candidates(endpoints)
        if decoded
        else (ipv4_candidates(strings) if variant == "dll_sideload_vvas_bundle" else [])
    )
    if ips and not decoded:
        parsed_endpoints = ((item, parse_endpoint(item)) for item in endpoints)
        endpoints = [
            item
            for item, parsed in parsed_endpoints
            if parsed is not None and parsed[0] in ips
        ]
    findings = [
        {
            "kind": "network.endpoint",
            "value": item,
            "role": "static_config_c2" if static_config_confirmed else "candidate_c2",
            "confidence": (
                "confirmed_static_config" if static_config_confirmed else "inferred"
            ),
            "source": (
                "nvml_dat_codemark"
                if nvml_recovery is not None
                else "decoded_vvas_config"
                if static_config_confirmed
                else "decoded_vvas_candidate"
                if decoded
                else "static_string"
            ),
        }
        for item in endpoints
    ]
    if not decoded:
        findings += [
            {
                "kind": "network.ip",
                "value": item,
                "role": "candidate_c2_host",
                "confidence": "inferred",
                "source": "decoded_static_string",
            }
            for item in ips
        ]
    findings += [
        {
            "kind": "network.url",
            "value": item,
            "role": "config_or_stage_url",
            "confidence": "inferred",
            "source": "static_string",
        }
        for item in urls
    ]
    result = build_result(
        "valleyrat",
        data,
        {
            "variant": variant,
            "decoded_vvas": decoded,
            "decoded_vvas_slots": (
                vvas_recovery.get("endpoint_slots", []) if decoded else []
            ),
            "decoded_config_recovered": bool(
                static_config_confirmed and nvml_recovery is None
            ),
            "static_config_recovered": static_config_confirmed,
            "candidate_config_recovered": candidate_config_recovered,
            "terminal_family_confirmed": static_config_confirmed,
            "attribution_scope": (
                "validated_terminal_component_structure"
                if static_config_confirmed
                else "component_handler_route"
            ),
            "c2_liveness_confirmed": False,
            "source_name": safe_name,
            "endpoints": endpoints,
            "ipv4": ips,
            "urls": urls,
            "string_scan": string_scan,
            "vvas_recovery": vvas_recovery,
            "nvml_dat": (
                public_recovery_summary(nvml_recovery, data)
                if nvml_recovery is not None
                else None
            ),
            **native_loader_observations,
            "placeholder_defaults_excluded": (
                ["192.168.1.200:6669", "192.168.1.200:9999"]
                if variant == "pdfcore8_winos_recovered_stage"
                else []
            ),
        },
        findings,
        [
            "外層PE構造または検証済み復元provenanceと同じlineageで確認した設定だけを終端設定として扱います。",
            "raw dataのodaktomk／単一byte XORだけで復元した値は候補に留め、familyや終端設定を確定しません。",
            "一般文字列だけから得た値はC2候補に留め、未解決外層では公開しません。",
            "Winos復元stageのRFC1918既定slotは実運用C2として公開しません。",
            "NVML.DATは復号stageを実行せず、codemarkで構造検証できたslotだけを静的設定として採用します。",
        ],
    )
    if nvml_recovery is not None:
        result["terminal_payload"] = {
            "role": "terminal_payload",
            "name": f"{nvml_recovery.stage_sha256}.bin",
            "data": nvml_recovery.stage,
        }
    _attach_final_payloads(result, loader_follow_ons)
    return result


__all__ = [
    "HANDLER_CONTRACT",
    "decode_vvas_reversed_config",
    "extract",
    "identify_variant",
    "probe_codemark_terminal_config",
    "probe_run_dll_native_core_config",
    "probe_vvas_config",
    "probe_x86_codemark_resource_config",
    "probe_xor_b1_downloader",
    "probe_xor_vvas_config",
]
