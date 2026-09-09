"""run export型native DLLの固定幅C2設定を合成PE境界で検証する。"""

from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from extractors.valleyrat import extractor

_SAMPLE_SIZE = 380 * 1024
_IMAGE_BASE = 0x10000000
_TEXT_RAW = 0x400
_TEXT_RVA = 0x1000
_TEXT_SIZE = 0x8000
_RDATA_RAW = _TEXT_RAW + _TEXT_SIZE
_RDATA_RVA = 0x9000
_RDATA_SIZE = 0x8000
_DATA_RAW = _RDATA_RAW + _RDATA_SIZE
_DATA_RVA = 0x11000
_DATA_SIZE = 0x28000
_FPTABLE_RAW = _DATA_RAW + _DATA_SIZE
_FPTABLE_RVA = 0x39000
_FPTABLE_SIZE = 0x10000
_RELOC_RAW = _FPTABLE_RAW + _FPTABLE_SIZE
_RELOC_RVA = 0x49000
_CONFIG_RAW = _DATA_RAW + 0x200
_CODE_RAW = _TEXT_RAW + 0x200
_CODE_RVA = _TEXT_RVA + 0x200
_PRIMARY_HOST = "45.67.89.123"
_FALLBACK_HOST = "127.0.0.1"

_IMPORTS = {
    "ADVAPI32.dll": ("RegOpenKeyExW",),
    "BCRYPT.dll": ("BCryptOpenAlgorithmProvider",),
    "DXGI.dll": ("CreateDXGIFactory",),
    "GDI32.dll": ("CreateCompatibleDC",),
    "gdiplus.dll": ("GdiplusStartup",),
    "KERNEL32.dll": (
        "CreateRemoteThread",
        "GetThreadContext",
        "SetThreadContext",
        "VirtualAllocEx",
        "WriteProcessMemory",
    ),
    "ole32.dll": ("CoInitialize",),
    "OLEAUT32.dll": ("SysAllocString",),
    "SHLWAPI.dll": ("PathFileExistsW",),
    "USER32.dll": ("EnumWindows",),
    "WINMM.dll": ("timeGetTime",),
    "WS2_32.dll": ("connect", "recv", "send", "socket"),
}


def _section(
    data: bytearray,
    name: str,
    raw_start: int,
    raw_size: int,
    rva: int,
    characteristics: int,
) -> SimpleNamespace:
    """pefile sectionのうち抽出器が参照する有界viewだけを作る。"""

    return SimpleNamespace(
        Name=name.encode("ascii").ljust(8, b"\x00"),
        VirtualAddress=rva,
        Misc_VirtualSize=raw_size,
        PointerToRawData=raw_start,
        SizeOfRawData=raw_size,
        Characteristics=characteristics,
        get_data=lambda: bytes(data[raw_start : raw_start + raw_size]),
        contains_rva=lambda value: rva <= value < rva + raw_size,
    )


def _write_utf16_field(
    data: bytearray,
    offset: int,
    width: int,
    value: str,
) -> None:
    """NUL終端・zero padding付き固定幅UTF-16LE fieldを書き込む。"""

    encoded = value.encode("utf-16le") + b"\x00\x00"
    assert len(encoded) <= width
    data[offset : offset + width] = encoded.ljust(width, b"\x00")


def _write_record(
    data: bytearray,
    start: int,
    host: str,
    port: int,
    selector: int,
) -> tuple[int, tuple[int, int, int]]:
    """host 510 byte、port 60 byte、4 byte整列selectorを1件作る。"""

    port_start = start + 510
    selector_start = (start + 570 + 3) & ~3
    _write_utf16_field(data, start, 510, host)
    _write_utf16_field(data, port_start, 60, str(port))
    struct.pack_into("<I", data, selector_start, selector)
    return selector_start + 4, (start, port_start, selector_start)


def _mapped_offset(rva: int) -> int:
    mappings = (
        (_TEXT_RVA, _TEXT_RAW, _TEXT_SIZE),
        (_RDATA_RVA, _RDATA_RAW, _RDATA_SIZE),
        (_DATA_RVA, _DATA_RAW, _DATA_SIZE),
        (_FPTABLE_RVA, _FPTABLE_RAW, _FPTABLE_SIZE),
        (_RELOC_RVA, _RELOC_RAW, _SAMPLE_SIZE - _RELOC_RAW),
    )
    for start_rva, start_raw, size in mappings:
        if start_rva <= rva < start_rva + size:
            return start_raw + rva - start_rva
    raise ValueError("unmapped RVA")


def _mapped_rva(offset: int) -> int:
    mappings = (
        (_TEXT_RAW, _TEXT_RVA, _TEXT_SIZE),
        (_RDATA_RAW, _RDATA_RVA, _RDATA_SIZE),
        (_DATA_RAW, _DATA_RVA, _DATA_SIZE),
        (_FPTABLE_RAW, _FPTABLE_RVA, _FPTABLE_SIZE),
        (_RELOC_RAW, _RELOC_RVA, _SAMPLE_SIZE - _RELOC_RAW),
    )
    for start_raw, start_rva, size in mappings:
        if start_raw <= offset < start_raw + size:
            return start_rva + offset - start_raw
    raise ValueError("unmapped file offset")


def _fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    sample_size: int = _SAMPLE_SIZE,
    primary_host: str = _PRIMARY_HOST,
    duplicate_host: str = _PRIMARY_HOST,
    primary_port: int = 441,
    duplicate_port: int = 441,
    fallback_host: str = _FALLBACK_HOST,
    fallback_port: int = 80,
    selectors: tuple[int, int, int] = (1, 1, 1),
    missing_reference: int | None = None,
    references_in_data: bool = False,
    extra_library: bool = False,
    missing_api: str | None = None,
    extra_export: bool = False,
    overlay: bool = False,
    security_directory: bool = False,
    resource_directory: bool = False,
    clr_directory: bool = False,
    nonzero_port_padding: bool = False,
    zero_raw_section: str | None = None,
    section_names: tuple[str, ...] = (
        ".text",
        ".rdata",
        ".data",
        ".fptable",
        ".reloc",
    ),
    machine: int = 0x14C,
    dll: bool = True,
    subsystem: int = 2,
) -> bytes:
    """実行せず、pefileとCapstoneの境界だけを通るnative DLL viewを作る。"""

    assert sample_size > _RELOC_RAW
    data = bytearray(sample_size)
    data[:2] = b"MZ"
    starts: list[int] = []
    next_start = _CONFIG_RAW
    for host, port, selector in (
        (primary_host, primary_port, selectors[0]),
        (duplicate_host, duplicate_port, selectors[1]),
        (fallback_host, fallback_port, selectors[2]),
    ):
        next_start, addresses = _write_record(data, next_start, host, port, selector)
        starts.extend(addresses)
    if nonzero_port_padding:
        first_port = _CONFIG_RAW + 510
        data[first_port + len(str(primary_port).encode("utf-16le")) + 2] = ord("X")

    referenced_values = [
        _IMAGE_BASE + _mapped_rva(offset)
        for index, offset in enumerate(starts)
        if index != missing_reference
    ]
    code = b"".join(b"\x68" + struct.pack("<I", value) + b"\x58" for value in referenced_values)
    code += b"\xc3"
    code_start = _DATA_RAW + 0x1000 if references_in_data else _CODE_RAW
    data[code_start : code_start + len(code)] = code

    section_specs = {
        ".text": (_TEXT_RAW, _TEXT_SIZE, _TEXT_RVA, 0x60000020),
        ".rdata": (_RDATA_RAW, _RDATA_SIZE, _RDATA_RVA, 0x40000040),
        ".data": (_DATA_RAW, _DATA_SIZE, _DATA_RVA, 0xC0000040),
        ".fptable": (
            _FPTABLE_RAW,
            _FPTABLE_SIZE,
            _FPTABLE_RVA,
            0x40000040,
        ),
        ".reloc": (
            _RELOC_RAW,
            sample_size - _RELOC_RAW,
            _RELOC_RVA,
            0x42000040,
        ),
    }
    if zero_raw_section is not None:
        raw_start, _raw_size, rva, characteristics = section_specs[
            zero_raw_section
        ]
        section_specs[zero_raw_section] = (
            raw_start,
            0,
            rva,
            characteristics,
        )
    sections = [
        _section(data, name, *section_specs[name])
        for name in section_names
    ]

    imports = {
        library: tuple(symbol for symbol in symbols if symbol != missing_api)
        for library, symbols in _IMPORTS.items()
    }
    if extra_library:
        imports["VERSION.dll"] = ("GetFileVersionInfoW",)
    import_descriptors = [
        SimpleNamespace(
            dll=library.encode("ascii"),
            imports=[
                SimpleNamespace(name=symbol.encode("ascii"), address=0x10070000 + index)
                for index, symbol in enumerate(symbols)
            ],
        )
        for library, symbols in imports.items()
    ]
    export_names = [b"run", *([b"extra"] if extra_export else [])]
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(16)]
    if resource_directory:
        directories[2] = SimpleNamespace(VirtualAddress=0x60000, Size=16)
    if security_directory:
        directories[4] = SimpleNamespace(
            VirtualAddress=sample_size - 64,
            Size=64,
        )
    if clr_directory:
        directories[14] = SimpleNamespace(VirtualAddress=0x61000, Size=72)

    image = SimpleNamespace(
        sections=sections,
        FILE_HEADER=SimpleNamespace(
            Machine=machine,
            Characteristics=0x210E if dll else 0x010E,
            NumberOfSections=len(sections),
        ),
        OPTIONAL_HEADER=SimpleNamespace(
            Magic=0x10B,
            ImageBase=_IMAGE_BASE,
            AddressOfEntryPoint=_CODE_RVA,
            Subsystem=subsystem,
            SizeOfHeaders=_TEXT_RAW,
            SizeOfImage=0x60000,
            DATA_DIRECTORY=directories,
        ),
        DIRECTORY_ENTRY_IMPORT=import_descriptors,
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(
            symbols=[
                SimpleNamespace(name=name, address=_CODE_RVA, ordinal=index + 1)
                for index, name in enumerate(export_names)
            ]
        ),
        get_overlay_data_start_offset=(
            (lambda: sample_size - 32) if overlay else (lambda: None)
        ),
        get_offset_from_rva=_mapped_offset,
        get_rva_from_offset=_mapped_rva,
        get_data=lambda rva, size: bytes(
            data[_mapped_offset(rva) : _mapped_offset(rva) + size]
        ),
        parse_data_directories=lambda *args, **kwargs: None,
        close=lambda: None,
    )
    if resource_directory:
        image.DIRECTORY_ENTRY_RESOURCE = SimpleNamespace(entries=[])

    sample = bytes(data)

    def fake_pe(*, data: bytes, fast_load: bool) -> SimpleNamespace:
        assert data == sample
        assert fast_load is False
        return image

    monkeypatch.setattr(extractor.pefile, "PE", fake_pe)
    return sample


def test_probe_recovers_three_fixed_width_records_and_excludes_loopback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同一primary 2件とloopback placeholder 1件を一意に復元する。"""

    sample = _fixture(monkeypatch)
    probe = extractor.probe_run_dll_native_core_config(sample)

    assert probe["matched"] is True
    assert probe["variant"] == "run_dll_native_core_static_triplet_candidate"
    assert probe["supports_family_attribution"] is False
    assert probe["static_config_recovered"] is True
    assert probe["candidate_config_recovered"] is True
    assert probe["terminal_family_confirmed"] is False
    assert probe["attribution_scope"] == "component_handler_route"
    assert probe["endpoints"] == [f"{_PRIMARY_HOST}:441"]
    assert probe["excluded_placeholder_defaults"] == [f"{_FALLBACK_HOST}:80"]
    assert probe["slots"] == [
        {
            "slot": 1,
            "host": _PRIMARY_HOST,
            "port": 441,
            "transport_selector": 1,
            "transport": "tcp",
            "role": "primary",
        },
        {
            "slot": 2,
            "host": _PRIMARY_HOST,
            "port": 441,
            "transport_selector": 1,
            "transport": "tcp",
            "role": "primary",
        },
        {
            "slot": 3,
            "host": _FALLBACK_HOST,
            "port": 80,
            "transport_selector": 1,
            "transport": "tcp",
            "role": "loopback_placeholder",
        },
    ]
    evidence = probe["evidence"]
    assert evidence["configuration_record_count"] == 3
    assert evidence["unique_configuration_count"] == 1
    assert evidence["validated_code_reference_target_count"] == 9
    assert evidence["validated_code_reference_count"] == 9
    assert evidence["raw_config_included"] is False


def test_extract_projects_route_only_config_and_confirmed_static_finding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """共通入口は外部primaryだけを候補artifactへ投影し、family確定しない。"""

    sample = _fixture(monkeypatch)
    result = extractor.extract(sample, r"C:\private\run-core.dll")
    config = result["config"]

    assert config["variant"] == "run_dll_native_core_static_triplet_candidate"
    assert config["decoded_config_recovered"] is False
    assert config["static_config_recovered"] is True
    assert config["candidate_config_recovered"] is True
    assert config["terminal_family_confirmed"] is False
    assert config["attribution_scope"] == "component_handler_route"
    assert config["endpoints"] == [f"{_PRIMARY_HOST}:441"]
    assert config["excluded_placeholder_defaults"] == [f"{_FALLBACK_HOST}:80"]
    assert config["source_name"] == "run-core.dll"
    assert result["findings"] == [
        {
            "kind": "network.endpoint",
            "value": f"{_PRIMARY_HOST}:441",
            "role": "static_config_c2",
            "confidence": "confirmed_static_config",
            "source": "validated_run_export_static_config",
        }
    ]
    assert result["executed"] is False
    assert result["network_contacted"] is False


@pytest.mark.parametrize("primary_port", [7, 80, 441])
def test_probe_reads_short_ports_from_fixed_width_fields(
    monkeypatch: pytest.MonkeyPatch,
    primary_port: int,
) -> None:
    """一般文字列抽出の4文字下限に依存せず1～3桁portを復元する。"""

    sample = _fixture(
        monkeypatch,
        primary_port=primary_port,
        duplicate_port=primary_port,
    )

    probe = extractor.probe_run_dll_native_core_config(sample)

    assert probe["matched"] is True
    assert probe["endpoints"] == [f"{_PRIMARY_HOST}:{primary_port}"]
    assert [slot["port"] for slot in probe["slots"]] == [
        primary_port,
        primary_port,
        80,
    ]


@pytest.mark.parametrize("sample_size", [350 * 1024, 450 * 1024])
def test_probe_accepts_inclusive_profile_size_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    sample_size: int,
) -> None:
    """既知profileの350～450 KiB境界を包含範囲として扱う。"""

    sample = _fixture(monkeypatch, sample_size=sample_size)

    assert extractor.probe_run_dll_native_core_config(sample)["matched"] is True


def test_probe_accepts_virtual_only_fptable_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """実検体と同じzero-raw `.fptable` を他の厳格条件が揃う場合だけ許容する。"""

    sample = _fixture(monkeypatch, zero_raw_section=".fptable")

    probe = extractor.probe_run_dll_native_core_config(sample)

    assert probe["matched"] is True
    assert probe["variant"] == "run_dll_native_core_static_triplet_candidate"
    assert probe["evidence"]["validated_code_reference_target_count"] == 9


@pytest.mark.parametrize("section_name", [".text", ".rdata", ".data", ".reloc"])
def test_probe_rejects_zero_raw_non_fptable_section(
    monkeypatch: pytest.MonkeyPatch,
    section_name: str,
) -> None:
    """`.fptable` 以外の必須sectionが空ならroute候補へ昇格しない。"""

    sample = _fixture(monkeypatch, zero_raw_section=section_name)

    probe = extractor.probe_run_dll_native_core_config(sample)

    assert probe["matched"] is False
    assert probe["evidence"]["status"] == "section_contract_rejected"


@pytest.mark.parametrize("sample_size", [350 * 1024 - 1, 450 * 1024 + 1])
def test_probe_rejects_values_outside_profile_size_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    sample_size: int,
) -> None:
    """既知profileのsize範囲から1 byteでも外れたPEを拒否する。"""

    sample = _fixture(monkeypatch, sample_size=sample_size)

    assert extractor.probe_run_dll_native_core_config(sample)["matched"] is False


@pytest.mark.parametrize(
    ("fixture_changes", "reason"),
    [
        ({"duplicate_host": "45.67.89.124"}, "primary host duplicate mismatch"),
        ({"duplicate_port": 442}, "primary port duplicate mismatch"),
        ({"fallback_host": "127.0.0.2"}, "fallback host mismatch"),
        ({"fallback_port": 81}, "fallback port mismatch"),
        ({"selectors": (1, 0, 1)}, "primary selector duplicate mismatch"),
        ({"selectors": (1, 1, 2)}, "unsupported selector"),
        ({"missing_reference": 0}, "first host reference missing"),
        ({"missing_reference": 4}, "second port reference missing"),
        ({"missing_reference": 8}, "fallback selector reference missing"),
        ({"references_in_data": True}, "references outside executable section"),
        ({"extra_library": True}, "unexpected import library"),
        ({"missing_api": "BCryptOpenAlgorithmProvider"}, "crypto API missing"),
        ({"missing_api": "CreateRemoteThread"}, "injection API missing"),
        ({"missing_api": "connect"}, "network API missing"),
        ({"extra_export": True}, "unexpected export"),
        ({"overlay": True}, "overlay present"),
        ({"security_directory": True}, "security directory present"),
        ({"resource_directory": True}, "resource directory present"),
        ({"clr_directory": True}, "CLR directory present"),
        (
            {"section_names": (".text", ".data", ".rdata", ".fptable", ".reloc")},
            "section sequence mismatch",
        ),
        ({"machine": 0x8664}, "non-x86 machine"),
        ({"dll": False}, "not a DLL"),
        ({"subsystem": 3}, "non-GUI subsystem"),
    ],
)
def test_probe_rejects_tampered_profile_or_record_contract(
    monkeypatch: pytest.MonkeyPatch,
    fixture_changes: dict[str, object],
    reason: str,
) -> None:
    """profile、三重record、code referenceの部分一致をfail-closedで拒否する。"""

    del reason
    sample = _fixture(monkeypatch, **fixture_changes)

    probe = extractor.probe_run_dll_native_core_config(sample)

    assert probe["matched"] is False


@pytest.mark.parametrize("invalid_port", [0, 65536])
def test_probe_rejects_out_of_range_primary_port(
    monkeypatch: pytest.MonkeyPatch,
    invalid_port: int,
) -> None:
    """固定幅field内でもport範囲外は設定候補へ昇格しない。"""

    sample = _fixture(
        monkeypatch,
        primary_port=invalid_port,
        duplicate_port=invalid_port,
    )

    assert extractor.probe_run_dll_native_core_config(sample)["matched"] is False


def test_probe_rejects_nonzero_padding_after_short_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """短いport文字列のNUL以降に別値がある曖昧なfieldを拒否する。"""

    sample = _fixture(monkeypatch, nonzero_port_padding=True)

    assert extractor.probe_run_dll_native_core_config(sample)["matched"] is False
