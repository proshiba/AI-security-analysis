"""run export型native terminal lineageを合成命令列で検証する。"""

from __future__ import annotations

import struct
from types import SimpleNamespace

import pytest

from extractors.valleyrat import run_dll_native_terminal as terminal

_BASE = 0x10000000
_TEXT_VA = _BASE + 0x1000
_TEXT_RAW = 0x400
_TEXT_SIZE = 0x5000
_DATA_VA = _BASE + 0x7000
_DATA_RAW = 0x6000
_DATA_SIZE = 0x2000


class _Builder:
    """外部assemblerを使わず必要最小限のx86命令を配置する。"""

    def __init__(self) -> None:
        self.data = bytearray(0x8000)
        self.data[:2] = b"MZ"

    def write(self, address: int, value: bytes) -> None:
        offset = _TEXT_RAW + address - _TEXT_VA
        self.data[offset : offset + len(value)] = value

    def function(self, address: int, body: bytes) -> None:
        self.write(address, body + b"\xc3\xcc\xcc")

    def data_u32(self, address: int, values: tuple[int, ...]) -> None:
        offset = _DATA_RAW + address - _DATA_VA
        struct.pack_into("<" + "I" * len(values), self.data, offset, *values)


def _push(value: int) -> bytes:
    return b"\x68" + struct.pack("<I", value & 0xFFFFFFFF)


def _call(source: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target - (source + 5))


def _call_iat(address: int) -> bytes:
    return b"\xff\x15" + struct.pack("<I", address)


def _mov_ecx_abs(address: int) -> bytes:
    return b"\x8b\x0d" + struct.pack("<I", address)


def _mov_abs_ecx(address: int) -> bytes:
    return b"\x89\x0d" + struct.pack("<I", address)


def _relative_body(start: int, parts: list[bytes | tuple[str, int]]) -> bytes:
    """現在位置に応じたrelative callを解決する。"""

    result = bytearray()
    for part in parts:
        if isinstance(part, bytes):
            result.extend(part)
        else:
            kind, target = part
            assert kind == "call"
            result.extend(_call(start + len(result), target))
    return bytes(result)


def _fixture(
    *,
    marker: int = 0xCA,
    send_socket_displacement: int = 0x64,
    command_bound: int = 0xCA,
    registration_command: int = 6,
) -> tuple[bytes, object, int, tuple[object, ...], tuple[int, int, int]]:
    builder = _Builder()
    addresses = {
        "run": _TEXT_VA + 0x000,
        "main": _TEXT_VA + 0x100,
        "copy": _TEXT_VA + 0x600,
        "port_parser": _TEXT_VA + 0x620,
        "constructor": _TEXT_VA + 0x700,
        "close": _TEXT_VA + 0x800,
        "status": _TEXT_VA + 0x820,
        "send": _TEXT_VA + 0x900,
        "setter": _TEXT_VA + 0xA00,
        "connect": _TEXT_VA + 0xB00,
        "wait": _TEXT_VA + 0xC00,
        "receive": _TEXT_VA + 0xD00,
        "keepalive": _TEXT_VA + 0xE00,
        "frame": _TEXT_VA + 0xF00,
        "dispatcher": _TEXT_VA + 0x1100,
        "registration": _TEXT_VA + 0x1300,
    }
    iat_names = (
        "CreateThread",
        "WSAStartup",
        "socket",
        "gethostbyname",
        "htons",
        "connect",
        "send",
        "recv",
        "CreateToolhelp32Snapshot",
        "CreateFileW",
        "RegSetValueExW",
        "ClearEventLogW",
        "gethostname",
        "GetSystemInfo",
        "GlobalMemoryStatusEx",
        "GetDriveTypeW",
    )
    iat = {name: _DATA_VA + 0x100 + index * 4 for index, name in enumerate(iat_names)}
    source_addresses = tuple(_DATA_VA + 0x400 + index * 0x80 for index in range(9))
    host_destination = _DATA_VA + 0x900
    port_destination = _DATA_VA + 0xA00
    selector_destination = _DATA_VA + 0xA80
    transport_global = _DATA_VA + 0xA84
    vtable = _DATA_VA + 0xB00
    derived_vtable = _DATA_VA + 0xB40
    jump_table = _DATA_VA + 0xB80

    run_body = b"".join(
        (
            _push(0),
            _push(0),
            _push(0),
            _push(addresses["main"]),
            _push(0),
            _push(0),
            _call_iat(iat["CreateThread"]),
        )
    )
    builder.function(addresses["run"], run_body)

    main_parts: list[bytes | tuple[str, int]] = []
    for index in range(3):
        main_parts.extend(
            (
                _push(source_addresses[index * 3]),
                _push(0xFF),
                _push(host_destination),
                ("call", addresses["copy"]),
                _push(source_addresses[index * 3 + 1]),
                _push(0x1E),
                _push(port_destination),
                ("call", addresses["copy"]),
                _mov_ecx_abs(source_addresses[index * 3 + 2]),
                _mov_abs_ecx(selector_destination),
            )
        )
    main_parts.extend(
        (
            ("call", addresses["constructor"]),
            b"\x89\xc6",  # mov esi,eax
            _mov_ecx_abs(selector_destination),
            b"\x83\xf9\x01",  # cmp ecx,1
            b"\x31\xc0",  # xor eax,eax
            b"\x0f\x44\xc6",  # cmove eax,esi
            b"\xa3" + struct.pack("<I", transport_global),
            _push(port_destination),
            ("call", addresses["port_parser"]),
            _mov_ecx_abs(transport_global),
            b"\x50",  # push eax: parsed port
            b"\x8b\x11",  # mov edx,[ecx]
            b"\x8b\x42\x10",  # mov eax,[edx+0x10]
            _push(host_destination),
            b"\xff\xd0",  # call eax
            _mov_ecx_abs(transport_global),
            b"\x8b\x11\x8d\x45\xe0\x50\xff\x52\x0c",
            b"\xc7\x45\xe0" + struct.pack("<I", derived_vtable),
            ("call", addresses["registration"]),
        )
    )
    builder.function(addresses["main"], _relative_body(addresses["main"], main_parts))
    builder.function(addresses["copy"], b"\x31\xc0")
    builder.function(addresses["port_parser"], b"\x31\xc0")

    constructor = b"\xc7\x06" + struct.pack("<I", vtable) + _call_iat(iat["WSAStartup"])
    builder.function(addresses["constructor"], constructor)
    for name in ("close", "status", "wait"):
        builder.function(addresses[name], b"\x31\xc0")
    builder.data_u32(
        vtable,
        (
            addresses["close"],
            addresses["status"],
            addresses["send"],
            addresses["setter"],
            addresses["connect"],
            addresses["wait"],
        ),
    )

    connect_body = b"".join(
        (
            b"\x66\xc7\x43\x28" + struct.pack("<H", marker),
            _push(6),
            _push(1),
            _push(2),
            _call_iat(iat["socket"]),
            b"\x89\x43\x64",
            b"\x57",
            _call_iat(iat["gethostbyname"]),
            b"\xff\x75\x0c",
            _call_iat(iat["htons"]),
            _push(0x10),
            b"\x8d\x45\xe0\x50",
            b"\xff\x73\x64",
            _call_iat(iat["connect"]),
            _push(addresses["receive"]),
            _push(addresses["keepalive"]),
        )
    )
    builder.function(addresses["connect"], connect_body)

    send_body = b"".join(
        (
            b"\x83\xc0\x0e\x83\xc0\x0a",
            b"\x8b\x43\x28\x8b\x43\x20",
            _push(0),
            _push(0x20),
            b"\x50",
            b"\xff\xb3" + struct.pack("<I", send_socket_displacement),
            _call_iat(iat["send"]),
        )
    )
    builder.function(addresses["send"], send_body)
    builder.function(
        addresses["setter"],
        b"\x55\x89\xe5\x8b\x45\x08\x89\x41\x1c\x5d\xc2\x04\x00",
    )
    receive_body = _relative_body(
        addresses["receive"],
        [
            _push(0),
            _push(0x100),
            b"\x8d\x45\xe0\x50",
            b"\xff\x73\x64",
            _call_iat(iat["recv"]),
            ("call", addresses["frame"]),
        ],
    )
    builder.function(addresses["receive"], receive_body)
    builder.function(
        addresses["keepalive"],
        b"".join(
            (
                b"\xc6\x45\xff\xc9",
                _push(0xA),
                _push(0x3E8),
                _push(0xEA60),
                b"\x8b\x07\xff\x50\x08",
            )
        ),
    )
    builder.function(
        addresses["frame"],
        b"\x83\xf9\x0e\x8b\x43\x28\x8b\x4b\x1c\x8b\x01\xff\x10",
    )

    dispatcher_body = b"".join(
        (
            b"\x3d" + struct.pack("<I", command_bound),
            b"\xff\x24\x85" + struct.pack("<I", jump_table),
            *(
                _call_iat(iat[name])
                for name in (
                    "CreateToolhelp32Snapshot",
                    "CreateFileW",
                    "RegSetValueExW",
                    "ClearEventLogW",
                )
            ),
            b"\x8b\x01\xff\x50\x08",
        )
    )
    builder.function(addresses["dispatcher"], dispatcher_body)
    builder.data_u32(derived_vtable, (addresses["dispatcher"],))
    registration_body = b"".join(
        (
            _push(0x124A),
            b"\xc6\x07" + bytes((registration_command,)),
            *(
                _call_iat(iat[name])
                for name in (
                    "gethostname",
                    "GetSystemInfo",
                    "GlobalMemoryStatusEx",
                    "GetDriveTypeW",
                )
            ),
            b"\x8b\x01\xff\x50\x08",
        )
    )
    builder.function(addresses["registration"], registration_body)

    sections = [
        SimpleNamespace(
            PointerToRawData=_TEXT_RAW,
            SizeOfRawData=_TEXT_SIZE,
            VirtualAddress=0x1000,
            Characteristics=0x60000020,
        ),
        SimpleNamespace(
            PointerToRawData=_DATA_RAW,
            SizeOfRawData=_DATA_SIZE,
            VirtualAddress=0x7000,
            Characteristics=0xC0000040,
        ),
    ]
    image = SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=_BASE),
        sections=sections,
        DIRECTORY_ENTRY_IMPORT=[
            SimpleNamespace(
                imports=[
                    SimpleNamespace(name=name.encode("ascii"), address=iat[name])
                    for name in iat_names
                ]
            )
        ],
    )
    source_kinds = ("host", "port", "selector") * 3
    source_sizes = (510, 60, 4) * 3
    sources = tuple(
        SimpleNamespace(
            name=f"slot_{index}_{kind}", address=address, size=size, kind=kind
        )
        for index, (address, size, kind) in enumerate(
            zip(source_addresses, source_sizes, source_kinds, strict=True),
            start=1,
        )
    )
    return bytes(builder.data), image, addresses["run"], sources, (1, 1, 1)


def _analyze(
    fixture: tuple[bytes, object, int, tuple[object, ...], tuple[int, int, int]],
) -> dict[str, object]:
    data, image, run_export, sources, selectors = fixture
    return terminal.analyze_run_dll_terminal_lineage(
        data,
        image,
        run_export=run_export,
        sources=sources,
        selector_values=selectors,
    )


def test_complete_terminal_lineage_is_strictly_confirmed() -> None:
    result = _analyze(_fixture())

    assert result["terminal_family_lineage_proven"] is True
    assert all(result["proof"].values())
    assert result["missing_proof_codes"] == []
    assert result["protocol"] == {
        "transport": "tcp",
        "length_prefix_size": 4,
        "session_header_size": 10,
        "frame_header_size": 14,
        "marker": "uint16_0x00ca",
        "initial_registration_command": 6,
        "raw_frame_included": False,
    }


@pytest.mark.parametrize(
    ("changes", "missing_code"),
    (
        ({"marker": 0xCB}, "run_dll_same_socket_lineage_unproven"),
        ({"send_socket_displacement": 0x68}, "run_dll_same_socket_lineage_unproven"),
        ({"command_bound": 0xC8}, "run_dll_receive_dispatcher_unproven"),
        (
            {"registration_command": 7},
            "run_dll_initial_registration_serializer_unproven",
        ),
    ),
)
def test_mutated_terminal_links_fail_closed(
    changes: dict[str, int],
    missing_code: str,
) -> None:
    result = _analyze(_fixture(**changes))

    assert result["terminal_family_lineage_proven"] is False
    assert missing_code in result["missing_proof_codes"]


def test_non_tcp_selector_fails_closed() -> None:
    data, image, run_export, sources, _selectors = _fixture()
    result = terminal.analyze_run_dll_terminal_lineage(
        data,
        image,
        run_export=run_export,
        sources=sources,
        selector_values=(0, 0, 0),
    )

    assert result["terminal_family_lineage_proven"] is False
    assert "run_dll_selector_one_tcp_binding_unproven" in result["missing_proof_codes"]


def test_decode_instruction_cap_accepts_exact_boundary_and_rejects_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """上限ちょうどの自然終了だけを完全とし、1命令超過を記録する。"""

    monkeypatch.setattr(terminal, "MAXIMUM_INSTRUCTIONS", 4)
    section = terminal._Section(
        address=_TEXT_VA,
        raw_start=0,
        raw_end=4,
        executable=True,
    )
    exact_coverage = terminal._DecodeCoverage()
    exact = terminal._decode(
        b"\x90" * 4,
        (section,),
        _TEXT_VA,
        coverage=exact_coverage,
        maximum_bytes=4,
    )
    assert len(exact) == 4
    assert exact_coverage.complete is True

    overflow_section = terminal._Section(
        address=_TEXT_VA,
        raw_start=0,
        raw_end=5,
        executable=True,
    )
    overflow_coverage = terminal._DecodeCoverage()
    overflow = terminal._decode(
        b"\x90" * 5,
        (overflow_section,),
        _TEXT_VA,
        coverage=overflow_coverage,
        maximum_bytes=5,
    )
    assert len(overflow) == 4
    assert overflow_coverage.complete is False
    assert overflow_coverage.instruction_limit_exceeded_count == 1


def test_partial_decode_can_never_confirm_terminal_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """必要なmarkerが部分列にあっても命令切捨て時は証拠を全破棄する。"""

    monkeypatch.setattr(terminal, "MAXIMUM_INSTRUCTIONS", 1)
    result = _analyze(_fixture())

    assert result["status"] == "analysis_incomplete"
    assert result["analysis_complete"] is False
    assert result["terminal_family_lineage_proven"] is False
    assert not any(result["proof"].values())
    assert result["coverage"]["instruction_decode_complete"] is False
    assert result["coverage"]["instruction_decode_limit_exceeded_count"] == 1
    assert result["missing_proof_codes"] == [
        "run_dll_instruction_decode_limit_exceeded"
    ]


def test_input_and_source_bounds_are_rejected_before_pe_access() -> None:
    fixture = _fixture()
    _data, image, run_export, sources, selectors = fixture
    oversized = b"MZ" + b"\x00" * terminal.MAXIMUM_INPUT_SIZE

    result = terminal.analyze_run_dll_terminal_lineage(
        oversized,
        image,
        run_export=run_export,
        sources=sources,
        selector_values=selectors,
    )
    assert result["status"] == "invalid_input"

    invalid_sources = (
        *sources[:-1],
        SimpleNamespace(name="duplicate", address=-1, size=4, kind="selector"),
    )
    result = terminal.analyze_run_dll_terminal_lineage(
        fixture[0],
        image,
        run_export=run_export,
        sources=invalid_sources,
        selector_values=selectors,
    )
    assert result["status"] == "invalid_input"
    assert result["sample_executed"] is False
    assert result["network_contacted"] is False

    malformed_sources = (*sources[:-1], object())
    result = terminal.analyze_run_dll_terminal_lineage(
        fixture[0],
        image,
        run_export=run_export,
        sources=malformed_sources,
        selector_values=selectors,
    )
    assert result["status"] == "invalid_input"
    assert result["terminal_family_lineage_proven"] is False
