"""Winos plaintext pipe設定とsource-to-network gateを合成PEで検証する。"""

from __future__ import annotations

import os
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from extractors.valleyrat import wide_pipe_config as WIDE
from extractors.valleyrat.extractor import _extract_wide_pipe_config

_BASE = 0x400000
_TEXT = 0x401000
_RDATA = 0x404000
_DATA = 0x405000
_TEXT_RAW = 0x200
_RDATA_RAW = 0x2600
_DATA_RAW = 0x3000

_ROOT = _TEXT
_PARSER = _TEXT + 0x100
_PARSE_FIELD = _TEXT + 0x380
_WORKER = _TEXT + 0x400
_SOCKET_CTOR = _TEXT + 0x600
_CONNECT = _TEXT + 0x700
_THREAD_WRAPPER = _TEXT + 0x850
_RECV_CALLBACK = _TEXT + 0x900
_RECV_PARSER = _TEXT + 0xA00
_SEND = _TEXT + 0xB00
_XOR = _TEXT + 0xC00
_SEND_SINK = _TEXT + 0xD00
_RECV_WAIT = _TEXT + 0xE00
_MANAGER_CTOR = _TEXT + 0xF00
_HANDLER = _TEXT + 0x1000
_WORKER_ALT = _TEXT + 0x1200
_SOCKET_CTOR_ALT = _TEXT + 0x1300
_CONNECT_ALT = _TEXT + 0x1380
_SEND_ALT = _TEXT + 0x13A0
_MANAGER_CTOR_ALT = _TEXT + 0x13C0
_XOR_ALT = _TEXT + 0x1600
_SEND_SINK_ALT = _TEXT + 0x1700
_SOCKET_VTABLE = _RDATA + 0x300
_MANAGER_VTABLE = _RDATA + 0x340
_SOCKET_VTABLE_ALT = _RDATA + 0x380
_IAT = _RDATA + 0x700

_CONFIG = (
    "|p1:198.51.100.24|o1:443|t1:1"
    "|p2:backup.example|o2:8443|t2:1"
    "|p3:127.0.0.1|o3:80|t3:1"
    "|dd:1|cl:1|fz:测试"
    "|bb:1.0|bz:2026. 9. 11|jp:0|bh:0|ll:0|dl:1|sh:1|kl:1|bd:0|"
)


def _call(source: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target - (source + 5))


def _iat(address: int) -> bytes:
    return b"\xff\x15" + struct.pack("<I", address)


def _push(value: int) -> bytes:
    return b"\x68" + struct.pack("<I", value)


def _thread_call(source: int, callback: int, target: int, *, imported: bool) -> bytes:
    code = b"\x6a\x00\x6a\x00\x6a\x00" + _push(callback) + b"\x6a\x00\x6a\x00"
    return code + (_iat(target) if imported else _call(source + len(code), target))


def _fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    config: str = _CONFIG,
    conflicting_config: str | None = None,
    remove_import: str | None = None,
    reference_all_runtime_fields: bool = True,
    frame_xor_constant: int = 0x1C8,
    dispatcher_marker: int = 0xC9,
    data_executable: bool = False,
    split_worker_evidence: bool = False,
    split_socket_table_evidence: bool = False,
) -> bytes:
    data = bytearray(b"\0" * 0x4800)
    data[:2] = b"MZ"
    data[_TEXT_RAW:_RDATA_RAW] = b"\xcc" * (_RDATA_RAW - _TEXT_RAW)

    def raw_offset(address: int) -> int:
        if _TEXT <= address < _TEXT + (_RDATA_RAW - _TEXT_RAW):
            return _TEXT_RAW + address - _TEXT
        if _RDATA <= address < _RDATA + (_DATA_RAW - _RDATA_RAW):
            return _RDATA_RAW + address - _RDATA
        if _DATA <= address < _DATA + 0x1800:
            return _DATA_RAW + address - _DATA
        raise AssertionError(f"fixture address outside sections: {address:#x}")

    def put(address: int, value: bytes) -> None:
        offset = raw_offset(address)
        data[offset : offset + len(value)] = value

    fields = dict(
        segment.split(":", 1) for segment in config.split("|") if ":" in segment
    )
    config_address = _DATA + 0x100
    put(config_address, config.encode("utf-16le") + b"\0\0")
    if conflicting_config is not None:
        put(_DATA + 0x400, conflicting_config.encode("utf-16le") + b"\0\0")

    source_addresses: list[int] = []
    source_cursor = _DATA + 0x900
    for index in (1, 2, 3):
        for prefix in ("p", "o"):
            value = fields[f"{prefix}{index}"]
            encoded = value.encode("utf-16le") + b"\0\0"
            put(source_cursor, encoded)
            source_addresses.append(source_cursor)
            source_cursor += len(encoded) + (len(encoded) % 4) + 4

    tag_addresses: dict[str, int] = {}
    tag_cursor = _RDATA
    for key in (
        key
        for key, _value in (
            item.split(":", 1) for item in config.split("|") if ":" in item
        )
    ):
        encoded = f"{key}:".encode("utf-16le") + b"\0\0"
        tag_addresses[key] = tag_cursor
        put(tag_cursor, encoded)
        tag_cursor += 8

    parser = bytearray()
    for key in tag_addresses:
        parser += _push(config_address)
        parser += _push(tag_addresses[key])
        parser += _call(_PARSER + len(parser), _PARSE_FIELD)
    parser += b"\xc3"
    put(_PARSER, parser)
    put(_PARSE_FIELD, b"\xc3")

    root = _call(_ROOT, _PARSER)
    root += _thread_call(_ROOT + len(root), _WORKER, _IAT, imported=True)
    if split_worker_evidence:
        root += _thread_call(
            _ROOT + len(root),
            _WORKER_ALT,
            _IAT,
            imported=True,
        )
    root += b"\xc3"
    put(_ROOT, root)

    def worker_code(
        address: int,
        socket_ctor: int,
        manager_ctor: int,
        extra_socket_ctor: int | None = None,
    ) -> bytes:
        worker = bytearray()
        for index, source_address in enumerate(source_addresses):
            worker += _push(
                source_address
                if reference_all_runtime_fields or index
                else _DATA + 0x40
            )
        worker += b"\x83\xc4\x18"
        worker += _call(address + len(worker), socket_ctor)
        if extra_socket_ctor is not None:
            worker += _call(address + len(worker), extra_socket_ctor)
        worker += _call(address + len(worker), manager_ctor)
        worker += b"\x8b\x06\x8b\x50\x10\xff\xd2"
        worker += b"\x8b\x06\x8b\x50\x08"
        worker += b"\x66\xc7\x45\xf0\x04\x00\x6a\x02\x8d\x45\xf0\x50\xff\xd2"
        worker += b"\x8b\x06\x8b\x50\x14\xff\xd2\xc3"
        return bytes(worker)

    put(
        _WORKER,
        worker_code(
            _WORKER,
            _SOCKET_CTOR,
            _MANAGER_CTOR_ALT if split_worker_evidence else _MANAGER_CTOR,
            _SOCKET_CTOR_ALT if split_socket_table_evidence else None,
        ),
    )
    if split_worker_evidence:
        put(
            _WORKER_ALT,
            worker_code(_WORKER_ALT, _SOCKET_CTOR_ALT, _MANAGER_CTOR),
        )

    put(
        _SOCKET_CTOR,
        _iat(_IAT + 4) + b"\xc7\x01" + struct.pack("<I", _SOCKET_VTABLE) + b"\xc3",
    )
    put(
        _SOCKET_CTOR_ALT,
        _iat(_IAT + 4) + b"\xc7\x01" + struct.pack("<I", _SOCKET_VTABLE_ALT) + b"\xc3",
    )
    put(_MANAGER_CTOR_ALT, b"\xc3")
    put(_CONNECT_ALT, b"\xc3")
    if split_socket_table_evidence:
        send_alt = b"\x8b\x44\x24\x08\x83\xc0\x0e\x6a\x04\x6a\x0a"
        send_alt += _call(_SEND_ALT + len(send_alt), _XOR_ALT)
        send_alt += _call(_SEND_ALT + len(send_alt), _SEND_SINK_ALT) + b"\xc3"
        put(_SEND_ALT, send_alt)
        put(
            _XOR_ALT,
            b"\xbb\xc8\x01\x00\x00\x80\xc2\x36\x30\x16\xc3",
        )
        put(_SEND_SINK_ALT, b"\xff\x71\x68" + _iat(_IAT + 28) + b"\xc3")
    else:
        put(_SEND_ALT, b"\xc3")

    connect = bytearray(_iat(_IAT + 8) + b"\x89\x41\x64")
    connect += _iat(_IAT + 12) + _iat(_IAT + 16)
    connect += b"\xff\x71\x64" + _iat(_IAT + 20)
    connect += _thread_call(
        _CONNECT + len(connect), _RECV_CALLBACK, _THREAD_WRAPPER, imported=False
    )
    connect += b"\xc3"
    put(_CONNECT, connect)
    put(
        _THREAD_WRAPPER,
        _thread_call(_THREAD_WRAPPER, _RECV_CALLBACK, _IAT, imported=True) + b"\xc3",
    )

    receive = b"\xff\x71\x64" + _iat(_IAT + 32)
    receive += _call(_RECV_CALLBACK + len(receive), _RECV_PARSER) + b"\xc3"
    put(_RECV_CALLBACK, receive)
    put(_RECV_PARSER, b"\x83\xf8\x0e\x6a\x0a\x6a\x04\xff\xd0\xc3")

    send = b"\x8b\x44\x24\x08\x83\xc0\x0e\x6a\x04\x6a\x0a"
    send += _call(_SEND + len(send), _XOR)
    send += _call(_SEND + len(send), _SEND_SINK) + b"\xc3"
    put(_SEND, send)
    put(
        _XOR,
        b"\xbb" + struct.pack("<I", frame_xor_constant) + b"\x80\xc2\x36\x30\x16\xc3",
    )
    put(_SEND_SINK, b"\xff\x71\x64" + _iat(_IAT + 28) + b"\xc3")
    put(_RECV_WAIT, b"\xc3")
    put(_MANAGER_CTOR, b"\xc7\x01" + struct.pack("<I", _MANAGER_VTABLE) + b"\xc3")

    handler = b"\x80\x38" + bytes([dispatcher_marker]) + b"\x83\xf9\x65\x6a\x40"
    handler += _iat(_IAT + 36) + _iat(_IAT + 40) + b"\xff\xd0\xc3"
    put(_HANDLER, handler)
    for index, target in enumerate(
        (_TEXT + 0x1100, _TEXT + 0x1120, _SEND, _TEXT + 0x1140, _CONNECT, _RECV_WAIT)
    ):
        put(_SOCKET_VTABLE + index * 4, struct.pack("<I", target))
        if target not in {_SEND, _CONNECT, _RECV_WAIT}:
            put(target, b"\xc3")
    put(_MANAGER_VTABLE, struct.pack("<II", _HANDLER, _TEXT + 0x1160))
    put(_TEXT + 0x1160, b"\xc3")
    alternate_connect = _CONNECT if split_socket_table_evidence else _CONNECT_ALT
    for index, target in enumerate(
        (
            _TEXT + 0x1500,
            _TEXT + 0x1520,
            _SEND_ALT,
            _TEXT + 0x1540,
            alternate_connect,
            _TEXT + 0x1560,
        )
    ):
        put(_SOCKET_VTABLE_ALT + index * 4, struct.pack("<I", target))
        if target not in {_SEND_ALT, alternate_connect}:
            put(target, b"\xc3")

    imports = [
        ("KERNEL32.dll", "CreateThread", _IAT),
        ("WS2_32.dll", "WSAStartup", _IAT + 4),
        ("WS2_32.dll", "socket", _IAT + 8),
        ("WS2_32.dll", "gethostbyname", _IAT + 12),
        ("WS2_32.dll", "ntohs", _IAT + 16),
        ("WS2_32.dll", "connect", _IAT + 20),
        ("WS2_32.dll", "send", _IAT + 28),
        ("WS2_32.dll", "recv", _IAT + 32),
        ("KERNEL32.dll", "VirtualAlloc", _IAT + 36),
        ("ADVAPI32.dll", "RegSetValueExW", _IAT + 40),
    ]
    grouped: dict[str, list[SimpleNamespace]] = {}
    for library, name, address in imports:
        if name.casefold() == (remove_import or "").casefold():
            continue
        grouped.setdefault(library, []).append(
            SimpleNamespace(name=name.encode("ascii"), address=address)
        )
    descriptors = [
        SimpleNamespace(dll=library.encode("ascii"), imports=items)
        for library, items in grouped.items()
    ]
    sections = [
        SimpleNamespace(
            Name=b".text\0\0\0",
            PointerToRawData=_TEXT_RAW,
            SizeOfRawData=_RDATA_RAW - _TEXT_RAW,
            Misc_VirtualSize=_RDATA_RAW - _TEXT_RAW,
            VirtualAddress=_TEXT - _BASE,
            Characteristics=0x60000020,
        ),
        SimpleNamespace(
            Name=b".rdata\0\0",
            PointerToRawData=_RDATA_RAW,
            SizeOfRawData=_DATA_RAW - _RDATA_RAW,
            Misc_VirtualSize=_DATA_RAW - _RDATA_RAW,
            VirtualAddress=_RDATA - _BASE,
            Characteristics=0x40000040,
        ),
        SimpleNamespace(
            Name=b".data\0\0\0",
            PointerToRawData=_DATA_RAW,
            SizeOfRawData=0x1800,
            Misc_VirtualSize=0x1800,
            VirtualAddress=_DATA - _BASE,
            Characteristics=(0xE0000040 if data_executable else 0xC0000040),
        ),
    ]
    image = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=_BASE),
        sections=sections,
        DIRECTORY_ENTRY_IMPORT=descriptors,
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(
            symbols=[SimpleNamespace(address=_ROOT - _BASE, forwarder=None)]
        ),
    )
    monkeypatch.setattr(WIDE.pefile, "PE", lambda **_kwargs: image)
    return bytes(data)


def test_strict_recovery_proves_family_config_and_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _fixture(monkeypatch)
    recovery = WIDE.recover_config(data)
    assert recovery is not None
    assert recovery.terminal_family_confirmed is True
    assert recovery.endpoints == ("198.51.100.24:443", "backup.example:8443")
    assert len(recovery.slots) == 3
    assert recovery.evidence["excluded_loopback_slot_count"] == 1
    lineage = recovery.evidence["lineage"]
    assert lineage["terminal_network_lineage_proven"] is True
    assert all(lineage["required_groups"].values())
    assert lineage["sample_executed"] is False
    assert lineage["network_contacted"] is False


def test_strict_recovery_is_independent_of_endpoint_build_and_export_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    alternate = (
        _CONFIG.replace("198.51.100.24", "203.0.113.88")
        .replace("backup.example", "edge.example.org")
        .replace("o1:443", "o1:9443")
        .replace("o2:8443", "o2:7443")
        .replace("bb:1.0", "bb:2.4")
        .replace("bz:2026. 9. 11", "bz:2030. 1. 2")
    )

    recovery = WIDE.recover_config(_fixture(monkeypatch, config=alternate))

    assert recovery is not None
    assert recovery.terminal_family_confirmed is True
    assert recovery.endpoints == ("203.0.113.88:9443", "edge.example.org:7443")
    assert all(recovery.evidence["lineage"]["required_groups"].values())


def test_probe_redacts_network_values_and_confirms_only_complete_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    data = _fixture(monkeypatch)
    probe = WIDE.probe_config(data)
    assert probe["family"] == "valleyrat"
    assert probe["variant"] == "winos_plaintext_pipe_bootstrap_terminal"
    assert probe["static_config_recovered"] is True
    rendered = repr(probe)
    assert "198.51.100.24" not in rendered
    assert "backup.example" not in rendered
    assert "configuration_identity_sha256" not in rendered


def test_extractor_result_exposes_config_only_with_explicit_attribution_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _extract_wide_pipe_config(_fixture(monkeypatch), "unknown.dll")

    assert result is not None
    assert result["family"] == "valleyrat"
    config = result["config"]
    assert config["variant"] == "winos_plaintext_pipe_bootstrap_terminal"
    assert config["decoded_config_recovered"] is True
    assert config["static_config_recovered"] is True
    assert config["candidate_config_recovered"] is False
    assert config["terminal_family_confirmed"] is True
    assert len(config["endpoints"]) == 2
    assert len(config["slots"]) == 2
    assert config["wide_pipe_config"]["raw_network_values_included"] is False
    assert result["executed"] is False
    assert result["network_contacted"] is False


def test_extractor_incomplete_lineage_is_candidate_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _extract_wide_pipe_config(
        _fixture(monkeypatch, remove_import="recv"), "unknown.dll"
    )

    assert result is not None
    config = result["config"]
    assert config["variant"] == "winos_plaintext_pipe_config_candidate"
    assert config["decoded_config_recovered"] is True
    assert config["static_config_recovered"] is False
    assert config["candidate_config_recovered"] is True
    assert config["terminal_family_confirmed"] is False


@pytest.mark.parametrize("missing", ["recv", "send", "connect", "WSAStartup"])
def test_missing_network_import_keeps_candidate_but_rejects_family(
    monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    recovery = WIDE.recover_config(_fixture(monkeypatch, remove_import=missing))
    assert recovery is not None
    assert recovery.terminal_family_confirmed is False
    probe = WIDE.probe_config(_fixture(monkeypatch, remove_import=missing))
    assert probe["family"] is None
    assert probe["candidate_config_recovered"] is True


def test_runtime_global_reference_is_required(monkeypatch: pytest.MonkeyPatch) -> None:
    recovery = WIDE.recover_config(
        _fixture(monkeypatch, reference_all_runtime_fields=False)
    )
    assert recovery is not None
    assert recovery.terminal_family_confirmed is False
    assert (
        recovery.evidence["lineage"]["required_groups"][
            "runtime_endpoint_globals_referenced"
        ]
        is False
    )


def test_cross_worker_and_socket_table_evidence_is_never_combined(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """socket証拠とmanager証拠が別workerなら終端lineageへ昇格しない。"""

    data = _fixture(monkeypatch, split_worker_evidence=True)
    recovery = WIDE.recover_config(data)

    assert recovery is not None
    assert recovery.terminal_family_confirmed is False
    lineage = recovery.evidence["lineage"]
    assert lineage["terminal_network_lineage_proven"] is False
    assert lineage["coverage"]["launcher_worker_candidate_count"] == 2
    assert lineage["coverage"]["analyzed_launcher_worker_branch_count"] == 2
    assert lineage["coverage"]["evaluated_socket_table_branch_count"] == 2
    assert lineage["coverage"]["evaluated_manager_table_branch_count"] == 1
    assert lineage["coverage"]["complete_launcher_worker_branch_count"] == 0
    assert lineage["coverage"]["proof_combined_across_branches"] is False
    assert not all(lineage["required_groups"].values())
    assert lineage["required_groups"]["tcp_connect_send_receive_chain"] is True
    assert lineage["required_groups"]["same_socket_field_connect_send_receive"] is True
    assert lineage["required_groups"]["winos_framing_and_xor"] is True
    assert lineage["required_groups"]["winos_receive_dispatcher"] is False
    probe = WIDE.probe_config(data)
    assert probe["family"] is None
    assert probe["terminal_family_confirmed"] is False
    assert probe["static_config_recovered"] is False
    assert probe["candidate_config_recovered"] is True


def test_connect_socket_identity_and_framing_must_share_one_socket_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同一workerでもsocket identityとframingが別tableなら確定しない。"""

    data = _fixture(
        monkeypatch,
        frame_xor_constant=0x1C7,
        split_socket_table_evidence=True,
    )
    recovery = WIDE.recover_config(data)

    assert recovery is not None
    assert recovery.terminal_family_confirmed is False
    lineage = recovery.evidence["lineage"]
    assert lineage["terminal_network_lineage_proven"] is False
    assert lineage["coverage"]["launcher_worker_candidate_count"] == 1
    assert lineage["coverage"]["evaluated_socket_table_branch_count"] == 2
    assert lineage["coverage"]["complete_launcher_worker_branch_count"] == 0
    assert lineage["coverage"]["proof_combined_across_branches"] is False
    required = lineage["required_groups"]
    assert required["tcp_connect_send_receive_chain"] is True
    assert (
        sum(
            required[key]
            for key in (
                "same_socket_field_connect_send_receive",
                "winos_framing_and_xor",
            )
        )
        == 1
    )
    probe = WIDE.probe_config(data)
    assert probe["family"] is None
    assert probe["static_config_recovered"] is False
    assert probe["candidate_config_recovered"] is True


def test_frame_transform_is_family_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    recovery = WIDE.recover_config(_fixture(monkeypatch, frame_xor_constant=0x1C7))
    assert recovery is not None
    assert recovery.terminal_family_confirmed is False
    assert (
        recovery.evidence["lineage"]["required_groups"]["winos_framing_and_xor"]
        is False
    )


def test_dispatcher_marker_is_family_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    recovery = WIDE.recover_config(_fixture(monkeypatch, dispatcher_marker=0xC8))
    assert recovery is not None
    assert recovery.terminal_family_confirmed is False
    assert (
        recovery.evidence["lineage"]["required_groups"]["winos_receive_dispatcher"]
        is False
    )


def test_conflicting_configuration_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    conflict = _CONFIG.replace("198.51.100.24", "203.0.113.77")
    assert (
        WIDE.recover_config(_fixture(monkeypatch, conflicting_config=conflict)) is None
    )


def test_half_empty_slot_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    malformed = _CONFIG.replace("|p2:backup.example|o2:8443|", "|p2:|o2:8443|")
    assert WIDE.recover_config(_fixture(monkeypatch, config=malformed)) is None


def test_executable_section_config_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    assert WIDE.recover_config(_fixture(monkeypatch, data_executable=True)) is None


def test_non_pe_and_size_limit_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _fixture(monkeypatch)
    assert WIDE.recover_config(b"not-a-pe") is None
    assert WIDE.recover_config(b"MZ" + b"\0" * WIDE.MAXIMUM_INPUT_SIZE) is None


_PRIVATE_WIDE_PIPE_SAMPLE = "VALLEYRAT_WIDE_PIPE_TEST_IMAGE"


@pytest.mark.skipif(
    not os.environ.get(_PRIVATE_WIDE_PIPE_SAMPLE),
    reason="repo外のValleyRAT wide-pipe実検体が未指定です",
)
def test_private_real_wide_pipe_sample_remains_terminal_positive() -> None:
    """実検体を実行・通信せず、閉じた単一branchで終端確定を回帰する。"""

    sample = Path(os.environ[_PRIVATE_WIDE_PIPE_SAMPLE]).read_bytes()
    recovery = WIDE.recover_config(sample)

    assert recovery is not None
    assert recovery.terminal_family_confirmed is True
    assert len(recovery.endpoints) >= 1
    lineage = recovery.evidence["lineage"]
    assert lineage["terminal_network_lineage_proven"] is True
    assert lineage["coverage"]["complete_launcher_worker_branch_count"] == 1
    assert lineage["coverage"]["proof_combined_across_branches"] is False
    assert all(lineage["required_groups"].values())
    assert lineage["sample_executed"] is False
    assert lineage["network_contacted"] is False
