"""ValleyRAT反転設定とnative PE data-flow gateを合成fixtureで検証する。"""

from __future__ import annotations

import json
import struct
from types import SimpleNamespace

import pytest

from extractors.valleyrat import extractor

_IMAGE_BASE = 0x400000
_TEXT_VA = 0x401000
_DATA_VA = 0x402000
_RESOURCE_VA = 0x403000
_TEXT_RAW = 0x200
_DATA_RAW = 0x800
_RESOURCE_RAW = 0xC00
_CREATE_THREAD_IAT = _DATA_VA + 0x300
_WSA_STARTUP_IAT = _DATA_VA + 0x304
_SOCKET_IAT = _DATA_VA + 0x308
_CONNECT_IAT = _DATA_VA + 0x30C
_SEND_IAT = _DATA_VA + 0x310
_RECV_IAT = _DATA_VA + 0x314
_ENTRY = _TEXT_VA
_MAIN = _TEXT_VA + 0x20
_PARSER = _TEXT_VA + 0x80
_REVERSE = _TEXT_VA + 0xE0
_PARSE_FIELD = _TEXT_VA + 0x110
_WORKER = _TEXT_VA + 0x120
_CONSTRUCTOR = _TEXT_VA + 0x160
_SOCKET_METHOD = _TEXT_VA + 0x1A0
_SEND_METHOD = _TEXT_VA + 0x1C0
_RECV_METHOD = _TEXT_VA + 0x1E0
_PARSER_LAUNCHER = _TEXT_VA + 0x240
_NETWORK_LAUNCHER = _TEXT_VA + 0x280
_PARSER_BRANCH = _TEXT_VA + 0x2C0
_CALLBACK_BRANCH = _TEXT_VA + 0x300
_DISPATCH_BRANCH = _TEXT_VA + 0x340
_FANIN_ROOT = _TEXT_VA + 0x380
_FANIN_FIRST = _TEXT_VA + 0x400
_FANIN_SHARED = _TEXT_VA + 0x500
_VTABLE = _DATA_VA + 0x180
_DEFAULT_CONFIG = "|p1:198.51.100.24|o1:443|t1:1|p2:|o2:|t2:1|p3:|o3:|t3:0|fz:测试|"


def _relative_call(source: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target - (source + 5))


def _relative_jump(source: int, target: int) -> bytes:
    return b"\xe9" + struct.pack("<i", target - (source + 5))


def _indirect_call(address: int) -> bytes:
    return b"\xff\x15" + struct.pack("<I", address)


def _create_thread_call(start_address: int) -> bytes:
    """x86 stdcallの6引数からlpStartAddressを一意に復元できる形を作る。"""

    return (
        b"\x6a\x00"  # lpThreadId
        b"\x6a\x00"  # dwCreationFlags
        b"\x6a\x00"  # lpParameter
        + b"\x68"
        + struct.pack("<I", start_address)
        + b"\x6a\x00"  # dwStackSize
        b"\x6a\x00"  # lpThreadAttributes
        + _indirect_call(_CREATE_THREAD_IAT)
    )


def _utf16_reverse_loop() -> bytes:
    """NUL走査と16-bit両端交換を含む最小の内部reverse CFGを返す。"""

    code = bytearray(b"\x66\x8b\x01\x66\x85\xc0")
    code += b"\x75\xf8"
    swap_start = len(code)
    code += b"\x66\x8b\x16\x66\x89\x11\x66\x89\x06"
    code += b"\x83\xc1\x02\x83\xee\x02\x66\x83\x39\x00"
    branch = len(code)
    code += b"\x0f\x82" + struct.pack("<i", swap_start - (branch + 6))
    return bytes(code + b"\xc3")


def _fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    config: str = _DEFAULT_CONFIG,
    config_location: str = "data",
    reference_config: bool = True,
    parser_reachable: bool = True,
    network_reachable: bool = True,
    disjoint_network_callees: bool = False,
    conflicting_config: str | None = None,
) -> bytes:
    """実行せずにCapstone/pefile境界を通る最小native x86 PE viewを作る。"""

    data = bytearray(0x1400)
    data[:2] = b"MZ"

    def put_code(address: int, value: bytes) -> None:
        offset = _TEXT_RAW + address - _TEXT_VA
        data[offset : offset + len(value)] = value

    config_offsets = {
        "data": (_DATA_RAW + 0x20, _DATA_VA + 0x20),
        "resource": (_RESOURCE_RAW + 0x20, _RESOURCE_VA + 0x20),
        "overlay": (0x1020, 0x404020),
    }
    config_offset, config_address = config_offsets[config_location]
    stored = config[::-1].encode("utf-16le")
    data[config_offset : config_offset + len(stored)] = stored
    if conflicting_config is not None:
        conflict = conflicting_config[::-1].encode("utf-16le")
        data[0x1120 : 0x1120 + len(conflict)] = conflict

    put_code(_ENTRY, _relative_call(_ENTRY, _MAIN) + b"\xc3")
    parser_target = _PARSER if parser_reachable else _REVERSE
    main = _relative_call(_MAIN, parser_target)
    main += _create_thread_call(_WORKER) + b"\xc3"
    put_code(_MAIN, main)

    referenced_address = config_address if reference_config else _DATA_VA + 0x250
    parser = b"\x68" + struct.pack("<I", referenced_address)
    parser += _relative_call(_PARSER + len(parser), _REVERSE)
    for _index in range(3):
        parser += _relative_call(_PARSER + len(parser), _PARSE_FIELD)
    parser += b"\xc3"
    put_code(_PARSER, parser)
    put_code(_REVERSE, _utf16_reverse_loop())
    put_code(
        _PARSE_FIELD,
        b"\x68" + struct.pack("<I", referenced_address) + b"\xc3",
    )

    worker = (
        _relative_call(_WORKER, _CONSTRUCTOR) + b"\xc3"
        if network_reachable
        else b"\xc3"
    )
    put_code(_WORKER, worker)
    constructor = _indirect_call(_WSA_STARTUP_IAT)
    constructor += b"\xc7\x00" + struct.pack("<I", _VTABLE) + b"\xc3"
    put_code(_CONSTRUCTOR, constructor)
    socket_method = _indirect_call(_SOCKET_IAT) + _indirect_call(_CONNECT_IAT)
    if not disjoint_network_callees:
        socket_method += _relative_call(
            _SOCKET_METHOD + len(socket_method),
            _SEND_METHOD,
        )
    socket_method += b"\xc3"
    put_code(
        _SOCKET_METHOD,
        socket_method,
    )
    put_code(_SEND_METHOD, _indirect_call(_SEND_IAT) + b"\xc3")
    put_code(_RECV_METHOD, _indirect_call(_RECV_IAT) + b"\xc3")
    struct.pack_into(
        "<III",
        data,
        _DATA_RAW + _VTABLE - _DATA_VA,
        _SOCKET_METHOD,
        _SEND_METHOD,
        _RECV_METHOD,
    )

    sections = [
        SimpleNamespace(
            Name=b".text\0\0\0",
            VirtualAddress=_TEXT_VA - _IMAGE_BASE,
            Misc_VirtualSize=0x600,
            PointerToRawData=_TEXT_RAW,
            SizeOfRawData=0x600,
            Characteristics=0x60000020,
        ),
        SimpleNamespace(
            Name=b".data\0\0\0",
            VirtualAddress=_DATA_VA - _IMAGE_BASE,
            Misc_VirtualSize=0x400,
            PointerToRawData=_DATA_RAW,
            SizeOfRawData=0x400,
            Characteristics=0xC0000040,
        ),
        SimpleNamespace(
            Name=b".rsrc\0\0\0",
            VirtualAddress=_RESOURCE_VA - _IMAGE_BASE,
            Misc_VirtualSize=0x400,
            PointerToRawData=_RESOURCE_RAW,
            SizeOfRawData=0x400,
            Characteristics=0x40000040,
        ),
    ]
    ws2_imports = [
        (b"WSAStartup", _WSA_STARTUP_IAT),
        (b"socket", _SOCKET_IAT),
        (b"connect", _CONNECT_IAT),
        (b"send", _SEND_IAT),
        (b"recv", _RECV_IAT),
    ]
    imports = [
        SimpleNamespace(
            dll=b"KERNEL32.dll",
            imports=[SimpleNamespace(name=b"CreateThread", address=_CREATE_THREAD_IAT)],
        ),
        SimpleNamespace(
            dll=b"WS2_32.dll",
            imports=[
                SimpleNamespace(name=name, address=address)
                for name, address in ws2_imports
            ],
        ),
    ]
    image = SimpleNamespace(
        sections=sections,
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        OPTIONAL_HEADER=SimpleNamespace(
            ImageBase=_IMAGE_BASE,
            AddressOfEntryPoint=_ENTRY - _IMAGE_BASE,
            DATA_DIRECTORY=[
                SimpleNamespace(VirtualAddress=0, Size=0),
                SimpleNamespace(VirtualAddress=0, Size=0),
                SimpleNamespace(
                    VirtualAddress=_RESOURCE_VA - _IMAGE_BASE,
                    Size=0x400,
                ),
            ],
        ),
        DIRECTORY_ENTRY_IMPORT=imports,
    )

    def fake_pe(*, data: bytes, fast_load: bool) -> SimpleNamespace:
        assert data.startswith(b"MZ")
        assert fast_load is False
        return image

    monkeypatch.setattr(extractor.pefile, "PE", fake_pe)
    return bytes(data)


def test_vvas_pe_accepts_mapped_reachable_config_and_empty_backups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """mapped configとparser／callback／vtable network pathを終端へ昇格する。"""

    sample = _fixture(monkeypatch)
    probe = extractor.probe_vvas_config(sample, input_format="pe")

    assert probe["matched"] is True
    assert probe["family"] == "valleyrat"
    assert probe["supports_family_attribution"] is True
    reversed_evidence = probe["evidence"]["vvas_reversed_config"]
    assert reversed_evidence["configured_slot_count"] == 3
    assert reversed_evidence["empty_backup_slot_count"] == 2
    assert reversed_evidence["tcp_transport_slot_count"] == 2
    assert reversed_evidence["udp_transport_slot_count"] == 1
    structure = probe["evidence"]["format_corroboration"]
    assert all(structure["required_groups"].values())
    assert structure["reachable_parser_path_count"] == 1
    assert structure["reachable_network_component_count"] == 1
    assert structure["validated_network_chain_count"] == 1
    assert structure["validated_network_chain_max_function_count"] >= 3
    assert all(structure["validated_network_chain_groups"].values())
    serialized = json.dumps(probe, ensure_ascii=False, sort_keys=True)
    assert "198.51.100.24" not in serialized
    assert _DEFAULT_CONFIG not in serialized

    result = extractor.extract(sample, r"C:\private\terminal.exe")
    assert result["config"]["variant"] == "vvas_reversed_config_terminal"
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["candidate_config_recovered"] is False
    assert result["config"]["endpoints"] == ["198.51.100.24:443"]
    assert result["config"]["decoded_vvas_slots"] == [
        {"slot": 1, "endpoint": "198.51.100.24:443", "transport": "tcp"}
    ]
    assert result["config"]["source_name"] == "terminal.exe"


@pytest.mark.parametrize(
    ("config_location", "reference_config", "parser_reachable", "network_reachable"),
    [
        ("resource", True, True, True),
        ("overlay", True, True, True),
        ("data", False, True, True),
        ("data", True, False, True),
        ("data", True, True, False),
    ],
)
def test_vvas_pe_unlinked_or_decoy_config_remains_route_only(
    monkeypatch: pytest.MonkeyPatch,
    config_location: str,
    reference_config: bool,
    parser_reachable: bool,
    network_reachable: bool,
) -> None:
    """resource／overlay／dead code／別function API unionを終端へ昇格しない。"""

    sample = _fixture(
        monkeypatch,
        config_location=config_location,
        reference_config=reference_config,
        parser_reachable=parser_reachable,
        network_reachable=network_reachable,
    )
    probe = extractor.probe_vvas_config(sample, input_format="pe")
    assert probe["matched"] is False
    assert probe["evidence"] == {}
    assert probe["config"] == {}

    result = extractor.extract(sample, "candidate.exe")
    assert result["config"]["variant"] == "vvas_reversed_config_pe_candidate"
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["candidate_config_recovered"] is True
    assert result["config"]["terminal_family_confirmed"] is False
    assert result["config"]["endpoints"] == ["198.51.100.24:443"]


def test_vvas_slots_reject_half_empty_unknown_transport_and_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """half-empty、未知transport、異なる設定の併存をfail-closedにする。"""

    half_empty = "|p1:198.51.100.24|o1:443|t1:1|p2:backup.example|o2:|t2:1|"
    unknown_transport = "|p1:198.51.100.24|o1:443|t1:2|"
    assert extractor.decode_vvas_reversed_config([half_empty[::-1]]) == {}
    assert extractor.decode_vvas_reversed_config([unknown_transport[::-1]]) == {}

    conflicting = _DEFAULT_CONFIG.replace("198.51.100.24", "203.0.113.44")
    sample = _fixture(monkeypatch, conflicting_config=conflicting)
    probe = extractor.probe_vvas_config(sample, input_format="pe")
    assert probe["matched"] is False
    assert probe["evidence"] == {}


def test_vvas_pe_reachability_instruction_limit_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """到達命令上限で未走査pathを正常扱いしない。"""

    sample = _fixture(monkeypatch)
    monkeypatch.setattr(extractor, "MAXIMUM_VVAS_REACHABLE_INSTRUCTIONS", 4)

    probe = extractor.probe_vvas_config(sample, input_format="pe")

    assert probe["matched"] is False
    assert probe["supports_family_attribution"] is False
    assert probe["evidence"] == {}


def test_vvas_x86_base_relative_memory_is_not_an_absolute_reference() -> None:
    """x86のbase付きmemory displacementをconfig／IATの絶対VAへ昇格しない。"""

    disassembler = extractor.Cs(extractor.CS_ARCH_X86, extractor.CS_MODE_32)
    disassembler.detail = True
    instruction = next(
        disassembler.disasm(
            b"\x8b\x81" + struct.pack("<I", _DATA_VA + 0x20),
            _TEXT_VA,
            1,
        )
    )

    assert (
        extractor._vvas_operand_address(
            instruction,
            instruction.operands[1],
            4,
        )
        is None
    )


def test_vvas_constant_false_branch_cannot_supply_parser_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ZFが確定した不成立枝内のparserをlauncher edgeとして数えない。"""

    sample = bytearray(_fixture(monkeypatch))
    dead_block = _PARSER_LAUNCHER
    main = bytearray(b"\x31\xc0")
    branch = _MAIN + len(main)
    main += b"\x0f\x85" + struct.pack("<i", dead_block - (branch + 6))
    main += _create_thread_call(_WORKER) + b"\xc3"
    main_offset = _TEXT_RAW + _MAIN - _TEXT_VA
    sample[main_offset : main_offset + len(main)] = main
    dead = _relative_call(dead_block, _PARSER) + b"\xc3"
    dead_offset = _TEXT_RAW + dead_block - _TEXT_VA
    sample[dead_offset : dead_offset + len(dead)] = dead

    probe = extractor.probe_vvas_config(bytes(sample), input_format="pe")

    assert probe["matched"] is False
    assert probe["evidence"] == {}


def test_vvas_independent_parser_and_network_branches_do_not_union(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """entrypoint配下でも別launcherのparserとnetworkをunionしない。"""

    sample = bytearray(_fixture(monkeypatch))
    entry = _relative_call(_ENTRY, _PARSER_LAUNCHER)
    entry += _relative_call(_ENTRY + len(entry), _NETWORK_LAUNCHER) + b"\xc3"
    entry_offset = _TEXT_RAW + _ENTRY - _TEXT_VA
    sample[entry_offset : entry_offset + len(entry)] = entry
    parser_launcher = _relative_call(_PARSER_LAUNCHER, _PARSER) + b"\xc3"
    parser_offset = _TEXT_RAW + _PARSER_LAUNCHER - _TEXT_VA
    sample[parser_offset : parser_offset + len(parser_launcher)] = parser_launcher
    network_launcher = _create_thread_call(_WORKER) + b"\xc3"
    network_offset = _TEXT_RAW + _NETWORK_LAUNCHER - _TEXT_VA
    sample[network_offset : network_offset + len(network_launcher)] = network_launcher

    probe = extractor.probe_vvas_config(bytes(sample), input_format="pe")

    assert probe["matched"] is False
    assert probe["evidence"] == {}


def test_vvas_disjoint_network_callees_do_not_union_winsock_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """vtableの互いに到達不能な兄弟calleeからWinsock群を合算しない。"""

    sample = _fixture(monkeypatch, disjoint_network_callees=True)

    probe = extractor.probe_vvas_config(sample, input_format="pe")

    assert probe["matched"] is False
    assert probe["evidence"] == {}


def test_vvas_parser_must_reach_create_thread_on_same_cfg_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """address順だけが成立する排他的CFG枝をparser→callbackに結び付けない。"""

    sample = bytearray(_fixture(monkeypatch))

    def put_code(address: int, value: bytes) -> None:
        offset = _TEXT_RAW + address - _TEXT_VA
        sample[offset : offset + len(value)] = value

    put_code(_MAIN, _relative_jump(_MAIN, _DISPATCH_BRANCH))
    put_code(
        _PARSER_BRANCH,
        _relative_call(_PARSER_BRANCH, _PARSER) + b"\xc3",
    )
    put_code(_CALLBACK_BRANCH, _create_thread_call(_WORKER) + b"\xc3")
    dispatch = bytearray(b"\x85\xc9")
    branch = _DISPATCH_BRANCH + len(dispatch)
    dispatch += b"\x0f\x85" + struct.pack(
        "<i",
        _PARSER_BRANCH - (branch + 6),
    )
    dispatch += _relative_jump(
        _DISPATCH_BRANCH + len(dispatch),
        _CALLBACK_BRANCH,
    )
    put_code(_DISPATCH_BRANCH, bytes(dispatch))

    probe = extractor.probe_vvas_config(bytes(sample), input_format="pe")

    assert probe["matched"] is False
    assert probe["evidence"] == {}


def test_vvas_dense_fanin_deduplicates_pending_functions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """多数callerが同じcalleeを指してもpending枠を重複消費しない。"""

    sample = bytearray(_fixture(monkeypatch))

    def put_code(address: int, value: bytes) -> None:
        offset = _TEXT_RAW + address - _TEXT_VA
        sample[offset : offset + len(value)] = value

    put_code(_ENTRY, _relative_jump(_ENTRY, _FANIN_ROOT))
    fanin_targets = [_FANIN_FIRST + index * 0x10 for index in range(8)]
    fanin_root = bytearray(_relative_call(_FANIN_ROOT, _MAIN))
    for target in fanin_targets:
        fanin_root += _relative_call(
            _FANIN_ROOT + len(fanin_root),
            target,
        )
        put_code(target, _relative_call(target, _FANIN_SHARED) + b"\xc3")
    fanin_root += b"\xc3"
    put_code(_FANIN_ROOT, bytes(fanin_root))
    put_code(_FANIN_SHARED, b"\xc3")
    monkeypatch.setattr(extractor, "MAXIMUM_VVAS_PENDING_FUNCTIONS", 10)

    probe = extractor.probe_vvas_config(bytes(sample), input_format="pe")

    assert probe["matched"] is True
    structure = probe["evidence"]["format_corroboration"]
    assert structure["reachable_function_count"] >= 16
    assert structure["reachable_call_graph_edge_count"] >= 20


def test_vvas_call_graph_edge_budget_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """到達function数とは独立したedge上限超過を成功扱いしない。"""

    sample = _fixture(monkeypatch)
    monkeypatch.setattr(extractor, "MAXIMUM_VVAS_CALL_GRAPH_EDGES", 1)

    probe = extractor.probe_vvas_config(sample, input_format="pe")

    assert probe["matched"] is False
    assert probe["evidence"] == {}


def test_vvas_pending_function_budget_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """edge数とは独立した未処理function枠の超過を成功扱いしない。"""

    sample = _fixture(monkeypatch)
    monkeypatch.setattr(extractor, "MAXIMUM_VVAS_PENDING_FUNCTIONS", 1)

    probe = extractor.probe_vvas_config(sample, input_format="pe")

    assert probe["matched"] is False
    assert probe["evidence"] == {}


def test_vvas_component_edge_budget_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """callback componentのedge予算を全体call graph予算と別に強制する。"""

    sample = _fixture(monkeypatch)
    monkeypatch.setattr(extractor, "MAXIMUM_VVAS_COMPONENT_EDGES", 1)

    probe = extractor.probe_vvas_config(sample, input_format="pe")

    assert probe["matched"] is False
    assert probe["evidence"] == {}


def test_vvas_create_thread_callsite_limit_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """callback探索はcallsite上限超過を未解析のまま成功扱いしない。"""

    sample = bytearray(_fixture(monkeypatch))
    monkeypatch.setattr(
        extractor,
        "MAXIMUM_VVAS_CREATE_THREAD_CALLS_PER_FUNCTION",
        1,
    )
    main = _relative_call(_MAIN, _PARSER)
    main += _create_thread_call(_WORKER)
    main += _create_thread_call(_WORKER) + b"\xc3"
    main_offset = _TEXT_RAW + _MAIN - _TEXT_VA
    sample[main_offset : main_offset + len(main)] = main

    probe = extractor.probe_vvas_config(bytes(sample), input_format="pe")

    assert probe["matched"] is False
    assert probe["evidence"] == {}
