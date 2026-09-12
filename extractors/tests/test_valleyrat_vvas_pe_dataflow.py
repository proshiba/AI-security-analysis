"""ValleyRAT反転設定とnative PE data-flow gateを合成fixtureで検証する。"""

from __future__ import annotations

import json
import struct
from types import SimpleNamespace

import pytest

from extractors.valleyrat import export_funnel, extractor

_IMAGE_BASE = 0x400000
_TEXT_VA = 0x401000
_DATA_VA = 0x402000
_RESOURCE_VA = 0x403000
_TEXT_RAW = 0x200
_DATA_RAW = 0x800
_RESOURCE_RAW = 0xC00
_EXTRA_DATA_VA = 0x405000
_CREATE_THREAD_IAT = _DATA_VA + 0x300
_WSA_STARTUP_IAT = _DATA_VA + 0x304
_SOCKET_IAT = _DATA_VA + 0x308
_CONNECT_IAT = _DATA_VA + 0x30C
_SEND_IAT = _DATA_VA + 0x310
_RECV_IAT = _DATA_VA + 0x314
_FIND_RESOURCE_IAT = _DATA_VA + 0x318
_LOAD_RESOURCE_IAT = _DATA_VA + 0x31C
_LOCK_RESOURCE_IAT = _DATA_VA + 0x320
_SIZEOF_RESOURCE_IAT = _DATA_VA + 0x324
_GETHOST_IAT = _DATA_VA + 0x328
_HTONS_IAT = _DATA_VA + 0x32C
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
    entry_reaches_main: bool = True,
    export_target: int | None = None,
    tls_callback: int | None = None,
    resource_source: bool = False,
    route_resources: bool = False,
    route_resource_labels: tuple[bytes, bytes] = (b"TYPE_A", b"TYPE_B"),
    extra_mapped_data_bytes: int = 0,
    config_encoding: str = "utf-16le",
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
    stored = config[::-1].encode(config_encoding)
    data[config_offset : config_offset + len(stored)] = stored
    if conflicting_config is not None:
        conflict = conflicting_config[::-1].encode("utf-16le")
        # 相反候補もfile-backed mapped section内へ置く。overlay上の文字列は
        # strict section scanの候補集合へ含めない。
        data[0xD20 : 0xD20 + len(conflict)] = conflict

    put_code(
        _ENTRY,
        _relative_call(_ENTRY, _MAIN) + b"\xc3"
        if entry_reaches_main
        else b"\xc3",
    )
    parser_target = _PARSER if parser_reachable else _REVERSE
    main = b""
    if resource_source:
        main += _indirect_call(_FIND_RESOURCE_IAT)
        main += _indirect_call(_SIZEOF_RESOURCE_IAT)
        main += _indirect_call(_LOAD_RESOURCE_IAT)
        main += _indirect_call(_LOCK_RESOURCE_IAT)
    main += _relative_call(_MAIN + len(main), parser_target)
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
    constructor += _indirect_call(_GETHOST_IAT)
    constructor += _indirect_call(_HTONS_IAT)
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
    extra_data_raw = len(data)
    if extra_mapped_data_bytes:
        data.extend(b"\0" * extra_mapped_data_bytes)

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
    if extra_mapped_data_bytes:
        sections.append(
            SimpleNamespace(
                Name=b".data2\0\0",
                VirtualAddress=_EXTRA_DATA_VA - _IMAGE_BASE,
                Misc_VirtualSize=extra_mapped_data_bytes,
                PointerToRawData=extra_data_raw,
                SizeOfRawData=extra_mapped_data_bytes,
                Characteristics=0xC0000040,
            )
        )
    ws2_imports = [
        (b"WSAStartup", _WSA_STARTUP_IAT),
        (b"socket", _SOCKET_IAT),
        (b"connect", _CONNECT_IAT),
        (b"send", _SEND_IAT),
        (b"recv", _RECV_IAT),
        (b"gethostbyname", _GETHOST_IAT),
        (b"htons", _HTONS_IAT),
    ]
    imports = [
        SimpleNamespace(
            dll=b"KERNEL32.dll",
            imports=[
                SimpleNamespace(name=b"CreateThread", address=_CREATE_THREAD_IAT),
                SimpleNamespace(name=b"FindResourceW", address=_FIND_RESOURCE_IAT),
                SimpleNamespace(name=b"LoadResource", address=_LOAD_RESOURCE_IAT),
                SimpleNamespace(name=b"LockResource", address=_LOCK_RESOURCE_IAT),
                SimpleNamespace(name=b"SizeofResource", address=_SIZEOF_RESOURCE_IAT),
            ],
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
        FILE_HEADER=SimpleNamespace(Machine=0x14C, Characteristics=0x2102),
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
    if export_target is not None:
        image.DIRECTORY_ENTRY_EXPORT = SimpleNamespace(
            symbols=[
                SimpleNamespace(
                    name=name,
                    ordinal=index + 1,
                    address=export_target - _IMAGE_BASE,
                    forwarder=None,
                )
                for index, name in enumerate((b"alpha", b"omega", None))
            ]
        )
    if tls_callback is not None:
        image.DIRECTORY_ENTRY_TLS = SimpleNamespace(callbacks=(tls_callback,))
    if route_resources:
        for index in range(2):
            start = _RESOURCE_RAW + index * 0x200
            data[start : start + 0x100] = bytes(range(256))

        def resource_type(label: bytes, index: int) -> SimpleNamespace:
            leaf = SimpleNamespace(
                data=SimpleNamespace(
                    struct=SimpleNamespace(
                        OffsetToData=(_RESOURCE_VA - _IMAGE_BASE) + index * 0x200,
                        Size=0x100,
                    )
                )
            )
            name = SimpleNamespace(directory=SimpleNamespace(entries=[leaf]))
            return SimpleNamespace(
                name=label,
                struct=SimpleNamespace(Id=100 + index),
                directory=SimpleNamespace(entries=[name]),
            )

        image.DIRECTORY_ENTRY_RESOURCE = SimpleNamespace(
            entries=[
                resource_type(label, index)
                for index, label in enumerate(route_resource_labels)
            ]
        )
        image.get_offset_from_rva = lambda rva: (
            _RESOURCE_RAW + rva - (_RESOURCE_VA - _IMAGE_BASE)
        )

    def fake_pe(*, data: bytes, fast_load: bool) -> SimpleNamespace:
        assert data.startswith(b"MZ")
        assert isinstance(fast_load, bool)
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


def test_vvas_marker_first_scan_ignores_global_string_quota(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """mapped設定は全体文字列prefixが不完全でも完全走査から復元する。"""

    sample = _fixture(monkeypatch)
    monkeypatch.setattr(extractor, "MAXIMUM_STRING_CHARACTERS", 1)
    marker_offset = sample.find(b":\x001\x00p\x00", _DATA_RAW)
    assert marker_offset >= _DATA_RAW
    # 最初のchunkをmarker途中で切り、carry境界でも1 hitだけになることを確認する。
    monkeypatch.setattr(
        extractor,
        "MAXIMUM_VVAS_MAPPED_SCAN_CHUNK_BYTES",
        marker_offset - _DATA_RAW + 2,
    )

    _strings, global_scan = extractor._bounded_strings(sample)
    assert global_scan["truncated"] is True
    probe = extractor.probe_vvas_config(sample, input_format="pe")

    assert probe["matched"] is True
    marker_scan = probe["evidence"]["vvas_reversed_config"][
        "mapped_config_scan"
    ]
    assert marker_scan["status"] == "complete_candidates"
    assert marker_scan["candidate_set_complete"] is True
    assert marker_scan["candidate_count"] == 1
    assert marker_scan["scanned_byte_count"] == marker_scan["total_section_bytes"]

    monkeypatch.setattr(
        extractor,
        "_bounded_strings",
        lambda _data: pytest.fail("mapped候補取得後に全PE文字列を再走査してはいけません"),
    )
    result = extractor.extract(sample, "large-data.exe")
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["string_scan"]["status"] == "not_attempted"
    assert result["config"]["string_scan"]["skip_reason"] == (
        "mapped_vvas_candidates_available"
    )
    assert result["config"]["string_scan"]["truncated"] is False
    assert result["config"]["vvas_recovery"]["mapped_config_scan"] == marker_scan


def test_vvas_marker_scan_handles_large_low_entropy_mapped_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """旧16 MiB境界を超える低entropy mapped dataも全体文字列化せず走査する。"""

    sample = _fixture(
        monkeypatch,
        extra_mapped_data_bytes=17 * 1024 * 1024,
    )
    assert len(sample) > 16 * 1024 * 1024

    probe = extractor.probe_vvas_config(sample, input_format="pe")

    assert probe["matched"] is True
    scan = probe["evidence"]["vvas_reversed_config"]["mapped_config_scan"]
    assert scan["candidate_set_complete"] is True
    assert scan["section_count"] == 4
    assert scan["scanned_byte_count"] > 16 * 1024 * 1024
    assert scan["scanned_byte_count"] == scan["total_section_bytes"]

    monkeypatch.setattr(
        extractor,
        "_bounded_strings",
        lambda _data: pytest.fail("大容量PEを全文字列走査してはいけません"),
    )
    result = extractor.extract(sample, "large-data.exe")
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["terminal_family_confirmed"] is True
    assert result["config"]["string_scan"]["skip_reason"] == (
        "mapped_vvas_candidates_available"
    )


def test_vvas_marker_first_scan_accepts_case_insensitive_field_marker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """field grammarと同様に大文字Pのmarkerも完全走査する。"""

    sample = _fixture(monkeypatch, config=_DEFAULT_CONFIG.upper())

    candidates, scan = extractor._vvas_mapped_config_candidates(sample)
    assert len(candidates) == 1
    assert scan["candidate_set_complete"] is True
    assert extractor.probe_vvas_config(sample, input_format="pe")["matched"] is True


@pytest.mark.parametrize(
    "config",
    (
        f"prefix{_DEFAULT_CONFIG}suffix",
        _DEFAULT_CONFIG.rstrip("|"),
    ),
)
def test_vvas_mapped_scan_rejects_non_exact_or_partial_string_boundary(
    monkeypatch: pytest.MonkeyPatch,
    config: str,
) -> None:
    """printable前後文字やsection端で切れたfield列を設定に採用しない。"""

    sample = _fixture(monkeypatch, config=config)

    candidates, scan = extractor._vvas_mapped_config_candidates(sample)
    assert candidates == ()
    assert scan["candidate_set_complete"] is True
    assert scan["rejected_marker_hit_count"] == 1
    assert extractor.probe_vvas_config(sample, input_format="pe")["matched"] is False


def test_vvas_ascii_candidate_cannot_use_utf16_reverse_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ASCII設定候補をUTF-16LE反転parserの終端証拠へ昇格しない。"""

    config = "|p1:198.51.100.24|o1:443|t1:1|"
    sample = _fixture(monkeypatch, config=config, config_encoding="ascii")

    candidates, scan = extractor._vvas_mapped_config_candidates(sample)
    assert len(candidates) == 1
    assert candidates[0].encoding == "ascii"
    assert scan["candidate_set_complete"] is True
    probe = extractor.probe_vvas_config(sample, input_format="pe")
    assert probe["matched"] is False
    assert probe["supports_family_attribution"] is False
    result = extractor.extract(sample, "ascii-candidate.exe")
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["terminal_family_confirmed"] is False
    assert result["config"]["candidate_config_recovered"] is True


def test_vvas_marker_first_scan_rejects_literal_url_false_positive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """literal URLとslot風substringだけでは設定・familyへ昇格しない。"""

    sample = _fixture(
        monkeypatch,
        config="|p1:https://updates.example.invalid/path/|",
    )
    candidates, scan = extractor._vvas_mapped_config_candidates(sample)

    assert candidates == ()
    assert scan["status"] == "complete_no_candidates"
    assert scan["candidate_set_complete"] is True
    assert scan["marker_hit_count"] == 1
    assert scan["rejected_marker_hit_count"] == 1
    probe = extractor.probe_vvas_config(sample, input_format="pe")
    assert probe["matched"] is False
    assert probe["family"] is None
    assert probe["config"] == {}
    assert probe["analysis_coverage"]["mapped_config_scan"][
        "candidate_set_complete"
    ] is True
    assert probe["analysis_coverage"]["decode_status"] == "not_found"
    result = extractor.extract(sample, "literal-only.exe")
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["candidate_config_recovered"] is False
    assert result["config"]["endpoints"] == []
    assert result["config"]["urls"] == []


def test_vvas_marker_hit_truncation_discards_partial_candidate_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """hit上限後に未走査候補が残る場合、先頭の正規設定も採用しない。"""

    sample = bytearray(_fixture(monkeypatch))
    sample[_RESOURCE_RAW + 0x180 : _RESOURCE_RAW + 0x186] = b":\x001\x00p\x00"
    monkeypatch.setattr(extractor, "MAXIMUM_VVAS_MAPPED_SCAN_HITS", 1)

    candidates, scan = extractor._vvas_mapped_config_candidates(bytes(sample))
    assert candidates == ()
    assert scan["status"] == "marker_hit_limit_rejected"
    assert scan["candidate_set_complete"] is False
    assert scan["truncated"] is True
    assert scan["truncation_reasons"] == ["maximum_marker_hits"]

    probe = extractor.probe_vvas_config(bytes(sample), input_format="pe")
    assert probe["matched"] is False
    assert probe["analysis_limits"]["mapped_config_scan"][
        "candidate_set_complete"
    ] is False
    result = extractor.extract(bytes(sample), "truncated.exe")
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["candidate_config_recovered"] is False
    assert result["config"]["endpoints"] == []


@pytest.mark.parametrize(
    ("limit_name", "limit", "status", "reason"),
    [
        (
            "MAXIMUM_VVAS_MAPPED_SCAN_SECTIONS",
            2,
            "section_count_limit_rejected",
            "maximum_section_count",
        ),
        (
            "MAXIMUM_VVAS_MAPPED_SCAN_SECTION_BYTES",
            0x500,
            "section_byte_limit_rejected",
            "maximum_section_bytes",
        ),
        (
            "MAXIMUM_VVAS_MAPPED_SCAN_TOTAL_BYTES",
            0xD00,
            "total_byte_limit_rejected",
            "maximum_total_bytes",
        ),
    ],
)
def test_vvas_marker_scan_budgets_are_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit: int,
    status: str,
    reason: str,
) -> None:
    """section数/単体byte/総byte予算超過では走査前に候補集合を破棄する。"""

    sample = _fixture(monkeypatch)
    monkeypatch.setattr(extractor, limit_name, limit)

    candidates, scan = extractor._vvas_mapped_config_candidates(sample)
    assert candidates == ()
    assert scan["status"] == status
    assert scan["candidate_set_complete"] is False
    assert scan["scanned_byte_count"] == 0
    assert scan["truncation_reasons"] == [reason]
    probe = extractor.probe_vvas_config(sample, input_format="pe")
    assert probe["matched"] is False
    assert probe["analysis_limits"]["mapped_config_scan"]["status"] == status


def test_vvas_marker_scan_candidate_window_limit_discards_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """候補windowを完読できなければparse可能なprefixも採用しない。"""

    sample = _fixture(monkeypatch)
    monkeypatch.setattr(
        extractor,
        "MAXIMUM_VVAS_MAPPED_CANDIDATE_CHARACTERS",
        16,
    )

    candidates, scan = extractor._vvas_mapped_config_candidates(sample)
    assert candidates == ()
    assert scan["status"] == "candidate_window_limit_rejected"
    assert scan["candidate_set_complete"] is False
    assert scan["truncation_reasons"] == ["maximum_candidate_characters"]
    probe = extractor.probe_vvas_config(sample, input_format="pe")
    assert probe["matched"] is False
    assert probe["analysis_limits"]["mapped_config_scan"]["status"] == (
        "candidate_window_limit_rejected"
    )


def test_vvas_marker_scan_input_oversize_precedes_pe_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """入力上限超過はPE parserを呼ばずmachine-readableに拒否する。"""

    sample = _fixture(monkeypatch)
    monkeypatch.setattr(extractor, "MAXIMUM_VVAS_PROBE_INPUT_SIZE", len(sample) - 1)
    monkeypatch.setattr(
        extractor.pefile,
        "PE",
        lambda **_kwargs: pytest.fail("上限超過後にPE parserを呼んではならない"),
    )

    probe = extractor.probe_vvas_config(sample, input_format="pe")
    scan = probe["analysis_limits"]["mapped_config_scan"]
    assert probe["matched"] is False
    assert scan["status"] == "input_size_limit_rejected"
    assert scan["candidate_set_complete"] is False
    assert scan["scanned_byte_count"] == 0


def test_vvas_marker_scan_tracks_identical_duplicate_locations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同一設定の複数mapped位置は相反扱いせず、全位置を計上する。"""

    sample = bytearray(_fixture(monkeypatch))
    duplicate = _DEFAULT_CONFIG[::-1].encode("utf-16le")
    sample[0xD20 : 0xD20 + len(duplicate)] = duplicate

    candidates, scan = extractor._vvas_mapped_config_candidates(bytes(sample))
    assert len(candidates) == 2
    assert scan["candidate_set_complete"] is True
    assert scan["candidate_count"] == 2
    assert scan["unique_configuration_count"] == 1
    probe = extractor.probe_vvas_config(bytes(sample), input_format="pe")
    assert probe["matched"] is True
    recovered = probe["evidence"]["vvas_reversed_config"]
    assert recovered["candidate_count"] == 2
    assert recovered["mapped_config_scan"]["candidate_count"] == 2


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
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["terminal_family_confirmed"] is False
    if config_location == "overlay":
        assert result["config"]["variant"] == "unresolved_variant"
        assert result["config"]["candidate_config_recovered"] is False
        assert result["config"]["endpoints"] == []
    else:
        assert result["config"]["variant"] == "vvas_reversed_config_pe_candidate"
        assert result["config"]["candidate_config_recovered"] is True
        assert result["config"]["endpoints"] == ["198.51.100.24:443"]


def test_vvas_resource_config_accepts_complete_export_root_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """名称非依存export rootからresource source／parser／networkを終端証明する。"""

    sample = _fixture(
        monkeypatch,
        config_location="resource",
        entry_reaches_main=False,
        export_target=_MAIN,
        resource_source=True,
    )

    probe = extractor.probe_vvas_config(sample, input_format="pe")

    assert probe["matched"] is True
    assert probe["terminal_family_confirmed"] is True
    structure = probe["evidence"]["format_corroboration"]
    assert structure["root_strategy"] == "export_tls"
    assert structure["configuration_storage"] == "resource"
    assert structure["export_root_count"] == 1
    assert structure["resource_source_parser_path_count"] >= 1
    assert all(structure["required_groups"].values())


def test_vvas_tls_root_is_analyzed_but_cannot_bypass_resource_source_gate(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """TLS callbackもrootに含め、resource取得lineage欠落時はfail-closedにする。"""

    accepted = _fixture(
        monkeypatch,
        config_location="resource",
        entry_reaches_main=False,
        export_target=_ENTRY,
        tls_callback=_MAIN,
        resource_source=True,
    )
    probe = extractor.probe_vvas_config(accepted, input_format="pe")
    assert probe["matched"] is True
    structure = probe["evidence"]["format_corroboration"]
    assert structure["tls_callback_root_count"] == 1

    rejected = _fixture(
        monkeypatch,
        config_location="resource",
        entry_reaches_main=False,
        export_target=_ENTRY,
        tls_callback=_MAIN,
        resource_source=False,
    )
    assert extractor.probe_vvas_config(rejected, input_format="pe")["matched"] is False


@pytest.mark.parametrize(
    "labels",
    ((b"FIRST_A", b"FIRST_B"), (b"RENAMED_X", b"RENAMED_Y")),
)
def test_export_funnel_shape_routes_without_provider_labels_or_attribution(
    monkeypatch: pytest.MonkeyPatch,
    labels: tuple[bytes, bytes],
) -> None:
    """provider labelを変更しても形状routeは維持し、終端確定はしない。"""

    monkeypatch.setattr(export_funnel, "MIN_RESOURCE_SIZE", 0x100)
    sample = _fixture(
        monkeypatch,
        entry_reaches_main=False,
        export_target=_MAIN,
        resource_source=True,
        route_resources=True,
        route_resource_labels=labels,
    )
    route = export_funnel.probe_export_funnel_route(sample)
    serialized = json.dumps(route, sort_keys=True)

    assert route["matched"] is True
    assert route["supports_family_attribution"] is False
    assert route["terminal_family_confirmed"] is False
    assert route["terminal_network_lineage_proven"] is False
    assert route["evidence"]["all_exports_share_one_target"] is True
    assert route["evidence"]["custom_high_entropy_resource_count"] == 2
    assert all(route["evidence"]["file_backed_iat_resource_call_groups"].values())
    assert all(route["evidence"]["file_backed_iat_network_call_groups"].values())
    assert all(label.decode() not in serialized for label in labels)


def test_export_funnel_shape_requires_file_backed_resource_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """importとresource形状だけではrouteにも採用しない。"""

    monkeypatch.setattr(export_funnel, "MIN_RESOURCE_SIZE", 0x100)
    sample = _fixture(
        monkeypatch,
        entry_reaches_main=False,
        export_target=_MAIN,
        resource_source=False,
        route_resources=True,
    )
    route = export_funnel.probe_export_funnel_route(sample)
    assert route["matched"] is False
    assert route["terminal_family_confirmed"] is False


def test_extract_prioritizes_terminal_vvas_over_export_funnel_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同一PEがroute形状にも一致しても、完全なVVAS系譜を先に採用する。"""

    monkeypatch.setattr(export_funnel, "MIN_RESOURCE_SIZE", 0x100)
    sample = _fixture(
        monkeypatch,
        export_target=_MAIN,
        resource_source=True,
        route_resources=True,
    )
    assert export_funnel.probe_export_funnel_route(sample)["matched"] is True
    monkeypatch.setattr(
        extractor,
        "probe_export_funnel_route",
        lambda _data: pytest.fail("VVAS候補取得後にroute-only判定を先行してはいけません"),
    )

    result = extractor.extract(sample, "terminal.exe")

    assert result["config"]["variant"] == "vvas_reversed_config_terminal"
    assert result["config"]["terminal_family_confirmed"] is True
    assert result["config"]["static_config_recovered"] is True
    assert "export_funnel_native_route" not in result["config"]


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
