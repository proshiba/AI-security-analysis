"""HHSTG resource extractorを実検体・実IOCなしで回帰検証する。"""

from __future__ import annotations

import struct
from types import SimpleNamespace

from capstone import CS_ARCH_X86, CS_MODE_64, Cs

from extractors.valleyrat.hhstg_resource import (
    HhstgResourceRecovery,
    StageEndpoint,
    _certificate_table_region_present,
    _cfg_dominates,
    _decode_chacha,
    _decode_shellcode,
    _direct_stack_literals,
    _entry_patch_lineage,
    _fallback_port_store_anchors,
    _fallback_route_write_anchors,
    _fallback_slots,
    _Function,
    _host_import_binding,
    _named_exports,
    _outer_proxy_file_binding,
    _outer_resource103_registry_write_binding,
    _path_reaches,
    _PeContext,
    _recover_hhstg_shellcode,
    _resource_proxy_host_roles,
    _runtime_function_graph,
    _unique_crypto_offsets,
    _validate_hhstg_transport,
    public_recovery_summary,
)


def _stack_literal(displacement: int, value: bytes) -> bytes:
    return b"".join(
        b"\xc6\x84\x24" + struct.pack("<I", displacement + index) + bytes([byte])
        for index, byte in enumerate(value + b"\0")
    )


def _fallback_slot(
    displacement: int,
    domain: bytes,
    *,
    mutually_exclusive: bool = False,
) -> bytes:
    """bytewise host、route table copy、443格納の最小命令fixtureを作る。"""

    counter = 0xD0 if displacement == 0x128 else 0xD4
    result = bytearray(_stack_literal(displacement, domain))
    result.extend(
        b"\x48\x63\x84\x24"
        + struct.pack("<I", counter)
        + b"\x0f\xbe\x84\x04"
        + struct.pack("<I", displacement)
        + b"\x48\x63\x84\x24"
        + struct.pack("<I", counter)
        + b"\x48\x63\x4c\x24\x38"
        + b"\x48\x6b\xc9\x42"
        + b"\x48\x8d\x8c\x0c\x80\x03\x00\x00"
        + b"\x48\x63\x94\x24"
        + struct.pack("<I", counter)
        + b"\x8a\x84\x04"
        + struct.pack("<I", displacement)
    )
    if mutually_exclusive:
        result.extend(b"\x85\xc0")
        conditional_offset = len(result)
        result.extend(b"\x0f\x84\0\0\0\0")
        result.extend(b"\x88\x04\x11")
        skip_offset = len(result)
        result.extend(b"\xe9\0\0\0\0")
        port_offset = len(result)
    else:
        conditional_offset = -1
        skip_offset = -1
        port_offset = -1
        result.extend(b"\x88\x04\x11")
    result.extend(
        b"\x48\x63\x44\x24\x38"
        b"\x48\x6b\xc0\x42"
        b"\xb9\xbb\x01\x00\x00\x66\x89\x8c\x04\xc0\x03\x00\x00"
    )
    after_port = len(result)
    result.extend(b"\x83\x7c\x24\x38\x08")
    if mutually_exclusive:
        struct.pack_into(
            "<i",
            result,
            conditional_offset + 2,
            port_offset - (conditional_offset + 6),
        )
        struct.pack_into("<i", result, skip_offset + 1, after_port - (skip_offset + 5))
    return bytes(result)


def _config() -> bytes:
    result = bytearray(0x11A)
    result[:8] = b"HHSTG\0\0\0"

    def put(offset: int, size: int, value: bytes) -> None:
        assert len(value) < size
        result[offset : offset + len(value)] = value

    put(0x08, 0x40, b"198.51.100.10")
    struct.pack_into("<H", result, 0x48, 4444)
    result[0x4A:0x5A] = bytes(range(1, 17))
    put(0x5A, 0x80, b"198.51.100.10:4444||203.0.113.20:5555")
    put(0xDA, 0x40, b"synthetic-fixture")
    return bytes(result)


def _synthetic_shellcode(*, mutually_exclusive_fallback: bool = False) -> bytes:
    code = bytearray(b"\x90" * 32)
    code.extend(_stack_literal(0x10C, b"ntdll"))
    code.extend(b"\x90")
    code.extend(_stack_literal(0x150, b"ws2_32.dll"))
    code.extend(b"\x66\xb9\x02\x02")
    for index, value in enumerate(b"HHv2\x01\x00\x01"):
        code.extend(b"\xc6\x84\x04\x14\x01\x00\x00" + bytes([value]))
    code.extend(b"\x83\xf8\x3a\x83\xf8\x3a")
    code.extend(b"\x83\xf8\x7c\x83\xf8\x7c")
    code.extend(
        _fallback_slot(
            0x128,
            b"stage-a.example",
            mutually_exclusive=mutually_exclusive_fallback,
        )
    )
    code.extend(_fallback_slot(0x160, b"stage-b.example"))
    code.extend(
        bytes.fromhex(
            "41b806000000"
            "ba01000000"
            "b902000000"
            "ff942438020000"
            "4889442468"
            "41b810000000"
            "488d9424e0020000"
            "488b4c2468"
            "ff942448020000"
            "41b807000000"
            "488d942414010000"
            "488b4c2468"
            "ff9424a8020000"
            "83f807"
            "837c244804"
            "488d8c24a8000000"
            "488bd1"
            "41b804000000"
            "488b4c2468"
            "ff942450020000"
            "81bc24a80000000000a000"
            "41b904000000"
            "41b800300000"
            "8b9424a8000000"
            "33c9"
            "ff942400020000"
            "4889442450"
            "488b542450"
            "448b8424a8000000"
            "488b4c2468"
            "ff942450020000"
            "48899424b0020000"
            "b910000000"
            "f7f1"
            "488b8c24c8000000"
            "0fb644014a"
            "488b4c2450"
            "488b9424b0020000"
            "0fb60c11"
            "33c8"
            "8bc1"
            "88040a"
        )
    )
    code.extend(_stack_literal(0x140, b"AppConfig"))
    code.extend(
        bytes.fromhex(
            "488bbc2460020000"
            "488b542450"
            "488d4c0820"
            "8a0407"
            "88040a"
            "8b442458"
            "488b4c2450"
            "8b942414020000"
            "89940124010000"
            "488bbc2470020000"
            "488b542450"
            "488d8c0828010000"
            "8a0407"
            "88040a"
            "8b442458"
            "488b4c2450"
            "8b9424f8010000"
            "8994012c020000"
            "488bbc24c8000000"
            "488b542450"
            "488d8c0894060000"
            "8a8407da000000"
            "88040a"
            "b940000000"
            "b904010000"
            "b904000000"
            "8b842484000000"
            "448bc0"
            "488b542450"
            "488b8c24e8000000"
            "ff942408020000"
            "8b842484000000"
            "4c8d8c24c8020000"
            "41b820000000"
            "8bd0"
            "488b8c24e8000000"
            "ff9424b8020000"
            "4c8b8424e8000000"
            "ff942478020000"
            "b960ea0000"
        )
    )
    if len(code) < 768:
        code.extend(b"\x90" * (768 - len(code)))
    return bytes(code) + _config()


def _decode_function(code: bytes, address: int = 0) -> _Function:
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    instructions = tuple(disassembler.disasm(code, address))
    assert instructions
    assert sum(item.size for item in instructions) == len(code)
    return _Function(address, address + len(code), instructions, True)


def _append_relative_call(code: bytearray, target: int) -> None:
    displacement = target - (len(code) + 5)
    code.extend(b"\xe8" + struct.pack("<i", displacement))


def _append_rip_call(code: bytearray, target: int) -> None:
    displacement = target - (len(code) + 6)
    code.extend(b"\xff\x15" + struct.pack("<i", displacement))


def _resource103_registry_fixture() -> tuple[_Function, int]:
    loader_target = 0x500
    registry_write_target = 0x600
    code = bytearray(b"\xb9\x67\x00\x00\x00")
    _append_relative_call(code, loader_target)
    code.extend(
        bytes.fromhex(
            "8b7c2460"
            "4c8da8be0e0000"
            "81c742f1ffff"
            "488b4c2450"
            "8bdf"
            "d1eb"
            "895c2428"
            "4533c0"
            "4c896c2420"
        )
    )
    _append_rip_call(code, registry_write_target)
    code.extend(bytes.fromhex("488b4c24502bfb4903dd897c24284533c048895c2420"))
    _append_rip_call(code, registry_write_target)
    return _decode_function(bytes(code)), loader_target


def _outer_proxy_binding_fixture(
    identity: bytes = b"proxy.dll",
) -> tuple[_PeContext, _Function]:
    code = bytearray(b"\xb9\x65\x00\x00\x00")
    _append_relative_call(code, 0x400)
    code.extend(b"\x4c\x8b\xe0\x90")
    identity_offset = 0x200
    code.extend(b"\x4c\x8d\x05" + struct.pack("<i", identity_offset - (len(code) + 7)))
    code.extend(bytes.fromhex("488d9590010000488d8db0030000"))
    _append_relative_call(code, 0x420)
    code.extend(b"\x90")
    code.extend(bytes.fromhex("488d8db0030000ba00000040"))
    _append_rip_call(code, 0x500)
    code.extend(b"\x90" * 10)
    code.extend(bytes.fromhex("4c89e2488bc8"))
    _append_rip_call(code, 0x508)
    function = _decode_function(bytes(code))
    data = bytes(code).ljust(identity_offset, b"\0") + identity

    class _Image:
        @staticmethod
        def get_rva_from_offset(offset: int) -> int:
            return offset

    return _PeContext(data, _Image(), 0, (function,)), function


def _entry_patch_fixture(*, entry_return: bool) -> _PeContext:
    bootstrap_address = 0x200
    worker_address = 0x300
    patch = bytearray(b"\xc3" if entry_return else b"")
    patch.extend(bytes.fromhex("65488b042560000000"))
    for immediate in (0x5A4D, 0x4550, 0xC, 0xB848, 0xE0FF):
        patch.extend(b"\xb8" + struct.pack("<I", immediate))
    patch.extend(bytes.fromhex("488b4010488b403c488b4028488b400a"))
    _append_rip_call(patch, 0x700)
    _append_rip_call(patch, 0x700)
    patch.extend(
        b"\x48\x8d\x05" + struct.pack("<i", bootstrap_address - (len(patch) + 7))
    )
    patch.extend(b"\xc3")

    bootstrap = bytearray(
        b"\x4c\x8d\x05" + struct.pack("<i", worker_address - (bootstrap_address + 7))
    )
    bootstrap.extend(bytes.fromhex("e800000000c3"))
    worker = b"\xc3"
    return _PeContext(
        b"",
        SimpleNamespace(),
        0,
        (
            _decode_function(bytes(patch)),
            _decode_function(bytes(bootstrap), bootstrap_address),
            _decode_function(worker, worker_address),
        ),
    )


def test_synthetic_hhstg_transport_recovers_route_and_two_fallbacks() -> None:
    recovered = _recover_hhstg_shellcode(_synthetic_shellcode())
    assert recovered is not None
    config, fallbacks = recovered
    assert config.route_endpoints == (
        ("198.51.100.10", 4444),
        ("203.0.113.20", 5555),
    )
    assert fallbacks == (
        ("stage-a.example", 443),
        ("stage-b.example", 443),
    )


def test_fallback_without_correlated_443_store_is_rejected() -> None:
    shellcode = bytearray(_synthetic_shellcode())
    signature = bytes.fromhex("b9bb01000066898c04c0030000")
    first = shellcode.find(signature)
    assert first >= 0
    shellcode[first + 1] ^= 1
    assert _recover_hhstg_shellcode(bytes(shellcode)) is None


def test_missing_appconfig_backup_port_patch_is_rejected() -> None:
    shellcode = bytearray(_synthetic_shellcode())
    patch = bytes.fromhex("8994012c020000")
    offset = shellcode.find(patch)
    assert offset >= 0
    shellcode[offset + 3] ^= 1
    assert _recover_hhstg_shellcode(bytes(shellcode)) is None


def test_dead_code_transport_is_rejected_by_entry_zero_cfg() -> None:
    shellcode = bytearray(_synthetic_shellcode())
    shellcode[0] = 0xC3
    assert _recover_hhstg_shellcode(bytes(shellcode)) is None


def test_nonreachable_fallback_is_rejected() -> None:
    shellcode = bytearray(_synthetic_shellcode())
    slot = _fallback_slot(0x128, b"stage-a.example")
    offset = shellcode.find(slot)
    assert offset >= 0
    displacement = len(slot) - 5
    shellcode[offset : offset + 5] = b"\xe9" + struct.pack("<i", displacement)
    assert _recover_hhstg_shellcode(bytes(shellcode)) is None


def test_mutually_exclusive_route_write_and_port_store_are_rejected() -> None:
    shellcode = _synthetic_shellcode(mutually_exclusive_fallback=True)
    marker = shellcode.find(b"HHSTG\0\0\0")
    graph = _decode_shellcode(shellcode, marker)
    assert graph is not None
    runs = _direct_stack_literals(graph.instructions)
    connect_addresses = _validate_hhstg_transport(graph, runs)
    assert connect_addresses is not None
    first = next(item for item in runs if item[1] == 0x128)
    route_anchors = _fallback_route_write_anchors(
        graph.instructions,
        first[1],
        graph,
    )
    port_anchors = _fallback_port_store_anchors(graph.instructions)
    assert len(route_anchors) == 1 and len(port_anchors) == 2
    literal_final = first[0] + len(first[2]) - 1
    route_address = int(graph.instructions[route_anchors[0]].address)
    port_address = int(graph.instructions[port_anchors[0]].address)
    assert _cfg_dominates(
        graph,
        int(graph.instructions[literal_final].address),
        route_address,
    )
    assert _cfg_dominates(
        graph,
        int(graph.instructions[literal_final].address),
        port_address,
    )
    assert _path_reaches(graph, route_address, port_address) is False
    assert (
        _fallback_slots(
            shellcode[:marker],
            graph.instructions,
            runs,
            graph,
            connect_addresses,
        )
        is None
    )
    assert _recover_hhstg_shellcode(shellcode) is None


def test_connect_data_flow_break_is_rejected() -> None:
    shellcode = bytearray(_synthetic_shellcode())
    connect_call = bytes.fromhex("ff942448020000")
    offset = shellcode.find(connect_call)
    assert offset >= 0
    shellcode[offset + 3] ^= 1
    assert _recover_hhstg_shellcode(bytes(shellcode)) is None


def test_stage_xor_buffer_data_flow_break_is_rejected() -> None:
    shellcode = bytearray(_synthetic_shellcode())
    stage_buffer = bytes.fromhex("488b9424b0020000")
    offset = shellcode.find(stage_buffer)
    assert offset >= 0
    shellcode[offset + 4] ^= 1
    assert _recover_hhstg_shellcode(bytes(shellcode)) is None


def test_connect_arguments_on_optional_branch_are_rejected() -> None:
    shellcode = bytearray(_synthetic_shellcode())
    arguments = bytes.fromhex("41b810000000488d9424e0020000488b4c2468")
    offset = shellcode.find(arguments)
    assert offset >= 0
    branch = b"\x85\xc0\x0f\x84" + struct.pack("<i", len(arguments))
    shellcode[offset:offset] = branch
    assert _recover_hhstg_shellcode(bytes(shellcode)) is None


def test_chacha_counter_zero_layout_round_trips_synthetic_data() -> None:
    key = bytes(range(32))
    nonce = bytes(range(12))
    plaintext = b"offline synthetic HHSTG stage" * 4
    ciphertext = _decode_chacha(plaintext, key, nonce)
    assert ciphertext is not None and ciphertext != plaintext
    assert _decode_chacha(ciphertext, key, nonce) == plaintext


def test_crypto_offsets_reject_decoy_or_multiple_candidates() -> None:
    assert _unique_crypto_offsets([0x100], [0x400], [0x120]) == (0x100, 0x120, 0x400)
    assert _unique_crypto_offsets([0x100, 0x180], [0x400], [0x120]) is None
    assert _unique_crypto_offsets([0x100], [0x400, 0x500], [0x120]) is None
    assert _unique_crypto_offsets([0x100], [0x400], [0x120, 0x1A0]) is None
    assert _unique_crypto_offsets([0x100], [0x400], [0x121]) is None


def test_resource103_tail_must_bind_to_both_registry_writes() -> None:
    function, loader_target = _resource103_registry_fixture()
    assert _outer_resource103_registry_write_binding(function, loader_target) is True

    mutated = bytearray(b"".join(bytes(item.bytes) for item in function.instructions))
    tail = bytes.fromhex("4c8da8be0e0000")
    offset = mutated.find(tail)
    assert offset >= 0
    mutated[offset + 3] ^= 1
    assert (
        _outer_resource103_registry_write_binding(
            _decode_function(bytes(mutated)),
            loader_target,
        )
        is False
    )


def test_runtime_function_entry_return_excludes_dead_registry_lineage() -> None:
    function, loader_target = _resource103_registry_fixture()
    raw = b"\xc3" + b"".join(bytes(item.bytes) for item in function.instructions)
    dead = _decode_function(raw)
    graph = _runtime_function_graph(dead)
    assert graph is not None
    assert len(graph.instructions) == 1
    assert _outer_resource103_registry_write_binding(dead, loader_target) is False


def test_proxy_export_and_import_descriptor_binding_is_exact() -> None:
    names = tuple(f"Export{index}" for index in range(8))
    symbols = [
        SimpleNamespace(name=name.encode("ascii"), forwarder=None, address=0x120)
        for name in names
    ]
    executable = SimpleNamespace(
        VirtualAddress=0x100,
        SizeOfRawData=0x100,
        PointerToRawData=0x100,
        Characteristics=0x60000020,
    )
    export_directory = SimpleNamespace(name=b"proxy.dll", symbols=symbols)
    proxy_image = SimpleNamespace(
        DIRECTORY_ENTRY_EXPORT=export_directory,
        sections=[executable],
    )
    proxy = _PeContext(bytes(0x300), proxy_image, 0, ())
    assert _named_exports(proxy) == (names, 0x120, "proxy.dll")

    non_executable = SimpleNamespace(**vars(executable))
    non_executable.Characteristics = 0x40000040
    invalid_proxy = _PeContext(
        bytes(0x300),
        SimpleNamespace(
            DIRECTORY_ENTRY_EXPORT=export_directory,
            sections=[non_executable],
        ),
        0,
        (),
    )
    assert _named_exports(invalid_proxy) is None

    descriptor = SimpleNamespace(
        dll=b"proxy.dll",
        imports=[SimpleNamespace(name=name.encode("ascii")) for name in names],
    )
    host = _PeContext(
        b"",
        SimpleNamespace(DIRECTORY_ENTRY_IMPORT=[descriptor]),
        0,
        (),
    )
    assert _host_import_binding(host, names) == "proxy.dll"
    mismatched = SimpleNamespace(
        dll=b"other.dll",
        imports=[SimpleNamespace(name=b"Unrelated")],
    )
    mismatch_host = _PeContext(
        b"",
        SimpleNamespace(DIRECTORY_ENTRY_IMPORT=[mismatched]),
        0,
        (),
    )
    assert _host_import_binding(mismatch_host, names) is None
    assert (
        _host_import_binding(_PeContext(b"", SimpleNamespace(), 0, ()), names) is None
    )
    empty_host = _PeContext(
        b"",
        SimpleNamespace(DIRECTORY_ENTRY_IMPORT=[]),
        0,
        (),
    )
    assert _host_import_binding(empty_host, names) is None


def test_outer_proxy_runtime_identity_mismatch_is_rejected() -> None:
    outer, function = _outer_proxy_binding_fixture()
    assert _outer_proxy_file_binding(outer, function, "proxy.dll", 0x400) is True
    assert _outer_proxy_file_binding(outer, function, "other.dll", 0x400) is False


def test_outer_proxy_binding_in_dead_code_after_entry_return_is_rejected() -> None:
    outer, function = _outer_proxy_binding_fixture()
    raw = b"\xc3" + b"".join(bytes(item.bytes) for item in function.instructions)
    dead = _decode_function(raw)
    dead_outer = _PeContext(outer.data, outer.image, outer.image_base, (dead,))
    assert _outer_proxy_file_binding(dead_outer, dead, "proxy.dll", 0x400) is False


def test_entry_patch_lineage_in_dead_code_after_entry_return_is_rejected() -> None:
    live = _entry_patch_fixture(entry_return=False)
    dead = _entry_patch_fixture(entry_return=True)

    assert _entry_patch_lineage(live) is not None
    assert _entry_patch_lineage(dead) is None


def test_resource_102_dll_cannot_replace_resource_101_proxy_role() -> None:
    resource_101_proxy = _PeContext(
        b"",
        SimpleNamespace(FILE_HEADER=SimpleNamespace(Characteristics=0x2000)),
        0,
        (),
    )
    resource_102_host = _PeContext(
        b"",
        SimpleNamespace(FILE_HEADER=SimpleNamespace(Characteristics=0)),
        0,
        (),
    )
    assert _resource_proxy_host_roles(resource_101_proxy, resource_102_host) == (
        resource_101_proxy,
        resource_102_host,
    )
    assert _resource_proxy_host_roles(resource_102_host, resource_101_proxy) is None
    assert _resource_proxy_host_roles(resource_101_proxy, resource_101_proxy) is None


def test_certificate_region_is_presence_only_not_signature_validation() -> None:
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(5)]
    directories[4] = SimpleNamespace(VirtualAddress=16, Size=8)
    context = _PeContext(
        bytes(64),
        SimpleNamespace(
            OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories),
        ),
        0,
        (),
    )
    assert _certificate_table_region_present(context) is True
    directories[4] = SimpleNamespace(VirtualAddress=60, Size=8)
    assert _certificate_table_region_present(context) is False


def test_public_summary_does_not_copy_endpoint_or_secret_material() -> None:
    recovery = HhstgResourceRecovery(
        endpoints=(StageEndpoint("198.51.100.10", 4444, "configured_route", 0),),
        configured_route_count=1,
        embedded_fallback_count=0,
        export_binding_count=21,
        campaign_present=True,
    )
    summary = public_recovery_summary(recovery)
    rendered = repr(summary)
    assert "198.51.100.10" not in rendered
    assert summary["endpoint_role"] == "stage_acquisition_route_candidate"
    assert summary["endpoint_confirmation"] == "unverified_static_candidate"
    assert summary["automatic_route_eligible"] is False
    assert summary["static_configuration_confirmed"] is False
    assert summary["loader_component_confirmed"] is False
    assert summary["command_c2_confirmed"] is False
    assert summary["supports_family_attribution"] is False
    assert summary["terminal_family_confirmed"] is False
    assert summary["route_only"] is True
    assert summary["resource_101_proxy_role_validated"] is True
    assert summary["resource_102_host_role_validated"] is True
    assert summary["fallback_literal_route_port_connect_cfg_validated"] is True
    assert summary["fallback_literal_dominance_validated"] is True
    assert summary["registry_base64_chacha20_validated"] is False
    assert summary["resource_103_registry_crypto_data_flow_validated"] is False
    assert summary["proxy_export_to_entry_patch_path_validated"] is False
    assert summary["configured_route_data_flow_validated"] is False
    assert summary["runtime_api_argument_data_flow_validated"] is False
    assert summary["appconfig_patch_data_flow_validated"] is False
    assert summary["certificate_table_region_present"] is True
    assert "signed_host_region_validated" not in summary
    assert summary["raw_key_included"] is False
    assert summary["raw_payload_included"] is False
