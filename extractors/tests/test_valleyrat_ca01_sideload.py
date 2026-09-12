"""CA01系x64サイドロード設定抽出の厳格な境界を検証する。"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from collections import Counter
from types import SimpleNamespace

import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_IMM

from extractors.valleyrat import ca01_sideload as ca01

_SYNTHETIC_REVIEWED_CEF_SHA256 = hashlib.sha256(
    b"synthetic-reviewed-cef-unit-test-fixture"
).hexdigest()


def _encoded_host(host: bytes) -> bytes:
    return base64.b64encode(base64.b64encode(host))


def _valid_recovery(outer_sha256: str) -> ca01.Ca01SideloadRecovery:
    slots = [
        {
            "index": 1,
            "host": "198.51.100.24",
            "port": 449,
            "transport": "tcp",
            "transport_selector": 1,
            "role": "primary",
            "enabled": True,
        },
        {
            "index": 2,
            "host": "198.51.100.24",
            "port": 449,
            "transport": "tcp",
            "transport_selector": 1,
            "role": "primary_duplicate",
            "enabled": True,
        },
        {
            "index": 3,
            "host": "198.51.100.24",
            "port": 443,
            "transport": "tcp",
            "transport_selector": 1,
            "role": "alternate",
            "enabled": True,
        },
    ]
    identity = "\n".join(
        f"{slot['index']}|{slot['host']}|{slot['port']}|"
        f"{slot['transport_selector']}|{slot['role']}"
        for slot in slots
    ).encode()
    return ca01.Ca01SideloadRecovery(
        outer_sha256=outer_sha256,
        config={
            "variant": "ca01_x64_double_base64_sideload_terminal",
            "slots": slots,
            "endpoints": [
                {
                    "host": "198.51.100.24",
                    "port": 449,
                    "transport": "tcp",
                    "role": "primary",
                },
                {
                    "host": "198.51.100.24",
                    "port": 443,
                    "transport": "tcp",
                    "role": "alternate",
                },
            ],
            "configuration_identity_sha256": hashlib.sha256(identity).hexdigest(),
        },
        structural_evidence={
            "architecture": "x64",
            "outer_profile": ca01._VULKAN_OUTER_PROFILE,
            "vulkan_export_count": 1,
            "export_reachable_thread_config_lineage_present": True,
            "create_thread_wrapper_reachable": True,
            "producer_candidate_count": 1,
            "lineage_counts": {
                "export_to_main_direct_call_count": 1,
                "main_to_thread_factory_direct_call_count": 1,
                "thread_factory_to_create_thread_wrapper_count": 1,
            },
            "producer": {
                "double_base64_decode_depth": 2,
                "slot_count": 3,
                "unique_endpoint_count": 2,
                "primary_slot_count": 2,
                "alternate_slot_count": 1,
                "explicit_transport_selector_count": 3,
                "periodic_wait_after_consumer_present": True,
                "raw_encoded_token_included": False,
                "raw_network_values_included": False,
                "raw_labels_included": False,
                "raw_addresses_included": False,
            },
            "sample_executed": False,
            "recovered_stage_executed": False,
            "network_contacted": False,
        },
    )


def _section(
    *,
    raw_start: int,
    virtual_start: int,
    size: int,
    executable: bool = False,
    resource: bool = False,
) -> ca01._Section:
    return ca01._Section(
        name=".rsrc" if resource else ".data",
        virtual_start=virtual_start,
        virtual_end=virtual_start + size,
        raw_start=raw_start,
        raw_end=raw_start + size,
        executable=executable,
        resource=resource,
    )


def _call(source: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target - (source + 5))


def _summary(code: bytes, *, start: int = 0x1000) -> ca01._FunctionSummary:
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    instructions = {
        int(instruction.address): instruction
        for instruction in disassembler.disasm(code, start)
    }
    direct_calls: set[int] = set()
    counts: Counter[int] = Counter()
    for instruction in instructions.values():
        operands = list(instruction.operands)
        if (
            instruction.mnemonic == "call"
            and operands
            and operands[0].type == X86_OP_IMM
        ):
            target = int(operands[0].imm) & 0xFFFFFFFFFFFFFFFF
            direct_calls.add(target)
            counts[target] += 1
    return ca01._FunctionSummary(
        start=start,
        instructions=instructions,
        direct_calls=direct_calls,
        direct_call_counts=counts,
        executable_references=set(),
        api_calls=[],
    )


def _builder_code(
    *,
    converters: tuple[int, int] = (0x3000, 0x3000),
    dead_second_chain: bool = False,
) -> tuple[bytes, int]:
    start = 0x1000
    decoder = 0x4000
    code = bytearray()
    for index, converter in enumerate(converters):
        if index == 1 and dead_second_chain:
            code += b"\xc3"
        address = start + len(code)
        code += _call(address, converter)
        code += b"\x48\x89\xc2"  # mov rdx, rax
        address = start + len(code)
        code += _call(address, decoder)
        code += b"\x48\x89\xc2"
        address = start + len(code)
        code += _call(address, decoder)
    code += b"\xc3"
    return bytes(code), decoder


def _decoder_code(
    *, split_last_value: bool = False, dead_accumulation: bool = False
) -> bytes:
    """0x400 allocationからtable lookup／6-bit accumulationまでのfixture。"""

    start = 0x1000
    code = bytearray(b"\xb9\x00\x04\x00\x00")  # mov ecx, 0x400
    code += _call(start + len(code), 0x3000)
    code += b"\x48\x89\xc3"  # mov rbx, rax
    for value in range(64):
        # mov dword ptr [rbx/rdx + ASCII-index], value
        modrm = b"\x82" if split_last_value and value == 63 else b"\x83"
        code += b"\xc7" + modrm + struct.pack("<i", value * 4)
        code += struct.pack("<I", value)
    if dead_accumulation:
        code += b"\xc3"
    code += b"\x8b\x0c\x83"  # mov ecx, dword ptr [rbx + rax*4]
    code += b"\xc1\xe0\x06"  # shl eax, 6
    code += b"\x01\xc8\xc3"  # add eax, ecx; ret
    return bytes(code)


def _consumer_summary(
    *, restore_begin: int = -0x60, indirect_begin: int = -0x60
) -> ca01._FunctionSummary:
    """3段準備と2回のVirtualProtectを持つ最小consumer fixture。"""

    start = 0x1000
    code = bytearray(b"\x48\x89\xca")  # mov rdx, rcx
    code += b"\x48\x8d\x4d\xd8"  # lea rcx, [rbp - 0x28]
    code += _call(start + len(code), 0x3000)
    code += b"\x48\x8d\x55\xd8\x48\x8d\x4d\xb8"
    code += _call(start + len(code), 0x3100)
    code += b"\x48\x8d\x55\xb8\x48\x8d\x4d\xa0"
    code += _call(start + len(code), 0x3200)
    code += b"\x48\x8b\x55\xa8\x48\x8b\x4d\xa0\x48\x29\xca"
    code += b"\x4c\x8d\x4d\x18\x41\xb8\x40\x00\x00\x00"
    first_protect = start + len(code)
    code += b"\xff\x15\x00\x00\x00\x00"
    code += b"\xff\x55" + struct.pack("b", indirect_begin)
    restore_end = restore_begin + 8
    code += b"\x48\x8b\x55" + struct.pack("b", restore_end)
    code += b"\x48\x8b\x4d" + struct.pack("b", restore_begin)
    code += b"\x48\x29\xca\x4c\x8d\x4d\x18\x44\x8b\x45\x18"
    second_protect = start + len(code)
    code += b"\xff\x15\x00\x00\x00\x00\xc3"
    summary = _summary(bytes(code), start=start)
    summary.api_calls = [
        (first_protect, "virtualprotect"),
        (second_protect, "virtualprotect"),
    ]
    return summary


def test_double_base64_scan_ignores_resource_and_unmapped_overlay_decoys() -> None:
    """mapped非resourceだけを走査し、resource／overlayの同値decoyを除外する。"""

    token = _encoded_host(b"198.51.100.24")
    false_token = _encoded_host(b"not a valid host")
    data = bytearray(b"\0" * 0x800)
    data[0x120 : 0x120 + len(false_token)] = false_token
    data[0x180 : 0x180 + len(token)] = token
    data[0x180 + len(token)] = 0
    data[0x420 : 0x420 + len(token)] = token
    data[0x420 + len(token)] = 0
    data[0x720 : 0x720 + len(token)] = token
    data[0x720 + len(token)] = 0
    sections = [
        _section(raw_start=0x100, virtual_start=0x180001000, size=0x200),
        _section(
            raw_start=0x400,
            virtual_start=0x180002000,
            size=0x200,
            resource=True,
        ),
    ]

    candidates = ca01._double_base64_candidates(bytes(data), sections)

    assert candidates is not None
    assert [(item.host, item.address) for item in candidates] == [
        ("198.51.100.24", 0x180001080)
    ]


def test_double_base64_scan_fails_closed_at_aggregate_run_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """候補run上限はtruncateせず、結果全体を不確定として拒否する。"""

    monkeypatch.setattr(ca01, "MAXIMUM_BASE64_RUNS", 1)
    token = _encoded_host(b"198.51.100.24")
    data = bytearray(b"\0" * 0x400)
    for offset in (0x120, 0x180):
        data[offset : offset + len(token)] = token
        data[offset + len(token)] = 0
    sections = [_section(raw_start=0x100, virtual_start=0x180001000, size=0x280)]

    assert ca01._double_base64_candidates(bytes(data), sections) is None


def test_required_kernel_apis_must_share_one_valid_descriptor() -> None:
    """必須APIの同名偽装と複数descriptorのpartial unionを拒否する。"""

    def descriptor(dll: bytes, names: tuple[bytes, ...], base: int) -> SimpleNamespace:
        return SimpleNamespace(
            dll=dll,
            imports=[
                SimpleNamespace(name=name, address=base + index * 8)
                for index, name in enumerate(names)
            ],
        )

    complete = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            descriptor(
                b"KERNEL32.dll",
                (b"CreateThread", b"VirtualProtect", b"Sleep"),
                0x180003000,
            )
        ]
    )
    split = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            descriptor(b"KERNEL32.dll", (b"CreateThread",), 0x180003000),
            descriptor(b"KERNEL32.dll", (b"VirtualProtect", b"Sleep"), 0x180004000),
        ]
    )
    spoofed = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            descriptor(
                b"UNRELATED.dll",
                (b"CreateThread", b"VirtualProtect", b"Sleep"),
                0x180003000,
            )
        ]
    )

    assert ca01._import_addresses(complete) is not None
    assert ca01._import_addresses(split) is None
    assert ca01._import_addresses(spoofed) is None


def test_cef_imports_require_kernel_and_crt_ownership() -> None:
    """CEF型はKERNEL APIと_beginthreadexを正規ownerへ個別に束縛する。"""

    def descriptor(
        dll: bytes,
        names: tuple[bytes, ...],
        base: int,
    ) -> SimpleNamespace:
        return SimpleNamespace(
            dll=dll,
            imports=[
                SimpleNamespace(name=name, address=base + index * 8)
                for index, name in enumerate(names)
            ],
        )

    kernel = descriptor(
        b"KERNEL32.dll",
        (b"VirtualProtect", b"Sleep"),
        0x180003000,
    )
    runtime = descriptor(
        b"api-ms-win-crt-runtime-l1-1-0.dll",
        (b"_beginthreadex",),
        0x180004000,
    )
    accepted = SimpleNamespace(DIRECTORY_ENTRY_IMPORT=[kernel, runtime])
    wrong_owner = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            kernel,
            descriptor(b"UNRELATED.dll", (b"_beginthreadex",), 0x180004000),
        ]
    )
    duplicate = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            kernel,
            runtime,
            descriptor(b"ucrtbase.dll", (b"_beginthreadex",), 0x180005000),
        ]
    )
    mixed_thread_api = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[
            descriptor(
                b"KERNEL32.dll",
                (b"VirtualProtect", b"Sleep", b"CreateThread"),
                0x180003000,
            ),
            runtime,
        ]
    )

    assert ca01._cef_import_addresses(accepted) is not None
    assert ca01._cef_import_addresses(wrong_owner) is None
    assert ca01._cef_import_addresses(duplicate) is None
    assert ca01._cef_import_addresses(mixed_thread_api) is None


def _cef_export_image(
    *,
    target_override: int | None = None,
    dll_name: bytes = b"IndCode.dll",
) -> SimpleNamespace:
    names = sorted(ca01._REQUIRED_CEF_EXPORTS)
    names.extend(
        f"cef_fixture_{index:03d}".encode()
        for index in range(128 - len(names))
    )
    symbols = [
        SimpleNamespace(
            name=name,
            address=(
                target_override
                if target_override is not None and index == 0
                else 0x1100
            ),
        )
        for index, name in enumerate(names)
    ]
    return SimpleNamespace(
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(
            name=dll_name,
            symbols=symbols,
        )
    )


def _valid_cef_recovery(outer_sha256: str) -> ca01.Ca01SideloadRecovery:
    recovery = _valid_recovery(outer_sha256)
    evidence = recovery.structural_evidence
    for key in (
        "vulkan_export_count",
        "export_reachable_thread_config_lineage_present",
        "create_thread_wrapper_reachable",
    ):
        evidence.pop(key)
    evidence.update(
        {
            "outer_profile": ca01._CEF_OUTER_PROFILE,
            "cef_export_count": 205,
            "cef_named_export_count": 205,
            "cef_export_count_with_prefix": 196,
            "cef_required_export_count": len(ca01._REQUIRED_CEF_EXPORTS),
            "coalesced_export_target_count": 1,
            "coalesced_export_peak_count": 205,
            "export_dll_name_matches_indcode": True,
            "mapped_loader_marker_count": len(ca01._CEF_LOADER_MARKERS),
            "mapped_loader_marker_set_complete": True,
            "export_reachable_beginthreadex_config_lineage_present": True,
            "beginthreadex_wrapper_reachable": True,
            "lineage_counts": {
                "export_to_main_direct_call_count": 1,
                "main_to_beginthreadex_wrapper_direct_call_count": 1,
                "beginthreadex_api_call_count": 1,
                "producer_pointer_store_count": 1,
                "callback_trampoline_indirect_call_count": 1,
            },
        }
    )
    return recovery


def test_cef_export_profile_requires_named_coalesced_facade() -> None:
    """必須CEF名が同一stubへ集約されたfacadeだけを受理する。"""

    sections = [
        _section(
            raw_start=0,
            virtual_start=0x180001000,
            size=0x1000,
            executable=True,
        )
    ]

    profile = ca01._cef_export_profile(
        _cef_export_image(),
        sections,
        0x180000000,
    )

    assert profile is not None
    assert profile.export_count == 128
    assert profile.cef_export_count == 128
    assert profile.root == 0x180001100
    assert (
        ca01._cef_export_profile(
            _cef_export_image(target_override=0x1180),
            sections,
            0x180000000,
        )
        is None
    )
    assert (
        ca01._cef_export_profile(
            _cef_export_image(dll_name=b"libcef.dll"),
            sections,
            0x180000000,
        )
        is None
    )


def test_cef_loader_markers_ignore_resource_only_decoys() -> None:
    """10 markerはmapped非resource領域に全て存在する場合だけ成立する。"""

    encoded = b"\0\0".join(
        marker.encode("utf-16le") for marker in ca01._CEF_LOADER_MARKERS
    )
    missing = encoded.replace(
        ca01._CEF_LOADER_MARKERS[-1].encode("utf-16le"),
        b"",
    )
    data = missing + b"\0" * 32 + encoded
    sections = [
        _section(raw_start=0, virtual_start=0x180001000, size=len(missing)),
        _section(
            raw_start=len(missing) + 32,
            virtual_start=0x180002000,
            size=len(encoded),
            resource=True,
        ),
    ]

    assert ca01._cef_loader_markers_present(data, sections) is False
    assert ca01._cef_loader_markers_present(
        encoded,
        [_section(raw_start=0, virtual_start=0x180001000, size=len(encoded))],
    ) is True


def _rip_lea(prefix: bytes, source: int, target: int) -> bytes:
    return prefix + struct.pack("<i", target - (source + len(prefix) + 4))


def _cef_lineage_summaries(
    *,
    argument_register: bytes = b"\x49\x89\xc1",
    trampoline_call: bytes = b"\xff\x11",
    allocation_size: int = 8,
) -> tuple[dict[int, ca01._FunctionSummary], list[ca01._Section]]:
    export = 0x1000
    main = 0x1100
    wrapper = 0x1200
    producer = 0x1400
    trampoline = 0x1500
    allocator = 0x1700
    export_summary = _summary(_call(export, main) + b"\xc3", start=export)
    main_summary = _summary(_call(main, wrapper) + b"\xc3", start=main)

    code = bytearray(b"\xb9" + struct.pack("<I", allocation_size))
    code += _call(wrapper + len(code), allocator)
    source = wrapper + len(code)
    code += _rip_lea(b"\x48\x8d\x0d", source, producer)
    code += b"\x48\x89\x08"
    code += argument_register
    source = wrapper + len(code)
    code += _rip_lea(b"\x4c\x8d\x05", source, trampoline)
    code += b"\x31\xd2\x31\xc9"
    beginthreadex_call = wrapper + len(code)
    code += b"\xff\x15\x00\x00\x00\x00\xc3"
    wrapper_summary = _summary(bytes(code), start=wrapper)
    wrapper_summary.api_calls = [(beginthreadex_call, "_beginthreadex")]
    trampoline_summary = _summary(trampoline_call + b"\xc3", start=trampoline)
    return (
        {
            export: export_summary,
            main: main_summary,
            wrapper: wrapper_summary,
            trampoline: trampoline_summary,
        },
        [
            _section(
                raw_start=0,
                virtual_start=0x1000,
                size=0x1000,
                executable=True,
            )
        ],
    )


def test_cef_callback_requires_argument_cell_and_rcx_trampoline() -> None:
    """producer cellのR9引渡しとtrampolineのcall [rcx]を同時に要求する。"""

    summaries, sections = _cef_lineage_summaries()
    lineage = ca01._cef_callback_lineage(
        sections,
        0x1000,
        summaries.get,
    )

    assert lineage is not None
    assert lineage.producer == 0x1400
    wrong_argument, _ = _cef_lineage_summaries(
        argument_register=b"\x49\x89\xd9"
    )
    wrong_trampoline, _ = _cef_lineage_summaries(
        trampoline_call=b"\xff\x12"
    )
    assert ca01._cef_callback_lineage(
        sections, 0x1000, wrong_argument.get
    ) is None
    assert ca01._cef_callback_lineage(
        sections, 0x1000, wrong_trampoline.get
    ) is None


def test_cef_callback_rejects_broken_cell_allocation_lineage() -> None:
    """8-byte call返値とstore後のR9 cell identityが崩れた経路を拒否する。"""

    wrong_size, sections = _cef_lineage_summaries(allocation_size=16)
    clobbered_cell, _ = _cef_lineage_summaries(
        argument_register=b"\x48\x31\xc0\x49\x89\xc1"
    )

    assert ca01._cef_callback_lineage(
        sections, 0x1000, wrong_size.get
    ) is None
    assert ca01._cef_callback_lineage(
        sections, 0x1000, clobbered_cell.get
    ) is None


def test_cef_trampoline_requires_preserved_rcx_and_mandatory_unique_callback() -> None:
    """entry RCXの変更、追加indirect call、callback迂回branchを拒否する。"""

    clobbered_rcx, sections = _cef_lineage_summaries(
        trampoline_call=b"\x48\x89\xc1\xff\x11"
    )
    extra_indirect, _ = _cef_lineage_summaries(
        trampoline_call=b"\xff\x12\xff\x11"
    )
    conditional_skip, _ = _cef_lineage_summaries(
        trampoline_call=b"\x85\xc0\x74\x02\xff\x11"
    )

    for summaries in (clobbered_rcx, extra_indirect, conditional_skip):
        assert ca01._cef_callback_lineage(
            sections,
            0x1000,
            summaries.get,
        ) is None


def test_builder_accepts_two_reachable_double_decode_chains() -> None:
    """実CA01と同じconverter共有・2組の二重decodeだけを強い証拠にする。"""

    code, decoder = _builder_code()
    evidence = ca01._builder_decoder_evidence(_summary(code), decoder)

    assert evidence == {
        "double_decode_chain_count": 2,
        "same_decoder_call_count": 4,
        "shared_input_converter_present": True,
        "single_reachable_builder_path_present": True,
    }


def test_builder_rejects_conflicting_converter_and_dead_code_union() -> None:
    """相反converterとRET後のdead decodeを到達可能証拠へ混在させない。"""

    conflicting, decoder = _builder_code(converters=(0x3000, 0x3100))
    dead, dead_decoder = _builder_code(dead_second_chain=True)

    assert ca01._builder_decoder_evidence(_summary(conflicting), decoder) is None
    assert ca01._builder_decoder_evidence(_summary(dead), dead_decoder) is None


def test_base64_decoder_requires_one_complete_table_base() -> None:
    """allocationから同一baseの0..63とlookupまで揃う場合だけ受理する。"""

    complete = ca01._base64_decoder_evidence(_summary(_decoder_code()))
    split = ca01._base64_decoder_evidence(
        _summary(_decoder_code(split_last_value=True))
    )
    dead = ca01._base64_decoder_evidence(
        _summary(_decoder_code(dead_accumulation=True))
    )

    assert complete is not None
    assert complete["allocation_table_lookup_dataflow_present"] is True
    assert split is None
    assert dead is None


def test_cfg_path_rejects_event_skipped_by_unconditional_branch() -> None:
    """address順で挟まるだけのdead callは同一data-flowとみなさない。"""

    start = 0x1000
    dead_call = start + 5
    live_return = dead_call + 6
    code = b"\xe9" + struct.pack("<i", live_return - (start + 5))
    code += _call(dead_call, 0x3000) + b"\xc3\xc3"
    summary = _summary(code, start=start)

    assert ca01._events_form_reachable_path(summary, [start, dead_call]) is False


def test_constant_false_branch_and_its_register_source_are_rejected() -> None:
    """既知zero flagで不成立の枝をeventにも引数sourceにも使わない。"""

    start = 0x1000
    dead_setup = start + 9
    call_address = start + 14
    code = b"\x31\xc0\x75\x05"  # xor eax,eax; jne dead_setup (false)
    code += b"\xe9\x05\x00\x00\x00"  # jmp call_address
    code += b"\xb9\x07\x00\x00\x00"  # dead: mov ecx, 7
    code += _call(call_address, 0x3000) + b"\xc3"
    summary = _summary(code, start=start)

    assert (
        ca01._events_form_reachable_path(summary, [start, dead_setup, call_address])
        is False
    )
    assert (
        ca01._latest_register_source(
            summary,
            call_address,
            {ca01.X86_REG_RCX, ca01.X86_REG_ECX},
        )
        is None
    )


def test_copy_helper_rejects_ret_only_and_call_only_decoys() -> None:
    """copy callsiteの形だけではRET-only／call-only helperを受理しない。"""

    ret_only = _summary(b"\xc3")
    call_only = _summary(_call(0x1000, 0x3000) + b"\xc3")

    for summary in (ret_only, call_only):
        assert ca01._copy_helper_evidence(summary, literal=True) is None
        assert ca01._copy_helper_evidence(summary, literal=False) is None


def test_consumer_requires_same_buffer_for_protect_call_and_restore() -> None:
    """実行許可、間接call、保護復帰のbuffer identityを統一する。"""

    valid = ca01._consumer_evidence(_consumer_summary())
    changed_restore = ca01._consumer_evidence(_consumer_summary(restore_begin=-0x40))
    changed_indirect = ca01._consumer_evidence(_consumer_summary(indirect_begin=-0x40))

    assert valid is not None
    assert valid["protected_buffer_identity_preserved"] is True
    assert valid["restored_protection_value_lineage_present"] is True
    assert changed_restore is None
    assert changed_indirect is None


def test_cfg_and_register_state_limits_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """敵対的CFGでedge／backward state上限をtruncateして成功させない。"""

    summary = _summary(
        b"\x90\x90\xb9\x07\x00\x00\x00" + _call(0x1007, 0x3000) + b"\xc3"
    )
    monkeypatch.setattr(ca01, "MAXIMUM_CFG_EDGE_COUNT", 1)

    assert ca01._reachable_instruction_addresses(summary) is None
    assert (
        ca01._latest_register_source(
            summary,
            0x1007,
            {ca01.X86_REG_RCX, ca01.X86_REG_ECX},
        )
        is None
    )


def test_unresolved_indirect_control_flow_cannot_be_terminal_evidence() -> None:
    """未知indirect jumpは記録し、設定producerの終端証拠として拒否する。"""

    start = 0x1000
    code = b"\xff\xe0"  # jmp rax
    section = _section(
        raw_start=0,
        virtual_start=start,
        size=len(code),
        executable=True,
    )
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    summary = ca01._function_summary(
        code,
        [section],
        disassembler,
        start,
        {},
    )

    assert summary is not None
    assert summary.unresolved_control_flow_count == 1
    assert (
        ca01._parse_producer(
            code,
            [section],
            disassembler,
            start,
            [],
            lambda _address: summary,
        )
        is None
    )


def test_probe_projection_never_includes_private_config_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """終端probeはendpoint、token、label、addressを件数へ射影する。"""

    recovery = _valid_recovery("a" * 64)
    recovery.config["slots"][0]["private_token"] = "UEVSSU9ESUM="
    recovery.config["slots"][0]["private_label"] = "秘密ラベル"
    recovery.structural_evidence["raw_endpoint_decoy"] = "198.51.100.24"
    recovery.structural_evidence["raw_token_decoy"] = "UEVSSU9ESUM="
    recovery.structural_evidence["nested_decoy"] = {
        "label": "秘密ラベル",
        "address": "0x180012340",
    }
    monkeypatch.setattr(ca01, "recover_config", lambda _data: recovery)

    probe = ca01.probe_config(b"MZ")
    serialized = json.dumps(probe, ensure_ascii=False)

    for private_value in (
        "198.51.100.24",
        "443",
        "UEVSSU9ESUM=",
        "秘密ラベル",
        "0x1800",
        recovery.config["configuration_identity_sha256"],
    ):
        assert private_value not in serialized
    assert '"endpoint_count": 2' in serialized
    assert probe["config"]["slot_count"] == 3
    assert '"raw_network_values_included": false' in serialized
    assert probe["family"] is None
    assert probe["supports_family_attribution"] is False
    assert probe["terminal_family_confirmed"] is False


def test_probe_confirms_family_only_for_reviewed_exact_outer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """強い構造だけでは未知hashを昇格せず、既知CA01完全一致だけを確定する。"""

    recovery = _valid_recovery(ca01._REVIEWED_CA01_OUTER_SHA256)
    monkeypatch.setattr(ca01, "recover_config", lambda _data: recovery)

    probe = ca01.probe_config(b"MZ")

    assert probe["family"] == "valleyrat"
    assert probe["supports_family_attribution"] is True
    assert probe["terminal_family_confirmed"] is True
    assert probe["classification_confidence"] == "high_structural_decoded_config"
    assert probe["config"]["slot_count"] == 3


def test_unknown_cef_profile_recovers_config_but_remains_route_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CEF構造だけでは未知hashをfamily確定へ昇格しない。"""

    recovery = _valid_cef_recovery("b" * 64)
    assert ca01.validate_recovery_contract(recovery) is True
    monkeypatch.setattr(ca01, "recover_config", lambda _data: recovery)

    probe = ca01.probe_config(b"MZ")

    assert probe["matched"] is True
    assert probe["outer_profile"] == ca01._CEF_OUTER_PROFILE
    assert probe["static_config_recovered"] is True
    assert probe["family"] is None
    assert probe["supports_family_attribution"] is False
    assert probe["terminal_family_confirmed"] is False
    assert probe["attribution_scope"] == "component_handler_route"


def test_reviewed_hash_must_match_its_outer_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """レビュー済みhashへ別profile証拠を結合する混在を拒否する。"""

    monkeypatch.setitem(
        ca01._REVIEWED_CA01_OUTER_PROFILES,
        _SYNTHETIC_REVIEWED_CEF_SHA256,
        ca01._CEF_OUTER_PROFILE,
    )
    wrong_profile = _valid_recovery(_SYNTHETIC_REVIEWED_CEF_SHA256)

    assert ca01.validate_recovery_contract(wrong_profile) is False


def test_synthetic_reviewed_cef_mapping_controls_family_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CEF family確定分岐はtest内だけの合成reviewed mappingで検証する。"""

    recovery = _valid_cef_recovery(_SYNTHETIC_REVIEWED_CEF_SHA256)
    monkeypatch.setattr(ca01, "recover_config", lambda _data: recovery)

    route_only = ca01.probe_config(b"MZ synthetic CEF route")
    assert route_only["family"] is None
    assert route_only["terminal_family_confirmed"] is False

    monkeypatch.setitem(
        ca01._REVIEWED_CA01_OUTER_PROFILES,
        _SYNTHETIC_REVIEWED_CEF_SHA256,
        ca01._CEF_OUTER_PROFILE,
    )
    reviewed = ca01.probe_config(b"MZ synthetic CEF reviewed")

    assert reviewed["family"] == "valleyrat"
    assert reviewed["terminal_family_confirmed"] is True


@pytest.mark.parametrize(
    "lineage_key",
    (
        "export_to_main_direct_call_count",
        "main_to_beginthreadex_wrapper_direct_call_count",
        "beginthreadex_api_call_count",
        "producer_pointer_store_count",
        "callback_trampoline_indirect_call_count",
    ),
)
def test_cef_contract_rejects_boolean_lineage_counts(lineage_key: str) -> None:
    """boolを整数1としてCEF lineage countへ受理しない。"""

    recovery = _valid_cef_recovery("b" * 64)
    recovery.structural_evidence["lineage_counts"][lineage_key] = True

    assert ca01.validate_recovery_contract(recovery) is False


def test_profiles_reject_partial_opposite_evidence_union() -> None:
    """profile名を跨いだ部分的なflag/count unionも拒否する。"""

    cef_recovery = _valid_cef_recovery("b" * 64)
    cef_recovery.structural_evidence[
        "export_reachable_thread_config_lineage_present"
    ] = True
    cef_recovery.structural_evidence["lineage_counts"][
        "thread_factory_to_create_thread_wrapper_count"
    ] = 1

    vulkan_recovery = _valid_recovery("c" * 64)
    vulkan_recovery.structural_evidence[
        "mapped_loader_marker_set_complete"
    ] = True
    vulkan_recovery.structural_evidence["lineage_counts"][
        "callback_trampoline_indirect_call_count"
    ] = 1

    assert ca01.validate_recovery_contract(cef_recovery) is False
    assert ca01.validate_recovery_contract(vulkan_recovery) is False


def test_recover_config_rejects_ambiguous_outer_profiles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Vulkan型とCEF型が同時成立した場合は一方を恣意的に選ばない。"""

    monkeypatch.setattr(ca01, "_recover", lambda _data: _valid_recovery("b" * 64))
    monkeypatch.setattr(
        ca01,
        "_recover_cef",
        lambda _data: _valid_cef_recovery("c" * 64),
    )

    profile_markers = b"|".join(
        [ca01._VULKAN_EXPORT, *sorted(ca01._REQUIRED_CEF_EXPORTS)]
    )
    assert ca01.recover_config(b"MZ ambiguous profiles " + profile_markers) is None


def test_recover_config_skips_both_profiles_without_export_markers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """一般PEは高コストな両profile復元を開始せず不一致にする。"""

    monkeypatch.setattr(
        ca01,
        "_recover",
        lambda _data: pytest.fail("Vulkan export marker不在で復元してはいけません"),
    )
    monkeypatch.setattr(
        ca01,
        "_recover_cef",
        lambda _data: pytest.fail("CEF export marker不在で復元してはいけません"),
    )

    assert ca01.recover_config(b"MZ unrelated PE") is None


def test_invalid_or_oversized_input_is_fail_closed() -> None:
    """非bytes、非PE、入力上限超過はいずれも例外なく未一致とする。"""

    assert ca01.recover_config(b"not-a-pe") is None
    assert ca01.recover_config(bytearray(b"MZ")) is None  # type: ignore[arg-type]
    assert ca01.recover_config(b"MZ" + b"\0" * ca01.MAXIMUM_INPUT_SIZE) is None
