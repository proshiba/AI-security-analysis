"""x64直結型ValleyRAT終端解析器のfail-closed境界を検証する。"""

from __future__ import annotations

import struct
from types import SimpleNamespace

from extractors.valleyrat import direct_native_terminal as terminal


def _strings(values: tuple[str, ...], *, base: int = 0x1000):
    return tuple(
        terminal._WideString(base + index * 16, value)
        for index, value in enumerate(values)
    )


def test_config_cluster_requires_two_external_and_one_loopback_slot():
    clusters = terminal._config_clusters(
        _strings(
            (
                "443",
                "198.51.100.10",
                "8443",
                "example.test",
                "80",
                "127.0.0.1",
            )
        )
    )

    assert len(clusters) == 1
    assert len(clusters[0].external_slots) == 2
    assert clusters[0].slots[2].loopback is True


def test_config_cluster_rejects_host_port_reordering_and_three_external_slots():
    reordered = _strings(
        (
            "198.51.100.10",
            "443",
            "8443",
            "example.test",
            "80",
            "127.0.0.1",
        )
    )
    all_external = _strings(
        (
            "443",
            "198.51.100.10",
            "8443",
            "example.test",
            "80",
            "203.0.113.20",
        )
    )

    assert terminal._config_clusters(reordered) == ()
    assert terminal._config_clusters(all_external) == ()


def test_non_pe_input_never_supports_family_attribution():
    result = terminal.probe_direct_native_terminal_config(b"MZ" + b"\x00" * 40000)

    assert result["matched"] is False
    assert result["family"] is None
    assert result["supports_family_attribution"] is False
    assert result["sample_executed"] is False
    assert result["network_contacted"] is False


def _exception_image(
    ranges: tuple[tuple[int, int], ...], *, image_base: int = 0x140000000
):
    return SimpleNamespace(
        OPTIONAL_HEADER=SimpleNamespace(ImageBase=image_base),
        DIRECTORY_ENTRY_EXCEPTION=[
            SimpleNamespace(
                struct=SimpleNamespace(BeginAddress=begin, EndAddress=end)
            )
            for begin, end in ranges
        ],
    )


def _executable_section(size: int, *, image_base: int = 0x140000000):
    return terminal._Section(
        name=".text",
        address=image_base,
        raw_start=0,
        raw_end=size,
        executable=True,
        writable=False,
    )


def _decode_x64(raw: bytes, *, address: int = 0x140000000):
    disassembler = terminal.Cs(terminal.CS_ARCH_X86, terminal.CS_MODE_64)
    disassembler.detail = True
    return list(disassembler.disasm(raw, address))


def test_dense_exception_table_uses_lightweight_summaries_and_lazy_detail():
    function_count = 4_096
    data = b"\xc3" * function_count
    image = _exception_image(
        tuple((offset, offset + 1) for offset in range(function_count))
    )

    analyzer = terminal._Analyzer(
        data,
        image,
        (_executable_section(len(data)),),
        {},
    )

    assert analyzer.coverage.complete is True
    assert len(analyzer.summaries) == function_count
    assert analyzer._cache == {}
    first = analyzer.function_starts[0]
    assert len(analyzer.decode(first)) == 1
    assert set(analyzer._cache) == {first}


def test_summary_budget_exhaustion_is_incomplete_without_detailed_decode(
    monkeypatch,
):
    monkeypatch.setattr(terminal, "MAXIMUM_SUMMARY_FUNCTION_BYTES", 4)
    data = b"\xc3" * 8
    image = _exception_image(tuple((offset, offset + 1) for offset in range(8)))

    analyzer = terminal._Analyzer(
        data,
        image,
        (_executable_section(len(data)),),
        {},
    )

    assert analyzer.coverage.complete is False
    assert "direct_native_summary_budget_exceeded" in (
        analyzer.coverage.missing_proof_codes
    )
    assert analyzer._cache == {}


def test_summary_aggregate_value_budget_is_fail_closed(monkeypatch):
    monkeypatch.setattr(terminal, "MAXIMUM_SUMMARY_VALUES", 0)
    data = b"\x0a\x00\xc3"
    analyzer = terminal._Analyzer(
        data,
        _exception_image(((0, len(data)),)),
        (_executable_section(len(data)),),
        {},
    )

    assert analyzer.coverage.complete is False
    assert "direct_native_summary_budget_exceeded" in (
        analyzer.coverage.missing_proof_codes
    )
    assert analyzer.summaries == {}


def test_exception_ranges_reject_overlap_and_non_file_backed_end():
    section = (_executable_section(16),)

    assert terminal._function_ranges(
        _exception_image(((0, 8), (4, 12))), section
    ) is None
    assert terminal._function_ranges(
        _exception_image(((0, 17),)), section
    ) is None


def test_contiguous_branch_fragment_is_merged_but_separate_return_is_not():
    image_base = 0x140000000
    branch = terminal._Analyzer(
        b"\xeb\x00\xc3",
        _exception_image(((0, 2), (2, 3))),
        (_executable_section(3),),
        {},
    )
    separate = terminal._Analyzer(
        b"\xc3\xc3",
        _exception_image(((0, 1), (1, 2))),
        (_executable_section(2),),
        {},
    )

    assert [item.mnemonic for item in branch.decode(image_base)] == ["jmp", "ret"]
    assert [item.mnemonic for item in separate.decode(image_base)] == ["ret"]


def test_gap_separated_fallthrough_fragment_is_not_merged():
    image_base = 0x140000000
    analyzer = terminal._Analyzer(
        b"\x90\x90\x90\xc3",
        _exception_image(((0, 1), (3, 4))),
        (_executable_section(4),),
        {},
    )

    assert [item.mnemonic for item in analyzer.decode(image_base)] == ["nop"]


def test_explicit_branch_merges_noncontiguous_pdata_fragment():
    image_base = 0x140000000
    analyzer = terminal._Analyzer(
        b"\xeb\x01\x90\xc3",
        _exception_image(((0, 2), (3, 4))),
        (_executable_section(4),),
        {},
    )

    assert [item.mnemonic for item in analyzer.decode(image_base)] == ["jmp", "ret"]


def test_internal_fragment_request_is_canonicalized_to_fallthrough_root():
    image_base = 0x140000000
    analyzer = terminal._Analyzer(
        b"\x90\x90\xc3",
        _exception_image(((0, 1), (1, 2), (2, 3))),
        (_executable_section(3),),
        {},
    )

    internal = analyzer.decode(image_base + 1)

    assert [item.mnemonic for item in internal] == ["nop", "nop", "ret"]
    assert analyzer.decode(image_base) is internal
    assert analyzer._range_owner == {0: image_base, 1: image_base, 2: image_base}


def test_terminal_closes_reachable_code_before_embedded_data_table():
    image_base = 0x140000000
    raw = b"\x90\xcc\x0f\x1f\x00" + b"\x11\xe0\x00\x00\xd4\xe1\x00\x00"
    analyzer = terminal._Analyzer(
        raw,
        _exception_image(((0, len(raw)),)),
        (_executable_section(len(raw)),),
        {},
    )

    assert [item.mnemonic for item in analyzer.decode(image_base)] == ["nop", "int3"]
    assert analyzer.coverage.complete is True


def test_reachable_invalid_instruction_is_rejected():
    image_base = 0x140000000
    raw = b"\x90\x0f"
    analyzer = terminal._Analyzer(
        raw,
        _exception_image(((0, len(raw)),)),
        (_executable_section(len(raw)),),
        {},
    )

    assert analyzer.decode(image_base) == []
    assert analyzer.coverage.complete is False
    assert "direct_native_detailed_decode_incomplete" in (
        analyzer.coverage.missing_proof_codes
    )


def _bounded_switch_fixture(byte_table: bytes) -> bytes:
    dispatcher = (
        b"\x48\x8d\x15\xf9\xff\xff\xff"
        b"\x41\x0f\xb6\x06"
        b"\x3c\x01"
        b"\x77\x31"
        b"\x0f\xb6\x84\x02\x88\x00\x00\x00"
        b"\x8b\x8c\x82\x80\x00\x00\x00"
        b"\x48\x01\xd1"
        b"\xff\xe1"
    )
    raw = bytearray(b"\xcc" * 0x88)
    raw[: len(dispatcher)] = dispatcher
    raw[0x40] = 0xC3
    raw[0x50] = 0xC3
    raw[0x80:0x88] = b"\x40\x00\x00\x00\x50\x00\x00\x00"
    raw.extend(byte_table)
    return bytes(raw)


def test_bounded_two_stage_switch_adds_only_validated_case_targets():
    image_base = 0x140000000
    raw = _bounded_switch_fixture(b"\x00\x01")
    analyzer = terminal._Analyzer(
        raw,
        _exception_image(((0, len(raw)),)),
        (_executable_section(len(raw)),),
        {},
    )

    instructions = analyzer.decode(image_base)

    assert {item.address for item in instructions if item.mnemonic == "ret"} == {
        image_base + 0x40,
        image_base + 0x50,
    }
    assert analyzer.coverage.complete is True


def test_bounded_switch_accepts_contiguous_predecessor_base_definition():
    image_base = 0x140000000
    raw = _bounded_switch_fixture(b"\x00\x01")
    analyzer = terminal._Analyzer(
        raw,
        _exception_image(((0, len(raw)),)),
        (_executable_section(len(raw)),),
        {},
    )
    split_context = raw[:15] + b"\x41\x89\xcc" + raw[15:35]
    decoded_context = _decode_x64(split_context, address=image_base)

    targets = analyzer._indexed_switch_targets(
        analyzer.function_ranges[0],
        decoded_context[1:],
        decoded_context,
    )

    assert targets == (image_base + 0x40, image_base + 0x50)


def test_bounded_switch_rejects_clobbered_predecessor_base_definition():
    image_base = 0x140000000
    raw = _bounded_switch_fixture(b"\x00\x01")
    analyzer = terminal._Analyzer(
        raw,
        _exception_image(((0, len(raw)),)),
        (_executable_section(len(raw)),),
        {},
    )
    clobbered = (
        raw[:7]
        + b"\x48\x31\xd2"
        + raw[7:15]
        + b"\x41\x89\xcc"
        + raw[15:35]
    )
    decoded_context = _decode_x64(clobbered, address=image_base)

    assert (
        analyzer._indexed_switch_targets(
            analyzer.function_ranges[0],
            decoded_context[2:],
            decoded_context,
        )
        is None
    )


def test_unknown_or_inconsistent_indirect_switch_is_fail_closed():
    image_base = 0x140000000
    raw = _bounded_switch_fixture(b"\x00\x02")
    analyzer = terminal._Analyzer(
        raw,
        _exception_image(((0, len(raw)),)),
        (_executable_section(len(raw)),),
        {},
    )

    assert analyzer.decode(image_base) == []
    assert analyzer.coverage.complete is False


def test_switch_reaching_value_aggregate_budget_is_fail_closed(monkeypatch):
    image_base = 0x140000000
    raw = _bounded_switch_fixture(b"\x00\x01")
    analyzer = terminal._Analyzer(
        raw,
        _exception_image(((0, len(raw)),)),
        (_executable_section(len(raw)),),
        {},
    )
    split_context = raw[:15] + b"\x41\x89\xcc" + raw[15:35]
    decoded_context = _decode_x64(split_context, address=image_base)
    monkeypatch.setattr(terminal, "MAXIMUM_SWITCH_REACHING_TOTAL_NODES", 0)

    assert (
        analyzer._indexed_switch_targets(
            analyzer.function_ranges[0],
            decoded_context[1:],
            decoded_context,
        )
        is None
    )
    assert "direct_native_detailed_decode_budget_exceeded" in (
        analyzer.coverage.missing_proof_codes
    )


def test_thread_entry_roots_require_r8_rip_relative_pdata_start():
    image_base = 0x140000000
    analyzer = terminal._Analyzer(
        b"\xc3" + b"\x90" * 15 + b"\xc3",
        _exception_image(((0, 1), (16, 17))),
        (_executable_section(17),),
        {},
    )
    r8_reference = _decode_x64(
        b"\x4c\x8d\x05\x09\xff\xff\xff",
        address=image_base + 0x100,
    )
    rdx_reference = _decode_x64(
        b"\x48\x8d\x15\x09\xff\xff\xff",
        address=image_base + 0x100,
    )

    assert terminal._thread_entry_roots(analyzer, r8_reference) == [image_base + 16]
    assert terminal._thread_entry_roots(analyzer, rdx_reference) == []


def test_fragment_budget_exhaustion_is_fail_closed(monkeypatch):
    image_base = 0x140000000
    monkeypatch.setattr(terminal, "MAXIMUM_FUNCTION_FRAGMENTS", 1)
    analyzer = terminal._Analyzer(
        b"\xeb\x00\xc3",
        _exception_image(((0, 2), (2, 3))),
        (_executable_section(3),),
        {},
    )

    assert analyzer.decode(image_base) == []
    assert analyzer.coverage.complete is False


def test_oversized_runtime_range_is_rejected_before_instruction_decode(monkeypatch):
    image_base = 0x140000000
    size = terminal.MAXIMUM_FUNCTION_BYTES + 1
    analyzer = terminal._Analyzer(
        b"\x90" * size,
        _exception_image(((0, size),)),
        (_executable_section(size),),
        {},
    )

    def unexpected_decode(*_args, **_kwargs):
        raise AssertionError("oversized rangeをdecodeしてはならない")

    monkeypatch.setattr(terminal, "_mapped_x64_instruction", unexpected_decode)

    assert analyzer.decode(image_base) == []
    assert "direct_native_per_function_decode_limit_exceeded" in (
        analyzer.coverage.missing_proof_codes
    )


def test_pdata_free_leaf_setter_requires_bounded_ret_terminated_store():
    image_base = 0x140000000
    data = b"\xc3" + b"\x90" * 15 + b"\x48\x89\x51\x20\xc3"
    analyzer = terminal._Analyzer(
        data,
        _exception_image(((0, 1),)),
        (_executable_section(len(data)),),
        {},
    )

    instructions = analyzer.decode_leaf_setter(image_base + 16)

    assert [item.mnemonic for item in instructions] == ["mov", "ret"]
    assert terminal._setter_displacement(instructions) == 0x20


def test_pdata_free_leaf_setter_rejects_control_flow_and_budget(monkeypatch):
    image_base = 0x140000000
    data = b"\xc3" + b"\x90" * 15 + b"\xeb\x00\xc3"
    analyzer = terminal._Analyzer(
        data,
        _exception_image(((0, 1),)),
        (_executable_section(len(data)),),
        {},
    )

    assert analyzer.decode_leaf_setter(image_base + 16) == []

    monkeypatch.setattr(terminal, "MAXIMUM_DETAILED_LEAF_ATTEMPTS", 0)
    budgeted = terminal._Analyzer(
        b"\xc3" + b"\x90" * 15 + b"\x48\x89\x51\x20\xc3",
        _exception_image(((0, 1),)),
        (_executable_section(21),),
        {},
    )
    assert budgeted.decode_leaf_setter(image_base + 16) == []
    assert "direct_native_detailed_decode_budget_exceeded" in (
        budgeted.coverage.missing_proof_codes
    )


def test_pdata_free_leaf_setter_rejects_extra_semantic_instruction():
    image_base = 0x140000000
    data = b"\xc3" + b"\x90" * 15 + b"\x48\x89\xd1\x48\x89\x51\x20\xc3"
    analyzer = terminal._Analyzer(
        data,
        _exception_image(((0, 1),)),
        (_executable_section(len(data)),),
        {},
    )

    assert analyzer.decode_leaf_setter(image_base + 16) == []


def test_pdata_free_executable_branch_target_marks_coverage_incomplete():
    image_base = 0x140000000
    raw = b"\xeb\x02\xcc\xcc\xc3"
    analyzer = terminal._Analyzer(
        raw,
        _exception_image(((0, 2),)),
        (_executable_section(len(raw)),),
        {},
    )

    assert [item.mnemonic for item in analyzer.decode(image_base)] == ["jmp"]
    assert "direct_native_detailed_decode_incomplete" in (
        analyzer.coverage.missing_proof_codes
    )
    assert "direct_native_reachable_direct_branch_unresolved" in (
        analyzer.coverage.missing_proof_codes
    )


def test_unmapped_reachable_branch_target_marks_coverage_incomplete():
    image_base = 0x140000000
    target = image_base + 0x1000
    raw = b"\xe9" + struct.pack("<i", target - (image_base + 5))
    analyzer = terminal._Analyzer(
        raw,
        _exception_image(((0, len(raw)),)),
        (_executable_section(len(raw)),),
        {},
    )

    assert [item.mnemonic for item in analyzer.decode(image_base)] == ["jmp"]
    assert "direct_native_reachable_direct_branch_unresolved" in (
        analyzer.coverage.missing_proof_codes
    )


def test_terminal_jump_allows_only_exact_stack_cookie_fast_fail_leaf():
    image_base = 0x140000000
    fast_fail = b"\xb9\x02\x00\x00\x00\xcd\x29\xc3"
    direct = terminal._Analyzer(
        b"\xeb\x02\xcc\xcc" + fast_fail,
        _exception_image(((0, 2),)),
        (_executable_section(4 + len(fast_fail)),),
        {},
    )
    conditional = terminal._Analyzer(
        b"\x74\x02\xcc\xcc" + fast_fail,
        _exception_image(((0, 2),)),
        (_executable_section(4 + len(fast_fail)),),
        {},
    )

    assert [item.mnemonic for item in direct.decode(image_base)] == ["jmp"]
    assert direct.coverage.complete is True
    assert [item.mnemonic for item in conditional.decode(image_base)] == ["je"]
    assert "direct_native_detailed_decode_incomplete" in (
        conditional.coverage.missing_proof_codes
    )


def test_import_register_tracking_stops_at_clobber():
    raw_load = b"\x48\x8b\x05\x20\x00\x00\x00"
    positive = _decode_x64(raw_load + b"\xff\xd0")
    clobbered = _decode_x64(raw_load + b"\x31\xc0\xff\xd0")
    import_target = terminal._rip_target(positive[0], positive[0].operands[1])
    assert import_target is not None
    imports = {import_target: "recv"}

    assert terminal._api_calls(positive, imports) == [(1, "recv")]
    assert terminal._api_calls(clobbered, imports) == []


def test_import_register_tracking_does_not_cross_return_or_address_gap():
    loaded_then_returned = _decode_x64(
        b"\x48\x8b\x05\x00\x00\x00\x00\xc3",
        address=0x1000,
    )
    separate_call = _decode_x64(b"\xff\xd0\xc3", address=0x2000)
    import_target = terminal._rip_target(
        loaded_then_returned[0], loaded_then_returned[0].operands[1]
    )

    assert import_target is not None
    assert terminal._api_calls(
        loaded_then_returned + separate_call,
        {import_target: "socket"},
    ) == []


def test_import_and_vcall_tracking_reject_untracked_or_clobbered_registers():
    imported_via_rbx = _decode_x64(
        b"\x48\x8b\x1d\x20\x00\x00\x00\xff\xd3"
    )
    import_target = terminal._rip_target(
        imported_via_rbx[0], imported_via_rbx[0].operands[1]
    )
    assert import_target is not None
    assert terminal._api_calls(imported_via_rbx, {import_target: "recv"}) == []

    vcall = _decode_x64(b"\x48\x8b\x41\x20\xff\xd0")
    vcall_clobbered = _decode_x64(b"\x48\x8b\x41\x20\x31\xc0\xff\xd0")
    vcall_via_rbx = _decode_x64(b"\x48\x8b\x59\x20\xff\xd3")
    assert terminal._vcall_slots(vcall) == [(1, 0x20)]
    assert terminal._vcall_slots(vcall_clobbered) == []
    assert terminal._vcall_slots(vcall_via_rbx) == []


def test_register_tracking_requires_all_mutually_exclusive_paths_to_agree():
    instructions = _decode_x64(
        b"\x85\xc9\x74\x09"
        b"\x48\x8b\x05\x00\x00\x00\x00\xeb\x07"
        b"\x48\x8b\x05\x00\x00\x00\x00"
        b"\xff\xd0\xc3",
        address=0x1000,
    )
    first_target = terminal._rip_target(
        instructions[2], instructions[2].operands[1]
    )
    second_target = terminal._rip_target(
        instructions[4], instructions[4].operands[1]
    )

    assert first_target is not None and second_target is not None
    assert terminal._api_calls(
        instructions,
        {first_target: "recv", second_target: "send"},
    ) == []


def test_vcall_tracking_does_not_cross_return_or_address_gap():
    loaded_then_returned = _decode_x64(
        b"\x48\x8b\x41\x20\xc3",
        address=0x1000,
    )
    separate_call = _decode_x64(b"\xff\xd0\xc3", address=0x2000)

    assert terminal._vcall_slots(loaded_then_returned + separate_call) == []


def test_pdata_setter_requires_only_one_rcx_rdx_store():
    valid = _decode_x64(b"\x48\x89\x51\x20\xc3")
    extra_store = _decode_x64(b"\x48\x89\x51\x20\x48\x89\x49\x28\xc3")
    wrong_source = _decode_x64(b"\x48\x89\x41\x20\xc3")

    assert terminal._setter_displacement(valid) == 0x20
    assert terminal._setter_displacement(extra_store) is None
    assert terminal._setter_displacement(wrong_source) is None


def test_socket_dataflow_stops_at_register_clobber():
    stored = _decode_x64(b"\x48\x89\xcb\xff\xd0\x48\x89\x43\x20")
    result_clobbered = _decode_x64(
        b"\x48\x89\xcb\xff\xd0\x31\xc0\x48\x89\x43\x20"
    )
    loaded = _decode_x64(b"\x48\x89\xcb\x48\x8b\x4b\x20\xff\xd0")
    argument_clobbered = _decode_x64(
        b"\x48\x89\xcb\x48\x8b\x4b\x20\x31\xc9\xff\xd0"
    )

    location = terminal._socket_store_displacement(stored, 1)
    assert location == terminal._SocketLocation(
        displacement=0x20,
        object_origin="entry:rcx",
        store_address=stored[2].address,
    )
    assert terminal._socket_store_displacement(result_clobbered, 1) is None
    assert terminal._call_uses_socket(loaded, 2, location) is True
    assert terminal._call_uses_socket(argument_clobbered, 3, location) is False


def test_socket_dataflow_rejects_same_offset_on_different_object():
    location = terminal._SocketLocation(
        displacement=0x20,
        object_origin="entry:rcx",
        store_address=0x5000,
    )
    different_object = _decode_x64(
        b"\x48\x89\xd3\x48\x8b\x4b\x20\xff\xd0"
    )

    assert terminal._call_uses_socket(different_object, 2, location) is False


def test_socket_store_must_dominate_same_function_load():
    instructions = _decode_x64(
        b"\x85\xd2\x74\x04"
        b"\x48\x89\x41\x20"
        b"\x48\x8b\x49\x20\xff\xd0"
    )
    location = terminal._SocketLocation(
        displacement=0x20,
        object_origin="entry:rcx",
        store_address=instructions[2].address,
    )

    assert terminal._call_uses_socket(instructions, 4, location) is False


def test_argument_assignment_stops_at_register_clobber():
    rip_loaded = _decode_x64(b"\x48\x8d\x15\x20\x00\x00\x00\xff\xd0")
    rip_clobbered = _decode_x64(
        b"\x48\x8d\x15\x20\x00\x00\x00\x31\xd2\xff\xd0"
    )
    size_loaded = _decode_x64(b"\x41\xb8\x50\x12\x00\x00\xff\xd0")
    size_clobbered = _decode_x64(
        b"\x41\xb8\x50\x12\x00\x00\x45\x31\xc0\xff\xd0"
    )

    expected = terminal._rip_target(rip_loaded[0], rip_loaded[0].operands[1])
    assert terminal._previous_rip_assignment(
        rip_loaded,
        1,
        register=terminal.X86_REG_RDX,
        mnemonic="lea",
    ) == expected
    assert terminal._previous_rip_assignment(
        rip_clobbered,
        2,
        register=terminal.X86_REG_RDX,
        mnemonic="lea",
    ) is None
    assert terminal._previous_immediate_assignment(
        size_loaded,
        1,
        family="r8",
        value=0x1250,
    ) is True
    assert terminal._previous_immediate_assignment(
        size_clobbered,
        2,
        family="r8",
        value=0x1250,
    ) is False


def test_parser_and_send_frame_evidence_must_share_one_cfg_path():
    parser = _decode_x64(
        b"\x48\x8d\x41\x10\x85\xd2\x74\x0e"
        b"\x48\x8b\x18\x48\x8b\x58\x08\xba\x0e\x00\x00\x00\xeb\x0e"
        b"\x48\x8b\x5e\x04\x48\x8b\x5e\x0c"
        b"\x48\x8b\x59\x28\xff\x13\xc3"
    )
    send = _decode_x64(
        b"\x85\xd2\x74\x0a"
        b"\x8b\x41\x10\xba\x0e\x00\x00\x00\xeb\x06"
        b"\x41\xb8\x0a\x00\x00\x00\xff\xd0"
    )
    positive_send = _decode_x64(
        b"\x8b\x41\x10\xba\x0e\x00\x00\x00"
        b"\x41\xb8\x0a\x00\x00\x00\xff\xd0"
    )

    assert terminal._parser_frame_proof(
        parser,
        marker_displacement=0x18,
        callback_displacement=0x28,
    ) is False
    assert terminal._send_frame_path_proof(
        send,
        6,
        marker_displacement=0x18,
    ) is False
    assert terminal._send_frame_path_proof(
        positive_send,
        3,
        marker_displacement=0x18,
    ) is True


def test_reaching_value_budget_marks_coverage_incomplete(monkeypatch):
    monkeypatch.setattr(terminal, "MAXIMUM_REACHING_VALUE_NODES", 8)
    image_base = 0x140000000
    raw = b"\x90" * 16 + b"\xe8\x00\x00\x00\x00\xc3"
    instructions = _decode_x64(raw, address=image_base)
    coverage = terminal._DecodeCoverage()

    assert terminal._copy_calls(
        instructions,
        (_executable_section(len(raw), image_base=image_base),),
        coverage,
    ) == []
    assert coverage.complete is False
    assert "direct_native_detailed_decode_incomplete" in coverage.missing_proof_codes


def test_copy_call_does_not_correlate_arguments_across_address_gap():
    destination = _decode_x64(b"\xb9\x00\x30\x00\x00", address=0x1000)
    remaining = _decode_x64(
        b"\xba\xff\x00\x00\x00\x49\xc7\xc0\x00\x40\x00\x00"
        b"\xe8\xef\x04\x00\x00",
        address=0x2000,
    )

    assert terminal._copy_calls(
        destination + remaining,
        (_executable_section(0x3000, image_base=0x1000),),
    ) == []


def test_direct_target_cap_marks_coverage_incomplete(monkeypatch):
    monkeypatch.setattr(terminal, "MAXIMUM_DIRECT_TARGETS", 1)
    image_base = 0x140000000
    raw = (
        b"\xe8\x0b\x00\x00\x00"
        b"\xe8\x06\x00\x00\x00"
        b"\xc3"
        b"\x90" * 5
        + b"\xc3"
    )
    coverage = terminal._DecodeCoverage()

    assert terminal._direct_targets(
        _decode_x64(raw, address=image_base),
        (_executable_section(len(raw), image_base=image_base),),
        coverage,
    ) == []
    assert "direct_native_detailed_decode_incomplete" in (
        coverage.missing_proof_codes
    )


def _dispatcher_test_analyzer():
    return SimpleNamespace(
        sections=(
            terminal._Section(
                name=".text",
                address=0x2000,
                raw_start=0,
                raw_end=0x400,
                executable=True,
                writable=False,
            ),
        ),
        coverage=terminal._DecodeCoverage(),
    )


def _stub_dispatcher_proofs(monkeypatch):
    monkeypatch.setattr(
        terminal,
        "_callback_table_handler",
        lambda _analyzer, table: 0x2200 if table == 0x1000 else None,
    )
    monkeypatch.setattr(
        terminal,
        "_dispatcher_shape",
        lambda _analyzer, address: (address == 0x2200, 3),
    )


def test_dispatcher_requires_table_store_and_consumer_dataflow(monkeypatch):
    _stub_dispatcher_proofs(monkeypatch)
    unused_table = _decode_x64(
        b"\xff\x50\x18\x48\x8d\x1d\xf6\xef\xff\xff\xc3",
        address=0x2000,
    )
    positive = _decode_x64(
        b"\xff\x50\x18"
        b"\x48\x8d\x05\xf6\xef\xff\xff"
        b"\x48\x89\x45\x20"
        b"\x48\x8d\x4d\x20"
        b"\xe8\x00\x00\x00\x00\xc3",
        address=0x2000,
    )
    analyzer = _dispatcher_test_analyzer()

    assert terminal._dispatcher_from_main(analyzer, unused_table) == (None, 0)
    assert terminal._dispatcher_from_main(analyzer, positive) == (0x2200, 3)


def test_dispatcher_rejects_local_overwrite_before_consumer(monkeypatch):
    _stub_dispatcher_proofs(monkeypatch)
    instructions = _decode_x64(
        b"\xff\x50\x18"
        b"\x48\x8d\x05\xf6\xef\xff\xff"
        b"\x48\x89\x45\x20"
        b"\x48\xc7\x45\x20\x00\x00\x00\x00"
        b"\x48\x8d\x4d\x20"
        b"\xe8\x00\x00\x00\x00\xc3",
        address=0x2000,
    )

    assert terminal._dispatcher_from_main(
        _dispatcher_test_analyzer(), instructions
    ) == (None, 0)


def test_dispatcher_store_must_dominate_consumer_after_setter(monkeypatch):
    _stub_dispatcher_proofs(monkeypatch)
    instructions = _decode_x64(
        b"\xff\x50\x18"
        b"\x48\x8d\x05\xf6\xef\xff\xff"
        b"\x85\xd2\x74\x04"
        b"\x48\x89\x45\x20"
        b"\x48\x8d\x4d\x20"
        b"\xe8\x00\x00\x00\x00\xc3",
        address=0x2000,
    )

    assert terminal._dispatcher_from_main(
        _dispatcher_test_analyzer(), instructions
    ) == (None, 0)


def test_callback_table_has_two_slots_and_strict_destructor_boundary(monkeypatch):
    image_base = 0x1000
    data = bytearray(0x200)
    struct.pack_into("<QQQ", data, 0, 0x2060, 0x2000, 0x1040)
    struct.pack_into("<IIIIII", data, 0x40, 1, 0, 0, 0x60, 0x70, 0x40)
    struct.pack_into("<Q", data, 0x80, 0x2060)
    destructor_raw = (
        b"\x48\x89\xcf\x89\xd3"
        b"\x48\x8d\x05" + struct.pack("<i", 0x1080 - 0x200C)
        + b"\x48\x89\x01"
        + b"\xff\x15" + struct.pack("<i", 0x1090 - 0x2015)
        + b"\xf6\xc3\x01\x74\x08\x48\x89\xf9"
        + b"\xe8" + struct.pack("<i", 0x2050 - 0x2022)
        + b"\xc3"
    )
    destructor = _decode_x64(destructor_raw, address=0x2000)
    sections = (
        terminal._Section(".rdata", 0x1000, 0, 0x100, False, False),
        terminal._Section(".text", 0x2000, 0x100, 0x200, True, False),
    )
    analyzer = SimpleNamespace(
        data=bytes(data),
        image=SimpleNamespace(
            OPTIONAL_HEADER=SimpleNamespace(ImageBase=image_base)
        ),
        sections=sections,
        imports={0x1090: "CloseHandle"},
        coverage=terminal._DecodeCoverage(),
        decode=lambda address: destructor if address == 0x2000 else [],
    )
    monkeypatch.setattr(terminal, "_deallocator_helper_shape", lambda *_args: True)

    assert terminal._callback_table_handler(analyzer, 0x1000) == 0x2060

    invalid_col = bytearray(data)
    struct.pack_into("<I", invalid_col, 0x40, 0)
    analyzer.data = bytes(invalid_col)
    assert terminal._callback_table_handler(analyzer, 0x1000) is None


def test_destructor_rejects_helper_path_that_never_returns(monkeypatch):
    data = bytearray(0x200)
    struct.pack_into("<Q", data, 0x80, 0x2060)
    raw = (
        b"\x48\x89\xcf\x89\xd3"
        b"\x48\x8d\x05" + struct.pack("<i", 0x1080 - 0x200C)
        + b"\x48\x89\x01"
        + b"\xff\x15" + struct.pack("<i", 0x1090 - 0x2015)
        + b"\xf6\xc3\x01\x74\x0a\x48\x89\xf9"
        + b"\xe8" + struct.pack("<i", 0x2050 - 0x2022)
        + b"\xeb\xfe\xc3"
    )
    analyzer = SimpleNamespace(
        data=bytes(data),
        sections=(
            terminal._Section(".rdata", 0x1000, 0, 0x100, False, False),
            terminal._Section(".text", 0x2000, 0x100, 0x200, True, False),
        ),
        imports={0x1090: "CloseHandle"},
        coverage=terminal._DecodeCoverage(),
        decode=lambda address: (
            _decode_x64(raw, address=0x2000) if address == 0x2000 else []
        ),
    )
    monkeypatch.setattr(terminal, "_deallocator_helper_shape", lambda *_args: True)

    assert terminal._callback_destructor_shape(analyzer, 0x2000) is False


def _deallocator_analyzer(*, cycle: bool = False, wrong_this: bool = False):
    image_base = 0x1000
    terminal_address = 0x1020
    terminal_raw = (
        b"\x48\x85\xc9\x74\x12"
        + (b"\x45\x31\xc0" if wrong_this else b"\x49\x89\xc8")
        + b"\x31\xd2"
        + b"\x48\x8b\x0d" + struct.pack("<i", 0x2010 - 0x1031)
        + b"\xff\x15" + struct.pack("<i", 0x2000 - 0x1037)
        + b"\xc3"
    )
    data = bytearray(0x180)
    data[0:5] = b"\xe9" + struct.pack("<i", 0x1010 - 0x1005)
    second_target = 0x1000 if cycle else terminal_address
    data[0x10:0x15] = b"\xe9" + struct.pack("<i", second_target - 0x1015)
    data[0x20 : 0x20 + len(terminal_raw)] = terminal_raw
    sections = (
        terminal._Section(".text", 0x1000, 0, 0x100, True, False),
        terminal._Section(".rdata", 0x2000, 0x100, 0x180, False, False),
    )
    image = _exception_image(
        ((0x20, 0x20 + len(terminal_raw)),),
        image_base=image_base,
    )
    return terminal._Analyzer(
        bytes(data),
        image,
        sections,
        {0x2000: "HeapFree"},
    )


def test_deallocator_helper_requires_bounded_thunks_and_heapfree_dataflow():
    assert terminal._deallocator_helper_shape(
        _deallocator_analyzer(), 0x1000
    ) is True
    assert terminal._deallocator_helper_shape(
        _deallocator_analyzer(cycle=True), 0x1000
    ) is False
    assert terminal._deallocator_helper_shape(
        _deallocator_analyzer(wrong_this=True), 0x1000
    ) is False


def test_register_must_definition_requires_every_cfg_path():
    positive = _decode_x64(
        b"\x48\x85\xc9\x74\x07"
        b"\xb8\x01\x00\x00\x00\xeb\x05"
        b"\xb8\x02\x00\x00\x00\xc3",
        address=0x1000,
    )
    negative = _decode_x64(
        b"\x48\x85\xc9\x74\x07"
        b"\xb8\x01\x00\x00\x00\xeb\x05"
        b"\x90\x90\x90\x90\x90\xc3",
        address=0x1000,
    )

    assert terminal._register_written_on_all_paths(
        positive,
        terminal._instruction_graph(positive),
        len(positive) - 1,
        "rax",
    ) is True
    assert terminal._register_written_on_all_paths(
        negative,
        terminal._instruction_graph(negative),
        len(negative) - 1,
        "rax",
    ) is False


def test_error_mapper_requires_read_only_lookup_and_all_path_return_value():
    base = 0x1000
    table = 0x2000
    raw = (
        b"\x83\xf9\x10\x77\x0c"
        b"\x48\x8d\x15" + struct.pack("<i", table - (base + 12))
        + b"\x8b\x04\x8a\xeb\x10"
        b"\x83\xf9\x20"
        b"\xb8\x16\x00\x00\x00"
        b"\xba\x05\x00\x00\x00"
        b"\x0f\x44\xc2\xc3"
    )
    instructions = _decode_x64(raw, address=base)

    def analyzer(*, writable: bool):
        return SimpleNamespace(
            sections=(
                terminal._Section(".text", base, 0, 0x100, True, False),
                terminal._Section(".rdata", table, 0x100, 0x200, False, writable),
            ),
            imports={},
            coverage=terminal._DecodeCoverage(),
            decode=lambda address: instructions if address == base else [],
        )

    assert terminal._error_mapping_helper_shape(analyzer(writable=False), base) is True
    assert terminal._error_mapping_helper_shape(analyzer(writable=True), base) is False


def test_errno_accessor_requires_provider_offset_and_writable_fallback(monkeypatch):
    base = 0x1000
    provider = 0x1100
    fallback = 0x2000
    raw = (
        b"\x48\x83\xec\x28"
        b"\xe8" + struct.pack("<i", provider - (base + 9))
        + b"\x48\x89\xc1"
        b"\x48\x8d\x15" + struct.pack("<i", fallback - (base + 19))
        + b"\x48\x83\xc0\x20"
        b"\x48\x85\xc9\x48\x0f\x44\xc2"
        b"\x48\x83\xc4\x28\xc3"
    )
    instructions = _decode_x64(raw, address=base)
    monkeypatch.setattr(terminal, "_tls_state_helper_shape", lambda *_args: True)

    def analyzer(*, writable: bool):
        return SimpleNamespace(
            sections=(
                terminal._Section(".text", base, 0, 0x200, True, False),
                terminal._Section(".data", fallback, 0x200, 0x300, False, writable),
            ),
            imports={},
            coverage=terminal._DecodeCoverage(),
            decode=lambda address: instructions if address == base else [],
        )

    assert terminal._errno_accessor_shape(analyzer(writable=True), base) is True
    assert terminal._errno_accessor_shape(analyzer(writable=False), base) is False


def test_heapfree_error_path_requires_mapper_accessor_and_exact_errno_store(monkeypatch):
    base = 0x1000
    heap_global = 0x2000
    heap_import = 0x2010
    error_import = 0x2018
    mapper = 0x1100
    accessor = 0x1200
    raw = bytearray(
        b"\x48\x85\xc9\x74\x36"
        b"\x53\x48\x83\xec\x20\x49\x89\xc8\x31\xd2"
        b"\x48\x8b\x0d\x00\x00\x00\x00"
        b"\xff\x15\x00\x00\x00\x00"
        b"\x85\xc0\x75\x16"
        b"\xff\x15\x00\x00\x00\x00"
        b"\x89\xc1\xe8\x00\x00\x00\x00"
        b"\x89\xc3\xe8\x00\x00\x00\x00"
        b"\x89\x18\x48\x83\xc4\x20\x5b\xc3"
    )
    struct.pack_into("<i", raw, 18, heap_global - (base + 22))
    struct.pack_into("<i", raw, 24, heap_import - (base + 28))
    struct.pack_into("<i", raw, 34, error_import - (base + 38))
    struct.pack_into("<i", raw, 41, mapper - (base + 45))
    struct.pack_into("<i", raw, 48, accessor - (base + 52))
    instructions = _decode_x64(bytes(raw), address=base)
    sections = (
        terminal._Section(".text", base, 0, 0x300, True, False),
        terminal._Section(".data", heap_global, 0x300, 0x400, False, True),
    )
    analyzer = SimpleNamespace(
        sections=sections,
        imports={heap_import: "HeapFree", error_import: "GetLastError"},
        coverage=terminal._DecodeCoverage(),
        decode=lambda address: instructions if address == base else [],
    )
    monkeypatch.setattr(terminal, "_error_mapping_helper_shape", lambda *_args: True)
    monkeypatch.setattr(terminal, "_errno_accessor_shape", lambda *_args: True)

    assert terminal._heap_deallocator_terminal_shape(analyzer, base) is True
    wrong_store = bytearray(raw)
    wrong_store[52:54] = b"\x89\x19"
    analyzer.decode = lambda address: (
        _decode_x64(bytes(wrong_store), address=base) if address == base else []
    )
    assert terminal._heap_deallocator_terminal_shape(analyzer, base) is False


def _source_section(
    raw_start: int,
    rva: int,
    size: int,
    *,
    virtual_size: int | None = None,
):
    return SimpleNamespace(
        Name=b".test\x00\x00\x00",
        PointerToRawData=raw_start,
        SizeOfRawData=size,
        Misc_VirtualSize=size if virtual_size is None else virtual_size,
        VirtualAddress=rva,
        Characteristics=0x40000040,
    )


def test_sections_reject_raw_and_virtual_aliases():
    data = bytes(0x400)
    base_header = SimpleNamespace(ImageBase=0x140000000, SizeOfImage=0x10000)
    raw_alias = SimpleNamespace(
        OPTIONAL_HEADER=base_header,
        sections=(
            _source_section(0, 0x1000, 0x200),
            _source_section(0, 0x3000, 0x200),
        ),
    )
    virtual_alias = SimpleNamespace(
        OPTIONAL_HEADER=base_header,
        sections=(
            _source_section(0, 0x1000, 0x200),
            _source_section(0x200, 0x1100, 0x200),
        ),
    )

    assert terminal._sections(data, raw_alias) is None
    assert terminal._sections(data, virtual_alias) is None


def test_sections_reject_virtual_only_alias_and_classify_zero_fill():
    data = bytes(0x400)
    base_header = SimpleNamespace(ImageBase=0x140000000, SizeOfImage=0x10000)
    virtual_alias = SimpleNamespace(
        OPTIONAL_HEADER=base_header,
        sections=(
            _source_section(0, 0x1000, 0x100, virtual_size=0x300),
            _source_section(0x200, 0x1200, 0x100),
        ),
    )
    valid = SimpleNamespace(
        OPTIONAL_HEADER=base_header,
        sections=(
            _source_section(0, 0x1000, 0x100, virtual_size=0x300),
            _source_section(0x200, 0x1400, 0x100),
        ),
    )

    assert terminal._sections(data, virtual_alias) is None
    sections = terminal._sections(data, valid)
    assert sections is not None
    zero_fill = base_header.ImageBase + 0x1200
    assert terminal._section_for_address(sections, zero_fill) is None
    virtual = terminal._virtual_section_for_address(sections, zero_fill)
    assert virtual is not None
    assert virtual.executable is False


def test_transport_scan_window_budget_is_fail_closed(monkeypatch):
    monkeypatch.setattr(terminal, "MAXIMUM_TRANSPORT_SCAN_WINDOWS", 1)
    coverage = terminal._DecodeCoverage()
    analyzer = SimpleNamespace(
        data=bytes(64),
        sections=(
            terminal._Section(".rdata", 0x1000, 0, 64, False, False),
        ),
        coverage=coverage,
    )

    assert terminal._transport(analyzer) == (None, 0)
    assert "direct_native_transport_scan_budget_exceeded" in (
        coverage.missing_proof_codes
    )
