"""x86 codemark resource終端の厳格な静的復元を検証する。"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from extractors.valleyrat import extractor
from extractors.valleyrat import x86_codemark_resource as x86_resource


def _strong_stage(*, second_host: bytes = b"backup.example") -> bytes:
    """命令として有効な独立構造と2-slot設定を持つ合成x86 stage。"""

    code = bytearray(b"\x64\xa1\x30\x00\x00\x00")
    for offset in (0x3C, 0x78, 0x20, 0x18, 0x24, 0x1C):
        code.extend(b"\x8b\x40" + bytes((offset,)))
    code.extend(b"\xc1\xc8\x0d\xc1\xcf\x0d")
    fragments = (
        b"ws2_",
        b"32.d",
        b"ll",
        b"WSAS",
        b"tart",
        b"up",
        b"geta",
        b"ddri",
        b"nfo",
        b"sock",
        b"et",
        b"hton",
        b"conn",
        b"ect",
        b"send",
        b"recv",
        b"clos",
        b"esoc",
        b"ket",
    )
    for index, fragment in enumerate(fragments, start=1):
        displacement = (-4 * index) & 0xFF
        code.extend(b"\xc7\x45" + bytes((displacement,)))
        code.extend(fragment.ljust(4, b"\0"))
    code.extend(b"\x6a\x40\x68\x00\x10\x00\x00")
    code.extend(b"\x30\x11")
    code.extend(b"\xff\xd0" * 8)
    code.extend(b"\x90" * (0x400 - len(code)))

    first = b"198.51.100.24\0"
    second = second_host + b"\0"
    header = bytearray(0x38)
    header[:8] = b"codemark"
    header[0x20:0x24] = len(first).to_bytes(4, "little")
    header[0x24:0x28] = (449).to_bytes(4, "little")
    header[0x28:0x2C] = (1).to_bytes(4, "little")
    header[0x2C:0x30] = len(second).to_bytes(4, "little")
    header[0x30:0x34] = (8856).to_bytes(4, "little")
    header[0x34:0x38] = (1).to_bytes(4, "little")
    return bytes(code + header + first + second)


def _identified(value: str | int) -> SimpleNamespace:
    return (
        SimpleNamespace(name=value)
        if isinstance(value, str)
        else SimpleNamespace(id=value)
    )


def _fake_pe(
    resources: list[tuple[str | int, str | int, int, int, bytes]],
    *,
    linked: bool = True,
    linked_resource_names: list[str] | None = None,
    include_process_call: bool = True,
    include_entry_chain: bool = True,
    dead_entry_call: bool = False,
    misaligned_entry_call: bool = False,
    dead_helper_iat: bool = False,
    misaligned_helper_iat: bool = False,
    helper_dataflow: bool = True,
    misaligned_resource_push: bool = False,
    split_import_descriptors: bool = False,
) -> tuple[SimpleNamespace, list[tuple[int, int]], bytes]:
    """resource tree、静的loader code、get_data呼出し記録を返す。"""

    mapping: dict[tuple[int, int], bytes] = {}
    type_entries = []
    for resource_type, name, language, rva, raw in resources:
        mapping[(rva, len(raw))] = raw
        leaf = SimpleNamespace(
            id=language,
            data=SimpleNamespace(
                struct=SimpleNamespace(OffsetToData=rva, Size=len(raw))
            ),
        )
        name_entry = _identified(name)
        name_entry.directory = SimpleNamespace(entries=[leaf])
        type_entry = _identified(resource_type)
        type_entry.directory = SimpleNamespace(entries=[name_entry])
        type_entries.append(type_entry)
    calls: list[tuple[int, int]] = []

    def get_data(rva: int, size: int) -> bytes:
        calls.append((rva, size))
        return mapping[(rva, size)]

    import_addresses = {
        name: 0x405000 + index * 4
        for index, name in enumerate(
            (*x86_resource._RESOURCE_HELPER_APIS, x86_resource._CREATE_PROCESS_API)
        )
    }
    section_rva = 0x1000
    helper_rva = 0x1100
    caller_rva = 0x1400
    main_rva = 0x1A00
    entrypoint_rva = 0x1020
    image_base = 0x400000
    binary_type_rva = 0x1B80
    binary_type_va = image_base + binary_type_rva
    section_code = bytearray(b"\x90" * 0xC00)
    section_code[
        binary_type_rva - section_rva : binary_type_rva - section_rva + 8
    ] = b"B\0I\0N\0\0\0"
    position = helper_rva - section_rva
    if linked:
        section_code[position : position + 4] = b"\x55\x89\xe5\x57"
        position += 4
        if helper_dataflow:
            section_code[position : position + 4] = b"\x8b\x7c\x24\x04"
            position += 4
        section_code[caller_rva - section_rva : caller_rva - section_rva + 3] = (
            b"\x55\x89\xe5"
        )
        section_code[main_rva - section_rva : main_rva - section_rva + 3] = (
            b"\x55\x89\xe5"
        )
        if dead_helper_iat:
            section_code[position] = 0xC3
            position += 1
        for api_index, api_name in enumerate(x86_resource._RESOURCE_HELPER_APIS):
            if helper_dataflow:
                argument_code = (
                    b"\x6a\x00"
                    if api_name == b"GetModuleHandleW"
                    else (
                        b"\x89\xc6"
                        + b"\x68"
                        + binary_type_va.to_bytes(4, "little")
                        + b"\x57\x50"
                    )
                    if api_name == b"FindResourceW"
                    else b"\x89\xc7\x57\x56"
                    if api_name == b"LoadResource"
                    else b"\x89\xc3\x57\x56"
                    if api_name == b"SizeofResource"
                    else b"\x53"
                )
                section_code[position : position + len(argument_code)] = argument_code
                position += len(argument_code)
            address = import_addresses[api_name].to_bytes(4, "little")
            if misaligned_helper_iat:
                section_code[position : position + 10] = (
                    b"\xc7\x05\xff\x15" + address + b"\x90\x90"
                )
                position += 12
            else:
                section_code[position : position + 6] = b"\xff\x15" + address
                position += 8
        section_code[position : position + 2] = b"\x5f\xc3"
        if linked_resource_names is None:
            linked_resource_names = []
            for resource_type, name, _language, _rva, _raw in resources:
                if (
                    resource_type == "BIN"
                    and isinstance(name, str)
                    and name not in linked_resource_names
                ):
                    linked_resource_names.append(name)
        last_call_offset = caller_rva - section_rva + 0x100
        for index, resource_name in enumerate(linked_resource_names):
            block_offset = caller_rva - section_rva + 0x100 + index * 0x100
            encoded = resource_name.encode("utf-16le") + b"\0\0"
            recovered = encoded.ljust(32, b"\0")
            assert len(recovered) == 32
            write_offset = block_offset
            for stack_offset, value in (
                (0x00, b"\0" * 4),
                (0x04, b"\0" * 4),
                (0x08, b"\0" * 4),
                (0x0C, b"\0" * 4),
                (0x10, recovered[0:4]),
                (0x14, recovered[4:8]),
                (0x18, recovered[8:12]),
                (0x1C, recovered[12:16]),
                (0x60, b"\0" * 4),
                (0x64, b"\0" * 4),
                (0x68, b"\0" * 4),
                (0x6C, b"\0" * 4),
                (0x20, recovered[16:20]),
                (0x24, recovered[20:24]),
                (0x28, recovered[24:28]),
                (0x2C, recovered[28:32]),
            ):
                section_code[write_offset : write_offset + 8] = (
                    b"\xc7\x44\x24" + bytes((stack_offset,)) + value
                )
                write_offset += 8
            vector = x86_resource._RESOURCE_NAME_VECTOR_XOR
            section_code[write_offset : write_offset + len(vector)] = vector
            write_offset += len(vector)
            object_offset = 0xB0 - index * 0x10
            selector = (
                b"\xf6\x84\x24"
                + object_offset.to_bytes(4, "little")
                + b"\x01"
            )
            if index == len(linked_resource_names) - 1:
                selector += (
                    b"\x8d\xbc\x24"
                    + (object_offset + 2).to_bytes(4, "little")
                    + b"\x89\xf8"
                )
            else:
                selector += (
                    b"\x8d\x84\x24"
                    + (object_offset + 2).to_bytes(4, "little")
                )
            selector += (
                b"\x74\x07\x8b\x84\x24"
                + (object_offset + 8).to_bytes(4, "little")
            )
            section_code[write_offset : write_offset + len(selector)] = selector
            write_offset += len(selector)
            if misaligned_resource_push:
                section_code[write_offset : write_offset + 10] = (
                    b"\x68\x00\x00\x00\x50\x8d\x44\x24\x14\x50"
                )
                write_offset += 10
            else:
                section_code[write_offset : write_offset + 6] = (
                    b"\x50\x8d\x44\x24\x14\x50"
                )
                write_offset += 6
            call_offset = write_offset
            call_rva = section_rva + call_offset
            relative = helper_rva - (call_rva + 5)
            section_code[call_offset : call_offset + 5] = (
                b"\xe8" + relative.to_bytes(4, "little", signed=True)
            )
            section_code[call_offset + 5 : call_offset + 8] = b"\x83\xc4\x08"
            last_call_offset = call_offset
        process_offset = last_call_offset + 8
        launched_object_offset = 0xB0 - (len(linked_resource_names) - 1) * 0x10
        process_selector = (
            b"\xf6\x84\x24"
            + launched_object_offset.to_bytes(4, "little")
            + b"\x01\x74\x07\x8b\xbc\x24"
            + (launched_object_offset + 8).to_bytes(4, "little")
            + b"\x83\xec\x28\x89\x3c\x24"
        )
        section_code[
            process_offset : process_offset + len(process_selector)
        ] = process_selector
        process_offset += len(process_selector)
        if include_process_call:
            section_code[process_offset : process_offset + 6] = (
                b"\xff\x15"
                + import_addresses[x86_resource._CREATE_PROCESS_API].to_bytes(4, "little")
            )
        section_code[process_offset + 6] = 0xC3
        if include_entry_chain:
            entry_call_offset = entrypoint_rva - section_rva + 0x10
            entry_relative = main_rva - (section_rva + entry_call_offset + 5)
            if misaligned_entry_call:
                raw_relative = (
                    main_rva - (entrypoint_rva + 1 + 5)
                ).to_bytes(4, "little", signed=True)
                entry_offset = entrypoint_rva - section_rva
                section_code[entry_offset : entry_offset + 8] = (
                    b"\x68\xe8"
                    + raw_relative[:3]
                    + raw_relative[3:]
                    + b"\xc0\xc3"
                )
            else:
                section_code[entry_call_offset : entry_call_offset + 5] = (
                    b"\xe8" + entry_relative.to_bytes(4, "little", signed=True)
                )
                section_code[entry_call_offset + 5] = 0xC3
                if dead_entry_call:
                    section_code[entrypoint_rva - section_rva] = 0xC3
            main_call_offset = main_rva - section_rva + 0x20
            main_relative = caller_rva - (section_rva + main_call_offset + 5)
            section_code[main_call_offset : main_call_offset + 5] = (
                b"\xe8" + main_relative.to_bytes(4, "little", signed=True)
            )
            section_code[main_call_offset + 5] = 0xC3
        else:
            section_code[entrypoint_rva - section_rva] = 0xC3
            section_code[main_rva - section_rva] = 0xC3
    section_offset = 0x200
    outer = bytearray(b"\0" * (section_offset + len(section_code)))
    outer[:2] = b"MZ"
    outer[section_offset:] = section_code
    # 実PEではresource bytesもouter file-backed data内に存在する。fakeの
    # get_data mappingだけでなく必要markerもouterへ含め、cheap prefilterを
    # 通過する現実的なfixtureにする。
    for raw in mapping.values():
        outer.extend(raw)
    imports = [
        SimpleNamespace(name=name, address=address)
        for name, address in import_addresses.items()
    ]
    import_descriptors = (
        [
            SimpleNamespace(dll=b"KERNEL32.dll", imports=imports[::2]),
            SimpleNamespace(dll=b"kernel32.DLL", imports=imports[1::2]),
        ]
        if split_import_descriptors
        else [SimpleNamespace(dll=b"KERNEL32.dll", imports=imports)]
    )
    image = SimpleNamespace(
        DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(entries=type_entries),
        DIRECTORY_ENTRY_IMPORT=import_descriptors if linked else [],
        FILE_HEADER=SimpleNamespace(Machine=0x014C),
        OPTIONAL_HEADER=SimpleNamespace(
            AddressOfEntryPoint=entrypoint_rva,
            ImageBase=image_base,
        ),
        sections=[
            SimpleNamespace(
                Characteristics=0x60000020,
                PointerToRawData=section_offset,
                SizeOfRawData=len(section_code),
                VirtualAddress=section_rva,
            )
        ],
        get_data=get_data,
    )
    return image, calls, bytes(outer)


def _install_fake_pe(
    monkeypatch: pytest.MonkeyPatch,
    resources: list[tuple[str | int, str | int, int, int, bytes]],
    *,
    linked: bool = True,
    linked_resource_names: list[str] | None = None,
    include_process_call: bool = True,
    include_entry_chain: bool = True,
    dead_entry_call: bool = False,
    misaligned_entry_call: bool = False,
    dead_helper_iat: bool = False,
    misaligned_helper_iat: bool = False,
    helper_dataflow: bool = True,
    misaligned_resource_push: bool = False,
    split_import_descriptors: bool = False,
) -> tuple[SimpleNamespace, list[tuple[int, int]], bytes]:
    image, calls, outer = _fake_pe(
        resources,
        linked=linked,
        linked_resource_names=linked_resource_names,
        include_process_call=include_process_call,
        include_entry_chain=include_entry_chain,
        dead_entry_call=dead_entry_call,
        misaligned_entry_call=misaligned_entry_call,
        dead_helper_iat=dead_helper_iat,
        misaligned_helper_iat=misaligned_helper_iat,
        helper_dataflow=helper_dataflow,
        misaligned_resource_push=misaligned_resource_push,
        split_import_descriptors=split_import_descriptors,
    )
    monkeypatch.setattr(x86_resource.pefile, "PE", lambda **_kwargs: image)
    return image, calls, outer


def test_strong_raw_x86_stage_is_route_only_and_publish_safe() -> None:
    stage = _strong_stage()
    analyzed = x86_resource.analyze_raw_stage(stage)

    assert analyzed is not None
    config, evidence = analyzed
    assert evidence["instruction_coverage"] == 1.0
    assert evidence["localized_peb_ror13_export_resolver_present"] is True
    assert evidence["winsock_api_group_count"] == 9
    assert evidence["decoded_stage_indirect_transfer_present"] is True
    assert len(config["endpoints"]) == 2

    probe = extractor.probe_codemark_terminal_config(stage)
    serialized = json.dumps(probe, sort_keys=True)
    assert probe["matched"] is True
    assert probe["supports_family_attribution"] is False
    assert probe["terminal_family_confirmed"] is False
    assert "198.51.100.24" not in serialized
    assert "backup.example" not in serialized


def test_raw_x86_rejects_weak_and_truncated_codemark() -> None:
    stage = _strong_stage()
    weak = b"\x90" * 0x400 + stage[0x400:]

    assert x86_resource.analyze_raw_stage(weak) is None
    assert x86_resource.analyze_raw_stage(stage[:-1]) is None
    assert extractor.probe_codemark_terminal_config(weak)["matched"] is False
    assert extractor.probe_codemark_terminal_config(stage[:-1])["matched"] is False


def test_raw_x86_rejects_strong_dead_bytes_after_entry_ret() -> None:
    """offset 0のRET後に置いた強い形状を到達命令へ数えない。"""

    assert x86_resource.analyze_raw_stage(b"\xc3" + _strong_stage()) is None


def test_outer_pe_deduplicates_aliased_stage_and_probe_hides_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """単なる埋込ではなく強いstageだけを採用し、同一locatorは一度だけ読む。"""

    stage = _strong_stage()
    _image, calls, outer = _install_fake_pe(
        monkeypatch,
        [
            ("BIN", "IDR_HELPER_DAT", 1033, 0x1000, stage),
            ("RDATA", 53944, 1033, 0x1000, stage),
        ],
    )
    recovery = x86_resource.recover_from_pe(outer)
    assert recovery is not None
    assert len(recovery.occurrences) == 2
    assert recovery.resource_leaf_count == 2
    assert recovery.unique_resource_locator_count == 1
    assert calls == [(0x1000, len(stage))]

    probe = x86_resource.probe_resource_config(outer)
    serialized = json.dumps(probe, sort_keys=True)
    assert probe["matched"] is True
    assert probe["supports_family_attribution"] is False
    assert probe["terminal_family_confirmed"] is False
    assert probe["attribution_scope"] == "component_handler_route"
    assert probe["evidence"]["duplicate_resource_count"] == 1
    assert probe["config"]["endpoint_count"] == 2
    assert "198.51.100.24" not in serialized
    assert "backup.example" not in serialized
    assert probe["evidence"]["raw_resource_included"] is False
    assert probe["evidence"]["raw_resource_identifiers_included"] is False
    assert probe["evidence"]["raw_code_included"] is False
    assert probe["evidence"]["raw_key_included"] is False
    assert probe["evidence"]["outer_loader_evidence"] == {
        "architecture": "x86",
        "resource_helper_api_sequence_cfg_linked": True,
        "resource_helper_argument_return_dataflow_validated": True,
        "resource_helper_api_cfg_dominance_validated": True,
        "resource_helper_api_count": 5,
        "resource_helper_direct_call_count": 1,
        "named_binary_resource_count": 1,
        "helper_call_count_matches_named_binary_resources": True,
        "findresource_name_argument_count": 1,
        "resource_name_decode_instruction_boundary_linked": True,
        "terminal_resource_name_argument_linked": True,
        "post_extraction_process_launch_cfg_route_present": True,
        "extraction_destination_to_process_argument_proven": True,
        "entrypoint_reachable_instruction_boundary_cfg_present": True,
        "loader_route_validated": True,
        "loader_linkage_validated": True,
        "resource_output_argument_dataflow_validated": True,
        "resource_output_object_count": 1,
        "resource_output_objects_unique": True,
        "create_process_application_argument_frame_validated": True,
        "create_process_application_argument_all_paths_equivalent": True,
        "launched_resource_extraction_destination_to_process_argument_proven": True,
        "launched_resource_count": 1,
        "terminal_resource_is_launched_application": True,
        "terminal_resource_to_process_argument_proven": True,
    }


def test_outer_pe_without_codemark_rejects_before_pe_parser(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """必須markerのない大容量PEをresource parserへ渡さない。"""

    parser_called = False

    def unexpected_parser(**_kwargs: object) -> object:
        nonlocal parser_called
        parser_called = True
        raise AssertionError("PE parser must not be called")

    monkeypatch.setattr(x86_resource.pefile, "PE", unexpected_parser)

    assert x86_resource.recover_from_pe(b"MZ" + b"\0" * (8 * 1024 * 1024)) is None
    assert parser_called is False


def test_outer_pe_rejects_required_apis_split_across_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """必要APIを複数KERNEL32 descriptorからunionしない。"""

    _image, _calls, outer = _install_fake_pe(
        monkeypatch,
        [("BIN", "ONLY", 1033, 0x1000, _strong_stage())],
        split_import_descriptors=True,
    )

    assert x86_resource.recover_from_pe(outer) is None


def test_outer_pe_rejects_order_only_resource_helper(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """API名順だけで引数・戻り値flowがないhelperを採用しない。"""

    _image, _calls, outer = _install_fake_pe(
        monkeypatch,
        [("BIN", "ONLY", 1033, 0x1000, _strong_stage())],
        helper_dataflow=False,
    )

    assert x86_resource.recover_from_pe(outer) is None


def test_outer_pe_rejects_misaligned_resource_output_push(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """直前命令の即値末尾にあるPUSH byteを引数設定へ数えない。"""

    _image, _calls, outer = _install_fake_pe(
        monkeypatch,
        [("BIN", "ONLY", 1033, 0x1000, _strong_stage())],
        misaligned_resource_push=True,
    )

    assert x86_resource.recover_from_pe(outer) is None


def test_outer_pe_hashes_ioc_like_resource_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IOC風resource名を公開要約へraw出力しない。"""

    resource_name = "198.51.100.24"
    _image, _calls, outer = _install_fake_pe(
        monkeypatch,
        [("BIN", resource_name, 1033, 0x1000, _strong_stage())],
    )

    probe = x86_resource.probe_resource_config(outer)
    serialized = json.dumps(probe, sort_keys=True)

    assert probe["matched"] is True
    assert resource_name not in serialized
    assert probe["evidence"]["raw_resource_identifiers_included"] is False


def test_outer_pe_rejects_leafless_resource_node_flood(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """leafがなくてもtype/name/language全nodeを上限へ数える。"""

    image, _calls, outer = _install_fake_pe(
        monkeypatch,
        [("BIN", "ONLY", 1033, 0x1000, _strong_stage())],
    )
    image.DIRECTORY_ENTRY_RESOURCE.entries = [
        SimpleNamespace(
            id=index,
            directory=SimpleNamespace(entries=[]),
        )
        for index in range(x86_resource.MAXIMUM_RESOURCE_DIRECTORY_NODES + 1)
    ]

    assert x86_resource.recover_from_pe(outer) is None


PRIVATE_X86_CODEMARK_SAMPLE = "VALLEYRAT_X86_CODEMARK_TEST_IMAGE"


@pytest.mark.skipif(
    not os.environ.get(PRIVATE_X86_CODEMARK_SAMPLE),
    reason="repo外のValleyRAT x86 codemark実検体が未指定です",
)
def test_private_real_0bab_sample_remains_static_route_positive() -> None:
    """実0babを実行・通信せずroute-onlyで静的復元できる。"""

    sample = Path(os.environ[PRIVATE_X86_CODEMARK_SAMPLE]).read_bytes()
    recovery = x86_resource.recover_from_pe(sample)

    assert recovery is not None
    assert recovery.outer_sha256 == (
        "0bab062af7894bc44d68ebc5b9633a84ffaae1f17671ff3949002c43321ec86a"
    )
    probe = x86_resource.probe_resource_config(sample)
    assert probe["matched"] is True
    assert probe["supports_family_attribution"] is False
    assert probe["terminal_family_confirmed"] is False
    assert probe["config"]["endpoint_count"] == 2
    assert probe["sample_executed"] is False
    assert probe["network_contacted"] is False


def test_outer_pe_rejects_inactive_strong_resource_embedding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """強いraw stageでもloaderから参照・起動されない埋込は昇格しない。"""

    stage = _strong_stage()
    _image, calls, outer = _install_fake_pe(
        monkeypatch,
        [("BIN", "INACTIVE_STAGE", 1033, 0x1000, stage)],
        linked=False,
    )

    assert x86_resource.recover_from_pe(outer) is None
    assert x86_resource.probe_resource_config(outer)["matched"] is False
    assert calls == [(0x1000, len(stage)), (0x1000, len(stage))]


def test_outer_pe_rejects_terminal_candidate_not_named_by_helper_calls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """別resourceだけを抽出するloaderへinactive terminalを足しても昇格しない。"""

    stage = _strong_stage()
    ordinary = b"A" * 600
    _image, _calls, outer = _install_fake_pe(
        monkeypatch,
        [
            ("BIN", "ACTIVE_A", 1033, 0x1000, ordinary),
            ("BIN", "ACTIVE_B", 1033, 0x2000, ordinary),
            ("BIN", "ACTIVE_C", 1033, 0x3000, ordinary),
            ("BIN", "INACTIVE_STAGE", 1033, 0x4000, stage),
        ],
        linked_resource_names=["ACTIVE_A", "ACTIVE_B", "ACTIVE_C"],
    )

    assert x86_resource.recover_from_pe(outer) is None


@pytest.mark.parametrize(
    ("include_process_call", "include_entry_chain"),
    [(False, True), (True, False)],
)
def test_outer_pe_rejects_unreachable_or_unlaunched_resource_chain(
    monkeypatch: pytest.MonkeyPatch,
    include_process_call: bool,
    include_entry_chain: bool,
) -> None:
    """name一致だけでは足りず、entry到達と後続process起動を必須にする。"""

    stage = _strong_stage()
    _image, _calls, outer = _install_fake_pe(
        monkeypatch,
        [("BIN", "ONLY", 1033, 0x1000, stage)],
        include_process_call=include_process_call,
        include_entry_chain=include_entry_chain,
    )

    assert x86_resource.recover_from_pe(outer) is None


@pytest.mark.parametrize(
    "malformed_call_evidence",
    ["entry_immediate", "helper_immediate"],
)
def test_outer_pe_rejects_calls_embedded_at_misaligned_offsets(
    monkeypatch: pytest.MonkeyPatch,
    malformed_call_evidence: str,
) -> None:
    """即値内のE8／FF15 byte列は命令境界のcall証拠に数えない。"""

    stage = _strong_stage()
    _image, _calls, outer = _install_fake_pe(
        monkeypatch,
        [("BIN", "ONLY", 1033, 0x1000, stage)],
        misaligned_entry_call=malformed_call_evidence == "entry_immediate",
        misaligned_helper_iat=malformed_call_evidence == "helper_immediate",
    )

    assert x86_resource.recover_from_pe(outer) is None
    assert x86_resource.probe_resource_config(outer)["matched"] is False


@pytest.mark.parametrize(
    "dead_call_evidence",
    ["entry_after_ret", "helper_after_ret"],
)
def test_outer_pe_rejects_call_bytes_after_reachable_ret(
    monkeypatch: pytest.MonkeyPatch,
    dead_call_evidence: str,
) -> None:
    """到達可能なret後のE8／FF15 byte列からcall chainを合成しない。"""

    stage = _strong_stage()
    _image, _calls, outer = _install_fake_pe(
        monkeypatch,
        [("BIN", "ONLY", 1033, 0x1000, stage)],
        dead_entry_call=dead_call_evidence == "entry_after_ret",
        dead_helper_iat=dead_call_evidence == "helper_after_ret",
    )

    assert x86_resource.recover_from_pe(outer) is None
    assert x86_resource.probe_resource_config(outer)["matched"] is False


def test_outer_pe_rejects_weak_or_conflicting_terminal_candidates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    strong = _strong_stage()
    weak = b"\x90" * 0x400 + strong[0x400:]
    _image, _calls, weak_outer = _install_fake_pe(
        monkeypatch,
        [
            ("BIN", "FIRST", 1033, 0x1000, strong),
            ("RCDATA", 102, 1033, 0x2000, weak),
        ],
    )
    assert x86_resource.recover_from_pe(weak_outer) is None

    conflicting = _strong_stage(second_host=b"other.example")
    _image, _calls, conflict_outer = _install_fake_pe(
        monkeypatch,
        [
            ("BIN", "FIRST", 1033, 0x1000, strong),
            ("RCDATA", 102, 1033, 0x2000, conflicting),
        ],
    )
    assert x86_resource.recover_from_pe(conflict_outer) is None


def test_aliased_leaf_fanout_and_total_work_limits_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stage = _strong_stage()
    repeated = [
        ("BIN", index, 1033, 0x1000, stage)
        for index in range(x86_resource.MAXIMUM_RESOURCE_LEAVES + 1)
    ]
    _image, calls, alias_outer = _install_fake_pe(monkeypatch, repeated)

    assert x86_resource.recover_from_pe(alias_outer) is None
    assert calls == [(0x1000, len(stage))]

    _image, _calls, limited_outer = _install_fake_pe(
        monkeypatch,
        [("BIN", "ONLY", 1033, 0x1000, stage)],
    )
    monkeypatch.setattr(x86_resource, "MAXIMUM_TOTAL_DISASSEMBLY_INSTRUCTIONS", 1)
    assert x86_resource.recover_from_pe(limited_outer) is None


def test_named_resource_linkage_work_limit_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stage = _strong_stage()
    resources = [
        (
            "BIN",
            f"NAME_{index}",
            1033,
            0x1000 + index * 0x1000,
            stage if index == 0 else b"A" * 600,
        )
        for index in range(x86_resource.MAXIMUM_LINKED_RESOURCE_NAMES + 1)
    ]
    _image, _calls, outer = _install_fake_pe(
        monkeypatch,
        resources,
        linked_resource_names=[],
    )

    assert x86_resource.recover_from_pe(outer) is None


def test_outer_extractor_keeps_terminal_payload_private_child(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """検証済みouterだけを終端へ昇格し、stageは子layerとして分離する。"""

    stage = _strong_stage()
    _image, _calls, outer = _install_fake_pe(
        monkeypatch,
        [("BIN", "IDR_HELPER_DAT", 1033, 0x1000, stage)],
    )
    recovery = x86_resource.recover_from_pe(outer)
    assert recovery is not None
    monkeypatch.setattr(
        extractor,
        "recover_x86_codemark_resource",
        lambda _data: recovery,
    )
    monkeypatch.setattr(extractor, "matches_onyx_qt_profile", lambda _data: False)

    result = extractor.extract(outer, r"C:\private\sample.exe")

    assert result["config"]["variant"] == "x86_codemark_resource_terminal"
    assert result["config"]["candidate_config_recovered"] is True
    assert result["config"]["terminal_family_confirmed"] is False
    assert result["config"]["attribution_scope"] == "component_handler_route"
    assert result["config"]["source_name"] == "sample.exe"
    assert result["terminal_payload"]["data"] == stage
    assert result["terminal_payload"]["role"] == "terminal_payload"
