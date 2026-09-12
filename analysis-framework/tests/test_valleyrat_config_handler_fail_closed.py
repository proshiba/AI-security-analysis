"""ValleyRAT campaign別config handlerのfail-closed契約を検証する。"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK_COMMON = REPOSITORY_ROOT / "analysis-framework" / "common"
for import_root in (REPOSITORY_ROOT, FRAMEWORK_COMMON):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

from analysis_contract import handler_result_quality  # noqa: E402
from handler_catalog import (  # noqa: E402
    discover_handlers,
    preflight_handler_for_assessment,
)


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CAMPAIGNS = REPOSITORY_ROOT / "analysis-framework" / "malware" / "valleyrat" / "campaigns"
SINGLE = _load(
    "valleyrat_single_config_fail_closed",
    CAMPAIGNS / "single_pe_vvas_resource" / "analyze.py",
)
APPDOMAIN = _load(
    "valleyrat_appdomain_config_fail_closed",
    CAMPAIGNS / "appdomainmanager_pixel_loader" / "analyze.py",
)

SINGLE_HANDLER_PATH = "analysis-framework/malware/valleyrat/campaigns/single_pe_vvas_resource/analyze.py"
INTEGRATED_EXTRACTOR_PATH = "extractors/valleyrat/extractor.py"


def test_single_pe_handler_passes_fail_closed_static_preflight() -> None:
    """vvaS resource handlerは反射的な動的呼出しなしで自動実行監査を通る。"""

    handler = next(item for item in discover_handlers() if item.relative_path == SINGLE_HANDLER_PATH)
    result = preflight_handler_for_assessment(
        handler,
        actual_format="pe",
        input_size=4_096,
    )

    assert handler.automatic is True
    assert result["eligible"] is True
    assert result["blockers"] == []
    assert result["dependency_audit"]["issues"] == []
    assert result["sample_execution_allowed"] is False
    assert result["network_allowed"] is False
    assert result["filesystem_write_allowed"] is False


def test_integrated_extractor_passes_source_scoped_capstone_preflight() -> None:
    """Capstone利用はValleyRATの有界命令decode経路だけを許可する。"""

    handler = next(item for item in discover_handlers() if item.relative_path == INTEGRATED_EXTRACTOR_PATH)
    result = preflight_handler_for_assessment(
        handler,
        actual_format="pe",
        input_size=4_096,
    )

    assert handler.automatic is True
    assert result["eligible"] is True, result["blockers"]
    assert result["blockers"] == []
    assert result["dependency_audit"]["issues"] == []
    dependency_paths = {
        item["path"] for item in result["dependency_audit"]["files"]
    }
    assert "extractors/valleyrat/ca01_sideload.py" in dependency_paths
    assert "extractors/valleyrat/native_loader_lineage.py" in dependency_paths
    assert "extractors/valleyrat/silverfox_loader_lineage.py" in dependency_paths
    assert result["sample_execution_allowed"] is False
    assert result["network_allowed"] is False
    assert result["filesystem_write_allowed"] is False


_IMAGE_BASE = 0x140000000
_ENTRY_RVA = 0x1000
_LOADER_RVA = 0x1100
_COPY_RVA = 0x1800
_IAT_RVAS = {name: 0x3000 + index * 8 for index, name in enumerate(sorted(SINGLE.REQUIRED_IMPORTS))}


def _relative_call(source_rva: int, target_rva: int) -> bytes:
    displacement = target_rva - (source_rva + 5)
    return b"\xe8" + displacement.to_bytes(4, "little", signed=True)


def _iat_call_at(code: bytearray, name: str, function_rva: int) -> None:
    source_rva = function_rva + len(code)
    displacement = _IAT_RVAS[name] - (source_rva + 6)
    code.extend(b"\xff\x15" + displacement.to_bytes(4, "little", signed=True))


def _iat_call(code: bytearray, name: str) -> None:
    _iat_call_at(code, name, _LOADER_RVA)


def _strict_loader_code(
    *,
    resource_id: int = 788,
    function_rva: int = _LOADER_RVA,
) -> bytes:
    """実0a306で確認したregister data-flowだけを持つ最小x64 fixture。"""

    code = bytearray(b"\x48\x83\xec\x28\x33\xc9")
    _iat_call_at(code, "GetModuleHandleW", function_rva)
    code.extend(b"\xba" + resource_id.to_bytes(4, "little"))
    code.extend(b"\x41\xb8\x0a\x00\x00\x00\x48\x8b\xc8\x48\x8b\xf8")
    _iat_call_at(code, "FindResourceA", function_rva)
    code.extend(b"\x48\x8b\xf0\x48\x8b\xd0\x48\x8b\xcf")
    _iat_call_at(code, "SizeofResource", function_rva)
    code.extend(b"\x8b\xd8\x48\x8b\xd6\x48\x8b\xcf")
    _iat_call_at(code, "LoadResource", function_rva)
    code.extend(b"\x48\x8b\xc8")
    _iat_call_at(code, "LockResource", function_rva)
    code.extend(b"\x48\x8b\xf0\xbf\x04\x00\x00\x00\x44\x8b\xcf\x41\xb8\x00\x30\x00\x00\x48\x8b\xd3\x33\xc9\x48\x8b\xeb")
    _iat_call_at(code, "VirtualAlloc", function_rva)
    code.extend(b"\x48\x8b\xd8\x4c\x8b\xc5\x48\x8b\xd6\x48\x8b\xcb")
    code.extend(_relative_call(function_rva + len(code), _COPY_RVA))
    code.extend(b"\x48\x8b\xd5\x41\xb8\x20\x00\x00\x00\x48\x8b\xcb")
    _iat_call_at(code, "VirtualProtect", function_rva)
    code.extend(b"\x45\x33\xc9\x4c\x8b\xc3\x33\xd2\x33\xc9")
    _iat_call_at(code, "CreateThread", function_rva)
    code.extend(b"\x48\x8b\xf8\x48\x8b\xcf")
    _iat_call_at(code, "WaitForSingleObject", function_rva)
    code.extend(b"\xc3")
    return bytes(code)


def _strict_copy_loop() -> bytes:
    """RCXへRDXからR8 byteをコピーする最小x64 loopを返す。"""

    return bytes.fromhex(
        "488bc14d85c07411448a0a44880948ffc248ffc149ffc875efc3"
    )


def _single_image_with_resource_blobs(
    resource_blobs: list[bytes],
    *,
    complete_imports: bool = True,
    resource_id: int = 788,
    loader_reachable: bool = True,
    loader_code: bytes | None = None,
    split_import_descriptors: bool = False,
    extra_functions: dict[int, bytes] | None = None,
    entry_targets: list[int] | None = None,
    copy_code: bytes | None = None,
) -> SimpleNamespace:
    """厳密なentrypoint→loaderとRCDATA/788を持つ合成PEを返す。"""

    blobs_by_rva: dict[int, bytes] = {}
    languages = []
    for index, blob in enumerate(resource_blobs):
        rva = 0x2000 + index * 0x1000
        blobs_by_rva[rva] = blob
        languages.append(
            SimpleNamespace(
                id=1033 + index,
                data=SimpleNamespace(struct=SimpleNamespace(OffsetToData=rva, Size=len(blob))),
            )
        )
    name = SimpleNamespace(id=788, directory=SimpleNamespace(entries=languages))
    resource_type = SimpleNamespace(id=10, directory=SimpleNamespace(entries=[name]))
    names = sorted(SINGLE.REQUIRED_IMPORTS)
    if not complete_imports:
        names.remove("CreateThread")
    imports = [
        SimpleNamespace(
            name=value.encode(),
            address=_IMAGE_BASE + _IAT_RVAS[value],
        )
        for value in names
    ]
    if split_import_descriptors:
        midpoint = len(imports) // 2
        descriptors = [
            SimpleNamespace(dll=b"KERNEL32.dll", imports=imports[:midpoint]),
            SimpleNamespace(dll=b"KERNEL32.dll", imports=imports[midpoint:]),
        ]
    else:
        descriptors = [SimpleNamespace(dll=b"KERNEL32.dll", imports=imports)]
    actual_loader = loader_code or _strict_loader_code(resource_id=resource_id)
    targets = entry_targets or [_LOADER_RVA if loader_reachable else 0x1900]
    entry_code = bytearray()
    for target in targets:
        entry_code.extend(_relative_call(_ENTRY_RVA + len(entry_code), target))
    entry_code.extend(b"\xc3")
    entry = bytes(entry_code)
    code_blobs = {
        _ENTRY_RVA: entry,
        _LOADER_RVA: actual_loader,
        _COPY_RVA: copy_code if copy_code is not None else _strict_copy_loop(),
        0x1900: b"\xc3",
    }
    if extra_functions:
        code_blobs.update(extra_functions)

    def get_data(rva: int, size: int) -> bytes:
        for start, blob in {**blobs_by_rva, **code_blobs}.items():
            offset = rva - start
            if 0 <= offset and offset + size <= len(blob):
                return blob[offset : offset + size]
        return b""

    exception_entries = [
        SimpleNamespace(
            struct=SimpleNamespace(
                BeginAddress=start,
                EndAddress=start + len(blob),
            )
        )
        for start, blob in sorted(code_blobs.items())
    ]
    return SimpleNamespace(
        DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(entries=[resource_type]),
        DIRECTORY_ENTRY_IMPORT=descriptors,
        DIRECTORY_ENTRY_EXCEPTION=exception_entries,
        FILE_HEADER=SimpleNamespace(Machine=SINGLE.AMD64_MACHINE),
        __data__=bytes(0x2000),
        sections=[
            SimpleNamespace(
                VirtualAddress=0x1000,
                PointerToRawData=0,
                SizeOfRawData=0x1000,
                Characteristics=0x60000020,
            )
        ],
        OPTIONAL_HEADER=SimpleNamespace(
            AddressOfEntryPoint=_ENTRY_RVA,
            ImageBase=_IMAGE_BASE,
        ),
        get_data=get_data,
    )


def _single_image(*, complete_imports: bool) -> SimpleNamespace:
    raw_config = "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    resource = b"\x48\x81\xec" + raw_config
    return _single_image_with_resource_blobs(
        [resource],
        complete_imports=complete_imports,
    )


def _managed_image() -> SimpleNamespace:
    directories = [SimpleNamespace(Size=0) for _ in range(15)]
    directories[14] = SimpleNamespace(Size=0x48)
    return SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(DATA_DIRECTORY=directories))


def test_single_pe_mismatch_does_not_publish_resource_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RCDATA設定だけがあってもloader API chain不成立なら証拠を返さない。"""

    monkeypatch.setattr(
        SINGLE.pefile,
        "PE",
        lambda **_kwargs: _single_image(complete_imports=False),
    )
    result = SINGLE.analyze(b"MZ synthetic", r"C:\private\single.exe")

    assert result["sample_name"] == "single.exe"
    assert result["campaign_type"] == "unknown_single_pe"
    assert result["resources"] == []
    assert result["config"]["decoded_config_recovered"] is False
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["endpoints"] == []
    assert (
        handler_result_quality(
            result,
            SINGLE.HANDLER_CONTRACT["minimum_evidence_score"],
        )["sufficient"]
        is False
    )


def test_single_pe_complete_structure_publishes_decoded_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """API chain、resource ID、実行対象先頭、反転設定の全一致を要求する。"""

    monkeypatch.setattr(
        SINGLE.pefile,
        "PE",
        lambda **_kwargs: _single_image(complete_imports=True),
    )
    result = SINGLE.analyze(b"MZ synthetic")

    assert result["campaign_type"] == "single_pe_vvas_resource"
    assert result["config"]["decoded_config_recovered"] is True
    assert result["config"]["endpoints"] == ["103.119.3.160:6666"]
    assert result["resources"][0]["content_profile"] == ("x64_function_prologue_candidate")
    assert result["loader_linkage"]["copy_callee_bounded_memory_move"] is True
    assert result["loader_linkage"]["copy_callee_profile"] == (
        "bounded_scalar_byte_copy_loop"
    )
    assert "header_hex" not in result["resources"][0]
    assert (
        handler_result_quality(
            result,
            SINGLE.HANDLER_CONTRACT["minimum_evidence_score"],
        )["sufficient"]
        is True
    )
    probe = SINGLE.probe_terminal_config(b"MZ synthetic")
    assert probe["matched"] is True
    assert probe["config"] == {
        "endpoint_count": 1,
        "raw_network_values_included": False,
    }
    assert "103.119.3.160" not in repr(probe)


def test_single_pe_rejects_bswap_followed_by_ret_and_dead_loader_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BSWAPをModR/M付きと誤復号して直後のRETを飲み込まない。"""

    resource = b"\x48\x81\xec" + "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    dead_loader = b"\x0f\xc8\xc3" + _strict_loader_code(
        function_rva=_LOADER_RVA + 3,
    )
    image = _single_image_with_resource_blobs(
        [resource],
        loader_code=dead_loader,
    )
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic bswap dead loader")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["markers"]["entrypoint_reachable_resource_loader_data_flow"] is False
    assert result["config"]["endpoints"] == []


def test_single_pe_starts_cfg_at_mid_function_entrypoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """runtime function先頭のdead callを途中entrypointから到達扱いしない。"""

    image = _single_image(complete_imports=True)
    image.OPTIONAL_HEADER.AddressOfEntryPoint = _ENTRY_RVA + 5
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic mid-function entrypoint")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["markers"]["entrypoint_reachable_resource_loader_data_flow"] is False
    assert result["config"]["endpoints"] == []


def test_single_pe_rejects_ret_only_copy_callee(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """引数形状だけでRET-only helperをmemory copyへ昇格しない。"""

    resource = b"\x48\x81\xec" + "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    image = _single_image_with_resource_blobs(
        [resource],
        copy_code=b"\xc3",
    )
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic ret-only copy")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["loader_linkage"] == {}
    assert result["config"]["endpoints"] == []


def test_single_pe_rejects_pdata_outside_executable_file_backed_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """non-executable sectionを指す.pdata functionをcode証拠にしない。"""

    image = _single_image(complete_imports=True)
    image.sections[0].Characteristics = 0x40000040
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic non-executable pdata")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["markers"]["entrypoint_reachable_resource_loader_data_flow"] is False
    assert result["config"]["endpoints"] == []


def test_single_pe_rejects_inactive_target_resource_when_loader_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """有効な設定resourceでもentrypointからloaderへ到達しなければ昇格しない。"""

    resource = b"\x48\x81\xec" + "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    image = _single_image_with_resource_blobs(
        [resource],
        loader_reachable=False,
    )
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic unreachable")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["markers"]["entrypoint_reachable_resource_loader_data_flow"] is False
    assert result["config"]["candidate_config_present"] is True
    assert result["config"]["candidate_endpoint_count"] == 1
    assert result["config"]["candidate_values_included"] is False
    assert result["config"]["endpoints"] == []
    assert SINGLE.probe_terminal_config(b"MZ synthetic unreachable")["matched"] is False


def test_single_pe_rejects_loader_for_a_different_resource_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RCDATA/788がdecoyでloaderが別IDを指定する場合は終端へ帰属しない。"""

    resource = b"\x48\x81\xec" + "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    image = _single_image_with_resource_blobs([resource], resource_id=789)
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic other resource")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["loader_linkage"] == {}
    assert result["config"]["candidate_endpoint_count"] == 1
    assert result["config"]["endpoints"] == []


def test_single_pe_rejects_api_union_split_across_import_descriptors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """必要API名を複数descriptorからunionしてloader証拠にしない。"""

    resource = b"\x48\x81\xec" + "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    image = _single_image_with_resource_blobs(
        [resource],
        split_import_descriptors=True,
    )
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic split descriptors")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["markers"]["entrypoint_reachable_resource_loader_data_flow"] is False
    assert result["config"]["endpoints"] == []


def test_single_pe_rejects_api_union_split_across_reachable_functions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """別々の到達可能functionに分散したAPI callを同一data-flowへunionしない。"""

    resource = b"\x48\x81\xec" + "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    loader = bytearray(_strict_loader_code())
    decoded = SINGLE._reachable_x64_instructions(bytes(loader), _LOADER_RVA)
    assert decoded is not None
    instructions, _successors, _targets = decoded
    create_sites = [
        (offset, instruction[0])
        for offset, instruction in instructions.items()
        if instruction[4] == _IAT_RVAS["CreateThread"]
    ]
    assert len(create_sites) == 1
    create_offset, create_end = create_sites[0]
    loader[create_offset:create_end] = b"\x90" * (create_end - create_offset)

    second_rva = 0x1A00
    second = bytearray(b"\x45\x33\xc9\x4c\x8b\xc3\x33\xd2\x33\xc9")
    _iat_call_at(second, "CreateThread", second_rva)
    second.extend(b"\xc3")
    image = _single_image_with_resource_blobs(
        [resource],
        loader_code=bytes(loader),
        extra_functions={second_rva: bytes(second)},
        entry_targets=[_LOADER_RVA, second_rva],
    )
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic function union")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["markers"]["entrypoint_reachable_resource_loader_data_flow"] is False
    assert result["config"]["candidate_endpoint_count"] == 1
    assert result["config"]["endpoints"] == []


def test_single_pe_rejects_loader_api_bytes_after_return(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RET後のdead bytesへ残るAPI列を到達可能なloader経路と誤認しない。"""

    resource = b"\x48\x81\xec" + "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    loader = _strict_loader_code()
    split = loader.index(b"\x48\x8b\xd5")
    dead_loader = loader[:split] + b"\xc3\x90\x90" + loader[split + 3 :]
    image = _single_image_with_resource_blobs(
        [resource],
        loader_code=dead_loader,
    )
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic dead bytes")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["markers"]["entrypoint_reachable_resource_loader_data_flow"] is False
    assert result["config"]["endpoints"] == []


def test_single_pe_rejects_helper_with_mismatched_locked_pointer_flow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """LockResource返り値とcopy sourceのregisterが異なるhelperを拒否する。"""

    resource = b"\x48\x81\xec" + "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    loader = _strict_loader_code().replace(
        b"\x4c\x8b\xc5\x48\x8b\xd6\x48\x8b\xcb",
        b"\x4c\x8b\xc5\x48\x8b\xd7\x48\x8b\xcb",
        1,
    )
    image = _single_image_with_resource_blobs([resource], loader_code=loader)
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic mismatched helper")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["loader_linkage"] == {}
    assert result["config"]["endpoints"] == []


def test_single_pe_rejects_conflicting_configs_across_resource_languages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """異なるlanguageの実行対象RCDATA設定をunionせず全候補を拒否する。"""

    first = b"\x48\x81\xec" + "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    second = b"\x48\x81\xec" + "|7777:1o|7.001.15.891:1p|".encode("utf-16le")
    image = _single_image_with_resource_blobs([first, second])
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["markers"]["executable_resource_with_decoded_config"] is True
    assert result["markers"]["unique_executable_resource_config"] is False
    assert result["resources"] == []
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["endpoints"] == []
    probe = SINGLE.probe_terminal_config(b"MZ synthetic")
    assert probe["matched"] is False
    assert "103.119.3.160" not in repr(probe)
    assert "198.51.100.7" not in repr(probe)


def test_single_pe_rejects_config_when_resource_string_scan_is_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """上限後の同一resource内相反設定を見落として先頭設定だけを確定しない。"""

    first = b"|6666:1o|061.3.911.301:1p|"
    conflicting = b"|7777:1o|7.001.15.891:1p|"
    resource = b"\x48\x81\xec" + first + b"\0" + conflicting
    image = _single_image_with_resource_blobs([resource])
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)
    monkeypatch.setattr(SINGLE, "MAXIMUM_RESOURCE_STRING_COUNT", 1)

    result = SINGLE.analyze(b"MZ synthetic")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["classification_confidence"] == "insufficient"
    assert result["recovery_status"] == "rejected_resource_string_scan_truncated"
    assert result["markers"]["resource_string_scans_complete"] is False
    assert result["resources"] == []
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["endpoints"] == []
    assert result["config"]["resource_string_scan"] == {
        "target_resource_count": 1,
        "truncated": True,
        "truncated_resource_count": 1,
        "truncation_reasons": ["maximum_string_count"],
    }

    probe = SINGLE.probe_terminal_config(b"MZ synthetic")
    assert probe["matched"] is False
    assert probe["supports_family_attribution"] is False
    assert probe["static_config_recovered"] is False


def test_single_pe_rejects_when_non_executable_target_scan_is_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同じRCDATA/788の未走査領域をdecoy扱いしてconfigを確定しない。"""

    selected = b"\x48\x81\xec|6666:1o|061.3.911.301:1p|"
    incomplete_decoy = b"not-code\0junk\0"
    image = _single_image_with_resource_blobs([selected, incomplete_decoy])
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)
    monkeypatch.setattr(SINGLE, "MAXIMUM_RESOURCE_STRING_COUNT", 1)

    result = SINGLE.analyze(b"MZ synthetic")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["recovery_status"] == "rejected_resource_string_scan_truncated"
    assert result["markers"]["resource_string_scans_complete"] is False
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["endpoints"] == []
    assert result["config"]["resource_string_scan"] == {
        "target_resource_count": 2,
        "truncated": True,
        "truncated_resource_count": 1,
        "truncation_reasons": ["maximum_string_count"],
    }


def test_single_pe_rejects_non_executable_target_resource_language_decoy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """FindResourceAで選択され得る非実行language leafがあれば確定しない。"""

    selected = b"\x48\x81\xec" + "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    decoy = b"not-code" + "|7777:1o|7.001.15.891:1p|".encode("utf-16le")
    image = _single_image_with_resource_blobs([selected, decoy])
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["recovery_status"] == "rejected_target_resource_language_ambiguity"
    assert result["markers"]["all_target_resource_languages_validated"] is False
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["endpoints"] == []
    assert result["config"]["raw_resource_strings_included"] is False
    assert result["config"]["raw_network_values_included"] is False
    assert result["resources"] == []
    assert "198.51.100.7" not in repr(result)


def test_single_pe_rejects_undecodable_executable_target_language(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """実行prologueだけの別language leafも曖昧な選択候補として拒否する。"""

    selected = b"\x48\x81\xec" + "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    undecodable = b"\x48\x81\xec" + b"\x90" * 64
    image = _single_image_with_resource_blobs([selected, undecodable])
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic")

    assert result["campaign_type"] == "unknown_single_pe"
    assert result["recovery_status"] == "rejected_target_resource_language_ambiguity"
    assert result["markers"]["all_target_resource_languages_validated"] is False
    assert result["markers"]["unique_executable_resource_config"] is False
    assert result["config"]["candidate_config_present"] is False
    assert result["config"]["endpoints"] == []


def test_single_pe_accepts_identical_config_across_resource_languages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """複数languageでも各resource内で同じ一意設定なら相反とは扱わない。"""

    resource = b"\x48\x81\xec" + "|6666:1o|061.3.911.301:1p|".encode("utf-16le")
    image = _single_image_with_resource_blobs([resource, resource])
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic")

    assert result["campaign_type"] == "single_pe_vvas_resource"
    assert result["markers"]["all_target_resource_languages_validated"] is True
    assert result["markers"]["unique_executable_resource_config"] is True
    assert result["config"]["endpoints"] == ["103.119.3.160:6666"]
    assert len(result["resources"]) == 2
    assert all("decoded_vvas" not in item for item in result["resources"])


def test_campaign_registry_matches_current_static_evidence_contracts() -> None:
    """registryが現在の厳格なdata-flow証拠と未検証境界を正しく表す。"""

    registry = json.loads((CAMPAIGNS.parent / "campaigns.json").read_text(encoding="utf-8"))["patterns"]
    n520 = " ".join(registry["single_pe_n520_managed"]["required_observations"])
    vvas = " ".join(registry["vvas_reversed_config_terminal"]["required_observations"])
    resource = " ".join(registry["single_pe_vvas_resource"]["required_observations"])
    raw_vvas = " ".join(registry["vvas_reversed_config_candidate"]["required_observations"])
    xor_vvas = registry["single_byte_xor_vvas_candidate"]
    appdomain = registry["appdomainmanager_pixel_loader"]

    assert "RuntimeHelpers.InitializeArray" in n520
    assert "cloud readerへのCIL data-flow" in n520
    assert "同一の1個のWS2_32.dll descriptor内" in vvas
    assert "odaktomk" not in vvas
    assert "正確に1件のodaktomk marker" in raw_vvas
    assert "family、終端component、静的configの確定には利用しない" in (xor_vvas["campaign_interpretation"])
    assert "FindResourceAがlanguageを固定しない" in resource
    assert "全てのRCDATA/788 language leafが実行候補かつ復号可能" in resource
    assert "resource handle data-flow" in resource
    assert "CreateThread start address" in resource
    assert ".exe.configでAppDomainManagerを指定" not in appdomain["description"]
    assert "IL call edge、.exe.config指定、画像復号結果、後段payloadは未検証" in (appdomain["required_observations"])


def test_single_pe_rejects_oversized_resource_before_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """resource宣言size上限超過時はblob読出しと部分config公開を行わない。"""

    image = _single_image(complete_imports=True)
    lang = image.DIRECTORY_ENTRY_RESOURCE.entries[0].directory.entries[0].directory.entries[0]
    lang.data.struct.Size = SINGLE.MAXIMUM_RESOURCE_SIZE + 1
    image.get_data = lambda *_args: pytest.fail("上限超過resourceを読んではならない")
    monkeypatch.setattr(SINGLE.pefile, "PE", lambda **_kwargs: image)

    result = SINGLE.analyze(b"MZ synthetic")
    assert result["recovery_status"] == "rejected_resource_bounds"
    assert result["resources"] == []
    assert result["config"]["endpoints"] == []


def test_appdomain_mismatch_hides_arbitrary_url_and_capabilities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """有効CLR headerだけと任意URLでは設定・能力を昇格しない。"""

    monkeypatch.setattr(APPDOMAIN.pefile, "PE", lambda **_kwargs: _managed_image())
    result = APPDOMAIN.analyze(
        b"MZ https://operator:password@download.example/stage.bin?token=hidden",
        r"C:\private\loader.exe",
    )

    assert result["sample_name"] == "loader.exe"
    assert result["campaign_type"] == "unknown"
    assert result["marker_hits"] == {}
    assert result["capabilities"] == []
    assert result["representative_functions"] == []
    assert result["endpoints"] == []
    assert result["config"]["static_config_recovered"] is False
    assert (
        handler_result_quality(
            result,
            APPDOMAIN.HANDLER_CONTRACT["minimum_evidence_score"],
        )["sufficient"]
        is False
    )


def test_appdomain_complete_gate_sanitizes_stage_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全marker groupとCLR header成立時だけ秘密部分を除いたstage URLを返す。"""

    monkeypatch.setattr(APPDOMAIN.pefile, "PE", lambda **_kwargs: _managed_image())
    markers = b" ".join(marker for values in APPDOMAIN.MARKERS.values() for marker in values)
    data = b"MZ " + markers + b" https://operator:password@download.example/stage.bin?token=hidden#x"
    result = APPDOMAIN.analyze(data)

    assert result["campaign_type"] == "appdomainmanager_pixel_loader"
    assert result["config"]["stage_urls"] == ["https://download.example/stage.bin"]
    assert result["config"]["static_config_recovered"] is False
    assert result["config"]["static_stage_locator_recovered"] is True
    assert result["config"]["endpoints"] == []
    assert result["il_call_graph_verified"] is False
    assert result["representative_functions"]
    assert all(
        item["call_graph_verified"] is False
        and item["confidence"] == "structural_marker_hypothesis"
        and "callees" not in item
        and "api_calls" not in item
        for item in result["representative_functions"]
    )
    quality = handler_result_quality(
        result,
        APPDOMAIN.HANDLER_CONTRACT["minimum_evidence_score"],
    )
    assert quality["tier_name"] == "validated_static_stage_locator"
    assert quality["sufficient"] is True

    secret_path = APPDOMAIN.analyze(b"MZ " + markers + b" https://download.example/token/private-value")
    assert secret_path["config"]["stage_urls"] == ["https://download.example/[REDACTED]"]


def test_appdomain_normalizes_ipv6_stage_url_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """IPv6 stage hostは角括弧を保ち、portを曖昧に連結しない。"""

    monkeypatch.setattr(APPDOMAIN.pefile, "PE", lambda **_kwargs: _managed_image())
    markers = b" ".join(marker for values in APPDOMAIN.MARKERS.values() for marker in values)
    result = APPDOMAIN.analyze(b"MZ " + markers + b" https://[2001:0DB8:0:0:0:0:0:1]:8443/stage.bin")

    assert result["config"]["stage_urls"] == ["https://[2001:db8::1]:8443/stage.bin"]
    assert result["config"]["static_stage_locator_recovered"] is True
    assert result["config"]["static_config_recovered"] is False


def test_appdomain_rejects_invalid_host_and_url_candidate_overflow(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全markerがあってもURL形式不正または候補上限超過ならconfigを返さない。"""

    monkeypatch.setattr(APPDOMAIN.pefile, "PE", lambda **_kwargs: _managed_image())
    markers = b" ".join(marker for values in APPDOMAIN.MARKERS.values() for marker in values)
    invalid = APPDOMAIN.analyze(b"MZ " + markers + b" http://999.999.999.999/stage.bin")
    assert invalid["config"]["stage_urls"] == []
    assert invalid["config"]["static_config_recovered"] is False

    monkeypatch.setattr(APPDOMAIN, "MAXIMUM_URL_COUNT", 1)
    overflow = APPDOMAIN.analyze(b"MZ " + markers + b" https://one.example/a.bin https://two.example/b.bin")
    assert overflow["config"]["stage_urls"] == []
    assert overflow["config"]["static_config_recovered"] is False


@pytest.mark.parametrize("module", [SINGLE, APPDOMAIN])
def test_campaign_handler_input_limit_precedes_pe_parser(
    module,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """64 MiB上限相当を超えた入力ではPE parserを呼ばない。"""

    monkeypatch.setattr(module, "MAXIMUM_INPUT_SIZE", 4)
    monkeypatch.setattr(
        module.pefile,
        "PE",
        lambda **_kwargs: pytest.fail("上限超過後にPE parserを呼んではならない"),
    )
    result = module.analyze(b"MZ123")
    assert result["recovery_status"] == "not_attempted_input_size_limit"
    assert result["config"]["static_config_recovered"] is False
    assert result.get("resources", []) == []
    assert result["endpoints"] == [] if "endpoints" in result else True
