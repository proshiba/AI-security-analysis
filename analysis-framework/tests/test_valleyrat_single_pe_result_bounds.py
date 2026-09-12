"""ValleyRAT generic単一PE handlerの公開結果上限を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
SINGLE_PE_ROOT = FRAMEWORK / "malware" / "valleyrat" / "campaigns" / "single_pe"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def catalog():
    return _load(COMMON / "handler_catalog.py", "single_pe_bounds_handler_catalog")


@pytest.fixture(scope="module")
def single_pe():
    return _load(SINGLE_PE_ROOT / "analyze_single_pe.py", "single_pe_bounds_native")


@pytest.fixture(scope="module")
def dotnet_il():
    return _load(SINGLE_PE_ROOT / "analyze_dotnet_il.py", "single_pe_bounds_dotnet")


def _assert_public_quota_complete(catalog, result: dict) -> None:
    budget = catalog._PublicValueBudget()
    catalog.sanitize_public_value(result, _budget=budget)
    assert budget.truncated is False
    assert budget.reasons == set()
    assert budget.entries < catalog.MAX_PUBLIC_RESULT_ENTRIES


class _Section:
    def __init__(self, index: int) -> None:
        self.Name = f".s{index}".encode().ljust(8, b"\0")
        self.VirtualAddress = 0x1000 + index * 0x1000
        self.SizeOfRawData = 8192
        self.Misc_VirtualSize = 8192
        self.Characteristics = 0x60000020
        self._index = index

    def get_data(self) -> bytes:
        return bytes([self._index % 251]) * 64

    def get_entropy(self) -> float:
        return 7.5


def _native_fake_pe() -> SimpleNamespace:
    imports = []
    for module_index in range(100):
        functions = [
            SimpleNamespace(
                name=(
                    f"ConnectFunction{function_index}" if function_index == 0 else f"Function{function_index}"
                ).encode(),
                ordinal=function_index,
            )
            for function_index in range(40)
        ]
        imports.append(SimpleNamespace(dll=f"library{module_index}.dll".encode(), imports=functions))
    exports = [
        SimpleNamespace(name=f"Export{index}".encode(), ordinal=index, address=index * 16) for index in range(200)
    ]
    languages = [
        SimpleNamespace(
            name=None,
            struct=SimpleNamespace(Id=index),
            data=SimpleNamespace(struct=SimpleNamespace(OffsetToData=index, Size=32)),
        )
        for index in range(200)
    ]
    name_entry = SimpleNamespace(
        name="private-resource-name",
        struct=SimpleNamespace(Id=1),
        directory=SimpleNamespace(entries=languages),
    )
    type_entry = SimpleNamespace(
        name=None,
        struct=SimpleNamespace(Id=10),
        directory=SimpleNamespace(entries=[name_entry]),
    )
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(15)]
    directories[14] = SimpleNamespace(VirtualAddress=1, Size=16)
    return SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=imports,
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(symbols=exports),
        DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(entries=[type_entry]),
        DIRECTORY_ENTRY_TLS=None,
        FILE_HEADER=SimpleNamespace(Machine=0x14C, TimeDateStamp=1),
        OPTIONAL_HEADER=SimpleNamespace(
            DATA_DIRECTORY=directories,
            AddressOfEntryPoint=0x1000,
            ImageBase=0x400000,
        ),
        sections=[_Section(index) for index in range(120)],
        get_data=lambda _offset, size: b"R" * size,
        get_imphash=lambda: "bounded-imphash",
        get_overlay_data_start_offset=lambda: None,
    )


def test_native_single_pe_large_collections_are_bounded_and_deterministic(
    monkeypatch: pytest.MonkeyPatch,
    catalog,
    single_pe,
) -> None:
    data = b"MZ" + b"\0" * 1022
    managed = [f"https://host{index}.example/path config PRIVATE-VALUE-{index}" for index in range(500)]
    native = [f"192.0.2.{index % 255}:443 socket PRIVATE-NATIVE-{index}" for index in range(500)]
    monkeypatch.setattr(single_pe.pefile, "PE", lambda **_kwargs: _native_fake_pe())
    monkeypatch.setattr(single_pe, "dotnet_user_strings", lambda _data: managed)
    monkeypatch.setattr(single_pe, "strings", lambda _data: native)

    expected = hashlib.sha256(data).hexdigest()
    first = single_pe.analyze(data, expected)
    second = single_pe.analyze(data, expected)

    assert first == second
    assert first["schema_version"] == 2
    assert len(first["imports"]) <= single_pe.MAX_RETAINED_IMPORT_MODULES
    assert sum(map(len, first["imports"].values())) <= single_pe.MAX_RETAINED_IMPORT_FUNCTIONS
    assert len(first["exports"]) == single_pe.MAX_RETAINED_EXPORTS
    assert len(first["sections"]) == single_pe.MAX_RETAINED_SECTIONS
    assert len(first["resources"]) == single_pe.MAX_RETAINED_RESOURCES
    assert first["collection_coverage"]["resources"]["omitted_count"] == 136
    assert first["collection_coverage"]["managed_user_strings"]["complete"] is False
    assert first["raw_config_included"] is False
    assert first["raw_payload_included"] is False
    assert first["source_name_included"] is False
    serialized = json.dumps(first, sort_keys=True)
    assert "PRIVATE-VALUE" not in serialized
    assert "PRIVATE-NATIVE" not in serialized
    for evidence in (
        *first["managed_user_string_evidence"],
        *first["suspicious_string_evidence"],
    ):
        assert "sha256" not in evidence
        assert evidence["content_exported"] is False
        assert evidence["identity_hash_exported"] is False
    _assert_public_quota_complete(catalog, first)


def test_native_member_name_summary_omits_content_and_identity_hash(single_pe) -> None:
    summary = single_pe._member_name_summary("PRIVATE-MEMBER.exe")

    assert summary == {
        "length": 18,
        "content_exported": False,
        "identity_hash_exported": False,
    }
    assert "PRIVATE-MEMBER" not in json.dumps(summary, sort_keys=True)


def test_native_url_iocs_remove_credentials_query_fragment_and_sensitive_path(single_pe) -> None:
    opaque = "A1b2_" * 8
    sensitive = (
        f"https://private-user:private-password@Safe.Example/token/{opaque}?api_key=private-query#private-fragment"
    )
    ordinary = "https://Safe.Example/releases/stage.bin?tracking=private-tracking#removed"

    iocs, coverage = single_pe._bounded_iocs([sensitive, ordinary])  # noqa: SLF001

    assert iocs["urls"] == [
        "https://safe.example/[REDACTED]",
        "https://safe.example/releases/stage.bin",
    ]
    assert coverage["urls"] == {
        "observed_count": 2,
        "retained_count": 2,
        "omitted_count": 0,
        "complete": True,
    }
    rendered = json.dumps(iocs, sort_keys=True)
    for secret in (
        "private-user",
        "private-password",
        opaque,
        "private-query",
        "private-fragment",
        "private-tracking",
    ):
        assert secret not in rendered


def _dotnet_fake_pe() -> SimpleNamespace:
    resources = [SimpleNamespace(name=f"PRIVATE-RESOURCE-{index}", data=b"R" * 16, size=16) for index in range(100)]
    methods = [SimpleNamespace(Rva=index + 2, Name=f"Method{index}") for index in range(200)]
    tables = SimpleNamespace(
        MethodDef=SimpleNamespace(rows=methods),
        TypeDef=SimpleNamespace(rows=[]),
    )
    return SimpleNamespace(
        net=SimpleNamespace(resources=resources, mdtables=tables),
        get_offset_from_rva=lambda rva: rva,
    )


def _method_body() -> SimpleNamespace:
    instructions = []
    for index in range(20):
        instructions.append(SimpleNamespace(opcode=SimpleNamespace(name="ldstr"), operand=0x70000001 + index))
    for index in range(20):
        instructions.append(SimpleNamespace(opcode=SimpleNamespace(name="call"), operand=0x0A000001 + index))
    for index in range(20):
        instructions.append(SimpleNamespace(opcode=SimpleNamespace(name="ldc.i4"), operand=index))
    return SimpleNamespace(instructions=instructions)


def _tiny_il_method(code: bytes) -> bytes:
    assert len(code) <= 63
    return bytes([(len(code) << 2) | 0x02]) + code


def _fat_il_header(code_size: int, *, more_sections: bool = False) -> bytes:
    flags_and_size = (3 << 12) | 0x03
    if more_sections:
        flags_and_size |= 0x08
    return (
        flags_and_size.to_bytes(2, "little")
        + (8).to_bytes(2, "little")
        + code_size.to_bytes(4, "little")
        + b"\0" * 4
    )


def _fat_il_method(code: bytes, *, extra_section: bytes | None = None) -> bytes:
    body = _fat_il_header(
        len(code),
        more_sections=extra_section is not None,
    ) + code
    if extra_section is None:
        return body
    return body + b"\0" * (-len(body) % 4) + extra_section


def _single_managed_method_pe(body_offset: int) -> SimpleNamespace:
    method = SimpleNamespace(Rva=body_offset, Name="Method")
    owner_link = SimpleNamespace(row_index=1)
    owner = SimpleNamespace(
        TypeNamespace="Synthetic",
        TypeName="Owner",
        MethodList=[owner_link],
    )
    return SimpleNamespace(
        net=SimpleNamespace(
            resources=[],
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[method]),
                TypeDef=SimpleNamespace(rows=[owner]),
            ),
        ),
        get_offset_from_rva=lambda rva: rva,
    )


@pytest.mark.parametrize(
    ("method_body", "header_format", "extra_section_count"),
    [
        (_tiny_il_method(b"\x2a"), "tiny", 0),
        (_fat_il_method(b"\x2a"), "fat", 0),
        (
            _fat_il_method(
                b"\x2a",
                extra_section=b"\x01\x10\x00\x00" + b"\0" * 12,
            ),
            "fat",
            1,
        ),
        (
            _fat_il_method(
                b"\x2a",
                extra_section=(
                    b"\x81\x10\x00\x00"
                    + b"\0" * 12
                    + b"\x01\x10\x00\x00"
                    + b"\0" * 12
                ),
            ),
            "fat",
            2,
        ),
    ],
)
def test_dotnet_reader_receives_only_validated_declared_method_body(
    monkeypatch: pytest.MonkeyPatch,
    dotnet_il,
    method_body: bytes,
    header_format: str,
    extra_section_count: int,
) -> None:
    body_offset = 4
    trailing = b"PRIVATE-TRAILING-DATA"
    data = b"MZ\0\0" + method_body + trailing
    observed_bodies: list[bytes] = []
    monkeypatch.setattr(
        dotnet_il.dnfile,
        "dnPE",
        lambda **_kwargs: _single_managed_method_pe(body_offset),
    )

    def read_body(value: bytes) -> SimpleNamespace:
        observed_bodies.append(value)
        return SimpleNamespace(instructions=[])

    monkeypatch.setattr(dotnet_il, "read_method_body_from_bytes", read_body)

    result = dotnet_il.analyze(data, hashlib.sha256(data).hexdigest())

    assert observed_bodies == [method_body]
    assert trailing not in observed_bodies[0]
    assert result["method_body_byte_budget"]["copied_bytes"] == len(method_body)
    assert result["method_body_validation"]["validated_count"] == 1
    assert result["method_body_validation"][f"{header_format}_header_count"] == 1
    assert (
        result["method_body_validation"]["extra_section_count"]
        == extra_section_count
    )
    assert result["method_body_validation"]["validation_failure_count"] == 0
    assert result["method_body_validation"]["parser_failure_count"] == 0
    assert result["analysis_status"] == "complete"


@pytest.mark.parametrize(
    ("method_body", "failure_reason"),
    [
        (b"\x00", "invalid_method_header_format"),
        (bytes([(3 << 2) | 0x02]) + b"\x2a", "truncated_tiny_method_code"),
        (b"\x03\x30" + b"\0" * 5, "truncated_fat_method_header"),
        (
            _fat_il_header(8) + b"\x2a",
            "truncated_fat_method_code",
        ),
        (
            _fat_il_header(512 * 1024),
            "method_body_size_limit",
        ),
        (
            _fat_il_header(0, more_sections=True),
            "truncated_method_extra_section_header",
        ),
        (
            _fat_il_header(0, more_sections=True)
            + b"\x41"
            + (262156).to_bytes(3, "little"),
            "method_extra_section_byte_limit",
        ),
    ],
)
def test_dotnet_invalid_truncated_or_oversize_method_never_reaches_reader(
    monkeypatch: pytest.MonkeyPatch,
    dotnet_il,
    method_body: bytes,
    failure_reason: str,
) -> None:
    body_offset = 4
    data = b"MZ\0\0" + method_body
    reader_calls = 0
    monkeypatch.setattr(
        dotnet_il.dnfile,
        "dnPE",
        lambda **_kwargs: _single_managed_method_pe(body_offset),
    )

    def read_body(_value: bytes) -> SimpleNamespace:
        nonlocal reader_calls
        reader_calls += 1
        return SimpleNamespace(instructions=[])

    monkeypatch.setattr(dotnet_il, "read_method_body_from_bytes", read_body)

    result = dotnet_il.analyze(data, hashlib.sha256(data).hexdigest())

    assert reader_calls == 0
    assert result["method_body_count"] == 0
    assert result["method_body_validation"]["validated_count"] == 0
    assert result["method_body_validation"]["validation_failure_count"] == 1
    assert result["method_body_validation"]["validation_failures_by_reason"] == {
        failure_reason: 1
    }
    assert result["analysis_status"] == "partial"


def test_dotnet_total_body_budget_never_forwards_a_partial_method(
    monkeypatch: pytest.MonkeyPatch,
    dotnet_il,
) -> None:
    method_body = _tiny_il_method(b"A" * 7)
    methods = [
        SimpleNamespace(Rva=2, Name="First"),
        SimpleNamespace(Rva=2 + len(method_body), Name="Second"),
    ]
    owner = SimpleNamespace(
        TypeNamespace="Synthetic",
        TypeName="Owner",
        MethodList=[
            SimpleNamespace(row_index=1),
            SimpleNamespace(row_index=2),
        ],
    )
    fake = SimpleNamespace(
        net=SimpleNamespace(
            resources=[],
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=methods),
                TypeDef=SimpleNamespace(rows=[owner]),
            ),
        ),
        get_offset_from_rva=lambda rva: rva,
    )
    observed_bodies: list[bytes] = []
    monkeypatch.setattr(dotnet_il.dnfile, "dnPE", lambda **_kwargs: fake)
    monkeypatch.setattr(
        dotnet_il,
        "read_method_body_from_bytes",
        lambda value: (
            observed_bodies.append(value)
            or SimpleNamespace(instructions=[])
        ),
    )
    monkeypatch.setattr(dotnet_il, "MAX_TOTAL_METHOD_BODY_BYTES", 10)
    data = b"MZ" + method_body * 2

    result = dotnet_il.analyze(data, hashlib.sha256(data).hexdigest())

    assert observed_bodies == [method_body]
    assert result["method_body_validation"]["validated_count"] == 2
    assert result["method_body_byte_budget"] == {
        "copied_bytes": len(method_body),
        "maximum_bytes": 10,
        "maximum_bytes_per_method": dotnet_il.MAX_METHOD_BODY_WINDOW_BYTES,
        "exhausted": True,
        "omitted_method_count": 1,
        "whole_input_copied_per_method": False,
    }
    assert result["analysis_status"] == "partial"


def _owner_coverage_pe(
    method_count: int,
    owner_method_indices: list[list[int]],
) -> SimpleNamespace:
    methods = [
        SimpleNamespace(Rva=0, Name=f"Method{index}")
        for index in range(method_count)
    ]
    owners = [
        SimpleNamespace(
            TypeNamespace="Synthetic",
            TypeName=f"Owner{owner_index}",
            MethodList=[
                SimpleNamespace(row_index=method_index)
                for method_index in method_indices
            ],
        )
        for owner_index, method_indices in enumerate(owner_method_indices)
    ]
    return SimpleNamespace(
        net=SimpleNamespace(
            resources=[],
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=methods),
                TypeDef=SimpleNamespace(rows=owners),
            ),
        ),
        get_offset_from_rva=lambda rva: rva,
    )


def test_dotnet_typedef_owner_sampling_marks_machine_readable_partial(
    monkeypatch: pytest.MonkeyPatch,
    dotnet_il,
) -> None:
    fake = _owner_coverage_pe(3, [[1], [2], [3]])
    monkeypatch.setattr(dotnet_il.dnfile, "dnPE", lambda **_kwargs: fake)
    monkeypatch.setattr(dotnet_il, "MAX_TYPE_ROWS_INSPECTED", 2)
    data = b"MZ"

    result = dotnet_il.analyze(data, hashlib.sha256(data).hexdigest())

    assert result["collection_coverage"]["method_owner_type_rows"] == {
        "observed_count": 3,
        "retained_count": 2,
        "omitted_count": 1,
        "complete": False,
        "limit_reached": True,
    }
    assert result["collection_coverage"]["method_owner_links"] == {
        "observed_count": 3,
        "retained_count": 2,
        "omitted_count": 1,
        "complete": False,
        "inspected_count": 2,
        "invalid_count": 0,
        "limit_reached": True,
    }
    assert result["analysis_status"] == "partial"


def test_dotnet_owner_link_limit_marks_machine_readable_partial(
    monkeypatch: pytest.MonkeyPatch,
    dotnet_il,
) -> None:
    fake = _owner_coverage_pe(3, [[1, 2, 3]])
    monkeypatch.setattr(dotnet_il.dnfile, "dnPE", lambda **_kwargs: fake)
    monkeypatch.setattr(dotnet_il, "MAX_METHOD_OWNER_LINKS_INSPECTED", 2)
    data = b"MZ"

    result = dotnet_il.analyze(data, hashlib.sha256(data).hexdigest())

    assert result["collection_coverage"]["method_owner_type_rows"] == {
        "observed_count": 1,
        "retained_count": 1,
        "omitted_count": 0,
        "complete": False,
        "limit_reached": True,
    }
    assert result["collection_coverage"]["method_owner_links"] == {
        "observed_count": 3,
        "retained_count": 2,
        "omitted_count": 1,
        "complete": False,
        "inspected_count": 2,
        "invalid_count": 0,
        "limit_reached": True,
    }
    assert result["analysis_status"] == "partial"


def test_dotnet_large_method_graph_is_bounded_and_resource_names_are_private(
    monkeypatch: pytest.MonkeyPatch,
    catalog,
    dotnet_il,
) -> None:
    data = b"MZ" + b"\x02" * 4094
    fake = _dotnet_fake_pe()
    monkeypatch.setattr(dotnet_il.dnfile, "dnPE", lambda **_kwargs: fake)
    monkeypatch.setattr(dotnet_il, "read_method_body_from_bytes", lambda _data: _method_body())
    monkeypatch.setattr(dotnet_il, "token_name", lambda _pe, token: f"ConnectReference{token}")

    expected = hashlib.sha256(data).hexdigest()
    first = dotnet_il.analyze(data, expected)
    second = dotnet_il.analyze(data, expected)

    assert first == second
    assert first["analysis_status"] == "partial"
    assert first["method_count"] == 200
    assert first["methods_with_references_count"] == 200
    assert len(first["methods_with_references"]) == dotnet_il.MAX_RETAINED_METHODS
    assert first["collection_coverage"]["methods_with_references"]["omitted_count"] == 152
    assert len(first["manifest_resources"]) == dotnet_il.MAX_RETAINED_MANIFEST_RESOURCES
    assert first["collection_coverage"]["manifest_resources"]["omitted_count"] == 36
    assert "PRIVATE-RESOURCE" not in json.dumps(first, sort_keys=True)
    assert all("name_sha256" not in resource for resource in first["manifest_resources"])
    assert all(resource["name_included"] is False for resource in first["manifest_resources"])
    assert all(resource["name_identity_hash_included"] is False for resource in first["manifest_resources"])
    assert first["raw_config_included"] is False
    assert first["raw_payload_included"] is False
    assert first["source_name_included"] is False
    _assert_public_quota_complete(catalog, first)


def test_dotnet_method_windows_and_total_row_budget_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
    dotnet_il,
) -> None:
    """巨大method tableでも末尾全体をmethodごとに複製せず、固定予算で停止する。"""

    method_size = 8
    methods = [
        SimpleNamespace(Rva=2 + index * method_size, Name=f"Method{index}")
        for index in range(10)
    ]
    fake = SimpleNamespace(
        net=SimpleNamespace(
            resources=[],
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=methods),
                TypeDef=SimpleNamespace(rows=[]),
            ),
        ),
        get_offset_from_rva=lambda rva: rva,
    )
    observed_windows: list[int] = []

    def read_window(data: bytes) -> SimpleNamespace:
        observed_windows.append(len(data))
        return SimpleNamespace(instructions=[])

    monkeypatch.setattr(dotnet_il.dnfile, "dnPE", lambda **_kwargs: fake)
    monkeypatch.setattr(dotnet_il, "read_method_body_from_bytes", read_window)
    monkeypatch.setattr(dotnet_il, "MAX_METHOD_ROWS_INSPECTED", 3)
    monkeypatch.setattr(dotnet_il, "MAX_METHOD_BODY_WINDOW_BYTES", 8)
    monkeypatch.setattr(dotnet_il, "MAX_TOTAL_METHOD_BODY_BYTES", 16)

    tiny_method = bytes([(7 << 2) | 0x02]) + b"A" * 7
    data = b"MZ" + tiny_method * len(methods)
    result = dotnet_il.analyze(data, hashlib.sha256(data).hexdigest())

    assert observed_windows == [8, 8]
    assert result["method_count"] == 10
    assert result["collection_coverage"]["method_rows"] == {
        "observed_count": 10,
        "retained_count": 2,
        "omitted_count": 8,
        "complete": False,
    }
    assert result["method_body_byte_budget"]["exhausted"] is True
    assert result["method_body_byte_budget"]["whole_input_copied_per_method"] is False
    assert result["analysis_status"] == "partial"


def test_dotnet_duplicate_references_do_not_falsely_mark_coverage_incomplete(
    monkeypatch: pytest.MonkeyPatch,
    dotnet_il,
) -> None:
    """同じtokenの反復回数と公開する一意reference件数を混同しない。"""

    method = SimpleNamespace(Rva=1, Name="Repeated")
    fake = SimpleNamespace(
        net=SimpleNamespace(
            resources=[],
            user_strings=SimpleNamespace(get=lambda _row: SimpleNamespace(value="socket")),
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[method]),
                TypeDef=SimpleNamespace(rows=[]),
            ),
        ),
        get_offset_from_rva=lambda _rva: 1,
    )
    instruction = SimpleNamespace(
        opcode=SimpleNamespace(name="ldstr"),
        operand=0x70000001,
    )
    monkeypatch.setattr(dotnet_il.dnfile, "dnPE", lambda **_kwargs: fake)
    monkeypatch.setattr(
        dotnet_il,
        "read_method_body_from_bytes",
        lambda _data: SimpleNamespace(instructions=[instruction] * 3),
    )

    data = b"MZ" + b"A" * 32
    result = dotnet_il.analyze(data, hashlib.sha256(data).hexdigest())

    item = result["methods_with_references"][0]
    assert item["string_reference_count"] == 1
    assert item["string_reference_occurrence_count"] == 3
    assert item["references_complete"] is True
    assert result["collection_coverage"]["string_references"]["complete"] is True


def test_dotnet_omitted_duplicate_reference_is_counted_once(
    monkeypatch: pytest.MonkeyPatch,
    dotnet_il,
) -> None:
    """保持上限外の同一token反復を別々のdistinct参照として数えない。"""

    method = SimpleNamespace(Rva=1, Name="OmittedRepeated")
    fake = SimpleNamespace(
        net=SimpleNamespace(
            resources=[],
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[method]),
                TypeDef=SimpleNamespace(rows=[]),
            ),
        ),
        get_offset_from_rva=lambda _rva: 1,
    )
    operands = [0x70000000 + index for index in range(1, 8)] + [0x70000007]
    instructions = [
        SimpleNamespace(opcode=SimpleNamespace(name="ldstr"), operand=operand)
        for operand in operands
    ]
    monkeypatch.setattr(dotnet_il.dnfile, "dnPE", lambda **_kwargs: fake)
    monkeypatch.setattr(
        dotnet_il,
        "read_method_body_from_bytes",
        lambda _data: SimpleNamespace(instructions=instructions),
    )
    monkeypatch.setattr(
        dotnet_il,
        "token_name",
        lambda _pe, token: f"Reference-{token:#x}",
    )
    monkeypatch.setattr(
        dotnet_il,
        "token_indicators",
        lambda _pe, _token, maximum_characters: (set(), 1, 1, True),
    )
    monkeypatch.setattr(dotnet_il, "MAX_RETAINED_STRING_REFERENCES_PER_METHOD", 6)

    data = b"MZ" + b"A" * 32
    result = dotnet_il.analyze(data, hashlib.sha256(data).hexdigest())

    item = result["methods_with_references"][0]
    assert item["string_reference_count"] == 7
    assert item["string_reference_occurrence_count"] == 8
    assert len(item["strings"]) == 6
    assert result["collection_coverage"]["string_references"] == {
        "observed_count": 7,
        "retained_count": 6,
        "omitted_count": 1,
        "complete": False,
    }


def test_dotnet_instruction_budget_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    dotnet_il,
) -> None:
    """method内instructionが上限を超えた場合は一部結果をcompleteにしない。"""

    method = SimpleNamespace(Rva=1, Name="Large")
    fake = SimpleNamespace(
        net=SimpleNamespace(
            resources=[],
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[method]),
                TypeDef=SimpleNamespace(rows=[]),
            ),
        ),
        get_offset_from_rva=lambda _rva: 1,
    )
    instructions = [SimpleNamespace(opcode=SimpleNamespace(name="ldc.i4"), operand=index) for index in range(5)]
    monkeypatch.setattr(dotnet_il.dnfile, "dnPE", lambda **_kwargs: fake)
    monkeypatch.setattr(
        dotnet_il,
        "read_method_body_from_bytes",
        lambda _data: SimpleNamespace(instructions=instructions),
    )
    monkeypatch.setattr(dotnet_il, "MAX_INSTRUCTIONS_PER_METHOD", 2)
    monkeypatch.setattr(dotnet_il, "MAX_TOTAL_INSTRUCTIONS", 2)

    data = b"MZ" + b"A" * 32
    result = dotnet_il.analyze(data, hashlib.sha256(data).hexdigest())

    assert result["instruction_budget"]["exhausted"] is True
    assert result["collection_coverage"]["instructions"] == {
        "observed_count": 5,
        "retained_count": 2,
        "omitted_count": 3,
        "complete": False,
    }
    assert result["analysis_status"] == "partial"


def test_dotnet_user_string_token_is_summarized_without_content_or_hash(dotnet_il) -> None:
    secret = "PRIVATE-CONFIG-CONTENT"
    user_strings = SimpleNamespace(get=lambda _row: SimpleNamespace(value=secret))
    pe = SimpleNamespace(net=SimpleNamespace(user_strings=user_strings))

    rendered = dotnet_il.token_name(pe, 0x70000001)

    assert secret not in rendered
    assert rendered == f"UserString[1]:length={len(secret)}"
    assert hashlib.sha256(secret.encode()).hexdigest() not in rendered


def test_dotnet_member_name_summary_omits_content_and_identity_hash(dotnet_il) -> None:
    summary = dotnet_il._member_name_summary("PRIVATE-MEMBER.exe")

    assert summary == {
        "length": 18,
        "content_exported": False,
        "identity_hash_exported": False,
    }
    assert "PRIVATE-MEMBER" not in json.dumps(summary, sort_keys=True)


def test_dotnet_raw_user_string_markers_rank_method_without_public_content(
    monkeypatch: pytest.MonkeyPatch,
    dotnet_il,
) -> None:
    raw_values = {
        1: "ordinary text",
        2: "socket connect decrypt config PRIVATE-RANKING-CONTENT",
    }
    user_strings = SimpleNamespace(
        get=lambda row: SimpleNamespace(value=raw_values[row]),
    )
    methods = [
        SimpleNamespace(Rva=2, Name="First"),
        SimpleNamespace(Rva=3, Name="Second"),
    ]
    fake = SimpleNamespace(
        net=SimpleNamespace(
            resources=[],
            user_strings=user_strings,
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=methods),
                TypeDef=SimpleNamespace(rows=[]),
            ),
        ),
        get_offset_from_rva=lambda rva: rva,
    )
    bodies = iter(
        [
            SimpleNamespace(instructions=[SimpleNamespace(opcode=SimpleNamespace(name="ldstr"), operand=0x70000001)]),
            SimpleNamespace(instructions=[SimpleNamespace(opcode=SimpleNamespace(name="ldstr"), operand=0x70000002)]),
        ]
    )
    monkeypatch.setattr(dotnet_il.dnfile, "dnPE", lambda **_kwargs: fake)
    monkeypatch.setattr(dotnet_il, "read_method_body_from_bytes", lambda _data: next(bodies))
    monkeypatch.setattr(dotnet_il, "MAX_RETAINED_METHODS", 1)

    data = b"MZ" + b"\x02\x02" + b"\0" * 62
    result = dotnet_il.analyze(data, hashlib.sha256(data).hexdigest())

    assert result["analysis_status"] == "partial"
    assert result["methods_with_references"][0]["token"] == "0x06000002"
    assert result["methods_with_references"][0]["relevance_indicators"] == [
        "config",
        "connect",
        "decrypt",
        "socket",
    ]
    assert "PRIVATE-RANKING-CONTENT" not in json.dumps(result, sort_keys=True)


def test_dotnet_resource_hash_and_indicator_scans_are_bounded(
    monkeypatch: pytest.MonkeyPatch,
    dotnet_il,
) -> None:
    """巨大resourceとUserStringを固定byte/文字予算外まで走査しない。"""

    secret = "socket " + ("PRIVATE-LONG-VALUE" * 64)
    method = SimpleNamespace(Rva=1, Name="Bounded")
    fake = SimpleNamespace(
        net=SimpleNamespace(
            resources=[SimpleNamespace(name="PRIVATE-NAME", data=b"R" * 33, size=33)],
            user_strings=SimpleNamespace(get=lambda _row: SimpleNamespace(value=secret)),
            mdtables=SimpleNamespace(
                MethodDef=SimpleNamespace(rows=[method]),
                TypeDef=SimpleNamespace(rows=[]),
            ),
        ),
        get_offset_from_rva=lambda _rva: 1,
    )
    instruction = SimpleNamespace(opcode=SimpleNamespace(name="ldstr"), operand=0x70000001)
    monkeypatch.setattr(dotnet_il.dnfile, "dnPE", lambda **_kwargs: fake)
    monkeypatch.setattr(
        dotnet_il,
        "read_method_body_from_bytes",
        lambda _data: SimpleNamespace(instructions=[instruction]),
    )
    monkeypatch.setattr(dotnet_il, "MAX_MANIFEST_RESOURCE_HASH_BYTES", 32)
    monkeypatch.setattr(dotnet_il, "MAX_TOTAL_MANIFEST_RESOURCE_HASH_BYTES", 32)
    monkeypatch.setattr(dotnet_il, "MAX_REFERENCE_INDICATOR_CHARS", 8)
    monkeypatch.setattr(dotnet_il, "MAX_TOTAL_REFERENCE_INDICATOR_CHARS", 8)

    data = b"MZ" + b"A" * 32
    result = dotnet_il.analyze(data, hashlib.sha256(data).hexdigest())

    resource = result["manifest_resources"][0]
    assert resource["sha256"] is None
    assert resource["content_hash_complete"] is False
    assert result["manifest_resource_hash_budget"]["exhausted"] is True
    assert result["collection_coverage"]["manifest_resource_hashes"]["complete"] is False
    assert result["reference_indicator_scan_budget"] == {
        "scanned_characters": 8,
        "maximum_total_characters": 8,
        "maximum_characters_per_reference": 8,
        "exhausted": True,
    }
    assert result["collection_coverage"]["reference_indicator_characters"]["complete"] is False
    assert result["analysis_status"] == "partial"
    assert "PRIVATE-LONG-VALUE" not in json.dumps(result, sort_keys=True)
