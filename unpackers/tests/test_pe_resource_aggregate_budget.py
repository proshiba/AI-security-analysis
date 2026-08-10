"""PE resource走査の集約budgetとpartial証跡を検証する。"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from unpackers import static_unpacker


class _Section:
    Name = b".text\0\0\0"
    SizeOfRawData = 16
    Misc_VirtualSize = 16
    Characteristics = 0x60000020
    VirtualAddress = 0x1000

    @staticmethod
    def get_data() -> bytes:
        return b"A" * 16


def _fake_image(resource_sizes: list[int]):
    """指定sizeのlanguage resourceを持つ最小PE parser doubleを返す。"""

    languages = [
        SimpleNamespace(
            data=SimpleNamespace(
                struct=SimpleNamespace(OffsetToData=index * 32, Size=size)
            )
        )
        for index, size in enumerate(resource_sizes)
    ]
    resource_tree = SimpleNamespace(
        entries=[
            SimpleNamespace(
                directory=SimpleNamespace(
                    entries=[
                        SimpleNamespace(
                            directory=SimpleNamespace(entries=languages)
                        )
                    ]
                )
            )
        ]
    )
    directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(15)]
    return SimpleNamespace(
        sections=[_Section()],
        OPTIONAL_HEADER=SimpleNamespace(
            DATA_DIRECTORY=directories,
            AddressOfEntryPoint=0x1000,
        ),
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        DIRECTORY_ENTRY_RESOURCE=resource_tree,
        parse_data_directories=lambda **_kwargs: None,
        get_overlay_data_start_offset=lambda: None,
        get_data=lambda _offset, size: b"R" * size,
    )


def _prepare(monkeypatch: pytest.MonkeyPatch, resource_sizes: list[int]) -> None:
    image = _fake_image(resource_sizes)
    monkeypatch.setattr(static_unpacker.pefile, "PE", lambda **_kwargs: image)
    monkeypatch.setattr(static_unpacker, "entropy", lambda _data: 1.0)
    monkeypatch.setattr(
        static_unpacker,
        "pe_resource_children",
        lambda _blob: ("data", [], None),
    )


def test_resource_count_budget_is_partial(monkeypatch: pytest.MonkeyPatch) -> None:
    """resource件数上限後の未走査をcompleteと誤表示しない。"""

    _prepare(monkeypatch, [8, 8, 8])
    monkeypatch.setattr(static_unpacker, "MAX_PE_RESOURCE_ENTRIES", 2)

    summary, _ = static_unpacker.pe_summary(b"MZ" + b"\0" * 126)
    resource_scan = summary["resource_scan"]

    assert resource_scan["status"] == "partial"
    assert resource_scan["entries_inspected"] == 2
    assert resource_scan["bytes_inspected"] == 16
    assert resource_scan["exhausted_reasons"] == ["resource_count_budget"]


def test_resource_byte_and_elapsed_budgets_are_structured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """resource総byte数と経過時間の両上限を独立して記録する。"""

    _prepare(monkeypatch, [8])
    monkeypatch.setattr(static_unpacker, "MAX_PE_RESOURCE_TOTAL_BYTES", 4)
    byte_summary, _ = static_unpacker.pe_summary(b"MZ" + b"\0" * 126)
    byte_scan = byte_summary["resource_scan"]
    assert byte_scan["status"] == "partial"
    assert byte_scan["bytes_inspected"] == 0
    assert byte_scan["exhausted_reasons"] == ["resource_total_bytes_budget"]

    _prepare(monkeypatch, [8])
    monkeypatch.setattr(static_unpacker, "MAX_PE_RESOURCE_TOTAL_BYTES", 1024)
    ticks = iter((0.0, 2.0))
    monkeypatch.setattr(static_unpacker.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(static_unpacker, "MAX_PE_RESOURCE_ELAPSED_SECONDS", 1.0)
    elapsed_summary, _ = static_unpacker.pe_summary(b"MZ" + b"\0" * 126)
    elapsed_scan = elapsed_summary["resource_scan"]
    assert elapsed_scan["status"] == "partial"
    assert elapsed_scan["entries_inspected"] == 0
    assert elapsed_scan["exhausted_reasons"] == ["resource_elapsed_time_budget"]


def test_oversized_resource_is_partial_and_propagates_to_coverage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """単体上限を超えるresourceを未走査のままcompleteと表示しない。"""

    _prepare(monkeypatch, [9])
    monkeypatch.setattr(static_unpacker, "MAX_ARTIFACT", 8)

    summary, _ = static_unpacker.pe_summary(b"MZ" + b"\0" * 126)

    assert summary["resource_scan"]["status"] == "partial"
    assert summary["resource_scan"]["bytes_inspected"] == 0
    assert summary["resource_scan"]["exhausted_reasons"] == [
        "resource_entry_size_budget"
    ]
    assert summary["analysis_coverage"] == {
        "status": "partial",
        "imports_known": True,
        "low_import_heuristics_applied": True,
        "resources_complete": False,
        "limitations": ["resource_scan_resource_entry_size_budget"],
    }


def test_resource_directory_parse_failure_is_partial(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """resource directory parser失敗をresource／全体coverageへ伝播する。"""

    image = _fake_image([])

    def parse_directories(*, directories):  # noqa: ANN001, ANN202
        if directories == [
            static_unpacker.pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]
        ]:
            raise ValueError("malformed resource directory")

    image.parse_data_directories = parse_directories
    monkeypatch.setattr(static_unpacker.pefile, "PE", lambda **_kwargs: image)
    monkeypatch.setattr(static_unpacker, "entropy", lambda _data: 1.0)

    summary, _ = static_unpacker.pe_summary(b"MZ" + b"\0" * 126)

    assert summary["directory_parse"]["resources"]["status"] == "parse_failed"
    assert summary["resource_scan"]["status"] == "partial"
    assert summary["resource_scan"]["exhausted_reasons"] == [
        "resource_directory_parse_failed"
    ]
    assert summary["analysis_coverage"]["status"] == "partial"
    assert summary["analysis_coverage"]["resources_complete"] is False
    assert summary["analysis_coverage"]["limitations"] == [
        "resource_scan_resource_directory_parse_failed"
    ]
