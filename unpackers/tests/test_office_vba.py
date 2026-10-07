"""Office VBA静的復元のfail-closed回帰テスト。"""

from __future__ import annotations

from collections.abc import Iterable
from typing import ClassVar

import pytest

from unpackers import office_vba, static_unpacker


class _FakeVbaParser:
    """VBAやOfficeを実行しないoletools境界fixture。"""

    detected = True
    macros: Iterable[tuple[object, object, object, bytes | str]] = (
        ("sample", "VBA/Module1", "Module1", "Sub AutoOpen()\nEnd Sub\n"),
        ("sample", b"VBA/Module2", b"Module2", b"Sub Test()\r\nEnd Sub\r\n"),
    )
    constructed: ClassVar[list[dict[str, object]]] = []
    closed = False

    def __init__(self, filename: str, data: bytes, **kwargs: object) -> None:
        self.constructed.append(
            {"filename": filename, "data": data, "kwargs": kwargs}
        )

    def detect_vba_macros(self) -> bool:
        return self.detected

    def extract_macros(
        self,
    ) -> Iterable[tuple[object, object, object, bytes | str]]:
        return iter(self.macros)

    def close(self) -> None:
        type(self).closed = True


def _install_fake_parser(monkeypatch: pytest.MonkeyPatch) -> None:
    _FakeVbaParser.constructed = []
    _FakeVbaParser.closed = False
    monkeypatch.setattr(office_vba.olevba, "VBA_Parser", _FakeVbaParser)


def test_vba_source_is_recovered_without_parser_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_parser(monkeypatch)
    data = office_vba.OLE_MAGIC + b"fixture"

    report, artifacts = office_vba.recover_vba_modules(data)

    assert report["status"] == "vba_source_recovered"
    assert report["module_count"] == 2
    assert report["executed"] is False
    assert report["network_contacted"] is False
    assert report["pcode_processed"] is False
    assert report["office_application_started"] is False
    assert artifacts[0][0] == "office-vba-module-001.vba"
    assert artifacts[0][1].startswith(b"Sub AutoOpen")
    assert "Module1" not in str(report)
    assert "VBA/Module1" not in str(report)
    assert _FakeVbaParser.constructed[0]["kwargs"] == {
        "relaxed": False,
        "disable_pcode": True,
    }
    assert _FakeVbaParser.closed is True


@pytest.mark.parametrize(
    ("macros", "kwargs"),
    [
        (
            (("sample", "VBA/M", "M", b"A" * 17),),
            {"maximum_module_size": 16},
        ),
        (
            (
                ("sample", "VBA/A", "A", b"A" * 10),
                ("sample", "VBA/B", "B", b"B" * 10),
            ),
            {"maximum_total_source_size": 19},
        ),
        (
            (
                ("sample", "VBA/A", "A", b"A"),
                ("sample", "VBA/B", "B", b"B"),
            ),
            {"maximum_modules": 1},
        ),
    ],
)
def test_vba_output_limits_discard_all_artifacts(
    monkeypatch: pytest.MonkeyPatch,
    macros: Iterable[tuple[object, object, object, bytes | str]],
    kwargs: dict[str, int],
) -> None:
    _install_fake_parser(monkeypatch)
    monkeypatch.setattr(_FakeVbaParser, "macros", macros)

    report, artifacts = office_vba.recover_vba_modules(
        office_vba.OLE_MAGIC + b"fixture",
        **kwargs,
    )

    assert report["status"] == "output_limit_blocked"
    assert artifacts == []
    assert _FakeVbaParser.closed is True


def test_non_vba_and_input_limit_do_not_return_artifacts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install_fake_parser(monkeypatch)
    monkeypatch.setattr(_FakeVbaParser, "detected", False)
    report, artifacts = office_vba.recover_vba_modules(
        office_vba.OLE_MAGIC + b"fixture"
    )
    assert report["status"] == "vba_not_detected"
    assert artifacts == []

    blocked, blocked_artifacts = office_vba.recover_vba_modules(
        office_vba.OLE_MAGIC + b"fixture",
        maximum_input_size=len(office_vba.OLE_MAGIC),
    )
    assert blocked["status"] == "input_size_blocked"
    assert blocked_artifacts == []


def test_parser_close_failure_does_not_abort_static_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """破損container由来のclose失敗でworker全体を停止しない。"""

    _install_fake_parser(monkeypatch)

    def _raise_on_close(_self: _FakeVbaParser) -> None:
        raise OSError("synthetic close failure")

    monkeypatch.setattr(_FakeVbaParser, "close", _raise_on_close)
    report, artifacts = office_vba.recover_vba_modules(
        office_vba.OLE_MAGIC + b"fixture"
    )

    assert report["status"] == "vba_source_recovered"
    assert len(artifacts) == 2


def test_static_unpacker_routes_vba_source_as_recursive_layer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = b"Sub AutoOpen()\r\nEnd Sub\r\n"
    monkeypatch.setattr(
        static_unpacker,
        "recover_default_password_ooxml",
        lambda *_args, **_kwargs: ({"status": "not_office_encrypted_ooxml"}, []),
    )
    monkeypatch.setattr(
        static_unpacker,
        "recover_vba_modules",
        lambda *_args, **_kwargs: (
            {"status": "vba_source_recovered"},
            [("office-vba-module-001.vba", source)],
        ),
    )
    monkeypatch.setattr(
        static_unpacker,
        "recover_ole_streams",
        lambda *_args, **_kwargs: ({"status": "no_artifact_recovered"}, []),
    )

    report, artifacts = static_unpacker.unpack_bytes(
        office_vba.OLE_MAGIC + b"fixture",
        "document.bin",
    )

    assert report["office_vba"]["status"] == "vba_source_recovered"
    assert ("office-vba-module-001.vba", source) in artifacts
