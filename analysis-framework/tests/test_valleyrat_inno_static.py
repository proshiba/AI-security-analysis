"""Inno暗号化内層の非実行復元境界を検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import ClassVar

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "malware"
    / "valleyrat"
    / "campaigns"
    / "protected_installer_bundle"
    / "inno_static.py"
)
COMMON_PATH = MODULE_PATH.parents[4] / "common"
if str(COMMON_PATH) not in sys.path:
    sys.path.insert(0, str(COMMON_PATH))
SPEC = importlib.util.spec_from_file_location("valleyrat_inno_static_test", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)

ANALYZE_PATH = MODULE_PATH.with_name("analyze.py")
ANALYZE_SPEC = importlib.util.spec_from_file_location(
    "valleyrat_protected_installer_analyze_test",
    ANALYZE_PATH,
)
assert ANALYZE_SPEC and ANALYZE_SPEC.loader
ANALYZE = importlib.util.module_from_spec(ANALYZE_SPEC)
ANALYZE_SPEC.loader.exec_module(ANALYZE)
bounded_process = importlib.import_module("bounded_process")
handler_catalog = importlib.import_module("handler_catalog")


def _contains_bytes(value: object) -> bool:
    if isinstance(value, (bytes, bytearray, memoryview)):
        return True
    if isinstance(value, dict):
        return any(_contains_bytes(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_bytes(item) for item in value)
    return False


def test_script_candidates_are_static_literals_only() -> None:
    script = "Assign LocalVar1 := 'abcdefghijklmnop'\nCall ExpandConstant\n"
    assert MODULE.script_password_candidates(script) == ("abcdefghijklmnop",)
    assert MODULE.script_password_candidates("Call TAC\n") == ()


def test_static_recovery_never_calls_script_emulator(monkeypatch: pytest.MonkeyPatch) -> None:
    import refinery.lib.inno.archive as archive_module

    expected = b"MZ synthetic inert fixture"
    item = SimpleNamespace(path="data/test.dll", size=len(expected), encrypted=True, dupe=False)

    class FakeScript:
        def disassembly(self) -> str:
            return "Assign LocalVar1 := 'abcdefghijklmnop'"

    class FakeArchive:
        files: ClassVar[list[object]] = [item]
        ifps = FakeScript()

        def __init__(self, data: bytearray):
            assert data == b"safe synthetic container"

        def read_file_and_check(self, file: object, password: str | None) -> bytes:
            assert file is item
            assert password == "abcdefghijklmnop"
            return expected

        def guess_password(self, timeout: int) -> bool:
            raise AssertionError("PascalScript emulator must not run")

    monkeypatch.setattr(archive_module, "InnoArchive", FakeArchive)
    summary, recovered = MODULE.recover_members(b"safe synthetic container")
    assert summary["status"] == "recovered"
    assert summary["archive_entry_count"] == 1
    assert summary["duplicate_entry_count"] == 0
    assert summary["recovered_member_count"] == 1
    assert summary["safety"]["script_emulated"] is False
    assert "abcdefghijklmnop" not in str(summary)
    assert recovered == [("data/test.dll", expected)]


def test_private_writer_rejects_repository_tree(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="リポジトリ"):
        MODULE._write_private_members(MODULE_PATH.parent, [("data/test.dll", b"MZ")])
    outside = tmp_path / "private"
    MODULE._write_private_members(outside, [("data/test.dll", b"MZ")])
    assert len(list(outside.glob("*.quarantine.bin"))) == 1
    # 冪等再実行でも既存fileを再hashし、上書きしない。
    MODULE._write_private_members(outside, [("data/test.dll", b"MZ")])


def test_private_writer_rejects_hardlinked_existing_member(tmp_path: Path) -> None:
    content = b"MZ inert hardlink fixture"
    digest = hashlib.sha256(content).hexdigest()
    source = tmp_path / "source.bin"
    source.write_bytes(content)
    output = tmp_path / "private"
    output.mkdir()
    os.link(source, output / f"{digest}.quarantine.bin")

    with pytest.raises(ValueError, match="file属性"):
        MODULE._write_private_members(output, [("data/test.dll", content)])


def test_input_and_candidate_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    assert MODULE.MAX_INPUT_SIZE == 64 * 1024 * 1024
    assert MODULE.MAX_ARCHIVE_ENTRY_COUNT == 256
    assert MODULE.MAX_MEMBER_COUNT == 64
    assert MODULE.MAX_MEMBER_SIZE == 64 * 1024 * 1024
    assert MODULE.MAX_TOTAL_SIZE == 64 * 1024 * 1024
    assert MODULE.CONTAINED_WORKER_MEMORY_BUDGET == (bounded_process.DEFAULT_CONTAINED_MEMORY_BYTES)
    # parser入力の保守的3重保持、復元bytesの2重保持、固定headroomを合算しても、
    # handler workerの512 MiB containment内に必ず収まる契約とする。
    assert (
        3 * MODULE.MAX_INPUT_SIZE + 2 * MODULE.MAX_TOTAL_SIZE + MODULE.ESTIMATED_PARSER_HEADROOM
        <= MODULE.CONTAINED_WORKER_MEMORY_BUDGET
    )
    # 64 MiB超の実体をtest processへ確保せず、境界判定そのものを確認する。
    monkeypatch.setattr(MODULE, "MAX_INPUT_SIZE", 4)
    with pytest.raises(ValueError, match="サイズ上限"):
        MODULE.recover_members(b"x" * 5)
    literals = "\n".join(f"Assign LocalVar1 := '{i:08d}'" for i in range(33))
    with pytest.raises(ValueError, match="候補上限"):
        MODULE.script_password_candidates(literals)


def test_cli_input_size_gate_runs_before_file_open(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sample = tmp_path / "oversized.bin"
    sample.write_bytes(b"12345")
    monkeypatch.setattr(MODULE, "MAX_INPUT_SIZE", 4)

    def unexpected_open(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("oversized input must be rejected before open")

    monkeypatch.setattr(Path, "open", unexpected_open)
    with pytest.raises(ValueError, match="サイズ上限"):
        MODULE._read_bounded_input(sample)


def test_unsafe_member_names_use_digest_fallback() -> None:
    content = b"inert member"
    fallback = f"{hashlib.sha256(content).hexdigest()}.bin"
    assert MODULE.safe_recovered_member_name("data/good.dll", content) == "good.dll"
    assert MODULE.safe_recovered_member_name("../../unsafe.dll", content) == fallback
    assert MODULE.safe_recovered_member_name("data/name:stream.dll", content) == fallback
    assert MODULE.safe_recovered_member_name("data/CON.txt", content) == fallback


def test_member_and_total_limits_fail_before_recovery(monkeypatch: pytest.MonkeyPatch) -> None:
    import refinery.lib.inno.archive as archive_module

    too_many = [
        SimpleNamespace(path=f"data/{index}.bin", size=1, encrypted=False, dupe=False)
        for index in range(MODULE.MAX_MEMBER_COUNT + 1)
    ]

    class TooManyArchive:
        files = too_many
        ifps = None

        def __init__(self, _data: bytearray):
            pass

    monkeypatch.setattr(archive_module, "InnoArchive", TooManyArchive)
    with pytest.raises(ValueError, match="メンバー数"):
        MODULE.recover_members(b"bounded fixture")

    oversized = SimpleNamespace(
        path="data/large.bin",
        size=MODULE.MAX_MEMBER_SIZE + 1,
        encrypted=False,
        dupe=False,
    )

    class OversizedArchive:
        files: ClassVar[list[object]] = [oversized]
        ifps = None

        def __init__(self, _data: bytearray):
            pass

    monkeypatch.setattr(archive_module, "InnoArchive", OversizedArchive)
    with pytest.raises(ValueError, match="サイズ上限"):
        MODULE.recover_members(b"bounded fixture")

    total_members = [
        SimpleNamespace(
            path=f"data/part-{index}.bin",
            size=32 * 1024 * 1024,
            encrypted=False,
            dupe=False,
        )
        for index in range(3)
    ]

    class ExcessiveTotalArchive:
        files = total_members
        ifps = None

        def __init__(self, _data: bytearray):
            pass

    monkeypatch.setattr(archive_module, "InnoArchive", ExcessiveTotalArchive)
    with pytest.raises(ValueError, match="合計サイズ上限"):
        MODULE.recover_members(b"bounded fixture")

    duplicate = SimpleNamespace(
        path="data/duplicate.bin",
        size=1,
        encrypted=False,
        dupe=True,
    )

    class ExcessiveRawEntryArchive:
        files: ClassVar[list[object]] = [
            SimpleNamespace(
                path="data/unique.bin",
                size=1,
                encrypted=False,
                dupe=False,
            ),
            *([duplicate] * MODULE.MAX_ARCHIVE_ENTRY_COUNT),
        ]
        ifps = None

        def __init__(self, _data: bytearray):
            pass

    monkeypatch.setattr(archive_module, "InnoArchive", ExcessiveRawEntryArchive)
    with pytest.raises(ValueError, match="archive entry数"):
        MODULE.recover_members(b"bounded fixture")


def test_duplicate_entries_are_bounded_and_reported_without_duplicate_payloads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import refinery.lib.inno.archive as archive_module

    content = b"inert unique member"
    unique = SimpleNamespace(
        path="data/unique.bin",
        size=len(content),
        encrypted=False,
        dupe=False,
    )
    duplicate = SimpleNamespace(
        path="data/duplicate.bin",
        size=len(content),
        encrypted=False,
        dupe=True,
    )

    class DuplicateArchive:
        files: ClassVar[list[object]] = [unique, duplicate, duplicate]
        ifps = None

        def __init__(self, _data: bytearray):
            pass

        def read_file_and_check(self, item: object, _password: str | None) -> bytes:
            assert item is unique
            return content

    monkeypatch.setattr(archive_module, "InnoArchive", DuplicateArchive)
    summary, recovered = MODULE.recover_members(b"bounded fixture")
    assert summary["status"] == "recovered"
    assert summary["archive_entry_count"] == 3
    assert summary["duplicate_entry_count"] == 2
    assert summary["member_count"] == 1
    assert recovered == [("data/unique.bin", content)]


def test_incomplete_or_size_mismatched_recovery_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import refinery.lib.inno.archive as archive_module

    item = SimpleNamespace(path="data/test.dll", size=8, encrypted=False, dupe=False)

    class SizeMismatchArchive:
        files: ClassVar[list[object]] = [item]
        ifps = None

        def __init__(self, _data: bytearray):
            pass

        def read_file_and_check(self, _item: object, _password: str | None) -> bytes:
            return b"short"

    monkeypatch.setattr(archive_module, "InnoArchive", SizeMismatchArchive)
    with pytest.raises(MODULE.InnoMemberContractError, match="宣言サイズ"):
        MODULE.recover_members(b"bounded fixture")


def test_wrong_password_remains_candidate_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    import refinery.lib.inno.archive as archive_module

    item = SimpleNamespace(path="data/test.dll", size=8, encrypted=True, dupe=False)

    class FakeScript:
        def disassembly(self) -> str:
            return "Assign LocalVar1 := 'candidate-password'"

    class WrongPasswordArchive:
        files: ClassVar[list[object]] = [item]
        ifps = FakeScript()

        def __init__(self, _data: bytearray):
            pass

        def read_file_and_check(self, _item: object, _password: str | None) -> bytes:
            raise archive_module.InvalidPassword("synthetic wrong password")

    monkeypatch.setattr(archive_module, "InnoArchive", WrongPasswordArchive)
    summary, recovered = MODULE.recover_members(b"bounded fixture")
    assert summary["status"] == "password_candidates_rejected"
    assert summary["recovery_complete"] is False
    assert recovered == []


@pytest.mark.parametrize("failure", [MemoryError("synthetic memory pressure"), OSError("synthetic I/O failure")])
def test_system_failures_are_not_misclassified_as_wrong_password(
    monkeypatch: pytest.MonkeyPatch,
    failure: BaseException,
) -> None:
    import refinery.lib.inno.archive as archive_module

    item = SimpleNamespace(path="data/test.dll", size=8, encrypted=True, dupe=False)

    class FakeScript:
        def disassembly(self) -> str:
            return "Assign LocalVar1 := 'candidate-password'"

    class FailingArchive:
        files: ClassVar[list[object]] = [item]
        ifps = FakeScript()

        def __init__(self, _data: bytearray):
            pass

        def read_file_and_check(self, _item: object, _password: str | None) -> bytes:
            raise failure

    monkeypatch.setattr(archive_module, "InnoArchive", FailingArchive)
    with pytest.raises(type(failure), match="synthetic"):
        MODULE.recover_members(b"bounded fixture")


def test_reparsed_inventory_conflict_is_fail_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    import refinery.lib.inno.archive as archive_module

    first = SimpleNamespace(path="data/first.dll", size=8, encrypted=False, dupe=False)
    changed = SimpleNamespace(path="data/changed.dll", size=8, encrypted=False, dupe=False)

    class InventoryChangesArchive:
        construction_count: ClassVar[int] = 0
        ifps = None

        def __init__(self, _data: bytearray):
            type(self).construction_count += 1
            self.files = [first] if self.construction_count == 1 else [changed]

        def read_file_and_check(self, _item: object, _password: str | None) -> bytes:
            raise AssertionError("inventory相反時にmemberを読み出してはいけません")

    monkeypatch.setattr(archive_module, "InnoArchive", InventoryChangesArchive)
    with pytest.raises(MODULE.InnoInventoryConflictError, match="inventory"):
        MODULE.recover_members(b"bounded fixture")


def test_analyze_returns_each_complete_member_for_fixed_point_without_bytes_in_summary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = b"MZ first inert recovered member"
    second = b"second inert recovered member"
    recovered = [
        ("data/good.dll", first),
        ("../../unsafe.bin", second),
    ]
    summary = MODULE._summary(
        b"MZ outer inno setup fixture",
        (
            ("data/good.dll", len(first), False, False),
            ("data/unsafe.bin", len(second), False, False),
        ),
        (),
        recovered,
        "recovered",
    )

    fake_pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x1000),
        get_overlay_data_start_offset=lambda: None,
    )
    monkeypatch.setattr(ANALYZE.pefile, "PE", lambda **_kwargs: fake_pe)
    monkeypatch.setattr(
        ANALYZE,
        "_pe_sibling_profile",
        lambda content: (
            {"pe_kind": "dll", "imports": [], "import_inventory_complete": True}
            if content == first
            else None
        ),
    )
    monkeypatch.setattr(ANALYZE, "section_summaries", lambda _pe: [])
    monkeypatch.setattr(ANALYZE, "embedded_pe_header_offsets", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ANALYZE, "bounded_entropy", lambda _data: 0.0)
    monkeypatch.setattr(ANALYZE, "recover_members", lambda _data: (summary, recovered))

    result = ANALYZE.analyze(b"MZ outer inno setup fixture")
    assert _contains_bytes(result["inno_static"]) is False
    assert result["inno_static"]["safety"]["raw_bytes_included"] is False
    assert result["recovered_payloads"] == [
        {
            "role": "recovered_payload",
            "name": "good.dll",
            "data": first,
            "source_name": "good.dll",
            "analysis_priority": 2,
        },
        {
            "role": "recovered_payload",
            "name": f"{hashlib.sha256(second).hexdigest()}.bin",
            "data": second,
            "source_name": f"{hashlib.sha256(second).hexdigest()}.bin",
            "analysis_priority": 3,
        },
    ]
    outputs, audit = handler_catalog._verified_binary_outputs(result)
    outputs_by_sha256 = {item["sha256"]: item for item in outputs}
    first_sha256 = hashlib.sha256(first).hexdigest()
    second_sha256 = hashlib.sha256(second).hexdigest()
    assert outputs_by_sha256[first_sha256]["role"] == "recovered_payload"
    assert outputs_by_sha256[first_sha256]["path"] == "good.dll"
    assert outputs_by_sha256[first_sha256]["source_name"] == "good.dll"
    assert outputs_by_sha256[first_sha256]["analysis_priority"] == 2
    assert outputs_by_sha256[second_sha256]["role"] == "recovered_payload"
    assert outputs_by_sha256[second_sha256]["path"] == f"{second_sha256}.bin"
    assert outputs_by_sha256[second_sha256]["source_name"] == f"{second_sha256}.bin"
    assert outputs_by_sha256[second_sha256]["analysis_priority"] == 3
    assert audit["observed_output_count"] == 2


def test_bundle_analysis_prioritizes_imported_sibling_and_preserves_launch_relation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launcher = b"MZ inert launcher"
    target = b"MZ inert target DLL"
    archive = b"PK\x03\x04 inert nested archive"
    recovered = [
        ("data/app/host.exe", launcher),
        ("data/app/version.dll", target),
        ("data/tmp/content.7z", archive),
    ]

    def profile(content: bytes) -> dict[str, object] | None:
        if content == launcher:
            return {
                "pe_kind": "executable",
                "imports": ["version.dll"],
                "import_inventory_complete": True,
            }
        if content == target:
            return {
                "pe_kind": "dll",
                "imports": [],
                "import_inventory_complete": True,
            }
        return None

    monkeypatch.setattr(ANALYZE, "_pe_sibling_profile", profile)
    bundle, hints = ANALYZE._bundle_analysis(
        {
            "run_entry_basenames": ["host.exe"],
            "script_executable_literal_basenames": ["host.exe"],
        },
        recovered,
    )

    launcher_sha256 = hashlib.sha256(launcher).hexdigest()
    target_sha256 = hashlib.sha256(target).hexdigest()
    archive_sha256 = hashlib.sha256(archive).hexdigest()
    assert bundle["side_load_candidate_count"] == 1
    assert bundle["relationships"] == [
        {
            "relationship": "imports_sibling",
            "source_name": "host.exe",
            "source_sha256": launcher_sha256,
            "target_name": "version.dll",
            "target_sha256": target_sha256,
            "side_load_candidate": True,
        }
    ]
    assert hints == {
        launcher_sha256: {"source_name": "host.exe", "analysis_priority": 1},
        target_sha256: {"source_name": "version.dll", "analysis_priority": 0},
        archive_sha256: {"source_name": "content.7z", "analysis_priority": 0},
    }
    records = ANALYZE._recovered_payload_records(
        MODULE._summary(
            b"MZ outer",
            tuple((path, len(content), False, False) for path, content in recovered),
            (),
            recovered,
            "recovered",
        ),
        recovered,
        analysis_hints=hints,
    )
    assert [item["source_name"] for item in records] == [
        "content.7z",
        "version.dll",
        "host.exe",
    ]


def test_static_launch_basenames_are_bounded_and_separate_run_from_script() -> None:
    archive = SimpleNamespace(
        setup_info=SimpleNamespace(
            RunEntries=[SimpleNamespace(Name="{app}\\host.exe")],
        )
    )
    run, script = MODULE._static_launch_basenames(
        archive,
        "Assign LocalVar1 := 'helper.exe'\nAssign LocalVar2 := 'not-a-program.txt'",
    )
    assert run == ("host.exe",)
    assert script == ("helper.exe",)


def test_analyze_does_not_publish_payload_records_for_incomplete_recovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake_pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x1000),
        get_overlay_data_start_offset=lambda: None,
    )
    monkeypatch.setattr(ANALYZE.pefile, "PE", lambda **_kwargs: fake_pe)
    monkeypatch.setattr(ANALYZE, "section_summaries", lambda _pe: [])
    monkeypatch.setattr(ANALYZE, "embedded_pe_header_offsets", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(ANALYZE, "bounded_entropy", lambda _data: 0.0)
    monkeypatch.setattr(
        ANALYZE,
        "recover_members",
        lambda _data: (
            {
                "status": "script_password_unavailable",
                "recovery_complete": False,
                "member_count": 1,
                "recovered_member_count": 0,
                "members": [],
            },
            [],
        ),
    )

    result = ANALYZE.analyze(b"MZ outer inno setup fixture")
    assert "recovered_payloads" not in result

    payload = b"MZ contradictory inert member"
    contradictory = MODULE._summary(
        b"MZ outer inno setup fixture",
        (("data/member.dll", len(payload), False, False),),
        (),
        [("data/member.dll", payload)],
        "recovered",
    )
    contradictory["recovery_complete"] = False
    monkeypatch.setattr(
        ANALYZE,
        "recover_members",
        lambda _data: (contradictory, [("data/member.dll", payload)]),
    )
    result = ANALYZE.analyze(b"MZ outer inno setup fixture")
    assert result["inno_static"]["status"] == "static_recovery_unavailable"
    assert "recovered_payloads" not in result


def test_analyze_keeps_outer_inventory_when_inno_parser_limit_is_exceeded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Inno復元上限は、より大きい外層PEの静的棚卸しを打ち切らない。"""

    data = b"MZ inno setup synthetic outer"
    fake_pe = SimpleNamespace(
        FILE_HEADER=SimpleNamespace(Machine=0x14C),
        OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x1000),
        get_overlay_data_start_offset=lambda: None,
    )
    monkeypatch.setattr(ANALYZE, "MAX_INPUT_SIZE", 8)
    monkeypatch.setattr(ANALYZE, "MAX_SCAN_SIZE", 64)
    monkeypatch.setattr(ANALYZE.pefile, "PE", lambda **_kwargs: fake_pe)
    monkeypatch.setattr(ANALYZE, "section_summaries", lambda _pe: [])
    monkeypatch.setattr(ANALYZE, "embedded_pe_header_offsets", lambda *_args, **_kwargs: [16])
    monkeypatch.setattr(ANALYZE, "bounded_entropy", lambda _data: 0.0)

    def unexpected_recover(_data: bytes) -> tuple[dict[str, object], list[object]]:
        raise AssertionError("Inno上限超過時にparserを呼び出してはいけません")

    monkeypatch.setattr(ANALYZE, "recover_members", unexpected_recover)

    result = ANALYZE.analyze(data)

    assert result["embedded_pe_offsets"] == [16]
    assert result["inno_static"] == {
        "status": "input_size_limit",
        "input_size": len(data),
        "maximum_input_size": 8,
        "recovery_complete": False,
        "recovered_member_count": 0,
        "safety": {
            "sample_executed": False,
            "script_emulated": False,
            "network_contacted": False,
            "raw_bytes_included": False,
        },
    }
    assert "recovered_payloads" not in result


def test_duplicate_basenames_use_digest_fallback_for_every_record() -> None:
    first = b"MZ first same-name inert member"
    second = b"MZ second same-name inert member"
    recovered = [
        ("first/same.dll", first),
        ("second/SAME.DLL", second),
    ]
    summary = MODULE._summary(
        b"MZ outer inno setup fixture",
        (
            ("first/same.dll", len(first), False, False),
            ("second/SAME.DLL", len(second), False, False),
        ),
        (),
        recovered,
        "recovered",
    )

    records = ANALYZE._recovered_payload_records(summary, recovered)
    assert records == [
        {
            "role": "recovered_payload",
            "name": f"{hashlib.sha256(first).hexdigest()}.bin",
            "data": first,
        },
        {
            "role": "recovered_payload",
            "name": f"{hashlib.sha256(second).hexdigest()}.bin",
            "data": second,
        },
    ]
    outputs, audit = handler_catalog._verified_binary_outputs({"records": records})
    assert {item["path"] for item in outputs} == {
        f"{hashlib.sha256(first).hexdigest()}.bin",
        f"{hashlib.sha256(second).hexdigest()}.bin",
    }
    assert audit["observed_output_count"] == 2
