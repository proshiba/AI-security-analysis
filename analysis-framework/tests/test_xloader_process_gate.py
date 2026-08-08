from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from malware.formbook_loader.process_gate import (
    ProcessGateError,
    build_protected_u32,
    build_report,
    crc32_bzip2_name,
    extract_blacklist_entries,
    parse_onemon_events,
)


def _relative_call(offset: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target - (offset + 5))


def _synthetic_entries(count: int = 20, builder: int = 0x800) -> bytes:
    data = bytearray()
    for index in range(count):
        data.extend(b"\x51")
        data.extend(b"\x6a" + bytes([(0x52 + index) & 0xFF]))
        data.extend(b"\x68" + struct.pack("<I", 0x55A2049A + index))
        data.extend(_relative_call(len(data), builder))
        data.extend(b"\x83\xc4\x08")
    return bytes(data)


def test_protected_hash_builder_matches_static_vectors() -> None:
    assert build_protected_u32(0x55A2049A, 0x52) == 0x3EBE9086
    assert build_protected_u32(0x748CB982, 0x4B) == 0x4C6FDDB5
    assert build_protected_u32(0x0502E0CC, 0xCA) == 0xF04C1AA9
    assert build_protected_u32(0x68D2DED8, 0x6C) == 0x7C81C71D


def test_name_crc_is_case_insensitive_and_matches_known_names() -> None:
    assert crc32_bzip2_name("VMWAREUSER.EXE") == 0x3EBE9086
    assert crc32_bzip2_name("explorer.exe") == 0x19996921
    assert crc32_bzip2_name("python.exe") == 0x911BC70E


def test_extract_blacklist_entries_reads_push_sequence() -> None:
    image = _synthetic_entries(2)
    entries = extract_blacklist_entries(
        image,
        function_start=0,
        function_end=len(image),
        builder_target=0x800,
        expected_count=2,
    )
    assert entries[0].constant == 0x55A2049A
    assert entries[0].seed == 0x52
    assert entries[0].expected_hash == 0x3EBE9086
    assert entries[0].known_name == "vmwareuser.exe"
    assert entries[1].constant == 0x55A2049B


def test_extract_blacklist_entries_fails_closed_on_bad_shape() -> None:
    image = _relative_call(0, 0x800)
    with pytest.raises(ProcessGateError, match="PUSH列"):
        extract_blacklist_entries(
            image,
            function_start=0,
            function_end=len(image),
            builder_target=0x800,
        )


def test_extract_blacklist_entries_rejects_count_mismatch() -> None:
    image = _synthetic_entries(1)
    with pytest.raises(ProcessGateError, match="ハッシュ数が不一致"):
        extract_blacklist_entries(
            image,
            function_start=0,
            function_end=len(image),
            builder_target=0x800,
            expected_count=20,
        )


def test_parse_onemon_events_filters_pid(tmp_path: Path) -> None:
    path = tmp_path / "onemon.json"
    rows = [
        {
            "kind": "onemon.Suspicious",
            "event": {
                "event": "EnumeratesProcesses",
                "pid": 42,
                "ts": 100,
            },
        },
        {
            "kind": "onemon.SyscallI",
            "event": {
                "kind": "Sleep",
                "arg0": 10000,
                "pid": 42,
                "ts": 200,
            },
        },
        {
            "kind": "onemon.Process",
            "event": {
                "status": "Terminate",
                "exitStatus": 0,
                "pid": 42,
                "ts": 31000,
            },
        },
        {
            "kind": "onemon.Suspicious",
            "event": {
                "event": "EnumeratesProcesses",
                "pid": 99,
                "ts": 300,
            },
        },
    ]
    path.write_text(
        "\n".join(json.dumps(row) for row in rows) + "\n",
        encoding="utf-8",
    )
    result = parse_onemon_events(path, pid=42)
    assert result["process_enumeration_count"] == 1
    assert result["sleep_10000ms_count"] == 1
    assert result["termination"]["exit_status"] == 0
    assert result["observed_pids"] == [42]


def test_parse_onemon_events_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_text("{", encoding="utf-8")
    with pytest.raises(ProcessGateError, match="1行目"):
        parse_onemon_events(path)


def test_build_report_correlates_expected_full_failure() -> None:
    image = _synthetic_entries()
    observation = {
        "source": "task-onemon.json",
        "process_enumeration_count": 7,
        "sleep_10000ms_count": 3,
        "termination": {"timestamp_ms": 31297, "exit_status": 0},
    }
    report = build_report(
        image,
        sample_sha256="a" * 64,
        function_start=0,
        function_end=len(image),
        builder_target=0x800,
        onemon=[observation],
    )
    assert report["safety"]["sample_executed_locally"] is False
    assert report["target_selection"][
        "total_process_enumerations_on_no_candidate"
    ] == 7
    assert report["assessment"]["direct_cause"] == (
        "no_eligible_explorer_child_candidate_in_three_retries"
    )
    assert report["correlation"] == [
        {
            "source": "task-onemon.json",
            "enumeration_count_matches": True,
            "sleep_count_matches": True,
            "normal_exit_after_retry_window": True,
        }
    ]
