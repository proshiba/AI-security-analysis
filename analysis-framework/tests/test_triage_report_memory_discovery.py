"""Triage task reportからのmemory region発見を安全境界込みで検証する。"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import triage_artifact_retrieval as retrieval  # noqa: E402

SHA256 = "d025a29613e300d7755f878eb1d23d8a8a042cb2d3eb9005d66664ab9b97c677"
SAMPLE_ID = "260623-xf5ppsfw4y"
TASK_ID = "behavioral1"
REGION_NAME = (
    "memory/1700-22-0x00000000047E0000-"
    "0x00000000047F8000-memory.dmp"
)


def report_region(
    *,
    name: str = REGION_NAME,
    pid: int = 1700,
    procid: int = 91,
    addr: int = 0x47E0000,
    length: int = 0x18000,
) -> dict:
    """PureRAT公開解析で観測したregion dump形式のfixtureを返す。"""

    return {
        "version": "0.2.2",
        "sample": {
            "id": SAMPLE_ID,
            "target": "AggregatorHost.exe",
            "size": 11205296,
            "sha256": SHA256,
        },
        "task": {
            "target": "AggregatorHost.exe",
            "size": 11205296,
            "sha256": SHA256,
        },
        "dumped": [
            {
                "at": 23547,
                "pid": pid,
                "procid": procid,
                "name": name,
                "kind": "region",
                "origin": "dotnet32",
                "addr": addr,
                "length": length,
            }
        ],
    }


def test_reported_behavioral_tasks_keeps_at_most_two_reported_tasks() -> None:
    overview = {
        "sample": {"id": SAMPLE_ID, "sha256": SHA256},
        "tasks": {
            f"{SAMPLE_ID}-behavioral1": {
                "kind": "behavioral",
                "status": "reported",
            },
            f"{SAMPLE_ID}-behavioral2": {
                "kind": "behavioral",
                "status": "reported",
            },
            f"{SAMPLE_ID}-behavioral3": {
                "kind": "behavioral",
                "status": "reported",
            },
            f"{SAMPLE_ID}-static1": {
                "kind": "static",
                "status": "reported",
            },
        },
    }
    assert retrieval.reported_behavioral_tasks(
        overview, sample_id=SAMPLE_ID
    ) == ["behavioral1", "behavioral2"]


def test_extract_report_region_builds_bounded_memory_candidate() -> None:
    candidates = retrieval.extract_report_memory_candidates(
        report_region(),
        expected_sha256=SHA256,
        sample_id=SAMPLE_ID,
        task_id=TASK_ID,
    )
    assert candidates == [
        {
            "parent_sha256": SHA256,
            "sample_id": SAMPLE_ID,
            "task_id": TASK_ID,
            "kind": "memory_image",
            "name": REGION_NAME.removeprefix("memory/"),
            "endpoint_path": (
                f"/samples/{SAMPLE_ID}/{TASK_ID}/memory/"
                + REGION_NAME.removeprefix("memory/")
            ),
            "reference_sha256": hashlib.sha256(
                REGION_NAME.encode("utf-8")
            ).hexdigest(),
            "selection": "reported_region_memory",
            "reported_pid": 1700,
            "reported_procid": 91,
            "reported_region_index": 22,
            "reported_address": 0x47E0000,
            "reported_length": 0x18000,
        }
    ]


@pytest.mark.parametrize(
    "name",
    [
        "memory/../1700-22-0x00000000047E0000-0x00000000047F8000-memory.dmp",
        "../1700-22-0x00000000047E0000-0x00000000047F8000-memory.dmp",
        "memory/nested/1700-22-0x00000000047E0000-0x00000000047F8000-memory.dmp",
    ],
)
def test_extract_report_region_rejects_path_traversal(name: str) -> None:
    with pytest.raises(ValueError, match="memory path"):
        retrieval.extract_report_memory_candidates(
            report_region(name=name),
            expected_sha256=SHA256,
            sample_id=SAMPLE_ID,
            task_id=TASK_ID,
        )


def test_extract_report_region_rejects_pid_and_length_mismatch() -> None:
    with pytest.raises(ValueError, match="pid"):
        retrieval.extract_report_memory_candidates(
            report_region(pid=1701),
            expected_sha256=SHA256,
            sample_id=SAMPLE_ID,
            task_id=TASK_ID,
        )
    with pytest.raises(ValueError, match="length"):
        retrieval.extract_report_memory_candidates(
            report_region(length=0x17000),
            expected_sha256=SHA256,
            sample_id=SAMPLE_ID,
            task_id=TASK_ID,
        )


def test_extract_report_region_rejects_oversize_and_aggregate_overflow() -> None:
    with pytest.raises(ValueError, match="length"):
        retrieval.extract_report_memory_candidates(
            report_region(),
            expected_sha256=SHA256,
            sample_id=SAMPLE_ID,
            task_id=TASK_ID,
            max_bytes=0x10000,
        )

    report = report_region()
    report["dumped"].append(
        {
            **report["dumped"][0],
            "name": (
                "memory/1700-23-0x0000000004800000-"
                "0x0000000004818000-memory.dmp"
            ),
            "addr": 0x4800000,
        }
    )
    with pytest.raises(ValueError, match="合計length"):
        retrieval.extract_report_memory_candidates(
            report,
            expected_sha256=SHA256,
            sample_id=SAMPLE_ID,
            task_id=TASK_ID,
            max_total_bytes=0x20000,
        )


def test_extract_report_region_rejects_too_many_candidates() -> None:
    report = report_region()
    report["dumped"].append(
        {
            **report["dumped"][0],
            "name": (
                "memory/1700-23-0x0000000004800000-"
                "0x0000000004818000-memory.dmp"
            ),
            "addr": 0x4800000,
        }
    )
    with pytest.raises(ValueError, match="候補件数"):
        retrieval.extract_report_memory_candidates(
            report,
            expected_sha256=SHA256,
            sample_id=SAMPLE_ID,
            task_id=TASK_ID,
            max_candidates=1,
        )


def test_extract_report_region_rejects_sample_or_task_mismatch() -> None:
    wrong_sample = report_region()
    wrong_sample["sample"]["id"] = "260623-abcdefghij"
    with pytest.raises(ValueError, match="sample ID"):
        retrieval.extract_report_memory_candidates(
            wrong_sample,
            expected_sha256=SHA256,
            sample_id=SAMPLE_ID,
            task_id=TASK_ID,
        )

    wrong_hash = report_region()
    wrong_hash["sample"]["sha256"] = "a" * 64
    with pytest.raises(ValueError, match="SHA-256"):
        retrieval.extract_report_memory_candidates(
            wrong_hash,
            expected_sha256=SHA256,
            sample_id=SAMPLE_ID,
            task_id=TASK_ID,
        )

    wrong_task = report_region()
    wrong_task["task"]["id"] = f"{SAMPLE_ID}-behavioral2"
    with pytest.raises(ValueError, match="task ID"):
        retrieval.extract_report_memory_candidates(
            wrong_task,
            expected_sha256=SHA256,
            sample_id=SAMPLE_ID,
            task_id=TASK_ID,
        )

    wrong_task_hash = report_region()
    wrong_task_hash["task"]["sha256"] = "b" * 64
    with pytest.raises(ValueError, match="task SHA-256"):
        retrieval.extract_report_memory_candidates(
            wrong_task_hash,
            expected_sha256=SHA256,
            sample_id=SAMPLE_ID,
            task_id=TASK_ID,
        )


def test_discover_candidates_uses_report_when_overview_extracted_is_empty(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    overview = {
        "sample": {"id": SAMPLE_ID, "sha256": SHA256},
        "tasks": {
            f"{SAMPLE_ID}-{TASK_ID}": {
                "kind": "behavioral",
                "status": "reported",
            }
        },
        "extracted": [],
    }
    responses = {
        f"/search?query=sha256%3A{SHA256}": {"data": [{"id": SAMPLE_ID}]},
        f"/samples/{SAMPLE_ID}": {"sha256": SHA256, "private": False},
        f"/samples/{SAMPLE_ID}/overview.json": overview,
        f"/samples/{SAMPLE_ID}/{TASK_ID}/report_triage.json": report_region(),
    }
    requested: list[str] = []

    def fake_api_json(  # noqa: ANN202
        path, api_key, *, opener, timeout  # noqa: ANN001, ARG001
    ):
        requested.append(path)
        return responses[path]

    monkeypatch.setattr(retrieval, "api_json", fake_api_json)
    candidates, errors = retrieval.discover_candidates(
        [SHA256],
        "test-key",
        opener=object(),
        timeout=1,
        include_memory=True,
    )
    assert errors == []
    assert len(candidates) == 1
    assert candidates[0]["selection"] == "reported_region_memory"
    assert candidates[0]["reported_length"] == 0x18000
    assert requested[-1].endswith(f"/{TASK_ID}/report_triage.json")


def _many_report_regions(*, task_offset: int, count: int) -> dict:
    """実データ同様に多数のregionを含むtask reportを構築する。"""

    report = report_region()
    report["dumped"] = []
    for index in range(count):
        region_index = task_offset + index
        start = 0x47E0000 + region_index * 0x20000
        end = start + 0x18000
        report["dumped"].append(
            {
                "at": 23547 + index,
                "pid": 1700,
                "procid": 91,
                "name": (
                    f"memory/1700-{region_index}-0x{start:016X}-"
                    f"0x{end:016X}-memory.dmp"
                ),
                "kind": "region",
                "origin": "dotnet32",
                "addr": start,
                "length": 0x18000,
            }
        )
    return report


def test_default_discovery_keeps_72_regions_independent_of_download_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """既定発見上限は、既定取得上限20より多い実PureRAT 72件を保持する。"""

    overview = {
        "sample": {"id": SAMPLE_ID, "sha256": SHA256},
        "tasks": {
            f"{SAMPLE_ID}-behavioral1": {
                "kind": "behavioral",
                "status": "reported",
            },
            f"{SAMPLE_ID}-behavioral2": {
                "kind": "behavioral",
                "status": "reported",
            },
        },
        "extracted": [],
    }
    responses = {
        f"/search?query=sha256%3A{SHA256}": {"data": [{"id": SAMPLE_ID}]},
        f"/samples/{SAMPLE_ID}": {"sha256": SHA256, "private": False},
        f"/samples/{SAMPLE_ID}/overview.json": overview,
        f"/samples/{SAMPLE_ID}/behavioral1/report_triage.json": (
            _many_report_regions(task_offset=22, count=36)
        ),
        f"/samples/{SAMPLE_ID}/behavioral2/report_triage.json": (
            _many_report_regions(task_offset=58, count=36)
        ),
    }

    def fake_api_json(path, api_key, *, opener, timeout):  # noqa: ANN001, ANN202, ARG001
        return responses[path]

    monkeypatch.setattr(retrieval, "api_json", fake_api_json)
    candidates, errors = retrieval.discover_candidates(
        [SHA256],
        "test-key",
        opener=object(),
        timeout=1,
        include_memory=True,
    )

    assert errors == []
    assert len(candidates) == 72
    assert any(
        candidate["name"].startswith("1700-22-") for candidate in candidates
    )
    assert retrieval.DEFAULT_MAX_REPORT_MEMORY_CANDIDATES == 100
    assert retrieval.build_parser().get_default("max_artifacts") == 20
