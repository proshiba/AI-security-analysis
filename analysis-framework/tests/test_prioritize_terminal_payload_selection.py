from __future__ import annotations

import importlib.util
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "common" / "prioritize_terminal_payload_selection.py"
SPEC = importlib.util.spec_from_file_location("prioritize_terminal_payload_selection", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _row(char: str, seen: str) -> dict[str, str]:
    return {"sha256_hash": char * 64, "first_seen": seen, "file_type": "exe"}


def _priority(family: str, row: dict[str, str]) -> tuple[str, dict[str, object]]:
    return (
        family,
        {
            "selection_mode": "signature_newest",
            "selected_hashes": [row["sha256_hash"]],
            "selected_metadata": [row],
        },
    )


def test_priority_merge_replaces_oldest_and_preserves_count() -> None:
    base_rows = [
        _row("a", "2026-08-11 03:00:00"),
        _row("b", "2026-08-11 02:00:00"),
        _row("c", "2026-08-11 01:00:00"),
    ]
    base = {
        "selection_mode": "windows_pe_newest",
        "requested": 3,
        "selected_hashes": [row["sha256_hash"] for row in base_rows],
        "selected_metadata": base_rows,
        "selection_provenance": {"method": "get_file_type"},
    }
    updated, plan = MODULE.build_priority_plan(
        base,
        [
            _priority("StealC", base_rows[1]),
            _priority("ValleyRAT", _row("d", "2026-08-10 23:00:00")),
        ],
    )

    assert plan["already_selected_count"] == 1
    assert plan["added_count"] == 1
    assert plan["replaced_count"] == 1
    assert updated["selected_hashes"] == ["a" * 64, "b" * 64, "d" * 64]
    assert updated["selected_metadata"][-1]["terminal_payload_priority_family"] == "valleyrat"
    assert updated["selection_only"] is True
    assert updated["complete"] is False


def test_priority_merge_never_replaces_already_selected_priority_candidate() -> None:
    base_rows = [
        _row("a", "2026-08-11 03:00:00"),
        _row("b", "2026-08-11 02:00:00"),
        _row("c", "2026-08-11 01:00:00"),
    ]
    base = {
        "selection_mode": "windows_pe_newest",
        "requested": 3,
        "selected_hashes": [row["sha256_hash"] for row in base_rows],
        "selected_metadata": base_rows,
    }

    updated, plan = MODULE.build_priority_plan(
        base,
        [
            _priority("Vidar", base_rows[2]),
            _priority("StealC", _row("d", "2026-08-10 23:00:00")),
        ],
    )

    assert updated["selected_hashes"] == ["a" * 64, "c" * 64, "d" * 64]
    assert plan["terminal_payload_priority"]["already_selected"] == [
        {"family": "Vidar", "sha256": "c" * 64}
    ]
    assert plan["terminal_payload_priority"]["replaced"] == [
        {"sha256": "b" * 64, "first_seen": "2026-08-11 02:00:00"}
    ]


def test_priority_merge_rejects_mismatched_metadata() -> None:
    base_row = _row("a", "2026-08-11 03:00:00")
    base = {
        "selection_mode": "windows_pe_newest",
        "requested": 1,
        "selected_hashes": [base_row["sha256_hash"]],
        "selected_metadata": [base_row],
    }
    family, manifest = _priority("ValleyRAT", _row("b", "2026-08-10 23:00:00"))
    manifest["selected_hashes"] = ["c" * 64]

    try:
        MODULE.build_priority_plan(base, [(family, manifest)])
    except ValueError as exc:
        assert "metadata mismatch" in str(exc)
    else:
        raise AssertionError("mismatched priority metadata must be rejected")


def test_priority_merge_accepts_multiple_windows_candidates_and_refreshes_commitment() -> None:
    base_rows = [
        _row("a", "2026-09-25 05:00:00"),
        _row("b", "2026-09-25 04:00:00"),
        _row("c", "2026-09-25 03:00:00"),
        _row("d", "2026-09-25 02:00:00"),
        _row("e", "2026-09-25 01:00:00"),
    ]
    base = {
        "selection_mode": "windows_pe_newest",
        "requested": 5,
        "selected_hashes": [row["sha256_hash"] for row in base_rows],
        "selected_metadata": base_rows,
        "selection_provenance": {"method": "get_file_type"},
        "selection_only": True,
        "downloaded": 0,
        "items": [],
    }
    contract = MODULE._batch_contract()
    base["selection_commitment_sha256"] = contract._windows_selection_commitment(base)
    valley_rows = [
        _row("f", "2026-09-24 23:00:00"),
        _row("1", "2026-09-24 22:00:00"),
    ]
    dcrat_rows = [
        {**_row("2", "2026-09-24 21:00:00"), "file_type": "zip"},
        _row("3", "2026-09-24 20:00:00"),
    ]
    updated, plan = MODULE.build_priority_plan(
        base,
        [
            ("ValleyRAT", {
                "selection_mode": "signature_newest",
                "selected_hashes": [row["sha256_hash"] for row in valley_rows],
                "selected_metadata": valley_rows,
            }),
            ("DcRAT", {
                "selection_mode": "signature_newest",
                "selected_hashes": [row["sha256_hash"] for row in dcrat_rows],
                "selected_metadata": dcrat_rows,
            }),
        ],
    )

    assert plan["priority_candidate_count"] == 3
    assert plan["skipped_non_windows_pe_count"] == 1
    assert plan["added_count"] == plan["replaced_count"] == 3
    assert updated["selected_hashes"] == ["a" * 64, "b" * 64, "f" * 64, "1" * 64, "3" * 64]
    assert updated["selection_commitment_sha256"] == contract._windows_selection_commitment(updated)


def test_priority_merge_rejects_invalid_base_commitment() -> None:
    row = _row("a", "2026-09-25 05:00:00")
    base = {
        "selection_mode": "windows_pe_newest",
        "requested": 1,
        "selected_hashes": [row["sha256_hash"]],
        "selected_metadata": [row],
        "selection_commitment_sha256": "0" * 64,
    }
    try:
        MODULE.build_priority_plan(base, [_priority("ValleyRAT", row)])
    except ValueError as exc:
        assert "commitment is invalid" in str(exc)
    else:
        raise AssertionError("invalid frozen selection must be rejected")
