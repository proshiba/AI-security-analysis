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
