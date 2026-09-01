"""共通remediation registryのexact-matchとfail-closed契約を検証する。"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

registry = importlib.import_module("remediation_registry")


def test_terminal_reason_and_action_sets_have_complete_closure() -> None:
    assert set(registry.TERMINAL_NEXT_ACTION_BY_REASON) == set(registry.TERMINAL_ACQUISITION_REASONS)
    assert len(registry.TERMINAL_ACQUISITION_REASONS) == 19


@pytest.mark.parametrize(
    "blocker",
    [
        " terminal_payload_not_recovered",
        "terminal_payload_not_recovered ",
        "Terminal_payload_not_recovered",
        "terminal_payload_not_recovered:extra",
        "orchestration:network:extra",
        "terminal_acquisition:child_timeout:extra",
        "terminal_acquisition:unknown_reason",
        "batch_error:unknown_failure",
        "batch_error:input_read_failed:extra",
        "selected_family_has_no_automatic_handler:bad:family",
    ],
)
def test_near_match_or_unknown_blocker_does_not_resolve(blocker: str) -> None:
    assert registry.action_key_for_blocker(blocker) is None
    assert registry.planner_policy_for_blocker(blocker) is None


def test_unknown_terminal_reason_raises_instead_of_guessing() -> None:
    with pytest.raises(registry.UnknownBlockerError):
        registry.terminal_next_action("child_timeout_extra")


def test_existing_action_ids_remain_compatible() -> None:
    assert registry.terminal_next_action("child_timeout") == "retry_child_static_analysis"
    assert registry.terminal_blocker_code("child_timeout") == "terminal_acquisition:child_timeout"
    assert registry.action_key_for_blocker("terminal_payload_not_recovered") == "terminal"
    assert registry.action_key_for_blocker("terminal_acquisition:child_timeout") == "terminal"
    policy = registry.planner_policy_for_blocker("terminal_payload_not_recovered")
    assert policy is not None
    assert policy.action_id == "recover_terminal_payload_statically"


@pytest.mark.parametrize(
    ("blocker", "action_key", "action_id", "target_phase"),
    [
        (
            "batch_error:input_read_failed",
            "manual",
            "review_machine_readable_blocker",
            "static_analysis",
        ),
        (
            "batch_error:resume_validation_failed",
            "static",
            "reanalyze_static_pipeline",
            "static_analysis",
        ),
        (
            "batch_error:root_static_analysis_failed",
            "static",
            "reanalyze_static_pipeline",
            "static_analysis",
        ),
    ],
)
def test_batch_errors_have_exact_fail_closed_policies(
    blocker: str,
    action_key: str,
    action_id: str,
    target_phase: str | None,
) -> None:
    assert registry.action_key_for_blocker(blocker) == action_key
    policy = registry.planner_policy_for_blocker(blocker)
    assert policy is not None
    assert policy.action_id == action_id
    assert policy.target_phase == target_phase
    assert policy.retryable is False
