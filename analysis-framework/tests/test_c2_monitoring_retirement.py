from __future__ import annotations

import sys
from pathlib import Path


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_monitoring_history as history  # noqa: E402


def point(timestamp: str, availability: str) -> dict:
    return {
        "date": timestamp[:10],
        "observed_at_utc": timestamp,
        "availability": availability,
    }


def test_retirement_days_are_counted_from_last_on() -> None:
    lifecycle = history._lifecycle(
        [
            point("2026-08-01T00:00:00+00:00", "on"),
            point("2026-08-02T00:00:00+00:00", "off"),
            point("2026-08-08T00:00:00+00:00", "off"),
        ],
        retirement_days=7,
        minimum_off_observations=2,
    )

    assert lifecycle["inactive_since_utc"] == "2026-08-01T00:00:00+00:00"
    assert lifecycle["inactive_days"] == 7.0
    assert lifecycle["status"] == "retired_stopped"


def test_unobserved_latest_result_is_not_retired() -> None:
    lifecycle = history._lifecycle(
        [
            point("2026-08-01T00:00:00+00:00", "on"),
            point("2026-08-02T00:00:00+00:00", "off"),
            point("2026-08-08T00:00:00+00:00", "not_observed"),
        ],
        retirement_days=7,
        minimum_off_observations=2,
    )

    assert lifecycle["status"] == "active_unobserved"
    assert lifecycle["active"] is True
