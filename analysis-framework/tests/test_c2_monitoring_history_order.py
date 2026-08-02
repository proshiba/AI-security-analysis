from __future__ import annotations

import json
import sys
from pathlib import Path


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_monitoring_history as history  # noqa: E402


def observation(timestamp: str, reachable: bool) -> dict:
    return {
        "host": "ordering.example",
        "port": 443,
        "protocol": "tcp",
        "transport": "direct",
        "observation": {
            "timestamp_utc": timestamp,
            "resolved_ips": ["192.0.2.1"],
            "target_contact_attempted": True,
            "alive": reachable,
        },
        "assessment": {
            "state": (
                "transport_reachable_c2_not_confirmed"
                if reachable
                else "not_reachable_at_observation"
            )
        },
    }


def test_future_run_is_not_imported_into_older_history(tmp_path: Path) -> None:
    future = tmp_path / "2026-08-09"
    future.mkdir()
    (future / "monitoring-results.json").write_text(
        json.dumps(
            {
                "policy": {"network_enabled": True},
                "results": [observation("2026-08-09T00:00:00+00:00", True)],
            }
        ),
        encoding="utf-8",
    )
    current = {
        "policy": {"network_enabled": True},
        "results": [observation("2026-08-08T00:00:00+00:00", False)],
    }
    plan = {
        "schema_version": 1,
        "targets": [
            {
                "host": "ordering.example",
                "port": 443,
                "protocol": "tcp",
                "transport": "direct",
            }
        ],
    }

    enriched, monitoring, _active = history.apply_monitoring_history(
        current,
        plan,
        history_root=tmp_path,
        current_run_name="2026-08-08",
    )

    assert enriched["results"][0]["monitoring_lifecycle"]["status"] == "active_grace"
    assert len(monitoring["endpoints"][0]["dns_tracking"]["history"]) == 1
