from __future__ import annotations

from datetime import UTC, datetime

import pytest
from run_c2_monitoring_pipeline import render_enriched_report, stale_build_epochs


def test_render_enriched_report_includes_maxmind_section_once() -> None:
    result = {
        "schema_version": 1,
        "analysis_window": {"start": "2026-08-01", "end": "2026-08-02"},
        "target_count": 0,
        "state_counts": {},
        "results": [],
        "maxmind": {
            "lookup_count": 0,
            "matched_count": 0,
            "attribution": "This product includes GeoLite2 Data created by MaxMind.",
            "city_database": {},
            "asn_database": {},
        },
    }

    rendered = render_enriched_report(result)

    assert rendered.count("## MaxMind Geo/ASエンリッチ") == 1
    assert rendered.index("## MaxMind Geo/ASエンリッチ") < rendered.index("## 安全境界")


def test_stale_build_epochs_refreshes_at_exactly_24_hours() -> None:
    now = datetime(2026, 8, 2, 12, tzinfo=UTC)
    epochs = {
        "GeoLite2-City": int(datetime(2026, 8, 1, 12, tzinfo=UTC).timestamp()),
        "GeoLite2-ASN": int(datetime(2026, 8, 1, 12, 0, 1, tzinfo=UTC).timestamp()),
    }

    result = stale_build_epochs(epochs, now=now, max_age_hours=24)

    assert result == {"GeoLite2-City": True, "GeoLite2-ASN": False}


def test_stale_build_epochs_rejects_invalid_threshold_and_naive_time() -> None:
    with pytest.raises(ValueError, match="正数"):
        stale_build_epochs({}, now=datetime.now(UTC), max_age_hours=0)
    with pytest.raises(ValueError, match="timezone-aware"):
        stale_build_epochs({}, now=datetime(2026, 8, 2), max_age_hours=24)


def test_daily_handoff_is_bound_to_result_without_network() -> None:
    from build_all_c2_monitoring_targets import daily_effective_target_commitment
    from run_c2_monitoring_pipeline import (
        attach_daily_handoff_result_bindings,
        validate_daily_handoff_plan,
    )

    source_date = "2026-08-24"
    target = {
        "target_id": "daily-fixture",
        "host": "c2.example",
        "port": 443,
        "protocol": "tcp",
        "transport": "direct",
        "method": "tcp_connect",
        "daily_source_dates": [source_date],
    }
    effective_sha256, effective_count, _hosts = daily_effective_target_commitment(
        [target],
        source_date,
    )
    plan = {
        "targets": [target],
        "daily_source_handoffs": [
            {
                "schema_version": 1,
                "source_date": source_date,
                "source_target_commitment_sha256": "a" * 64,
                "source_target_count": 1,
                "effective_target_commitment_sha256": effective_sha256,
                "effective_target_count": effective_count,
            }
        ],
    }
    result = {
        "results": [
            {
                "target_id": "daily-fixture",
                "host": "c2.example",
                "port": 443,
                "protocol": "tcp",
                "transport": "direct",
                "method": "tcp_connect",
            }
        ]
    }

    handoffs = validate_daily_handoff_plan(plan)
    attach_daily_handoff_result_bindings(result, plan, handoffs)

    assert result["results"][0]["daily_source_dates"] == [source_date]
    binding = result["daily_source_handoffs"][0]
    assert binding["result_target_commitment_sha256"] == effective_sha256
    assert binding["result_target_count"] == 1

    tampered = {
        **plan,
        "targets": [{**target, "host": "other.example"}],
    }
    with pytest.raises(ValueError, match="実効C2 target集合"):
        validate_daily_handoff_plan(tampered)

    orphan_tag = {**plan, "daily_source_handoffs": []}
    with pytest.raises(ValueError, match="完全一致"):
        validate_daily_handoff_plan(orphan_tag)

    for invalid_dates in (
        [source_date, source_date],
        ["20260824"],
        ["2026-08-25", source_date],
    ):
        invalid_tags = {
            **plan,
            "targets": [{**target, "daily_source_dates": invalid_dates}],
        }
        with pytest.raises(ValueError, match="daily_source_dates"):
            validate_daily_handoff_plan(invalid_tags)

    wrong_source_count = {
        **plan,
        "daily_source_handoffs": [
            {
                **plan["daily_source_handoffs"][0],
                "source_target_count": 2,
            }
        ],
    }
    with pytest.raises(ValueError, match="実効C2 target集合"):
        validate_daily_handoff_plan(wrong_source_count)
