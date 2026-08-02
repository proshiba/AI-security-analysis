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
