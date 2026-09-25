from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import json
import sys

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from run_c2_monitoring_pipeline import (
    effective_target_addition_count,
    enforce_carry_forward_scope_authorization,
    load_same_day_observations,
    normalize_public_source_fields,
    render_enriched_report,
    restrict_to_reviewed_profiles,
    stale_build_epochs,
)
from monitor_recent_c2 import PlanError


def test_same_day_resume_reuses_only_unchanged_wire_targets(tmp_path: Path) -> None:
    window = {"start": "リポジトリ収録開始", "end": "2026-09-25T23:59:59+09:00"}
    old = {
        "target_id": "old",
        "family": "fixture",
        "host": "old.example",
        "port": 443,
        "protocol": "tcp",
        "transport": "direct",
        "method": "tcp_connect",
        "timeout_seconds": 3.0,
        "maximum_response_bytes": 256,
        "sources": ["old-source"],
    }
    result = {
        "target_id": "old",
        "host": "old.example",
        "port": 443,
        "protocol": "tcp",
        "transport": "direct",
        "method": "tcp_connect",
        "observation": {"timestamp_utc": "2026-09-25T00:00:00+00:00", "request_count": 0},
    }
    (tmp_path / "effective-targets.json").write_text(
        json.dumps({"analysis_window": window, "targets": [old]}), encoding="utf-8"
    )
    (tmp_path / "monitoring-results.json").write_text(
        json.dumps({
            "analysis_window": window,
            "target_count": 1,
            "policy": {
                "network_enabled": True,
                "one_bounded_probe_per_target": True,
                "network_execution_backend": "nmap_nse_only",
            },
            "results": [result],
        }), encoding="utf-8"
    )
    new = {"target_id": "new", "host": "new.example", "port": 0, "protocol": "dns"}
    plan = {"analysis_window": window, "targets": [{**old, "sources": ["new-source"]}, new]}
    assert load_same_day_observations(tmp_path, plan) == {"old": result["observation"]}
    with pytest.raises(ValueError, match="通信仕様"):
        load_same_day_observations(
            tmp_path,
            {**plan, "targets": [{**old, "timeout_seconds": 5.0}, new]},
        )


def test_effective_target_addition_count_uses_network_endpoint_boundary() -> None:
    requested = {
        "targets": [
            {
                "target_id": "today",
                "host": "same.example",
                "port": 443,
                "protocol": "tcp",
                "transport": "direct",
            }
        ]
    }
    effective = {
        "targets": [
            {
                "target_id": "renamed-metadata-only",
                "host": "same.example",
                "port": 443,
                "protocol": "tcp",
                "transport": "direct",
            },
            {
                "target_id": "carry-forward",
                "host": "prior.example",
                "port": 8443,
                "protocol": "tcp",
                "transport": "direct",
            },
        ]
    }

    assert effective_target_addition_count(requested, effective) == 1


def test_network_rejects_unapproved_carry_forward_before_probe() -> None:
    with pytest.raises(PlanError, match="独立した明示許可"):
        enforce_carry_forward_scope_authorization(
            additional_target_count=1,
            allow_network=True,
            allow_carry_forward_targets=False,
        )

    enforce_carry_forward_scope_authorization(
        additional_target_count=1,
        allow_network=False,
        allow_carry_forward_targets=False,
    )
    enforce_carry_forward_scope_authorization(
        additional_target_count=1,
        allow_network=True,
        allow_carry_forward_targets=True,
    )
    enforce_carry_forward_scope_authorization(
        additional_target_count=0,
        allow_network=True,
        allow_carry_forward_targets=False,
    )


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


def test_restrict_to_reviewed_profiles_removes_unapproved_targets_and_daily_binding() -> None:
    plan = {
        "schema_version": 1,
        "collection_scope": "all_historical_c2",
        "daily_source_handoffs": [{"source_date": "2026-08-24"}],
        "targets": [
            {
                "target_id": "reviewed",
                "host": "reviewed.example",
                "port": 443,
                "protocol_profile_id": "fixture-profile",
                "daily_source_dates": ["2026-08-24"],
            },
            {
                "target_id": "ordinary",
                "host": "ordinary.example",
                "port": 443,
            },
        ],
    }

    restricted = restrict_to_reviewed_profiles(plan)

    assert restricted["collection_scope"] == "reviewed_protocol_profiles_only"
    assert restricted["daily_source_handoffs"] == []
    assert [item["target_id"] for item in restricted["targets"]] == ["reviewed"]
    assert "daily_source_dates" not in restricted["targets"][0]
    assert len(plan["targets"]) == 2


def test_restrict_to_reviewed_profiles_rejects_empty_selection() -> None:
    with pytest.raises(ValueError, match="完全一致"):
        restrict_to_reviewed_profiles({"targets": [{"target_id": "ordinary"}]})


def test_normalize_public_source_fields_removes_absolute_prefix_and_duplicates() -> None:
    payload = {
        "source": "C:/Users/operator/repo/analysis-results/research/item.json",
        "targets": [
            {
                "sources": [
                    "analysis-results/malware/example/iocs.json:network[0]",
                    "C:/Users/operator/repo/analysis-results/malware/example/iocs.json:network[0]",
                ]
            }
        ],
    }

    changes = normalize_public_source_fields(payload)

    assert changes == 3
    assert payload["source"] == "analysis-results/research/item.json"
    assert payload["targets"][0]["sources"] == [
        "analysis-results/malware/example/iocs.json:network[0]"
    ]


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
                "schema_version": 2,
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


def test_daily_handoff_accepts_canonical_policy_excluded_endpoints() -> None:
    from build_all_c2_monitoring_targets import daily_effective_target_commitment
    from run_c2_monitoring_pipeline import (
        attach_daily_handoff_result_bindings,
        validate_daily_handoff_plan,
    )

    source_date = "2026-08-24"
    target = {
        "target_id": "daily-onion-fixture",
        "host": "c2.example",
        "port": 443,
        "protocol": "tcp",
        "transport": "direct",
        "method": "tcp_connect",
        "daily_source_dates": [source_date],
    }
    effective_sha256, effective_count, _hosts = daily_effective_target_commitment(
        [target], source_date
    )
    record = {
        "schema_version": 2,
        "source_date": source_date,
        "source_target_commitment_sha256": "b" * 64,
        "source_target_count": 3,
        "effective_target_commitment_sha256": effective_sha256,
        "effective_target_count": effective_count,
        "policy_excluded_endpoints": [
            "first-hidden-service.onion|0|dns",
            "second-hidden-service.onion|0|dns",
        ],
    }
    plan = {"targets": [target], "daily_source_handoffs": [record]}
    result = {
        "results": [
            {
                "target_id": target["target_id"],
                "host": target["host"],
                "port": target["port"],
                "protocol": target["protocol"],
                "transport": target["transport"],
                "method": target["method"],
            }
        ]
    }

    handoffs = validate_daily_handoff_plan(plan)
    attach_daily_handoff_result_bindings(result, plan, handoffs)

    assert result["daily_source_handoffs"][0]["policy_excluded_endpoints"] == record[
        "policy_excluded_endpoints"
    ]
    for invalid_hosts in (
        ["NOT-CANONICAL.onion|0|dns"],
        ["missing-wire.example|0"],
        ["duplicate.onion|0|dns", "duplicate.onion|0|dns"],
        ["z.onion|0|dns", "a.onion|0|dns"],
    ):
        invalid = {
            **plan,
            "daily_source_handoffs": [
                {**record, "policy_excluded_endpoints": invalid_hosts}
            ],
        }
        with pytest.raises(ValueError, match="型またはcommitment"):
            validate_daily_handoff_plan(invalid)
