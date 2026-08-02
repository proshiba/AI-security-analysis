from __future__ import annotations

import sys
from pathlib import Path


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import render_c2_monitoring_report as renderer  # noqa: E402


def test_renders_tor_provenance_before_safety_boundary() -> None:
    result = {
        "analysis_window": {"start": "2026-08-01", "end": "2026-08-02"},
        "target_count": 1,
        "state_counts": {"not_reachable_at_observation": 1},
        "results": [{
            "family": "Efimer",
            "host": "fixtureexamplefixtureexamplefixtureexamplefixtureexample.onion",
            "port": 80,
            "transport": "tor-socks5",
            "method_description": "DNS解決＋単一TCP接続（送受信なし）",
            "associated_case_count": 1,
            "sources": ["fixture"],
            "observation": {"timestamp_utc": "2026-08-02T00:00:00+00:00"},
            "assessment": {
                "state": "not_reachable_at_observation",
                "reason": "fixture",
                "reachability_confidence": 0.0,
                "c2_operational_confidence": 0.0,
                "method_confidence_ceiling": 0.25,
            },
        }],
    }
    rendered = renderer.render_with_tor(
        result,
        bundle_version="15.0.18",
        tor_version="0.4.9.11",
        archive_sha256="a" * 64,
        checksum_url="https://example.invalid/checksum",
    )
    assert "## Tor観測環境" in rendered
    assert "bootstrap 100%" in rendered
    assert rendered.index("## Tor観測環境") < rendered.index("## 安全境界")
