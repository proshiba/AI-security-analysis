"""Tests for the shared profile-defined detector."""

from __future__ import annotations

from pathlib import Path
import sys

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import profiled_family_detector as detector  # noqa: E402


def test_known_hash_loading_and_campaign_routing(tmp_path: Path) -> None:
    """Load a generated registry and route scripts, loaders, and configs."""
    path = tmp_path / "malware" / "fixture" / "campaigns.json"
    path.parent.mkdir(parents=True)
    path.write_text('{"known_sample_sha256":["' + "a" * 64 + '"]}', encoding="utf-8")
    assert detector.known_hashes("fixture", tmp_path) == {"a" * 64}
    assert detector.campaign_type("x", Path("a.js"), "rat", False) == "script_delivery"
    assert detector.campaign_type("x", Path("a.exe"), "loader", False) == "staged_loader_or_container"
    assert detector.campaign_type("x", Path("a.exe"), "rat", True) == "static_config_candidate_recovered"


def test_detector_exact_and_structural_paths(monkeypatch) -> None:
    """Match correlated literals without claiming a decoded config."""
    monkeypatch.setattr(detector, "known_hashes", lambda _family: set())
    monkeypatch.setattr(
        detector,
        "extract_family",
        lambda *_args: {
            "config": {
                "profile_literal_correlation": True,
                "decoded_config_recovered": False,
                "static_config_recovered": False,
                "marker_hits": ["asyncrat server", "hwid"],
                "observed_config_keys": ["Hosts"],
            },
            "findings": [{"value": "example"}],
        },
    )
    result = detector.detect_family("asyncrat", b"AsyncRAT Server HWID fixture", Path("x.exe"))
    assert result["matched"] is True
    assert result["campaigns"][0]["confidence"] == "medium"
    assert result["campaigns"][0]["campaign_type"] == "reviewed_direct_payload_or_wrapper"
    assert result["observations"]["profile_literal_correlation"] is True
    assert result["observations"]["static_config_recovered"] is False
    assert result["observations"]["network_contacted"] is False


def test_detector_rejects_one_overlapping_family_literal(monkeypatch) -> None:
    """Reject one compound profile literal before invoking extraction."""
    monkeypatch.setattr(detector, "known_hashes", lambda _family: set())
    monkeypatch.setattr(
        detector,
        "extract_family",
        lambda *_args: (_ for _ in ()).throw(AssertionError("extractor should not run")),
    )
    result = detector.detect_family("asyncrat", b"AsyncRAT Server", Path("x.exe"))
    assert result["matched"] is False
    assert result["observations"]["marker_hits"] == ["asyncrat server"]
