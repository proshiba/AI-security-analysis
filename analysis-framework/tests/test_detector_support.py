"""Tests for conservative shared detector evidence thresholds."""

from __future__ import annotations

import hashlib
from pathlib import Path
import sys

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from detector_support import known_campaign_result  # noqa: E402


def test_single_signature_is_observed_but_not_matched() -> None:
    """Retain a lone literal for review without selecting its family."""
    result = known_campaign_result(
        b"Quasar.Client",
        {},
        [(b"Quasar.Client", "namespace"), (b"xClient.Core", "second namespace")],
    )
    assert result["matched"] is False
    assert result["campaigns"] == []
    assert result["observations"]["signature_hits"] == ["namespace"]
    overlapping = known_campaign_result(
        b"Quasar.Client",
        {},
        [
            (b"", "empty"),
            (b"Quasar", "generic namespace"),
            (b"Quasar.Client", "specific namespace"),
            (b"quasar.client", "duplicate namespace"),
        ],
    )
    assert overlapping["matched"] is False
    assert overlapping["observations"]["signature_hits"] == ["specific namespace"]


def test_two_signatures_or_exact_hash_can_match() -> None:
    """Require correlation for unknown bytes while preserving exact-hash routing."""
    signatures = [(b"Quasar.Client", "namespace"), (b"xClient.Core", "second namespace")]
    correlated = known_campaign_result(b"Quasar.Client xClient.Core", {}, signatures)
    assert correlated["matched"] is True
    assert correlated["campaigns"][0]["confidence"] == "medium"
    data = b"reviewed"
    exact = known_campaign_result(data, {hashlib.sha256(data).hexdigest(): "reviewed_case"}, signatures)
    assert exact["matched"] is True
    assert exact["campaigns"][0]["confidence"] == "high"


def test_signature_threshold_cannot_be_lowered_to_one() -> None:
    """Make the multi-evidence safety invariant non-optional."""
    with pytest.raises(ValueError, match="at least two"):
        known_campaign_result(b"marker", {}, [(b"marker", "marker")], minimum_signatures=1)
