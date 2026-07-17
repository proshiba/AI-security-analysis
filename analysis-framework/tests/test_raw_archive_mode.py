"""Tests for analyzing a multi-member archive as the retained raw sample."""

from __future__ import annotations

import zipfile
from pathlib import Path

from asa.discovery import discover, read_submission
from asa.runner import run_analysis

DEFINITIONS = Path(__file__).parents[1] / "definitions"


def test_multi_member_zip_can_remain_the_raw_subject(tmp_path: Path) -> None:
    """Avoid mistaking a malware-owned ZIP container for an intake wrapper."""
    sample = tmp_path / "payload.zip"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("one.bin", b"one")
        archive.writestr("two.bin", b"two")
    data, name, metadata = read_submission(sample, unwrap_archive=False)
    assert data == sample.read_bytes()
    assert name == sample.name
    assert "inner_sha256" not in metadata
    _, facts = discover(
        sample,
        family_hint="amadey",
        campaign_hint="direct_pe_or_container",
        unwrap_archive=False,
    )
    assert facts["submission"]["name"] == sample.name
    result = run_analysis(
        sample,
        DEFINITIONS,
        tmp_path / "result",
        family_hint="amadey",
        campaign_hint="direct_pe_or_container",
        unwrap_archive=False,
    )
    assert result["family"] == "amadey"
    assert result["network_contacted"] is False
