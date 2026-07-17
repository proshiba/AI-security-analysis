"""Validate generated YARA and shared Sigma material for profiled families."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest
import yaml

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import generate_family_expansion_reports as reports  # noqa: E402


def test_every_profile_yara_compiles() -> None:
    """Compile every generated profile rule with yara-python when available."""
    yara = pytest.importorskip("yara")
    for family, profile in reports.load_profiles().items():
        yara.compile(source=reports.yara_rule(family, profile))


def test_shared_sigma_has_required_process_correlation() -> None:
    """Parse the low-confidence script template and require its two-part condition."""
    repository = Path(__file__).parents[2]
    path = repository / "analysis-results" / "_shared" / "rules" / "sigma" / "profiled_family_script_delivery.yml"
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert rule["status"] == "test"
    assert rule["logsource"] == {"category": "process_creation", "product": "windows"}
    assert rule["detection"]["condition"] == "selection_image and selection_remote_syntax"
    assert rule["falsepositives"]
