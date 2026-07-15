"""Tests for the offline C2 candidate detector."""

from __future__ import annotations

import json
from pathlib import Path
import sys

COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

import c2_candidate_detector as detector  # noqa: E402


def test_target_queries_and_assessment() -> None:
    """Cover URL/endpoint parsing, passive queries, and confidence selection."""
    assert detector.target_from_finding({"kind": "network.url", "value": "https://evil.example:8443/a"}) == (
        "evil.example",
        8443,
    )
    assert detector.target_from_finding({"kind": "network.endpoint", "value": "1.2.3.4:443"}) == (
        "1.2.3.4",
        443,
    )
    assert detector.target_from_finding({"kind": "exfiltration.endpoint", "value": "mail.example:587"}) == (
        "mail.example",
        587,
    )
    assert detector.shodan_queries("1.2.3.4", 443) == ["ip:1.2.3.4 port:443"]
    result = detector.assess(
        {
            "family": "fixture",
            "findings": [
                {
                    "kind": "network.url",
                    "value": "https://evil.example/api/",
                    "confidence": "probable",
                }
            ],
        }
    )
    assert result["assessment"] == "probable" and result["network_contacted"] is False


def test_cli(tmp_path: Path) -> None:
    """Exercise parser and deterministic CLI output."""
    source, output = tmp_path / "extractor.json", tmp_path / "c2.json"
    source.write_text(json.dumps({"family": "fixture", "findings": []}), encoding="utf-8")
    args = ["--extractor-result", str(source), "--output", str(output)]
    assert detector.build_parser().parse_args(args).output == output
    assert detector.main(args) == 0
    assert json.loads(output.read_text())["targets"] == []
