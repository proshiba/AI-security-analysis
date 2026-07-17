"""Tests for raw-directory and shared payload batch orchestration."""

from __future__ import annotations

from pathlib import Path
import sys

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analyze_stealer_set as batch  # noqa: E402

DEFINITIONS = Path(__file__).parents[1] / "definitions"


def test_findings_and_summary_helpers() -> None:
    """Deduplicate evidence and count completed/error cases."""
    finding = {"kind": "network.url", "value": "https://example.test/x", "role": "c2"}
    assert batch.merge_findings([{"findings": [finding]}, {"findings": [finding]}]) == [finding]
    summary = batch.build_summary(
        "Fixture",
        "amosstealer",
        [
            {"packing_suspected": True, "recovered_artifacts": 1, "static_config_recovered": True, "config_findings": 1},
            {"error": "FixtureError"},
        ],
        "fixture",
    )
    assert summary["counts"] == {
        "total": 2,
        "errors": 1,
        "packing_suspected": 1,
        "with_recovered_artifacts": 1,
        "with_static_config": 1,
        "with_config_findings": 1,
    }


def test_raw_directory_analysis_and_cli_parser(tmp_path: Path) -> None:
    """Analyze one raw fixture and deduplicate an identical peer."""
    source = tmp_path / "source"
    source.mkdir()
    payload = b'Atomic keychain https://evil.example/ledger/id'
    (source / "one.bin").write_bytes(payload)
    (source / "duplicate.bin").write_bytes(payload)
    output = tmp_path / "out"
    summary = batch.analyze_directory(
        "amosstealer", source, output, DEFINITIONS, signature="AMOS fixture"
    )
    assert summary["counts"]["total"] == 1
    assert summary["counts"]["with_config_findings"] == 1
    assert (output / summary["cases"][0]["sha256"] / "config.json").is_file()
    args = batch.build_parser().parse_args(
        [
            "--input-root",
            str(source),
            "--family",
            "amosstealer",
            "--output",
            str(output),
            "--definitions",
            str(DEFINITIONS),
        ]
    )
    assert args.family == "amosstealer" and args.max_depth == 3
