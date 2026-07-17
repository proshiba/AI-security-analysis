"""Tests for stealer report generation."""

from __future__ import annotations

import json
from pathlib import Path
import sys

COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

import generate_stealer_reports as reports  # noqa: E402


def fixture_case(root: Path, sha256: str) -> None:
    """Create one normalized report-input fixture."""
    root.mkdir(parents=True)
    config = {
        "config": {
            "features": {"browser_collection": True},
            "version": "1.2.3",
            "decoded_strings": ["large evidence omitted from README"],
            "static_config_recovered": True,
        },
        "findings": [
            {
                "kind": "network.url",
                "value": "https://evil.example/api/",
                "role": "c2_or_exfil_candidate",
                "confidence": "probable",
                "source": "embedded_literal",
            }
        ],
        "limitations": ["fixture"],
        "layers_analyzed": 0,
    }
    (root / "config.json").write_text(json.dumps(config), encoding="utf-8")
    (root / "c2-candidates.json").write_text(json.dumps({"targets": []}), encoding="utf-8")
    (root / "unpack.json").write_text(json.dumps({"entropy": 7.0, "pe": {}}), encoding="utf-8")
    (root / "layers.json").write_text(json.dumps({"layers": []}), encoding="utf-8")


def test_load_summarize_render_generate_and_cli(tmp_path: Path) -> None:
    """Exercise every public report-generation function."""
    sha256 = "a" * 64
    pipeline = tmp_path / "pipeline"
    fixture_case(pipeline / sha256, sha256)
    item = {
        "sha256": sha256,
        "name": "x.exe",
        "family": "fixture",
        "campaign": "direct_pe_or_pe_loader",
        "format": "pe",
        "packing_suspected": True,
        "recovered_artifacts": 0,
        "config_findings": 1,
    }
    summary = {
        "family": "fixture",
        "signature": "Fixture",
        "source": "vx-underground",
        "counts": {"errors": 0, "with_static_config": 1},
        "cases": [item],
    }
    summary_path = tmp_path / "summary.json"
    summary_path.write_text(json.dumps(summary), encoding="utf-8")
    case = reports.load_case(pipeline / sha256)
    value = reports.summarize_family(summary, pipeline)
    case_text = reports.render_case(item, case)
    assert "Config and C2" in case_text
    assert "large evidence omitted from README" not in case_text
    family_text = reports.render_family(value)
    assert "Detection considerations" in family_text
    assert "`vx-underground`" in family_text
    assert value["config_values"]["version"] == {"1.2.3": 1}
    destination = tmp_path / "results"
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(
        json.dumps({"items": [{"sha256": sha256, "zip_path": "local.zip"}]}), encoding="utf-8"
    )
    assert reports.generate(summary_path, pipeline, destination, manifest_path)["case_count"] == 1
    public = json.loads((destination / "malwarebazaar-manifest.json").read_text())
    assert public["items"] == [{"sha256": sha256}]
    args = ["--summary", str(summary_path), "--pipeline-root", str(pipeline), "--destination", str(destination)]
    assert reports.build_parser().parse_args(args).summary == summary_path
    assert reports.main(args) == 0
