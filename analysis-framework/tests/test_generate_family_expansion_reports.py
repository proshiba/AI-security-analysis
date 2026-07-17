"""Tests for publish-safe family expansion report generation helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import generate_family_expansion_reports as reports  # noqa: E402


def test_public_source_and_findings_remove_private_paths() -> None:
    """Exclude local ZIP paths/reporters and preserve candidate confidence."""
    item = {
        "sha256": "a" * 64,
        "zip_path": "private.zip",
        "requested_signature": "AsyncRAT",
        "metadata": {"reporter": "private", "file_name": "x.exe", "tags": ["AsyncRAT"]},
    }
    source = reports.public_source(item)
    assert "zip_path" not in source and "reporter" not in source
    merged = reports.merge_findings(
        {"findings": [{"kind": "network.url", "value": "https://evil.example/a", "role": "c2_candidate", "confidence": "candidate"}]},
        {"iocs": {"urls": ["https://evil.example/a", "https://stage.example/b"], "ips": ["8.8.8.8:443"]}},
    )
    assert len(merged) == 2
    assert all(item["confidence"] in {"candidate", "probable"} for item in merged)


def test_case_markdown_iocs_yara_and_table() -> None:
    """Render case evidence, IOC-only output, and a bounded YARA profile."""
    profile = reports.load_profiles()["asyncrat"]
    case = {
        "display_name": "AsyncRAT",
        "family": "asyncrat",
        "source": {"sha256": "a" * 64, "first_seen": "2026", "file_name": "x.exe", "file_type": "exe", "file_size": 10},
        "static_analysis": {"root_unpack": {}, "layers": [], "profile_config": {"category": "rat", "transport": "tcp", "marker_hits": [], "observed_config_keys": [], "static_config_recovered": False}, "findings": []},
    }
    assert "Operator/campaign: not attributed" in reports.case_markdown(case)
    assert "None recovered" in reports.ioc_markdown(["a" * 64], [])
    rule = reports.yara_rule("asyncrat", profile)
    assert "false_positive" in rule and "filesize < 100MB" in rule
    assert reports.markdown_table([["A", "B"], ["x|y", "z"]]).count("\\|") == 1


def test_build_case_and_parser() -> None:
    """Build a non-executing case and exercise command-line parsing."""
    item = {"sha256": "b" * 64, "requested_signature": "AsyncRAT", "metadata": {}}
    profile = {"family": "asyncrat", "display_name": "AsyncRAT"}
    case = reports.build_case(item, {"root_unpack": {}, "layers": [], "iocs": {}}, {"config": {}, "findings": []}, {"network_contacted": False}, profile)
    assert case["sample_executed"] is False and case["network_contacted"] is False
    args = reports.build_parser().parse_args(["--manifest", "m.json", "--cache", "cache"])
    assert args.cache == Path("cache")
    assert reports.normalize_finding({"value": ""}) is None


def test_generate_and_main(tmp_path: Path, monkeypatch) -> None:
    """Generate a complete one-case tree and cover the command dispatcher."""
    data = b"AsyncRAT Server HWID Hosts Ports https://evil.example.org/gate"
    digest = hashlib.sha256(data).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"items": [{"requested_signature": "AsyncRAT", "sha256": digest, "zip_path": "fixture.zip", "metadata": {"file_type": "exe"}}]}), encoding="utf-8")
    cache = tmp_path / "cache"
    (cache / "cases" / digest).mkdir(parents=True)
    (cache / "cases" / digest / "case.json").write_text(json.dumps({"root_unpack": {}, "layers": [], "iocs": {}}), encoding="utf-8")
    output = tmp_path / "results"
    profile = {
        "display_name": "AsyncRAT", "category": "rat", "aliases": [],
        "markers": ["AsyncRAT", "HWID"], "minimum_markers": 2,
        "config_keys": ["Hosts", "Ports"], "transport": "tcp",
        "endpoint_role": "c2_candidate", "confirmation": "decode fixture",
    }
    monkeypatch.setattr(reports, "load_profiles", lambda: {"asyncrat": profile})
    monkeypatch.setattr(reports, "read_single_aes_zip_member", lambda path: SimpleNamespace(data=data, name="fixture.exe"))
    result = reports.generate(manifest, cache, output)
    case = output / "asyncrat" / reports.RUN_ID / "cases" / digest
    assert result["cases"] == 1 and (case / "README.md").is_file()
    assert "AsyncRAT" in reports.family_markdown("asyncrat", {"family": "asyncrat", **profile}, [json.loads((case / "indicators.json").read_text())])
    target = tmp_path / "nested" / "text.txt"
    reports.write_text(target, "x\r\n")
    assert target.read_bytes() == b"x\n"
    monkeypatch.setattr(reports, "generate", lambda *args: {"cases": 0})
    assert reports.main(["--manifest", str(manifest), "--cache", str(cache), "--output-root", str(output)]) == 0
