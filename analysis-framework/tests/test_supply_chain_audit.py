"""Tests for the shared offline supply-chain audit."""

from __future__ import annotations

import json

from supply_chain_audit import audit_path, audit_text, main


def test_audit_text_finds_npm_and_trivy_indicators() -> None:
    """Find exact malicious versions, mutable actions, and exfil markers."""
    text = '''
      "axios": "1.14.1",
      "plain-crypto-js": "4.2.1"
      uses: aquasecurity/trivy-action@0.34.2
      image: aquasec/trivy:0.69.6
      scan.aquasecurtiy.org tpcp-docs-victim
    '''
    rule_ids = {finding["rule_id"] for finding in audit_text("fixture.yml", text)}
    assert {
        "npm.axios.malicious_version",
        "npm.plain_crypto_js.malicious_version",
        "trivy.action.mutable_reference",
        "trivy.malicious_release",
        "trivy.typosquat",
        "trivy.exfiltration_fallback",
    } <= rule_ids


def test_audit_path_and_cli(tmp_path) -> None:
    """Scan supported text files and write a JSON report."""
    (tmp_path / "package-lock.json").write_text(json.dumps({"axios": "0.30.4"}), encoding="utf-8")
    (tmp_path / "ignored.bin").write_bytes(b"axios 1.14.1")
    report = audit_path(tmp_path)
    assert report["inspected_files"] == 1
    assert report["network_contacted"] is False
    output = tmp_path / "report.json"
    assert main([str(tmp_path), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["findings"]
