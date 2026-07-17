"""Offline repository audit for the March 2026 Trivy and npm compromises."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

MAX_TEXT_FILE = 5 * 1024 * 1024
TEXT_SUFFIXES = {".json", ".yaml", ".yml", ".lock", ".txt", ".toml", ".md"}


def audit_text(name: str, text: str) -> list[dict]:
    """Return evidence-oriented findings from one manifest or workflow."""
    rules = [
        (
            "npm.axios.malicious_version",
            r'(?is)(?:node_modules/axios|["\']axios["\'])[^\n]{0,180}["\']?1\.14\.1["\']?',
            "malicious axios version 1.14.1",
            "high",
        ),
        (
            "npm.axios.malicious_version",
            r'(?is)(?:node_modules/axios|["\']axios["\'])[^\n]{0,180}["\']?0\.30\.4["\']?',
            "malicious axios version 0.30.4",
            "high",
        ),
        (
            "npm.plain_crypto_js.malicious_version",
            r'(?is)(?:node_modules/plain-crypto-js|["\']plain-crypto-js["\'])[^\n]{0,180}["\']?4\.2\.1["\']?',
            "malicious plain-crypto-js version 4.2.1",
            "high",
        ),
        (
            "trivy.malicious_release",
            r"(?i)(?:trivy[:@/ _-]|version\s*[:=]\s*)v?0\.69\.(?:4|5|6)\b",
            "malicious Trivy release reference",
            "high",
        ),
        (
            "trivy.action.mutable_reference",
            r"(?i)aquasecurity/(?:trivy-action|setup-trivy)@(?![0-9a-f]{40}\b)[^\s#\"']+",
            "mutable Trivy GitHub Action reference; correlate with the exposure window",
            "medium",
        ),
        (
            "trivy.exfiltration_fallback",
            r"(?i)\btpcp-docs(?:-[a-z0-9_-]+)?\b",
            "TeamPCP fallback exfiltration repository marker",
            "high",
        ),
        (
            "trivy.typosquat",
            r"(?i)\bscan\.aquasecurtiy\.org\b",
            "Trivy compromise typosquat",
            "high",
        ),
    ]
    findings = []
    for rule_id, pattern, description, confidence in rules:
        for match in re.finditer(pattern, text):
            line = text.count("\n", 0, match.start()) + 1
            findings.append(
                {
                    "rule_id": rule_id,
                    "file": name,
                    "line": line,
                    "description": description,
                    "confidence": confidence,
                    "matched": match.group(0)[:200],
                }
            )
    return findings


def audit_path(root: Path) -> dict:
    """Recursively audit bounded text files without following external content."""
    if not root.exists():
        raise ValueError(f"path does not exist: {root}")
    paths = [root] if root.is_file() else sorted(path for path in root.rglob("*") if path.is_file())
    findings, inspected, skipped = [], 0, 0
    for path in paths:
        if path.suffix.lower() not in TEXT_SUFFIXES and path.name not in {"package-lock.json", "npm-shrinkwrap.json"}:
            skipped += 1
            continue
        try:
            if path.stat().st_size > MAX_TEXT_FILE:
                skipped += 1
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            skipped += 1
            continue
        inspected += 1
        name = str(path if root.is_file() else path.relative_to(root))
        findings.extend(audit_text(name, text))
    return {
        "schema_version": 1,
        "root": str(root),
        "inspected_files": inspected,
        "skipped_files": skipped,
        "findings": findings,
        "executed": False,
        "network_contacted": False,
    }


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser for offline repository auditing."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Audit a path and emit deterministic JSON."""
    args = build_parser().parse_args(argv)
    report = audit_path(args.path)
    payload = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
