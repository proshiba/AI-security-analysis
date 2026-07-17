"""Tests for deterministic, publish-safe IOC list generation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from generate_ioc_lists import (  # noqa: E402
    generate,
    indicator_type,
    indicators_from_config,
    indicators_from_ioc_json,
    read_relevant_markdown,
    sanitize_url,
)


def test_sanitize_url_removes_secrets_and_tracking_data() -> None:
    """Credentials, queries, and fragments must never reach a published list."""
    assert sanitize_url("https://user:pass@Example.COM:8443/a/b?token=secret#x") == "https://example.com:8443/a/b"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a" * 64, "sha256"),
        ("203.0.113.8", "ipv4"),
        ("example.test:443", "endpoint"),
        ("example.test", "domain"),
        (r"C:\\Users\\Public\\stage.dll", "file_path"),
        ("sha256:" + "b" * 64, "container_digest"),
    ],
)
def test_indicator_type_covers_supported_values(value: str, expected: str) -> None:
    """Supported IOC types should receive stable type labels."""
    assert indicator_type(value) == expected


def test_markdown_parser_uses_only_explicit_ioc_sections(tmp_path: Path) -> None:
    """Narrative and search-query sections must not be mined as IOC evidence."""
    path = tmp_path / "README.md"
    path.write_text(
        "# Case\n\n"
        "Narrative mentions 198.51.100.1 but is not evidence.\n\n"
        "## C2 / network IOC\n\n"
        "- Confirmed: `https://user:pw@evil.example/check?token=secret`\n"
        "- Source: `https://tria.ge/123/behavioral1`\n"
        "- Namespace: `Quasar.Client`\n"
        "- Legitimate DNS: `8.8.8.8:53`\n"
        "- Process attribution: `mesedge.exe`\n"
        "- Signed host (valid signature): `" + "a" * 64 + "`\n\n"
        "## Shodan\n\n"
        "- Query: `203.0.113.99:443`\n",
        encoding="utf-8",
    )

    values = read_relevant_markdown(path)

    assert [(item.type, item.value) for item in values] == [("url", "https://evil.example/check")]
    assert indicator_type("stage.msi") == "file_name"


def test_ioc_json_excludes_context_only_and_sanitizes_urls(tmp_path: Path) -> None:
    """Structured context-only artifacts must be omitted from IOC-only output."""
    path = tmp_path / "iocs.json"
    path.write_text(
        json.dumps(
            {
                "network": [
                    {"value": "https://user:pw@c2.example/a?key=x", "role": "c2", "confidence": "confirmed"},
                    {"value": "benign.example", "role": "context_only", "confidence": "confirmed"},
                ],
                "certificate": {"sha1_thumbprint": "c" * 40, "role": "server_certificate"},
            }
        ),
        encoding="utf-8",
    )

    values = indicators_from_ioc_json(path)

    assert {item.value for item in values} == {"https://c2.example/a", "c" * 40}


def test_config_json_excludes_context_only_findings(tmp_path: Path) -> None:
    """Private or otherwise contextual config values must not become public IOCs."""
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "findings": [
                    {
                        "value": "http://10.0.123.1:8080",
                        "role": "context_only_private_config",
                        "confidence": "confirmed",
                    },
                    {
                        "value": "https://c2.example",
                        "role": "shadowpad_config_network",
                        "confidence": "confirmed",
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    values = indicators_from_config(path)

    assert [item.value for item in values] == ["https://c2.example"]


def test_hash_like_url_path_is_not_mislabeled_as_a_file_hash(tmp_path: Path) -> None:
    """Identifiers embedded in URLs must remain URL components, not file hashes."""
    identifier = "e" * 64
    path = tmp_path / "README.md"
    path.write_text(
        f"# Case\n\n## C2\n\n- Stage: `https://delivery.example/ledger/{identifier}`\n",
        encoding="utf-8",
    )

    values = read_relevant_markdown(path)

    assert [(item.type, item.value) for item in values] == [("url", f"https://delivery.example/ledger/{identifier}")]


def test_generate_and_check_repository_outputs(tmp_path: Path) -> None:
    """Generation should backfill a case, build an index, and detect stale output."""
    sample_hash = "d" * 64
    case = tmp_path / "analysis-results" / "example" / "cases" / sample_hash
    case.mkdir(parents=True)
    (case / "README.md").write_text(
        "# Example\n\n## IOC\n\n- C2: `c2.example:443`\n",
        encoding="utf-8",
    )
    (tmp_path / "analysis_history.yaml").write_text(
        "analyses:\n"
        f"  - sample_sha256: {sample_hash}\n"
        "    result_path: analysis-results/example/cases/" + sample_hash + "\n"
        "    c2:\n"
        "      - c2.example:443\n",
        encoding="utf-8",
    )

    result = generate(tmp_path)

    assert result == {"analyses": 1, "indicators": 2, "mismatches": []}
    content = (case / "IOC-LIST.md").read_text(encoding="utf-8")
    assert sample_hash in content
    assert "c2.example:443" in content
    assert "example/cases" in (tmp_path / "analysis-results" / "IOC-INDEX.md").read_text(encoding="utf-8")
    assert generate(tmp_path, check=True)["mismatches"] == []

    (case / "IOC-LIST.md").write_text("stale\n", encoding="utf-8")
    with pytest.raises(ValueError, match="outdated IOC lists"):
        generate(tmp_path, check=True)
