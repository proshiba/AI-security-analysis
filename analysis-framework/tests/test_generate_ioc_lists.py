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
    Indicator,
    generate,
    indicator_type,
    indicators_from_config,
    indicators_from_ioc_json,
    read_relevant_markdown,
    render_ioc_list,
    sanitize_url,
)


def test_sanitize_url_removes_secrets_and_tracking_data() -> None:
    """Credentials, queries, and fragments must never reach a published list."""
    assert sanitize_url("https://user:pass@Example.COM:8443/a/b?token=secret#x") == "https://example.com:8443/a/b"
    assert (
        sanitize_url("https://user:pass@[2001:db8::7]:8443/a?token=secret#x")
        == "https://[2001:db8::7]:8443/a"
    )


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("a" * 64, "sha256"),
        ("203.0.113.8", "ipv4"),
        ("example.test:443", "endpoint"),
        ("example.test", "domain"),
        ("0xB70dbaf0e42E51eDddbf3b6a1Bac28eD18227119", "ethereum_address"),
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
        "- Supporting report: `c2-observation-plan.json`\n"
        r"- Local cache: `C:\Users\Analyst\case.json`" "\n"
        "- Signed host (valid signature): `" + "a" * 64 + "`\n\n"
        "## Shodan\n\n"
        "- Query: `203.0.113.99:443`\n",
        encoding="utf-8",
    )

    values = read_relevant_markdown(path)

    assert [(item.type, item.value) for item in values] == [("url", "https://evil.example/check")]
    assert indicator_type("stage.msi") == "file_name"


def test_markdown_network_sections_reject_file_and_local_path_references(tmp_path: Path) -> None:
    """Markdown filenames and analyst-local paths require structured IOC evidence."""
    path = tmp_path / "README.md"
    path.write_text(
        "# Case\n\n## Candidate infrastructure\n\n"
        "- Details: `c2-observation-plan.json`\n"
        r"- Analyst cache: `C:\Users\Analyst\review\stage.dll`" "\n\n"
        "## File IOC\n\n"
        "- Generated report: `analysis.json`\n"
        r"- Review path: `C:\Users\Analyst\review\payload.exe`" "\n",
        encoding="utf-8",
    )

    assert read_relevant_markdown(path) == []


def test_markdown_parser_accepts_localized_ioc_headings(tmp_path: Path) -> None:
    """日本語化されたネットワーク、設定、侵害指標の見出しも抽出対象にする。"""
    path = tmp_path / "README.md"
    path.write_text(
        "# ケース\n\n"
        "## ネットワーク観測情報\n\n- `c2-one.example:443`\n\n"
        "## 静的設定のスナップショット\n\n- `https://c2-two.example/check`\n\n"
        "## ファイル侵害指標\n\n- `" + "a" * 64 + "`\n",
        encoding="utf-8",
    )

    values = read_relevant_markdown(path)

    assert {(item.type, item.value) for item in values} == {
        ("endpoint", "c2-one.example:443"),
        ("url", "https://c2-two.example/check"),
        ("sha256", "a" * 64),
    }


def test_markdown_config_does_not_misclassify_crypto_keys_or_context_only_edges(tmp_path: Path) -> None:
    """設定内の暗号鍵や共有エッジを、ファイルハッシュや C2 と誤認しない。"""
    path = tmp_path / "README.md"
    path.write_text(
        "# ケース\n\n## 静的設定\n\n"
        '- `rc4_key`: `90b149c69b149c4b99c04d1dc9b940b9`\n'
        '- `payload_sha256`: `' + "b" * 64 + "`\n"
        "- `xclient.core`\n\n"
        "## ネットワークの証拠\n\n"
        "- `162.159.36.2` は Cloudflare-関連の解決結果で、インフラ文脈のみ。\n",
        encoding="utf-8",
    )

    values = read_relevant_markdown(path)

    assert [(item.type, item.value) for item in values] == [("sha256", "b" * 64)]


def test_ioc_table_uses_japanese_display_labels() -> None:
    """公開用IOC表では、人が読む種別・役割・確度を日本語で表示する。"""
    content = render_ioc_list(
        [Indicator("endpoint", "c2.example:443", "delivery", "confirmed", "iocs.json")]
    )

    assert "| 接続先 | c2.example:443 | 配布 | 確認済み | iocs.json |" in content


def test_ioc_json_excludes_context_only_and_sanitizes_urls(tmp_path: Path) -> None:
    """Structured context-only artifacts must be omitted from IOC-only output."""
    path = tmp_path / "iocs.json"
    path.write_text(
        json.dumps(
            {
                "network": [
                    {"value": "https://user:pw@c2.example/a?key=x", "role": "c2", "confidence": "confirmed"},
                    {"value": "benign.example", "role": "context_only", "confidence": "confirmed"},
                    {"value": "kill-switch.example:80", "role": "not_c2_kill_switch", "confidence": "confirmed"},
                    {"value": "0xB70dbaf0e42E51eDddbf3b6a1Bac28eD18227119", "role": "payload_contract", "confidence": "confirmed"},
                ],
                "certificate": {"sha1_thumbprint": "c" * 40, "role": "server_certificate"},
            }
        ),
        encoding="utf-8",
    )

    values = indicators_from_ioc_json(path)

    assert {item.value for item in values} == {
        "https://c2.example/a",
        "0xb70dbaf0e42e51edddbf3b6a1bac28ed18227119",
        "c" * 40,
    }


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
    case = (
        tmp_path
        / "analysis-results"
        / "malware"
        / "example"
        / "versions"
        / "unknown"
        / "cases"
        / sample_hash
    )
    case.mkdir(parents=True)
    (case / "README.md").write_text(
        "# Example\n\n## IOC\n\n- C2: `c2.example:443`\n",
        encoding="utf-8",
    )
    (tmp_path / "analysis_history.yaml").write_text(
        "analyses:\n"
        f"  - sample_sha256: {sample_hash}\n"
        "    result_path: analysis-results/malware/example/versions/unknown/cases/"
        + sample_hash
        + "\n"
        "    c2:\n"
        "      - c2.example:443\n",
        encoding="utf-8",
    )

    result = generate(tmp_path)

    assert result == {"analyses": 1, "indicators": 2, "mismatches": []}
    content = (case / "IOC-LIST.md").read_text(encoding="utf-8")
    assert sample_hash in content
    assert "c2.example:443" in content
    assert "malware/example/versions/unknown/cases" in (
        tmp_path / "analysis-results" / "IOC-INDEX.md"
    ).read_text(encoding="utf-8")
    assert "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |" in content
    assert generate(tmp_path, check=True)["mismatches"] == []

    (case / "IOC-LIST.md").write_text("stale\n", encoding="utf-8")
    with pytest.raises(ValueError, match="outdated IOC lists"):
        generate(tmp_path, check=True)


def test_generate_indexes_profile_run_aggregate(tmp_path: Path) -> None:
    """Profile-family run IOC lists are generated and indexed from public cases."""
    sample_hash = "e" * 64
    results = tmp_path / "analysis-results"
    run = results / "collections" / "malwarebazaar-run" / "sources" / "example"
    case = (
        results
        / "malware"
        / "example"
        / "versions"
        / "unknown"
        / "cases"
        / sample_hash
    )
    case.mkdir(parents=True)
    run.mkdir(parents=True)
    (run / "README.md").write_text("# run\n", encoding="utf-8")
    (run / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "source": "MalwareBazaar exact signature query",
                "run_id": "malwarebazaar-run",
                "family": "example",
                "items": [{"sha256": sample_hash}],
            }
        ),
        encoding="utf-8",
    )
    (results / "collections" / "malwarebazaar-run" / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "collection_id": "malwarebazaar-run",
                "family_sources": [
                    {"family": "example", "path": "sources/example"}
                ],
                "cases": [{"case_id": f"sha256:{sample_hash}"}],
            }
        ),
        encoding="utf-8",
    )
    (case / "indicators.json").write_text(
        json.dumps(
            {
                "source": {"sha256": sample_hash},
                "static_analysis": {
                    "findings": [
                        {
                            "value": "https://user:pw@c2.example.org/gate?token=x#fragment",
                            "role": "c2_candidate",
                            "confidence": "candidate",
                            "source": "fixture",
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "analysis_history.yaml").write_text("analyses: []\n", encoding="utf-8")

    result = generate(tmp_path)

    assert result == {"analyses": 1, "indicators": 2, "mismatches": []}
    content = (run / "IOC-LIST.md").read_text(encoding="utf-8")
    assert sample_hash in content and "https://c2.example.org/gate" in content
    assert "token=" not in content and "user:pw@" not in content
    assert "collections/malwarebazaar-run/sources/example" in (
        tmp_path / "analysis-results" / "IOC-INDEX.md"
    ).read_text(encoding="utf-8")


def test_generate_discovers_canonical_campaign_and_research(tmp_path: Path) -> None:
    """canonical research namespace の campaign と incident を索引化する。"""
    results = tmp_path / "analysis-results"
    campaign = results / "research" / "campaigns" / "example" / "operation-one"
    incident = results / "research" / "supply-chain" / "npm" / "incident-one"
    for directory in (campaign, incident):
        directory.mkdir(parents=True)
        (directory / "README.md").write_text(
            "# 解析\n\n## IOC\n\n- C2: `c2.example:443`\n",
            encoding="utf-8",
        )
    (tmp_path / "analysis_history.yaml").write_text("analyses: []\n", encoding="utf-8")

    result = generate(tmp_path)

    assert result["analyses"] == 2
    assert (campaign / "IOC-LIST.md").is_file()
    assert (incident / "IOC-LIST.md").is_file()
