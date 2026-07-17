"""Tests for hash-only OSINT enrichment and evidence management."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import osint_hash_enricher as osint


def test_registry_requires_non_submission_policy(tmp_path: Path) -> None:
    """Reject a source registry that does not prohibit sample submission."""
    path = tmp_path / "sources.yaml"
    path.write_text("schema_version: 1\npolicy: {sample_submission: allowed}\nsources: {x: {}}\n", encoding="utf-8")
    with pytest.raises(ValueError):
        osint.load_source_registry(path)


def test_family_mapping_rejects_generic_and_maps_aliases() -> None:
    """Map reviewed family aliases without promoting generic AV words."""
    assert osint.family_from_label("Script-BAT.Trojan.BeaverTail") == "beavertail"
    assert osint.family_from_label("InvisibleFerret") == "invisibleferret"
    assert osint.family_from_label("Win64.Trojan.Generic") is None

def test_label_sanitization_removes_public_secrets() -> None:
    """Redact accidental URLs, email addresses, and long credential-like tokens."""
    label = osint.sanitize_label("Vidar https://x.example/a?q=z a@example.com " + "A" * 45)
    assert label == "Vidar [URL] [EMAIL] [REDACTED]"



def test_malwarebazaar_normalization_separates_providers() -> None:
    """Preserve underlying provider independence and avoid aggregator votes."""
    result = osint.normalize_malwarebazaar({
        "tags": ["unknown"],
        "yara_rules": [{"rule_name": "GenesisStealer_Installer"}],
        "vendor_intel": {
            "Triage": {"malware_family": "Genesis Stealer", "tags": ["BeaverTail"], "link": "https://tria.ge/r/1/?token=x"},
            "VMRay": {"malware_family": "GenesisStealer", "report_link": "https://vmray.example/r/2"},
            "NewProvider": {"threat": "ACRStealer"},
        },
    })
    assert {item["provider"] for item in result["evidence"]} == {"malwarebazaar_yara", "triage", "vmray", "newprovider"}
    assert all("token=" not in str(item.get("reference")) for item in result["evidence"])
    assert any(item["provider"] == "triage" and item["family"] == "beavertail" for item in result["evidence"])
    assert any(item["provider"] == "newprovider" and item["family"] == "acrstealer" for item in result["evidence"])


def test_otx_and_virustotal_normalization() -> None:
    """Extract bounded family labels from OTX pulses and VT sandbox metadata."""
    otx = osint.normalize_otx({"pulse_info": {"pulses": [{"name": "ACRStealer campaign", "tags": ["stealer"]}]}})
    vt = osint.normalize_virustotal({"data": {"attributes": {
        "popular_threat_classification": {"suggested_threat_label": "InvisibleFerret"},
        "sandbox_verdicts": {"box": {"malware_names": ["BeaverTail"]}},
    }}})
    assert otx["evidence"][0]["family"] == "acrstealer"
    assert {item["family"] for item in vt["evidence"]} == {"beavertail", "invisibleferret"}


def test_combination_requires_independent_agreement() -> None:
    """Require two providers for medium confidence and retain exact conflicts."""
    one = [{"provider": "triage", "family": "stealc", "label": "StealC", "strength": 3}]
    assert osint.combine_attribution({"family": "unknown", "evidence": []}, one)["confidence"] == "low"
    two = one + [{"provider": "vmray", "family": "stealc", "label": "StealC", "strength": 3}]
    assert osint.combine_attribution({"family": "unknown", "evidence": []}, two)["confidence"] == "medium"
    conflict = one + [{"provider": "vmray", "family": "vidar", "label": "Vidar", "strength": 3}]
    assert osint.combine_attribution({"family": "unknown", "evidence": []}, conflict)["status"] == "conflicting"
    majority_with_conflict = two + [{"provider": "otx", "family": "vidar", "label": "Vidar", "strength": 2}]
    assert osint.combine_attribution({"family": "unknown", "evidence": []}, majority_with_conflict)["confidence"] == "low"
    assert osint.combine_attribution({"family": "unknown", "evidence": []}, majority_with_conflict)["conflicts"] == ["vidar"]


def test_collect_case_uses_offline_metadata(monkeypatch: pytest.MonkeyPatch) -> None:
    """Use the private MalwareBazaar snapshot without issuing a network request."""
    monkeypatch.setattr(osint, "collect_network_source", lambda *args, **kwargs: {"status": "not_found"})
    registry = {"sources": {"malwarebazaar": {"enabled": True}, "circl_hashlookup": {"enabled": True, "endpoint": "https://x/{sha256}"}}}
    result = osint.collect_case("a" * 64, registry, offline_metadata={"tags": []}, network=True)
    assert result["malwarebazaar"]["status"] == "ok"
    assert result["circl_hashlookup"]["status"] == "not_found"
    monkeypatch.setattr(osint, "collect_network_source", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret detail")))
    assert osint.collect_case(
        "a" * 64, registry, offline_metadata={"tags": []}, network=True,
    )["circl_hashlookup"]["reason"] == "RuntimeError during hash lookup"


def test_collect_case_defaults_to_no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Do not invoke a provider unless the caller explicitly enables network."""
    monkeypatch.setattr(
        osint,
        "collect_network_source",
        lambda *args, **kwargs: pytest.fail("network collector must not be called"),
    )
    registry = {
        "sources": {
            "circl_hashlookup": {
                "enabled": True,
                "endpoint": "https://example.test/{sha256}",
            },
        },
    }
    result = osint.collect_case("f" * 64, registry)
    assert result["circl_hashlookup"] == {
        "status": "not_queried",
        "reason": "network collection disabled",
    }


def test_cli_requires_positive_network_opt_in() -> None:
    """Expose only a positive network acknowledgement and default it off."""
    required = [
        "--summary", "summary.json", "--output", "out", "--registry", "sources.yaml",
        "--cache", "cache",
    ]
    offline = osint.build_parser().parse_args(required)
    online = osint.build_parser().parse_args([*required, "--allow-network"])
    assert offline.allow_network is False
    assert online.allow_network is True
    assert not hasattr(offline, "offline")


def test_public_record_and_markdown_upsert_are_publish_safe() -> None:
    """Remove raw responses and replace generated Markdown idempotently."""
    raw = {"otx": {"status": "ok", "reference": "https://otx.example/x?q=secret", "response": {"pulse_info": {"pulses": [{"name": "Vidar"}]}}}}
    record = osint.build_public_evidence("b" * 64, {"family": "unknown", "evidence": []}, raw, "2026-07-17T00:00:00+00:00")
    serialized = json.dumps(record)
    assert "pulse_info" not in serialized and "secret" not in serialized
    section = osint.render_case_osint(record)
    updated = osint.upsert_marked_section("# Case\n", section)
    assert osint.upsert_marked_section(updated, section) == updated


def test_history_update_is_scoped_and_idempotent(tmp_path: Path) -> None:
    """Update only the matching history entry with combined OSINT state."""
    path = tmp_path / "history.yaml"
    path.write_text("analyses:\n  - malware_type: \"Unclassified\"\n    analyzed_at: 2026-07-17\n    sample_sha256: " + "c" * 64 + "\n    analysis_level: static_family_attribution\n    matched_patterns:\n      - \"family:unknown\"\n      - \"confidence:low\"\n    c2: []\n    notes: \"old\"\n    result_path: x\n", encoding="utf-8")
    record = {"sha256": "c" * 64, "combined_attribution": {"family": "stealc", "confidence": "medium", "provider_count": 2}}
    assert osint.update_history_from_enrichment(path, [record]) == 1
    text = path.read_text(encoding="utf-8")
    assert 'malware_type: "stealc"' in text and "static_plus_hash_osint" in text


def test_select_targets_only_returns_low_or_unknown() -> None:
    """Limit enrichment to unresolved or low-confidence cases."""
    summary = {"cases": [
        {"sha256": "a", "attribution": {"family": "x", "confidence": "medium"}},
        {"sha256": "b", "attribution": {"family": "unknown", "confidence": "medium"}},
        {"sha256": "c", "attribution": {"family": "x", "confidence": "low"}},
    ]}
    assert [item["sha256"] for item in osint.select_targets(summary)] == ["b", "c"]


def test_new_family_aliases_are_available() -> None:
    """Map additional researched labels without treating generic tags as families."""
    assert osint.family_from_label("OtterCookie") == "ottercookie"
    assert osint.family_from_label("ExaStealer") == "exastealer"


def test_curated_evidence_is_reviewed_and_replayable(tmp_path: Path) -> None:
    """Load reviewed evidence and combine external research with local static review."""
    path = tmp_path / "research.yaml"
    path.write_text(
        "schema_version: 1\n"
        "policy: {sample_submission: prohibited}\n"
        "records:\n"
        f"  {'d' * 64}:\n"
        "    reviewed: true\n"
        "    evidence:\n"
        "      - {provider: external_report, family: OtterCookie, label: exact hash, strength: 4, reference: 'https://example.test/report?q=secret'}\n"
        "      - {provider: local_reviewed_static, family: OtterCookie, label: static match, strength: 4}\n",
        encoding="utf-8",
    )
    loaded = osint.load_curated_evidence(path)
    normalized = osint.normalize_curated_evidence(loaded["d" * 64])
    assert {item["provider"] for item in normalized["evidence"]} == {"external_report", "local_reviewed_static"}
    combined = osint.combine_attribution({"family": "unknown", "evidence": []}, normalized["evidence"])
    assert combined["family"] == "ottercookie"
    assert combined["confidence"] == "medium"
    assert all("secret" not in str(item.get("reference")) for item in normalized["evidence"])


def test_public_failure_reason_hides_credential_names() -> None:
    """Keep public source errors useful without exposing environment variable names."""
    assert osint.public_failure_reason("unavailable", "VT_API_KEY is not set") == "required API credential is not configured"
    record = osint.build_public_evidence(
        "e" * 64, {"family": "unknown", "evidence": []},
        {"virustotal": {"status": "unavailable", "reason": "VT_API_KEY is not set"}},
        "2026-07-17T00:00:00+00:00",
    )
    assert "VT_API_KEY" not in json.dumps(record)


def test_markdown_renderers_are_japanese_and_keep_enums_as_code() -> None:
    """日本語本文と技術enumの保全、canonicalリンク差し替えを確認する。"""
    digest = "7" * 64
    record = {
        "sha256": digest,
        "collected_at": "2026-07-17T00:00:00+00:00",
        "family_evidence": [{
            "provider": "triage",
            "family": "stealc",
            "label": "StealC",
            "reference": "https://example.test/report",
        }],
        "combined_attribution": {
            "family": "stealc",
            "confidence": "medium",
            "status": "supported",
            "provider_count": 2,
            "conflicts": [],
        },
        "sources": {"triage": {"status": "ok"}},
    }
    section = osint.render_case_osint(record)
    assert "## ハッシュOSINTによる補強" in section
    assert "### ファミリー根拠" in section
    assert "`stealc`" in section
    assert "## Hash OSINT enrichment" not in section

    link = "../../../../malware/unclassified/case/README.md"
    aggregate = osint.render_osint_summary([record], {digest: link})
    assert "# ハッシュOSINTによる補強" in aggregate
    assert "| 情報源 | 状態 | 件数 |" in aggregate
    assert f"]({link})" in aggregate
    assert "`medium`" in aggregate
    assert record["combined_attribution"]["confidence"] == "medium"


def test_canonical_output_separates_cases_and_validates_manifest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ケース正本とcollection集約を分離し、リンクとmanifestを整合させる。"""
    repository = tmp_path / "r"
    results = repository / "analysis-results"
    collection_id = "malwarebazaar-unknown-20260717"
    aggregate = (
        results / "collections" / collection_id / "sources" / "unclassified"
    )
    digest = "8" * 64
    case_dir = (
        results
        / "malware"
        / "unclassified"
        / "versions"
        / "unknown"
        / "cases"
        / digest
    )
    case_dir.mkdir(parents=True)
    (case_dir / "README.md").write_text("# 未分類ケース\n", encoding="utf-8")
    (case_dir / "case.json").write_text(
        json.dumps({"sha256": digest}) + "\n", encoding="utf-8"
    )
    (results / "catalog").mkdir(parents=True)
    (results / "catalog" / "cases.json").write_text(
        json.dumps({
            "schema_version": 1,
            "cases": {
                digest: {
                    "case_id": f"sha256:{digest}",
                    "case_kind": "unclassified",
                    "family": "unclassified",
                    "version_key": "unknown",
                    "canonical_path": case_dir.relative_to(repository).as_posix(),
                },
            },
        }),
        encoding="utf-8",
    )
    collection_root = results / "collections" / collection_id
    collection_root.mkdir(parents=True)
    manifest_path = collection_root / "manifest.json"
    manifest_path.write_text(
        json.dumps({
            "schema_version": 1,
            "collection_id": collection_id,
            "family_sources": [{
                "family": "unclassified",
                "path": "sources/unclassified",
            }],
            "cases": [{"case_id": f"sha256:{digest}"}],
        }),
        encoding="utf-8",
    )
    manifest_before = manifest_path.read_bytes()
    aggregate.mkdir(parents=True)
    summary_path = aggregate / "summary.json"
    summary_path.write_text(
        json.dumps({
            "schema_version": 1,
            "cases": [{
                "sha256": digest,
                "attribution": {
                    "family": "unknown",
                    "confidence": "low",
                    "evidence": [],
                },
            }],
        }),
        encoding="utf-8",
    )
    (aggregate / "README.md").write_text("# 集約\n", encoding="utf-8")
    registry = repository / "sources.yaml"
    registry.write_text(
        "schema_version: 1\n"
        "policy: {sample_submission: prohibited}\n"
        "sources:\n"
        "  circl_hashlookup:\n"
        "    enabled: true\n"
        "    endpoint: 'https://example.test/{sha256}'\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(
        osint,
        "collect_network_source",
        lambda *_args, **_kwargs: pytest.fail(
            "network collector must not be called"
        ),
    )

    counts = osint.enrich_batch(
        summary_path,
        aggregate,
        registry,
        repository / "cache",
        results_root=results,
        collection_id=collection_id,
    )

    assert counts["targeted"] == 1
    assert not (aggregate / "cases").exists()
    assert (case_dir / "osint-evidence.json").is_file()
    assert "## ハッシュOSINTによる補強" in (
        case_dir / "README.md"
    ).read_text(encoding="utf-8")
    osint_markdown = (aggregate / "OSINT.md").read_text(encoding="utf-8")
    match = __import__("re").search(
        rf"\[{digest}\]\(([^)]+)\)", osint_markdown
    )
    assert match is not None
    assert (aggregate / match.group(1)).resolve() == (
        case_dir / "README.md"
    ).resolve()
    assert (aggregate / match.group(1)).resolve().is_file()
    updated_summary = json.loads(summary_path.read_text(encoding="utf-8"))
    evidence_link = updated_summary["cases"][0]["hash_osint"]["evidence_file"]
    assert (summary_path.parent / evidence_link).resolve().is_file()
    assert manifest_path.read_bytes() == manifest_before
