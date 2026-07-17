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
    result = osint.collect_case("a" * 64, registry, offline_metadata={"tags": []})
    assert result["malwarebazaar"]["status"] == "ok"
    assert result["circl_hashlookup"]["status"] == "not_found"
    monkeypatch.setattr(osint, "collect_network_source", lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("secret detail")))
    assert osint.collect_case("a" * 64, registry, offline_metadata={"tags": []})["circl_hashlookup"]["reason"] == "RuntimeError during hash lookup"


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
