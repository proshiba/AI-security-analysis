"""campaign相関の強い証拠要件と自動labelを検証する。"""

from __future__ import annotations

from pathlib import Path
import sys


FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
sys.path.insert(0, str(COMMON))

from campaign_correlation import (  # noqa: E402
    _indicator_is_excluded,
    build_fingerprints,
    correlate_cases,
    load_rules,
    match_fingerprints,
)


RULES = load_rules(FRAMEWORK / "registry" / "campaign_correlation_rules.json")


def _evidence(sha: str, family: str, urls: list[str], campaign: str) -> dict:
    return {
        "sha256": sha * 64,
        "family": family,
        "campaign_type": campaign,
        "feature_ids": ["execution:powershell", "crypto:aes"],
        "indicators": [
            {
                "type": "url",
                "value": value,
                "role": "c2_candidate",
                "confidence": "confirmed",
                "source": "fixture",
            }
            for value in urls
        ],
    }


def test_two_independent_shared_urls_create_campaign_candidate() -> None:
    urls = ["https://one.example/live/", "https://two.example/live/"]
    left = _evidence("a", "fixture", urls, "specific_chain")
    right = _evidence("b", "fixture", urls, "specific_chain")
    unrelated = _evidence("c", "other", [urls[0]], "unknown")
    report = correlate_cases([left, right, unrelated], RULES)
    assert report["counts"]["campaign_candidates"] == 1
    campaign = report["campaigns"][0]
    assert campaign["members"] == ["a" * 64, "b" * 64]
    assert campaign["confidence"] == "high"
    fingerprints = build_fingerprints(report)
    labels = match_fingerprints(left, fingerprints)
    assert [item["campaign_id"] for item in labels] == [campaign["campaign_id"]]
    unrelated_family = _evidence("f", "unrelated-family", urls, "specific_chain")
    assert match_fingerprints(unrelated_family, fingerprints) == []


def test_reference_infrastructure_is_excluded() -> None:
    assert _indicator_is_excluded("url", "http://schemas.microsoft.com/smi/2016/windowssettings", RULES)
    assert _indicator_is_excluded("url", "http://ocsp.verisign.com/", RULES)
    assert _indicator_is_excluded("url", "http://ocsp.verisign.com0/", RULES)
    assert _indicator_is_excluded("endpoint", "127.0.0.1:9050", RULES)
    assert _indicator_is_excluded("domain", "payload.php", RULES)
    assert not _indicator_is_excluded("url", "https://one.example/live/", RULES)


def test_ip_alone_and_generic_campaign_do_not_correlate() -> None:
    left = _evidence("d", "fixture", [], "direct_pe_or_pe_loader")
    right = _evidence("e", "fixture", [], "direct_pe_or_pe_loader")
    for item in (left, right):
        item["indicators"] = [
            {
                "type": "ip",
                "value": "192.0.2.10",
                "role": "candidate",
                "confidence": "candidate",
                "source": "fixture",
            }
        ]
    report = correlate_cases([left, right], RULES)
    assert report["counts"]["campaign_candidates"] == 0
    assert report["labels"] == {}
