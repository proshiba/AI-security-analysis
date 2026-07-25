"""campaign相関の強い証拠要件と自動labelを検証する。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys


FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
sys.path.insert(0, str(COMMON))

from analysis_contract import seal_report, verify_artifact_hashes, verify_report_semantics  # noqa: E402
from campaign_correlation import (  # noqa: E402
    _indicator_is_excluded,
    build_fingerprints,
    correlate_cases,
    extract_campaign_evidence,
    load_rules,
    match_fingerprints,
)


RULES = load_rules(FRAMEWORK / "registry" / "campaign_correlation_rules.json")

from correlate_campaigns import _synchronize_tracked_campaign_label_seal  # noqa: E402


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


def test_existing_ioc_list_without_network_ioc_does_not_use_json_fallback(
    tmp_path: Path,
) -> None:
    """canonical一覧がroot hashだけなら汎用文字列をcampaign証拠へ昇格しない。"""

    digest = "a" * 64
    (tmp_path / "IOC-LIST.md").write_text(
        "# IOC ??\n\n"
        "| ?? (Type) | ? (Value) | ?? (Role) | ?? (Confidence) | ?? (Source) |\n"
        "|---|---|---|---|---|\n"
        f"| SHA-256 | {digest} | 提出検体 | 確認済み | fixture |\n",
        encoding="utf-8",
    )
    (tmp_path / "analysis.json").write_text(
        '{"network": {"domains": ["sfxrar.pdb", "1.ib"]}}',
        encoding="utf-8",
    )
    profile = {
        "sha256": digest,
        "family": "fixture",
        "campaign_type": "unknown",
        "sample_characteristics": [],
        "behaviors": [],
    }

    evidence = extract_campaign_evidence(tmp_path, profile, RULES)

    assert evidence["indicators"] == []


def test_json_fallback_remains_available_only_without_ioc_list(tmp_path: Path) -> None:
    """legacy caseでIOC一覧自体がない場合だけ明示network fieldを補助利用する。"""

    digest = "b" * 64
    (tmp_path / "analysis.json").write_text(
        '{"network": {"c2_url": "https://legacy.example/task"}}',
        encoding="utf-8",
    )
    profile = {
        "sha256": digest,
        "family": "fixture",
        "campaign_type": "unknown",
        "sample_characteristics": [],
        "behaviors": [],
    }

    evidence = extract_campaign_evidence(tmp_path, profile, RULES)

    assert [(item["type"], item["value"]) for item in evidence["indicators"]] == [
        ("url", "https://legacy.example/task"),
    ]


def test_campaign_label_update_reseals_only_after_other_artifacts_validate(
    tmp_path: Path,
) -> None:
    """campaign label変更時に追跡済みhashとreport sealを同期する。"""

    label = tmp_path / "campaign-labels.json"
    other = tmp_path / "analysis.json"
    label.write_text('{"labels": []}\n', encoding="utf-8")
    other.write_text('{"safe": true}\n', encoding="utf-8")
    report = {
        "schema_version": 1,
        "artifact_sha256": {
            "campaign-labels.json": hashlib.sha256(label.read_bytes()).hexdigest(),
            "analysis.json": hashlib.sha256(other.read_bytes()).hexdigest(),
        },
    }
    seal_report(report)
    (tmp_path / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    label.write_text('{"labels": ["campaign-a"]}\n', encoding="utf-8")

    _synchronize_tracked_campaign_label_seal(tmp_path)

    refreshed = json.loads((tmp_path / "report.json").read_text(encoding="utf-8"))
    assert verify_report_semantics(refreshed) == []
    assert verify_artifact_hashes(tmp_path, refreshed["artifact_sha256"]) == []


def test_campaign_label_reseal_rejects_unrelated_artifact_tampering(
    tmp_path: Path,
) -> None:
    """label以外の改変を新しいreport sealで覆い隠さない。"""

    label = tmp_path / "campaign-labels.json"
    other = tmp_path / "analysis.json"
    label.write_text('{"labels": []}\n', encoding="utf-8")
    other.write_text('{"safe": true}\n', encoding="utf-8")
    report = {
        "schema_version": 1,
        "artifact_sha256": {
            "campaign-labels.json": hashlib.sha256(label.read_bytes()).hexdigest(),
            "analysis.json": hashlib.sha256(other.read_bytes()).hexdigest(),
        },
    }
    seal_report(report)
    (tmp_path / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    label.write_text('{"labels": ["campaign-a"]}\n', encoding="utf-8")
    other.write_text('{"safe": false}\n', encoding="utf-8")

    try:
        _synchronize_tracked_campaign_label_seal(tmp_path)
    except ValueError as error:
        assert "campaign label以外" in str(error)
    else:
        raise AssertionError("unrelated artifact tampering was not rejected")
