"""family別解析要件の拡張監査とカバレッジを検証する。"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path

FRAMEWORK = Path(__file__).resolve().parents[1]
REPOSITORY = FRAMEWORK.parent
COMMON = FRAMEWORK / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from automation_coverage import (
    QUALITY_POLICY_CATEGORIES,
    _load_quality_policies,
    _registered_families,
)

POLICY = FRAMEWORK / "registry" / "family_analysis_requirements.json"
AUDIT = FRAMEWORK / "inventories" / "family-analysis-requirements-audit.json"
COVERAGE = REPOSITORY / "analysis-results" / "catalog" / "automation-coverage.json"
REGISTRY = FRAMEWORK / "registry" / "malware_types.json"

BASIS_POLICIES = {
    "networked_config_nonterminal": {
        "config_required": True,
        "network_required": True,
        "terminal_payload_required": False,
    },
    "networked_config_terminal": {
        "config_required": True,
        "network_required": True,
        "terminal_payload_required": True,
    },
    "offline_nonterminal": {
        "config_required": False,
        "network_required": False,
        "terminal_payload_required": False,
    },
    "offline_loader_terminal": {
        "config_required": False,
        "network_required": False,
        "terminal_payload_required": True,
    },
}

REPRESENTATIVES = {
    "backdoor": "freepbx_k_php",
    "bot": "catddos",
    "downloader": "amadey",
    "keylogger": "snakekeylogger",
    "loader": "latrodectus",
    "miner": "blackhorse_miner_agent",
    "other": "screenconnect_rmm",
    "ransomware": "wannacry",
    "rat": "atlascross",
    "stealer": "efimer",
    "worm": "mirai",
}


def _load_audit() -> dict:
    return json.loads(AUDIT.read_text(encoding="utf-8"))


def _load_coverage() -> dict:
    return json.loads(COVERAGE.read_text(encoding="utf-8"))


def test_policy_loader_accepts_representatives_from_all_allowed_categories() -> None:
    """厳格loaderが許容する11カテゴリを実在familyで一つずつ検証する。"""

    policies = _load_quality_policies(POLICY)
    assert set(REPRESENTATIVES) == QUALITY_POLICY_CATEGORIES
    for category, family in REPRESENTATIVES.items():
        assert policies[family]["category"] == category


def test_audit_is_complete_and_matches_loaded_policies() -> None:
    """51件の監査判断を重複なくpolicyへ反映していることを検証する。"""

    audit = _load_audit()
    assert set(audit) == {
        "schema_version",
        "audit_id",
        "baseline",
        "basis_definitions_ja",
        "reviewed",
        "left_missing",
    }
    assert audit["schema_version"] == 1
    assert audit["left_missing"] == []

    reviewed = audit["reviewed"]
    families = [item["family"] for item in reviewed]
    assert len(families) == 51
    assert families == sorted(families)
    assert len(families) == len(set(families))
    assert Counter(item["baseline_cohort"] for item in reviewed) == {
        "detector_registered": 29,
        "detector_missing": 22,
    }
    assert audit["baseline"] == {
        "coverage_artifact": "analysis-results/catalog/automation-coverage.json",
        "safe_automatic_policy_gap_count": 51,
        "detector_registered_count": 29,
        "detector_missing_count": 22,
    }
    assert set(audit["basis_definitions_ja"]) == set(BASIS_POLICIES)

    policies = _load_quality_policies(POLICY)
    for item in reviewed:
        assert set(item) == {
            "family",
            "baseline_cohort",
            "policy",
            "basis",
            "classification_evidence_ja",
            "evidence_paths",
        }
        assert item["policy"] == policies[item["family"]]
        assert item["policy"]["category"] in QUALITY_POLICY_CATEGORIES
        assert {
            key: item["policy"][key]
            for key in (
                "config_required",
                "network_required",
                "terminal_payload_required",
            )
        } == BASIS_POLICIES[item["basis"]]
        assert item["classification_evidence_ja"]
        assert item["evidence_paths"]
        for relative in item["evidence_paths"]:
            assert (REPOSITORY / relative).is_file(), relative


def test_every_safe_automatic_family_has_a_quality_policy() -> None:
    """既存の安全preflight済み84 familyにpolicy漏れがないことを検証する。"""

    policies = _load_quality_policies(POLICY)
    coverage = _load_coverage()
    safe_families = {
        item["family"]
        for item in coverage["families"]
        if item["script_only_handler_available"] is True
    }
    assert len(safe_families) == 84
    assert len(policies) == 84
    assert set(policies) == safe_families

    registered = _registered_families(REGISTRY)
    assert safe_families & registered <= set(policies)
