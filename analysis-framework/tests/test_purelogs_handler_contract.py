"""PureLogs handlerの証拠品質境界を回帰検証する。"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
COMMON = REPOSITORY / "analysis-framework" / "common"
for value in (REPOSITORY, COMMON):
    if str(value) not in sys.path:
        sys.path.insert(0, str(value))

from analysis_contract import handler_result_quality
from extractors.purelogs import extract
from handler_catalog import assess_candidate_handlers, discover_handlers
from handler_evidence import build_route_config_candidate_document


def _handler_spec():
    values = [
        item
        for item in discover_handlers()
        if item.family == "purelogs" and item.relative_path == "extractors/purelogs/extractor.py"
    ]
    assert len(values) == 1
    return values[0]


def test_empty_result_is_not_structural_route_evidence() -> None:
    """routeされただけの入力をfamily証拠にしない。"""

    result = extract(b"ordinary unrelated input", "unrelated.bin")
    quality = handler_result_quality(result)

    assert result["config"]["variant"] == "unresolved_variant"
    assert result["config"]["decoded_config_recovered"] is False
    assert result["supports_family_attribution"] is False
    assert result["c2"] == []
    assert quality["tier"] == 0
    assert quality["tier_name"] == "no_evidence"
    assert quality["sufficient"] is False
    assert quality["structural_groups"] == []


def test_corroborated_http_profile_remains_structural_evidence() -> None:
    """複数の固有pathで裏付けたプロファイルは構造証拠のままにする。"""

    result = extract(
        b"https://logs.example.test/plugin\n/userinfo\n/filesearch/req\n/finish\n",
        "decrypted-http.txt",
    )
    quality = handler_result_quality(result)

    assert result["config"]["variant"] == "purelogs_http_api"
    assert result["supports_family_attribution"] is True
    assert quality["tier"] == 2
    assert quality["tier_name"] == "structural_corroboration"
    assert quality["sufficient"] is True
    assert quality["structural_groups"] == ["variant"]


def test_unmatched_real_handler_creates_no_route_projection_noise() -> None:
    """実handlerの証拠なし結果をroute評価・拒否件数へ含めない。"""

    data = b"ordinary unrelated input"
    digest = hashlib.sha256(data).hexdigest()
    assessment = assess_candidate_handlers(
        ["purelogs"],
        [
            {
                "name": "unrelated.bin",
                "data": data,
                "sha256": digest,
                "parent_sha256": None,
                "depth": 0,
                "transform": "submission",
            }
        ],
        specs=[_handler_spec()],
        handler_timeout_seconds=30,
    )

    family = assessment["families"][0]
    assert family["status"] == "no_evidence"
    assert family["attempts"][0]["status"] == "no_evidence"

    document = build_route_config_candidate_document(
        sha256=digest,
        assessment=assessment,
    )
    assert document["status"] == "no_route_config_candidate"
    assert document["evaluated_route_attempt_count"] == 0
    assert document["observed_excluded_route_attempt_count"] == 1
    assert document["rejected_route_attempt_count"] == 0
    assert document["route_attempt_exclusion_reason_counts"] == {"attempt_status_no_evidence": 1}
    assert document["route_attempt_rejection_reason_counts"] == {}
