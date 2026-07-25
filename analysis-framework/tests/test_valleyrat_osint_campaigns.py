"""ValleyRATのOSINT campaign帰属を合成成果物だけで検証する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys


COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

from attribute_valleyrat_campaigns import (  # noqa: E402
    build_attribution,
    build_imphash_clusters,
    extract_case_evidence,
    load_registry,
    match_public_campaigns,
)


REGISTRY = Path(__file__).parents[1] / "registry" / "valleyrat_osint_campaigns.json"


def _case(sha256: str, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "sha256": sha256,
        "case_path": f"analysis-results/malware/valleyrat/versions/unknown/cases/{sha256}",
        "artifact_sha256": [sha256],
        "md5": "",
        "first_seen": None,
        "file_name": None,
        "file_type": "exe",
        "imphash": "",
        "tlsh": None,
        "tags": [],
        "collection": None,
        "delivery_pattern": "single_pe",
        "endpoints": [],
    }
    value.update(overrides)
    return value


def test_public_sha256_exact_match_is_confirmed() -> None:
    registry = load_registry(REGISTRY)
    public_hash = registry["public_campaigns"][0]["sha256"][0]
    matches = match_public_campaigns(_case("a" * 64, artifact_sha256=[public_hash]), registry)
    assert len(matches) == 1
    assert matches[0]["status"] == "confirmed_exact_hash"
    assert matches[0]["matched_sha256"] == [public_hash]


def test_network_match_alone_is_not_confirmed() -> None:
    registry = load_registry(REGISTRY)
    matches = match_public_campaigns(
        _case("b" * 64, endpoints=["103.215.77.17:4499"]),
        registry,
    )
    assert len(matches) == 1
    assert matches[0]["status"] == "supporting_network_match_only"
    assert matches[0]["confidence"] == "低"


def test_imphash_cluster_does_not_become_public_campaign() -> None:
    imphash = "0123456789abcdef0123456789abcdef"
    cases = [
        _case("c" * 64, imphash=imphash),
        _case("d" * 64, imphash=imphash),
    ]
    clusters = build_imphash_clusters(cases)
    assert len(clusters) == 1
    assert clusters[0]["classification"] == "local_code_cluster_candidate"
    assert clusters[0]["confidence"] == "低"


def test_community_silverfox_tag_is_not_actor_attribution() -> None:
    registry = load_registry(REGISTRY)
    report = build_attribution(
        [_case("e" * 64, tags=["SilverFox", "ValleyRAT"])],
        registry,
    )
    case = report["cases"][0]
    assert case["status"] == "unresolved"
    assert case["actor_assessment"]["status"] == "unresolved"
    assert case["actor_assessment"]["community_tags_not_used_for_attribution"] == [
        "SilverFox"
    ]


def test_curated_parent_child_members_are_local_candidates() -> None:
    registry = load_registry(REGISTRY)
    cluster = registry["curated_local_clusters"][0]
    report = build_attribution(
        [_case(cluster["members"][0]), _case(cluster["members"][1])],
        registry,
    )
    assert {item["status"] for item in report["cases"]} == {
        "local_campaign_candidate"
    }
    assert {
        item["local_campaign_candidates"][0]["campaign_id"]
        for item in report["cases"]
    } == {cluster["campaign_id"]}


def test_case_evidence_uses_text_artifacts_without_execution(tmp_path: Path) -> None:
    digest = "f" * 64
    case = tmp_path / digest
    case.mkdir()
    (case / "features.json").write_text(
        json.dumps({"campaign_type": "dll_sideload_vvas_bundle"}),
        encoding="utf-8",
    )
    (case / "analysis.json").write_text(
        '{"value":"203.0.113.10:443","sha256":"' + "1" * 64 + '"}',
        encoding="utf-8",
    )
    evidence = extract_case_evidence(case)
    assert evidence["delivery_pattern"] == "dll_sideload_vvas_bundle"
    assert evidence["endpoints"] == ["203.0.113.10:443"]
    assert evidence["artifact_sha256"] == sorted([digest, "1" * 64])
