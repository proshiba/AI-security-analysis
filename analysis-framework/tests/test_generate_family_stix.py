"""ファミリー別STIXの根拠境界、参照整合性、再生成時の版を検証する。"""

from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import sys

import pytest


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import generate_family_stix as stix  # noqa: E402


def test_atlas_rat_does_not_alias_atlascross_actor_or_atlasagent() -> None:
    """内部IDの後方互換とファミリー／アクター同一性を分離する。"""

    knowledge = json.loads((Path(__file__).parents[1] / "knowledge" / "malware_families" / "a_m.json").read_text(encoding="utf-8"))
    atlas = next(item for item in knowledge["families"] if item["id"] == "atlascross")
    assert atlas["display_name"] == "Atlas RAT"
    assert not {"AtlasCross", "AtlasAgent", "DangerAds"} & set(atlas["aliases"])
    assert any(source["id"] == "am-atlas-nsfocus-2023" for source in atlas["sources"])


def _knowledge() -> dict:
    return {
        "display_name": "検証RAT",
        "overview_ja": "メール添付で配布された。[[research-1]]",
        "aliases": ["検証別名"],
        "developer": {
            "assessment_ja": "公開資料では作者が判明している。",
            "confidence": "high",
            "source_ids": ["research-1"],
        },
        "actors": [
            {
                "name": "Test Actor",
                "relationship_ja": "Test Actorが攻撃で利用した。",
                "confidence": "high",
                "source_ids": ["research-1"],
            },
            {
                "name": "未特定の購入者",
                "relationship_ja": "利用の可能性がある。",
                "confidence": "low",
                "source_ids": ["research-1"],
            },
        ],
        "commodity": {
            "classification": "maas",
            "assessment_ja": "複数の利用者が購入できる。単一アクター専用ではない。",
            "source_ids": ["research-1"],
        },
        "historical_use": [
            {"period": "2025年", "summary_ja": "請求書メールからRATを配布した。", "actors": ["Test Actor"], "source_ids": ["research-1"]},
            {"period": "2026年", "summary_ja": "MalwareBazaarで検体を発見した。", "actors": [], "source_ids": ["research-1"]},
        ],
        "sources": [{
            "id": "research-1", "publisher": "検証機関", "title_ja": "攻撃経路の調査",
            "url": "https://example.org/report",
        }],
    }


def test_attack_route_excludes_sample_discovery() -> None:
    assert stix._assert_attack_history("請求書メールから配布された。")
    assert not stix._assert_attack_history("MalwareBazaarで検体を発見した。")
    assert not stix._assert_attack_history("逮捕により活動が停止した。")
    assert not stix._named_actor("未特定の購入者")
    assert not stix._named_actor("シリア政権支持派")
    assert not stix._named_actor("DEV-0569 / BATLOADER")


def test_family_bundle_has_sourced_relationships_and_code_caveat() -> None:
    objects = stix._family_objects(
        "test-rat", _knowledge(), ["a" * 64, "b" * 64],
        {"capabilities": Counter({"network:tcp": 2})},
        [{"fingerprint": "c" * 64, "role": "network", "case_count": 2}],
        [("other-rat", [{"fingerprint": "d" * 64, "role": "network", "left_sha256": "a" * 64, "right_sha256": "e" * 64}])],
        [{"name": "請求書攻撃", "description_ja": "請求書メールによる配布。", "confidence": "medium", "source_ids": ["research-1"], "attributed_actor_names": ["Test Actor"], "attribution_ja": "検証アクターの活動。", "attribution_confidence": "medium"}],
        [{"name": "Test Developer", "description_ja": "公開資料で開発を確認。", "confidence": "high", "source_ids": ["research-1"]}],
        "2026-09-21T00:00:00Z",
    )
    bundle = {"type": "bundle", "id": stix._identifier("bundle", "test-rat"), "objects": objects}
    stix._validate_bundle(bundle)
    relationships = [obj for obj in objects if obj["type"] == "relationship"]
    assert {obj["relationship_type"] for obj in relationships} == {"uses", "authored-by", "attributed-to"}
    assert len([obj for obj in relationships if obj["source_ref"].startswith("threat-actor--")]) == 1
    assert all(obj.get("external_references") for obj in relationships)
    notes = "\n".join(obj["content"] for obj in objects if obj["type"] == "note")
    assert "MalwareBazaar" not in notes
    assert "同じ開発者・攻撃者・campaign・派生関係を意味しない" in notes
    assert "提供形態: maas" in notes


def test_bundle_validation_rejects_broken_reference() -> None:
    stamp = "2026-09-21T00:00:00Z"
    malware = stix._object("malware", "broken", stamp, name="検証", is_family=True)
    note = stix._object("note", "broken:note", stamp, content="検証", object_refs=["malware--" + "0" * 36])
    with pytest.raises(ValueError, match="参照先がない"):
        stix._validate_bundle({"type": "bundle", "objects": [malware, note]})


def test_reconcile_versions_preserves_created_and_unchanged_modified(tmp_path: Path) -> None:
    old = stix._object("malware", "one", "2026-09-20T00:00:00Z", name="旧名", is_family=True)
    old_path = tmp_path / "old.json"
    old_path.write_text(json.dumps({"type": "bundle", "objects": [old]}), encoding="utf-8")
    same = stix._object("malware", "one", "2026-09-21T00:00:00Z", name="旧名", is_family=True)
    changed = stix._object("malware", "one", "2026-09-21T00:00:00Z", name="新名", is_family=True)
    stix._reconcile_versions({"objects": [same]}, old_path, "2026-09-21T00:00:00Z")
    stix._reconcile_versions({"objects": [changed]}, old_path, "2026-09-21T00:00:00Z")
    assert same["created"] == same["modified"] == "2026-09-20T00:00:00Z"
    assert changed["created"] == "2026-09-20T00:00:00Z"
    assert changed["modified"] == "2026-09-21T00:00:00Z"


def test_streaming_array_reader(tmp_path: Path) -> None:
    path = tmp_path / "index.json"
    path.write_text(json.dumps({"exact_groups": [{"members": ["a", "b"]}], "function_records": [{"record_id": "a"}]}, indent=2), encoding="utf-8")
    assert list(stix._iter_array_objects(path, "exact_groups")) == [{"members": ["a", "b"]}]
    assert list(stix._iter_array_objects(path, "function_records")) == [{"record_id": "a"}]


def test_strong_case_gate_rejects_placement_and_operator_selection(tmp_path: Path) -> None:
    family = "test-rat"
    hashes = {"a" * 64: ("high", "known_outer_sha256"),
              "b" * 64: ("low", "no_unique_detection_above_threshold"),
              "c" * 64: ("high", "explicit_operator_selection")}
    for sha, (confidence, basis) in hashes.items():
        case = tmp_path / "analysis-results/malware" / family / "versions/unknown/cases" / sha
        case.mkdir(parents=True)
        (case / "report.json").write_text(json.dumps({"classification": {
            "family": family, "confidence": confidence, "selection_basis": basis,
        }}), encoding="utf-8")
    assert stix._strong_case_hashes(tmp_path, {family: sorted(hashes)}) == {"a" * 64}


def test_code_group_requires_source_verified_non_generic_exact_function(tmp_path: Path) -> None:
    family = "test-rat"
    sha1, sha2 = "a" * 64, "b" * 64
    sources = []
    for sha in (sha1, sha2):
        case = tmp_path / "analysis-results/malware" / family / "versions/unknown/cases" / sha
        case.mkdir(parents=True)
        functions = []
        for name, digest in (("runtime.chansend", "c" * 64), ("Core.Dispatch", "d" * 64)):
            functions.append({
                "function_id": f"{sha}:{name}", "name": name,
                "evidence": {"source": "ghidra-mcp", "confidence": "confirmed_static_decompilation"},
                "fingerprints": {"normalized_logic_sha256": digest},
            })
        (case / "static-logic.json").write_text(json.dumps({"functions": functions}), encoding="utf-8")
        sources.append((case / "static-logic.json").relative_to(tmp_path).as_posix())
    records = []
    for index, (sha, source) in enumerate(zip((sha1, sha2), sources)):
        for suffix, digest in (("runtime.chansend", "e" * 64), ("Core.Dispatch", "f" * 64)):
            records.append({
                # 関数recordのSHAは復元済み内部layerのことがあり、root caseとは限らない。
                "record_id": f"fn-{index}-{suffix}", "family": family, "sha256": "9" * 64,
                "source": source, "function_id": f"{sha}:{suffix}",
                "role": "network_communication", "semantic_token_count": 20,
                "semantic_sequence_sha256": digest,
            })
    index_path = tmp_path / "code-similarity.json"
    index_path.write_text(json.dumps({
        "exact_groups": [
            {"semantic_sequence_sha256": "e" * 64, "members": ["fn-0-runtime.chansend", "fn-1-runtime.chansend"]},
            {"semantic_sequence_sha256": "f" * 64, "members": ["fn-0-Core.Dispatch", "fn-1-Core.Dispatch"]},
        ], "function_records": records,
    }, indent=2), encoding="utf-8")
    within, across = stix._code_groups(index_path, {family}, tmp_path, {sha1, sha2})
    assert across == {}
    assert [item["fingerprint"] for item in within[family]] == ["f" * 64]
    assert within[family][0]["case_count"] == 2


def test_local_overview_skips_discovery_and_sensitive_paragraphs(tmp_path: Path) -> None:
    path = tmp_path / "README.md"
    path.write_text(
        "# 検証対象\n\n提出ファイル名から推測された分類。\n\n"
        "詳細はhttps://example.org/rawを参照。\n\n## 技術概要\n\n"
        "Linux上で遠隔命令を受け取る処理がある。\n",
        encoding="utf-8",
    )
    assert stix._local_overview(path) == "公開済みローカル概要: Linux上で遠隔命令を受け取る処理がある。"


def test_published_bundles_have_valid_local_references() -> None:
    repository = Path(__file__).parents[2]
    root = repository / "analysis-results/stix"
    index = json.loads((root / "index.json").read_text(encoding="utf-8"))
    assert index["counts"]["families"] == len(index["families"])
    assert "credential-phishing-html" not in index["families"]
    assert "manageengine-endpoint-central-abuse" not in index["families"]
    assert "infrastructure-decoy-hta" not in index["families"]
    assert "linux-reverse-shell" not in index["families"]
    assert "linux-downloader" not in index["families"]
    assert "mig-logcleaner" not in index["families"]
    assert not stix.TECHNICAL_CLUSTERS.intersection(index["families"])
    for family in index["families"]:
        bundle = json.loads((root / "families" / f"{family}.json").read_text(encoding="utf-8"))
        stix._validate_bundle(bundle)
        assert not stix.DISCOVERY_ONLY.search(json.dumps(bundle, ensure_ascii=False)), family
        if "開発主体: " not in "\n".join(obj.get("content", "") for obj in bundle["objects"]):
            assert any("本STIXでは、出典付きの開発者" in obj.get("content", "") for obj in bundle["objects"]), family
        for obj in bundle["objects"]:
            for source in obj.get("external_references", []):
                url = source["url"]
                if url.startswith(stix.BASE_URL):
                    assert (repository / url.removeprefix(stix.BASE_URL)).is_file(), (family, url)


def test_new_public_api_is_documented() -> None:
    repository = Path(__file__).parents[2]
    html = (repository / "docs/pydoc/generate_family_stix.html").read_text(encoding="utf-8")
    assert 'name="-generate"' in html
    assert 'name="-main"' in html


def test_check_allows_independently_managed_infrastructure_bundle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """ファミリー成果物だけを照合し、別generatorの横断Bundleは許容する。"""
    root = tmp_path / "analysis-results" / "stix"
    (root / "families").mkdir(parents=True)
    (root / "infrastructure").mkdir()
    outputs = {"index.json": "{}\n", "families/demo.json": "{}\n"}
    for relative, content in outputs.items():
        (root / relative).write_text(content, encoding="utf-8")
    (root / "infrastructure" / "bundle.json").write_text("{}\n", encoding="utf-8")
    monkeypatch.setattr(stix, "generate", lambda repository, as_of: (outputs, {"counts": {}}))
    monkeypatch.setattr(sys, "argv", ["generate_family_stix.py", "--repository", str(tmp_path), "--as-of", "2026-09-21", "--check"])
    assert stix.main() == 0
    (root / "families" / "unexpected.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(SystemExit, match="余分"):
        stix.main()
