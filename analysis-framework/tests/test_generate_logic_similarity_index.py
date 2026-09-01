"""感染チェーン・全体ロジック比較索引を検証する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import generate_logic_similarity_index as logic_similarity  # noqa: E402
from generate_logic_similarity_index import (  # noqa: E402
    build_index,
    build_profile,
    compare_profiles,
    generate,
)


LEFT_SHA = "a" * 64
RIGHT_SHA = "b" * 64
THIRD_SHA = "c" * 64


def _report(*, family: str = "agenttesla") -> dict[str, object]:
    return {
        "sha256": LEFT_SHA,
        "family": family,
        "overall_logic": {
            "phases": [
                {"phase_id": "payload_decoding", "roles": ["decrypt_payload"]},
                {"phase_id": "exfiltration", "roles": ["ftp_upload"]},
                {"phase_id": "cleanup", "title_ja": "temporary file delete"},
            ]
        },
        "program_evidence": [
            {
                "format": ".NET PE",
                "relationship": "statically_recovered_program",
            }
        ],
        "functions": [
            {
                "role": "ftp_exfiltration",
                "fingerprints": {
                    "semantic_sequence_sha256": "d" * 64,
                    "semantic_token_count": 12,
                },
            }
        ],
    }


def _layers() -> dict[str, object]:
    return {
        "layers": [
            {
                "sha256": LEFT_SHA,
                "parent_sha256": None,
                "format": "script",
                "transform": "submission",
            },
            {
                "sha256": RIGHT_SHA,
                "parent_sha256": LEFT_SHA,
                "format": "pe",
                "transform": "base64_decode",
            },
        ]
    }


def _features() -> dict[str, object]:
    return {
        "sample_characteristics": [
            {"id": "obfuscation:base64"},
            {"id": "version:key"},
        ],
        "behaviors": [{"id": "network:ftp"}],
    }


def _profile(sha256: str, *, family: str = "agenttesla") -> dict[str, object]:
    return build_profile(
        sha256=sha256,
        case_record={
            "family": family,
            "version_key": "test",
            "canonical_path": f"analysis-results/malware/{family}/versions/test/cases/{sha256}",
        },
        report=_report(family=family),
        static_layers=_layers(),
        features=_features(),
    )


def test_profile_uses_canonical_independent_dimensions() -> None:
    profile = _profile(LEFT_SHA)
    dimensions = profile["dimensions"]

    assert dimensions["execution_stages"] == [
        "cleanup",
        "exfiltration",
        "payload_decoding",
    ]
    assert "script--base64_decode-->pe" in dimensions["layer_chain"]
    assert dimensions["capabilities"] == ["network:ftp", "obfuscation:base64"]
    assert dimensions["function_roles"] == ["ftp_exfiltration"]
    assert dimensions["code_fingerprints"] == [f"semantic:{'d' * 64}"]


def test_single_matching_dimension_is_not_a_similarity_candidate() -> None:
    left = _profile(LEFT_SHA)
    right = _profile(RIGHT_SHA)
    right["dimensions"] = {
        "execution_stages": ["exfiltration"],
        "layer_chain": ["root:archive"],
        "module_stack": [],
        "capabilities": [],
        "function_roles": [],
        "code_fingerprints": [],
    }

    assert compare_profiles(left, right) is None


def test_multiple_dimensions_create_review_candidate_not_attribution() -> None:
    match = compare_profiles(_profile(LEFT_SHA), _profile(RIGHT_SHA))

    assert match is not None
    assert match["independent_evidence_axes"] >= 2
    assert match["same_family"] is True
    assert "campaignまたはactorの同一性を意味しません" in match["assessment"]


def test_cross_family_without_code_or_strong_layer_evidence_is_suppressed() -> None:
    left = _profile(LEFT_SHA)
    right = _profile(RIGHT_SHA, family="formbook")
    right["dimensions"]["code_fingerprints"] = []
    right["dimensions"]["layer_chain"] = ["root:script"]

    assert compare_profiles(left, right) is None


def test_generate_writes_and_then_passes_check(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    catalog_dir = repository / "analysis-results" / "catalog"
    catalog_dir.mkdir(parents=True)
    cases = {}
    for sha256 in (LEFT_SHA, RIGHT_SHA, THIRD_SHA):
        case_path = (
            repository
            / "analysis-results"
            / "malware"
            / "agenttesla"
            / "versions"
            / "test"
            / "cases"
            / sha256
        )
        case_path.mkdir(parents=True)
        (case_path / "README.md").write_text("# test case\n", encoding="utf-8")
        report = _report()
        report["sha256"] = sha256
        (case_path / "static-logic.json").write_text(
            json.dumps(report, ensure_ascii=False),
            encoding="utf-8",
        )
        (case_path / "static-layers.json").write_text(
            json.dumps(_layers(), ensure_ascii=False),
            encoding="utf-8",
        )
        (case_path / "features.json").write_text(
            json.dumps(_features(), ensure_ascii=False),
            encoding="utf-8",
        )
        cases[sha256] = {
            "canonical_path": case_path.relative_to(repository).as_posix(),
            "family": "agenttesla",
            "version_key": "test",
        }
    (catalog_dir / "cases.json").write_text(
        json.dumps({"schema_version": 1, "cases": cases}, ensure_ascii=False),
        encoding="utf-8",
    )

    index = build_index(repository)
    assert index["counts"]["profiled_cases"] == 3
    assert index["counts"]["retained_pairs"] == 3

    output_json = catalog_dir / "logic-similarity.json"
    output_markdown = catalog_dir / "LOGIC-SIMILARITY.md"
    written = generate(
        repository,
        output_json=output_json,
        output_markdown=output_markdown,
        write=True,
    )
    checked = generate(
        repository,
        output_json=output_json,
        output_markdown=output_markdown,
        check=True,
    )

    assert written["write_performed"] is True
    assert checked["check_failed"] is False
    markdown = output_markdown.read_text(encoding="utf-8")
    assert "最低2つの独立軸" in markdown
    assert "../malware/agenttesla/versions/test/cases/" in markdown
    assert "/README.md" in markdown


def test_build_index_bounds_candidates_before_global_ranking(
    monkeypatch, tmp_path: Path
) -> None:
    """全pair件数を残しつつendpoint heapの和集合だけを順位付けへ渡す。"""

    monkeypatch.setattr(logic_similarity, "MAX_CANDIDATES_PER_CASE", 2)
    repository = tmp_path / "repository"
    catalog_dir = repository / "analysis-results" / "catalog"
    catalog_dir.mkdir(parents=True)
    cases = {}
    for index in range(6):
        sha256 = f"{index + 1:064x}"
        case_path = (
            repository
            / "analysis-results"
            / "malware"
            / "agenttesla"
            / "versions"
            / "test"
            / "cases"
            / sha256
        )
        case_path.mkdir(parents=True)
        report = _report()
        report["sha256"] = sha256
        for name, value in (
            ("static-logic.json", report),
            ("static-layers.json", _layers()),
            ("features.json", _features()),
        ):
            (case_path / name).write_text(
                json.dumps(value, ensure_ascii=False),
                encoding="utf-8",
            )
        cases[sha256] = {
            "canonical_path": case_path.relative_to(repository).as_posix(),
            "family": "agenttesla",
            "version_key": "test",
        }
    (catalog_dir / "cases.json").write_text(
        json.dumps({"schema_version": 1, "cases": cases}, ensure_ascii=False),
        encoding="utf-8",
    )

    index = logic_similarity.build_index(repository)

    assert index["counts"]["candidate_pairs_before_limit"] == 15
    assert index["counts"]["candidate_pairs_retained_for_ranking"] <= 12
    assert index["counts"]["candidate_pairs_omitted_before_ranking"] >= 3
    assert (
        index["comparison_contract"]["max_candidates_per_case_before_ranking"]
        == 2
    )
