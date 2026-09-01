"""コード類似性索引の同一fingerprint group化を確認する。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import generate_code_similarity_index as similarity  # noqa: E402
from generate_code_similarity_index import build_index, render_markdown  # noqa: E402
from static_logic import build_static_logic_report  # noqa: E402


def test_identical_functions_are_grouped_without_quadratic_pairs(
    tmp_path: Path,
) -> None:
    """同一関数を全member付きgroupへ集約し、二者pairへ展開しない。"""

    results = tmp_path / "analysis-results"
    for index in range(40):
        sha256 = f"{index + 1:064x}"
        report = build_static_logic_report(
            sha256=sha256,
            family="fixture",
            source_name="review.json",
            records=[
                {
                    "function_id": "decode_config",
                    "name": "decode_config",
                    "address": "0x1000",
                    "role": "config_decoder",
                    "summary_ja": "設定を復号します。",
                    "logic_steps_ja": ["入力を確認します。", "設定を復号します。"],
                    "pseudocode": ("if (buffer) { value = decrypt_config(buffer); return parse_config(value); }"),
                    "api_calls": ["decrypt_config"],
                    "source": "fixture",
                    "tool": "fixture",
                    "program_selector": "/Fixture/sample",
                    "confidence": "confirmed_static_decompilation",
                }
            ],
        )
        case = results / "malware" / "fixture" / "versions" / "unknown" / "cases" / sha256
        case.mkdir(parents=True)
        (case / "static-logic.json").write_text(
            json.dumps(report, ensure_ascii=False),
            encoding="utf-8",
        )

    index = build_index(results)

    assert index["counts"]["exact_groups"] == 1
    assert index["counts"]["simhash_groups"] == 1
    assert index["counts"]["similarity_pairs"] == 0
    assert len(index["simhash_groups"][0]["members"]) == 40


def test_similar_pairs_reference_normalized_function_records(tmp_path: Path) -> None:
    """類似pairへ関数recordを複製せず、安定したIDで参照する。"""

    results = tmp_path / "analysis-results"
    fixtures = (
        ("1" * 64, "0000000000000000", "a" * 64),
        ("2" * 64, "0000000000000001", "b" * 64),
    )
    for index, (sha256, simhash, semantic_sha256) in enumerate(fixtures):
        case = results / "malware" / "fixture" / "versions" / "unknown" / "cases" / sha256
        case.mkdir(parents=True)
        (case / "static-logic.json").write_text(
            json.dumps(
                {
                    "sha256": sha256,
                    "family": "fixture",
                    "functions": [
                        {
                            "function_id": f"function_{index}",
                            "role": "config_decoder",
                            "api_calls": ["decrypt_config", "parse_config"],
                            "fingerprints": {
                                "semantic_simhash64": simhash,
                                "semantic_sequence_sha256": semantic_sha256,
                                "semantic_token_count": 8,
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    index = build_index(results)

    assert index["schema_version"] == 2
    assert len(index["function_records"]) == 2
    assert index["counts"]["similarity_pairs"] == 1
    pair = index["similarity_pairs"][0]
    assert set(pair) >= {"left_id", "right_id", "similarity", "same_family"}
    assert "left" not in pair
    assert "right" not in pair
    assert {pair["left_id"], pair["right_id"]} == {item["record_id"] for item in index["function_records"]}
    markdown = render_markdown(index)
    assert "function_0" in markdown
    assert "function_1" in markdown


def test_similarity_pairs_are_bounded_and_counts_preserve_total(tmp_path: Path) -> None:
    """近似pairを有界に保持し、省略前の総数を集計へ残す。"""

    results = tmp_path / "analysis-results"
    for index, simhash in enumerate(("0000000000000000", "0000000000000001", "0000000000000002")):
        sha256 = f"{index + 1:064x}"
        case = results / "malware" / "fixture" / "versions" / "unknown" / "cases" / sha256
        case.mkdir(parents=True)
        (case / "static-logic.json").write_text(
            json.dumps(
                {
                    "sha256": sha256,
                    "family": "fixture",
                    "functions": [
                        {
                            "function_id": f"function_{index}",
                            "role": "config_decoder",
                            "api_calls": ["decrypt_config", "parse_config"],
                            "fingerprints": {
                                "semantic_simhash64": simhash,
                                "semantic_sequence_sha256": f"{index + 10:064x}",
                                "semantic_token_count": 8,
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    index = build_index(results, pair_limit=10, per_function_limit=1)

    assert index["counts"]["similarity_pairs_total"] == 3
    assert index["counts"]["similarity_pairs"] == 1
    assert index["counts"]["similarity_pairs_omitted"] == 2
    assert index["counts"]["similarity_pair_limit"] == 10
    assert index["counts"]["similarity_pair_limit_per_function"] == 1
    assert len(index["similarity_pairs"]) == 1
    markdown = render_markdown(index)
    assert "条件に一致した類似候補pair | 3" in markdown
    assert "上限により省略した類似候補pair | 2" in markdown


def test_similarity_candidate_memory_is_bounded_before_ranking(
    tmp_path: Path,
) -> None:
    """endpoint別候補上限により全一致pairをメモリへ保持しない。"""

    results = tmp_path / "analysis-results"
    for index in range(10):
        sha256 = f"{index + 1:064x}"
        case = (
            results
            / "malware"
            / "fixture"
            / "versions"
            / "unknown"
            / "cases"
            / sha256
        )
        case.mkdir(parents=True)
        (case / "static-logic.json").write_text(
            json.dumps(
                {
                    "sha256": sha256,
                    "family": "fixture",
                    "functions": [
                        {
                            "function_id": f"function_{index}",
                            "role": "config_decoder",
                            "api_calls": ["decrypt_config", "parse_config"],
                            "fingerprints": {
                                "semantic_simhash64": f"{index:016x}",
                                "semantic_sequence_sha256": f"{index + 100:064x}",
                                "semantic_token_count": 8,
                            },
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    index = build_index(results, pair_limit=100, per_function_limit=1)

    assert index["counts"]["similarity_pairs_total"] == 45
    assert index["counts"]["similarity_pairs_retained_for_ranking"] <= 10
    assert index["counts"]["similarity_pairs_omitted_before_ranking"] >= 35
    assert index["counts"]["similarity_pair_candidate_limit_per_function"] == 1


def test_large_output_comparison_is_streamed_and_bom_tolerant(
    monkeypatch, tmp_path: Path
) -> None:
    target = tmp_path / "index.json"
    target.write_bytes(b"\xef\xbb\xbf{\r\n  \"ok\": true\r\n}\r\n")
    monkeypatch.setattr(similarity, "TEXT_COMPARE_CHARS", 3)

    assert similarity._text_matches(target, '{\n  "ok": true\n}\n') is True
    assert similarity._text_matches(target, '{\n  "ok": false\n}\n') is False
