"""コード類似性索引の同一fingerprint group化を確認する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys


COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

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
