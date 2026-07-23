"""関数ロジック成果物とコード類似性fingerprintを検証する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys


COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

from backfill_static_logic import generate as generate_static_logic_backfill  # noqa: E402
from generate_code_similarity_index import build_index  # noqa: E402
from record_static_logic import generate as generate_static_logic_artifacts  # noqa: E402
from static_logic import (  # noqa: E402
    build_static_logic_report,
    normalize_logic_text,
    render_static_logic_markdown,
    simhash_similarity,
)


SHA_A = "a" * 64
SHA_B = "b" * 64


def _reviewed_record(pseudocode: str, address: str) -> dict:
    return {
        "name": f"FUN_{address}",
        "address": f"0x{address}",
        "role": "config_decoder",
        "summary_ja": "設定blobを復号して項目を返します。",
        "logic_steps_ja": [
            "入力長を確認します。",
            "復号関数を呼び出します。",
            "復元した設定を返します。",
        ],
        "pseudocode": pseudocode,
        "callees": ["decrypt_config"],
        "api_calls": ["CryptDecrypt"],
        "source": "ghidra-mcp",
        "tool": "ghidra-mcp",
        "program_selector": f"sha256:{SHA_A}",
        "confidence": "confirmed_static_decompilation",
    }


def test_normalization_ignores_addresses_literals_and_local_names() -> None:
    left = 'FUN_00401000(local_10) { if (local_10 == 0x1234) return decrypt_config("one"); }'
    right = 'FUN_00902000(local_20) { if (local_20 == 9876) return decrypt_config("two"); }'
    assert normalize_logic_text(left) == normalize_logic_text(right)
    left_report = build_static_logic_report(
        sha256=SHA_A,
        family="fixture",
        source_name="review.json",
        records=[_reviewed_record(left, "00401000")],
    )
    right_report = build_static_logic_report(
        sha256=SHA_B,
        family="fixture",
        source_name="review.json",
        records=[_reviewed_record(right, "00902000")],
    )
    left_fp = left_report["functions"][0]["fingerprints"]
    right_fp = right_report["functions"][0]["fingerprints"]
    assert left_fp["normalized_logic_sha256"] == right_fp["normalized_logic_sha256"]
    assert simhash_similarity(left_fp["semantic_simhash64"], right_fp["semantic_simhash64"]) == 1.0


def test_public_record_retains_all_sanitized_static_analysis_fields() -> None:
    """公開結果は無害化しつつ件数・本文長の上限で静的解析内容を捨てない。"""

    record = _reviewed_record(
        " ".join(f"if (value == {index}) call_{index}(value);" for index in range(600)),
        "00401000",
    )
    record["logic_steps_ja"] = [f"処理段階{index}を確認します。" for index in range(300)]
    record["callers"] = [f"caller_{index}" for index in range(300)]
    record["callees"] = [f"callee_{index}" for index in range(300)]
    record["api_calls"] = [f"ApiCall{index}" for index in range(300)]
    record["constants"] = [f"constant_{index}" for index in range(100)]

    report = build_static_logic_report(
        sha256=SHA_A,
        family="fixture",
        source_name="review.json",
        records=[record],
    )
    function = report["functions"][0]

    assert len(function["logic_steps_ja"]) == 300
    assert len(function["callers"]) == 300
    assert len(function["callees"]) == 300
    assert len(function["api_calls"]) >= 300
    assert len(function["constants"]) == 100
    assert len(function["normalized_logic"]) > 4000


def test_script_logic_is_recorded_without_raw_literals() -> None:
    script = b"""function decodeConfig(value) {
      if (value) { return fetch("https://c2.example.invalid/gate") ^ 0x41; }
    }
    """
    report = build_static_logic_report(
        sha256=SHA_A,
        family="fixture",
        source_name="fixture.js",
        data=script,
    )
    assert report["status"] == "automated_script_structure"
    assert report["coverage"]["function_count"] == 1
    assert report["coverage"]["call_edge_count"] == 0
    serialized = json.dumps(report, ensure_ascii=False)
    assert "c2.example.invalid" not in serialized
    assert report["functions"][0]["raw_pseudocode_exported"] is False
    assert "静的ロジック解析" in render_static_logic_markdown(report)


def test_reviewed_call_graph_resolves_names_and_callers() -> None:
    report = build_static_logic_report(
        sha256="c" * 64,
        family="example",
        source_name="review.json",
        records=[
            {
                "name": "entry",
                "address": "00401000",
                "callees": ["decode_config"],
                "pseudocode": "decode_config(buffer);",
            },
            {
                "name": "decode_config",
                "address": "00402000",
                "callers": ["00401000"],
                "pseudocode": "return transform(buffer);",
            },
        ],
    )

    assert report["status"] == "function_logic_review_required"
    assert report["coverage"]["function_bodies_reviewed"] is False
    assert report["call_edges"] == [
        {
            "caller": "entry@00401000",
            "callee": "decode_config@00402000",
        }
    ]


def test_japanese_review_steps_without_pseudocode_have_similarity_tokens() -> None:
    record = {
        "name": "DecodeConfig",
        "address": "401000",
        "role": "config_decoder",
        "summary_ja": "設定を復号して接続先を検証します。",
        "logic_steps_ja": [
            "入力長を確認します。",
            "復号関数を呼び出します。",
            "接続先とポートを検証します。",
        ],
        "callees": ["DecryptBuffer"],
        "api_calls": ["CryptDecrypt"],
        "source": "静的レビュー",
        "tool": "ghidra-mcp",
        "program_selector": f"sha256:{SHA_A}",
        "confidence": "confirmed_static_review",
    }
    left = build_static_logic_report(
        sha256=SHA_A,
        family="fixture",
        source_name="review.json",
        records=[record],
    )
    right = build_static_logic_report(
        sha256=SHA_B,
        family="fixture",
        source_name="review.json",
        records=[record],
    )

    left_fp = left["functions"][0]["fingerprints"]
    right_fp = right["functions"][0]["fingerprints"]
    assert left_fp["semantic_token_count"] >= 4
    assert left_fp["semantic_sequence_sha256"] == right_fp["semantic_sequence_sha256"]
    assert left_fp["semantic_simhash64"] == right_fp["semantic_simhash64"]
    assert "呼出関係" in render_static_logic_markdown(left)


def test_record_static_logic_writes_and_checks_case_artifacts(tmp_path: Path) -> None:
    case = tmp_path / "analysis-results" / "malware" / "fixture" / "versions" / "unknown" / "cases" / SHA_A
    case.mkdir(parents=True)
    (case / "README.md").write_text("# 検体解析\n", encoding="utf-8")
    source = tmp_path / ".work" / "reviewed-functions.json"
    source.parent.mkdir()
    source.write_text(
        json.dumps({"functions": [_reviewed_record("return decode(value);", "401000")]}),
        encoding="utf-8",
    )

    written = generate_static_logic_artifacts(tmp_path, case, source, write=True)
    checked = generate_static_logic_artifacts(tmp_path, case, source, check=True)
    report = json.loads((case / "static-logic.json").read_text(encoding="utf-8"))

    assert written["write_performed"] is True
    assert checked["check_failed"] is False
    assert report["status"] == "reviewed_function_logic"
    assert (case / "STATIC-LOGIC.md").read_text(encoding="utf-8").startswith("# 静的ロジック解析")


def test_similarity_index_correlates_distinct_cases(tmp_path: Path) -> None:
    results = tmp_path / "analysis-results"
    left = build_static_logic_report(
        sha256=SHA_A,
        family="fixture",
        source_name="review.json",
        records=[
            _reviewed_record(
                'FUN_00401000(local_10) { return decrypt_config("one"); }',
                "00401000",
            )
        ],
    )
    right = build_static_logic_report(
        sha256=SHA_B,
        family="fixture",
        source_name="review.json",
        records=[
            _reviewed_record(
                'FUN_00902000(local_20) { return decrypt_config("two"); }',
                "00902000",
            )
        ],
    )
    for report, selector, address in (
        (left, "left.exe", "00401000"),
        (right, "right.exe", "00902000"),
    ):
        report["program_evidence"] = [
            {
                "program_selector": selector,
                "relationship": "primary_program",
                "function_hashes": [
                    {
                        "name": "decode_config",
                        "address": address,
                        "hash": "c" * 64,
                        "instruction_count": 12,
                    }
                ],
            }
        ]
    for sha256, report in ((SHA_A, left), (SHA_B, right)):
        case = results / "malware" / "fixture" / "versions" / "unknown" / "cases" / sha256
        case.mkdir(parents=True)
        (case / "static-logic.json").write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
    index = build_index(results)
    assert index["counts"]["functions"] == 2
    assert index["counts"]["exact_groups"] == 1
    assert index["counts"]["simhash_groups"] == 1
    assert index["counts"]["similarity_pairs"] == 0
    assert index["counts"]["ghidra_function_hashes"] == 2
    assert index["counts"]["ghidra_exact_groups"] == 1


def test_processing_units_and_ghidra_hashes_do_not_complete_function_review() -> None:
    report = build_static_logic_report(
        sha256=SHA_A,
        family="fixture",
        source_name="README.md",
        processing_units=[
            {
                "unit_id": "loader_flow",
                "role": "loader_flow",
                "summary_ja": "既存レポートから復元した処理です。",
                "logic_steps_ja": ["resourceを確認します。", "子payloadを復元します。"],
                "source_artifacts": ["README.md"],
            }
        ],
        program_evidence=[
            {
                "program_selector": "fixture.exe",
                "name": "fixture.exe",
                "language": "x86:LE:32:default",
                "function_count": 1,
                "entry_points": [{"name": "entry", "address": "00401000", "kind": "Function"}],
                "function_hashes": [
                    {
                        "name": "entry",
                        "address": "00401000",
                        "hash": "c" * 64,
                        "instruction_count": 12,
                    },
                    {
                        "name": "empty_stub",
                        "address": "00401020",
                        "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                        "instruction_count": 0,
                    },
                ],
            }
        ],
    )

    assert report["status"] == "function_analysis_required"
    assert report["coverage"]["processing_unit_count"] == 1
    assert report["coverage"]["ghidra_function_hash_count"] == 1
    assert report["processing_units"][0]["code_similarity_eligible"] is False
    markdown = render_static_logic_markdown(report)
    assert "既存成果物から補完した処理単位" in markdown
    assert "fixture.exe" in markdown
    assert "### 上限付き関数hash" in markdown
    assert "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" in markdown


def test_backfill_static_logic_uses_only_sanitized_repository_evidence(
    tmp_path: Path,
) -> None:
    case = tmp_path / "analysis-results" / "malware" / "fixture" / "versions" / "unknown" / "cases" / SHA_A
    case.mkdir(parents=True)
    (case / "README.md").write_text(
        "# fixture\n\n## 静的解析\n\n"
        "- resourceを確認し、https://example.invalid/gateへ渡す設定を復元する。\n"
        "- 192.0.2.10を接続候補として保持する。\n\n"
        "## 制約\n\n- 関数境界は未確認。\n",
        encoding="utf-8",
    )
    (case / "metadata.json").write_text(json.dumps({"family": "fixture"}), encoding="utf-8")
    (case / "analysis.json").write_text(
        json.dumps(
            {"format": "pe", "pe": {"classification": "not_packed"}},
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (case / "config.json").write_text(
        json.dumps({"features": {"persistence": True}, "c2_url": "secret"}),
        encoding="utf-8",
    )
    inventory = tmp_path / "ghidra.json"
    inventory.write_text(
        json.dumps(
            {
                "cases": {
                    SHA_A: [
                        {
                            "program_selector": "fixture.exe",
                            "name": "fixture.exe",
                            "function_count": 1,
                            "function_hashes": [{"hash": "d" * 64}],
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    written = generate_static_logic_backfill(tmp_path, write=True, ghidra_inventory=inventory)
    checked = generate_static_logic_backfill(tmp_path, check=True, ghidra_inventory=inventory)
    report_text = (case / "static-logic.json").read_text(encoding="utf-8")
    report = json.loads(report_text)

    assert written["backfilled"] == 1
    assert checked["check_failed"] is False
    assert report["status"] == "function_analysis_required"
    assert report["processing_units"]
    assert "example.invalid" not in report_text
    assert "192.0.2.10" not in report_text
    assert "c2_url" not in json.dumps(report["processing_units"], ensure_ascii=False)


def test_markdown_escapes_embedded_control_characters() -> None:
    """抽出値の制御文字を人向けMarkdownへ生のまま出力しない。"""

    report = build_static_logic_report(
        sha256=SHA_A,
        family="fixture",
        source_name="analysis.json",
        processing_units=[
            {
                "unit_id": "section_summary",
                "role": "static_structure",
                "summary_ja": "静的構造を整理します。",
                "logic_steps_ja": ["高entropy sectionは \x00 と pcxsfzhs です。"],
                "source_artifacts": ["analysis.json"],
            }
        ],
    )

    markdown = render_static_logic_markdown(report)

    assert "\x00" not in markdown
    assert "\\u0000" in markdown
