"""挙動・検体特徴の正規化と充足度判定を検証する。"""

from __future__ import annotations

import importlib
import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

feature_generator = importlib.import_module("generate_case_features")
case_features = importlib.import_module("case_features")
build_case_profile = case_features.build_case_profile
render_features_markdown = case_features.render_features_markdown
build_parser = feature_generator.build_parser
generate = feature_generator.generate

SHA256 = "a" * 64


def _case(repository: Path, digest: str = SHA256) -> Path:
    case = repository / "analysis-results" / "malware" / "fixture" / "versions" / "unknown" / "cases" / digest
    case.mkdir(parents=True)
    (case / "metadata.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_id": f"sha256:{digest}",
                "family": "fixture",
                "malware_version": {"status": "unknown", "normalized_key": "unknown"},
            }
        ),
        encoding="utf-8",
    )
    (case / "analysis.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case": {
                    "campaign": "specific_script_chain",
                    "format": "script",
                    "packing_suspected": False,
                    "unpack_status": "recovered",
                    "recovered_artifacts": 1,
                    "static_config_recovered": True,
                    "declarative_status": "ready",
                    "layer_count": 1,
                },
                "c2": {"assessment": "candidate"},
                "config": {
                    "config": {
                        "profile": {"c2_url": "https://c2.example.invalid/gate"}
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    (case / "README.md").write_text(
        """# fixture

## 詳細静的解析

1. JavaScriptがPowerShellを復元し、AES-CBCで内包PEを復号して https://c2.example.invalid/gate を参照します。
2. RunPEで子プロセスへpayloadを配置します。
3. mutexで多重起動を制御し、自動起動とUAC回避を設定します。
4. VirtualProtectで復元領域をRWX化し、間接callで制御を移します。

## 制約

- 外部C2へ接続していないため、通信は未確認です。
""",
        encoding="utf-8",
    )
    (case / "IOC-LIST.md").write_text(
        "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |\n"
        "|---|---|---|---|---|\n",
        encoding="utf-8",
    )
    return case


def test_profile_contains_only_positive_documented_behavior(tmp_path: Path) -> None:
    case = _case(tmp_path)
    profile = build_case_profile(case)
    behavior_ids = {item["id"] for item in profile["behaviors"]}
    feature_ids = {item["id"] for item in profile["sample_characteristics"]}
    assert "execution:powershell" in behavior_ids
    assert "execution:runpe" in behavior_ids
    assert "execution:single_instance_mutex" in behavior_ids
    assert "persistence:auto_start" in behavior_ids
    assert "evasion:uac_bypass" in behavior_ids
    assert "execution:memory_permission_change" in behavior_ids
    assert "execution:indirect_payload_dispatch" in behavior_ids
    assert "crypto:aes" in feature_ids
    assert profile["analysis_assessment"]["status"] == "complete"
    serialized = json.dumps(profile, ensure_ascii=False)
    assert "https://c2.example.invalid/gate" not in serialized
    assert "[URLはIOC-LIST.mdを参照]" in serialized
    rendered = render_features_markdown(profile)
    assert "YARA、Sigma" in rendered
    assert "通信は未確認" not in rendered


def test_profile_records_screenconnect_remote_command_capability(tmp_path: Path) -> None:
    """双用途clientの実コマンド能力を、悪性利用の断定と分離して残す。"""

    case = _case(tmp_path)
    (case / "README.md").write_text(
        """# fixture

## 双用途管理・コマンド実行能力

- 遠隔コマンド実行能力: `RunCommandLineProgram`は実行時のFileName／ArgumentsをProcess.Startへ渡します。
- 固定operator commandは静的に未復元です。

## 制約

- 悪性利用そのものは未確認です。
""",
        encoding="utf-8",
    )

    profile = build_case_profile(case)

    assert "execution:remote_command" in {
        item["id"] for item in profile["behaviors"]
    }
    serialized = json.dumps(profile, ensure_ascii=False)
    assert "固定operator command" not in serialized
    assert "悪性利用そのもの" not in serialized


def test_profile_records_in_memory_processing_behavior(tmp_path: Path) -> None:
    """network機能がない計算programも実挙動を空欄にしない。"""

    case = _case(tmp_path)
    (case / "README.md").write_text(
        """# fixture

## 静的な処理能力の手掛かり

- 固定整数表をGo runtime mapへ集計します。
- 値を並べ替え、consoleへ集計reportを出力します。

## 制約

- 外部通信は行っていません。
""",
        encoding="utf-8",
    )

    profile = build_case_profile(case)
    behavior_ids = {item["id"] for item in profile["behaviors"]}
    assert behavior_ids >= {
        "processing:map_aggregation",
        "processing:sorting",
        "output:console_report",
    }


def test_generator_is_reproducible_and_checkable(tmp_path: Path) -> None:
    case = _case(tmp_path)
    (tmp_path / "analysis_history.yaml").write_text("analyses: []\n", encoding="utf-8")
    first = generate(tmp_path, write=True)
    assert first["case_count"] == 1
    assert (case / "FEATURES.md").is_file()
    assert (case / "features.json").is_file()
    (case / "campaign-labels.json").write_text(
        json.dumps({"schema_version": 1, "labels": []}), encoding="utf-8"
    )
    second = generate(tmp_path, check=True)
    assert second["mismatches"] == []


def test_generator_can_write_and_check_only_selected_cases(tmp_path: Path) -> None:
    """明示したcaseだけを更新し、history相関とcheck範囲を維持する。"""

    selected = _case(tmp_path)
    untouched = _case(tmp_path, "b" * 64)
    analysis = json.loads((selected / "analysis.json").read_text(encoding="utf-8"))
    del analysis["case"]["campaign"]
    (selected / "analysis.json").write_text(json.dumps(analysis), encoding="utf-8")
    (tmp_path / "analysis_history.yaml").write_text(
        f"analyses:\n  - sample_sha256: {SHA256}\n    campaign_type: history_campaign\n",
        encoding="utf-8",
    )
    selector = selected.relative_to(tmp_path)

    written = generate(tmp_path, write=True, case_dirs=[selector])

    assert written["case_count"] == 1
    assert (selected / "FEATURES.md").is_file()
    assert (selected / "features.json").is_file()
    assert not (untouched / "FEATURES.md").exists()
    assert not (untouched / "features.json").exists()
    profile = json.loads((selected / "features.json").read_text(encoding="utf-8"))
    assert profile["campaign_type"] == "history_campaign"
    assert profile["campaign_type_source"] == "analysis_history.yaml"

    (untouched / "features.json").write_text("not generated\n", encoding="utf-8")
    assert generate(tmp_path, check=True, case_dirs=[selector])["mismatches"] == []
    (selected / "FEATURES.md").write_text("stale\n", encoding="utf-8")
    checked = generate(tmp_path, check=True, case_dirs=[selector])
    assert checked["check_failed"] is True
    assert checked["mismatches"] == [
        selected.relative_to(tmp_path).joinpath("FEATURES.md").as_posix()
    ]


def test_case_dir_option_is_repeatable() -> None:
    """CLIでは複数caseを明示でき、省略時は従来の全件指定になる。"""

    first = Path("analysis-results/malware/a/versions/unknown/cases") / ("a" * 64)
    second = Path("analysis-results/malware/b/versions/unknown/cases") / ("b" * 64)
    selected = build_parser().parse_args(
        ["--case-dir", str(first), "--case-dir", str(second), "--check"]
    )
    assert selected.case_dir == [first, second]
    assert build_parser().parse_args([]).case_dir is None


@pytest.mark.parametrize(
    "selector_kind",
    ["absolute", "traversal", "outside_results", "non_sha", "duplicate"],
)
def test_selected_case_rejects_unsafe_paths(
    tmp_path: Path, selector_kind: str
) -> None:
    """repository外・非SHA・重複の明示指定をfail closedにする。"""

    case = _case(tmp_path)
    relative = case.relative_to(tmp_path)
    if selector_kind == "absolute":
        selectors = [case]
    elif selector_kind == "traversal":
        selectors = [Path("analysis-results") / ".." / relative]
    elif selector_kind == "outside_results":
        outside = tmp_path / "other" / SHA256
        outside.mkdir(parents=True)
        (outside / "README.md").write_text("# outside\n", encoding="utf-8")
        selectors = [outside.relative_to(tmp_path)]
    elif selector_kind == "non_sha":
        invalid = case.parent / "not-a-sha256"
        invalid.mkdir()
        (invalid / "README.md").write_text("# invalid\n", encoding="utf-8")
        selectors = [invalid.relative_to(tmp_path)]
    else:
        selectors = [relative, relative]

    with pytest.raises(ValueError):
        generate(tmp_path, check=True, case_dirs=selectors)


def test_selected_case_rejects_reparse_path_component(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """case自身だけでなく祖先のjunction／symlinkも拒否する。"""

    case = _case(tmp_path)
    relative = case.relative_to(tmp_path)
    marked = (tmp_path / "analysis-results" / "malware").resolve()
    original = feature_generator._is_reparse_point
    monkeypatch.setattr(
        feature_generator,
        "_is_reparse_point",
        lambda path: path.resolve() == marked or original(path),
    )

    with pytest.raises(ValueError, match="reparse point"):
        generate(tmp_path, check=True, case_dirs=[relative])


def test_c2_protocol_pending_forces_partial_assessment(tmp_path: Path) -> None:
    """終端復元済みでもC2 protocol待ちならcase全体をcompleteにしない。"""

    case = _case(tmp_path)
    analysis_path = case / "analysis.json"
    analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
    analysis["case"]["declarative_status"] = "c2_protocol_confirmation_pending"
    analysis_path.write_text(json.dumps(analysis), encoding="utf-8")

    assessment = build_case_profile(case)["analysis_assessment"]
    assert assessment["status"] == "partial"
    assert "declarative_analysis_needs_review" in assessment["unresolved"]
    assert any("C2 protocol・live確認" in item for item in assessment["next_actions"])


def test_report_case_state_and_live_c2_gate_force_partial_assessment(
    tmp_path: Path,
) -> None:
    """詳細文書が揃ってもreportの未完了宣言とlive未検証を上書きしない。"""

    case = _case(tmp_path)
    (case / "report.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_state": {
                    "status": "partial",
                    "complete": False,
                    "resumable": True,
                },
                "static_recovery": {
                    "terminal_payload_recovered": True,
                    "c2_endpoints_recovered": 3,
                    "protocol_profile_recovered": True,
                    "live_c2_verified": False,
                },
            }
        ),
        encoding="utf-8",
    )

    assessment = build_case_profile(case)["analysis_assessment"]
    assert assessment["status"] == "partial"
    assert "declared_case_state_incomplete" in assessment["unresolved"]
    assert "live_c2_unverified" in assessment["unresolved"]
    assert any("完全一致protocol profile" in item for item in assessment["next_actions"])


def test_live_only_partial_reports_only_live_c2_unverified(tmp_path: Path) -> None:
    """終端解析が完了し、live確認だけが残るcaseへ重複理由を追加しない。"""

    case = _case(tmp_path)
    (case / "report.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "case_state": {
                    "status": "partial",
                    "complete": False,
                    "resumable": True,
                    "blockers": ["live_c2_unverified"],
                },
                "static_recovery": {
                    "terminal_payload_recovered": True,
                    "c2_endpoints_recovered": 1,
                    "protocol_profile_recovered": True,
                    "live_c2_verified": False,
                },
            }
        ),
        encoding="utf-8",
    )

    assessment = build_case_profile(case)["analysis_assessment"]
    assert assessment["status"] == "partial"
    assert assessment["unresolved"] == ["live_c2_unverified"]
    assert not any(
        "report.case_state" in item for item in assessment["next_actions"]
    )


def test_complete_report_does_not_reduce_complete_assessment(tmp_path: Path) -> None:
    """reportが明示的に完了なら従来の内容ベース完了判定を維持する。"""

    case = _case(tmp_path)
    (case / "report.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_state": {
                    "status": "complete",
                    "complete": True,
                    "resumable": True,
                },
            }
        ),
        encoding="utf-8",
    )

    assessment = build_case_profile(case)["analysis_assessment"]
    assert assessment["status"] == "complete"
    assert "declared_case_state_incomplete" not in assessment["unresolved"]


def test_false_runtime_line_is_not_positive_evidence(tmp_path: Path) -> None:
    """READMEの`.NET: false`を.NET観測済みへ誤変換しない。"""
    case = _case(tmp_path)
    (case / "README.md").write_text(
        "# fixture\n\n## 概要\n\n- 形式: `PE`\n- .NET: `False`\n",
        encoding="utf-8",
    )
    profile = build_case_profile(case)
    feature_ids = {item["id"] for item in profile["sample_characteristics"]}
    assert "format:pe" in feature_ids
    assert "runtime:dotnet" not in feature_ids

def test_import_capability_heading_produces_conservative_behavior(tmp_path: Path) -> None:
    """import由来能力を実行断定せず標準挙動材料へ残す。"""
    case = _case(tmp_path)
    (case / "README.md").write_text(
        "# fixture\n\n## 静的な処理能力の手掛かり\n\n"
        "- `process_creation`: プロセス起動APIのimportを確認。importだけでは実行経路を確定しません。\n"
        "- `network_access`: ネットワーク接続・取得APIのimportを確認。importだけでは実行経路を確定しません。\n",
        encoding="utf-8",
    )
    profile = build_case_profile(case)
    behavior_ids = {item["id"] for item in profile["behaviors"]}
    assert "execution:process_creation" in behavior_ids
    assert "network:api_access" in behavior_ids
