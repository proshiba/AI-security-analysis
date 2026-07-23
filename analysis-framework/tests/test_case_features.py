"""挙動・検体特徴の正規化と充足度判定を検証する。"""

from __future__ import annotations

import json
from pathlib import Path
import sys


COMMON = Path(__file__).parents[1] / "common"
sys.path.insert(0, str(COMMON))

from case_features import build_case_profile, render_features_markdown  # noqa: E402
from generate_case_features import generate  # noqa: E402


SHA256 = "a" * 64


def _case(repository: Path) -> Path:
    case = repository / "analysis-results" / "malware" / "fixture" / "versions" / "unknown" / "cases" / SHA256
    case.mkdir(parents=True)
    (case / "metadata.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "case_id": f"sha256:{SHA256}",
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
