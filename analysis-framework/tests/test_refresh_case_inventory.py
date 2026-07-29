"""全case一括反映の文書件数とchecksum同期を検証する。"""

from __future__ import annotations

from pathlib import Path
import sys

COMMON = Path(__file__).resolve().parents[1] / "common"
sys.path.insert(0, str(COMMON))

import refresh_case_inventory as inventory  # noqa: E402


def _counts() -> dict[str, int]:
    return {
        "unique_case_hashes": 12,
        "malware_cases": 9,
        "unclassified_cases": 2,
        "supply_chain_payload_cases": 1,
        "confirmed_malware_versions": 3,
        "reported_malware_versions": 1,
        "unknown_malware_versions": 5,
    }


def test_sync_documented_case_counts_updates_both_readmes(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "現在は未分類検体を含む1件のSHA-256 caseを扱い、解析します。\n",
        encoding="utf-8",
    )
    results = tmp_path / "analysis-results"
    results.mkdir()
    (results / "README.md").write_text(
        """# 成果物

## 現在の収録状況

| 区分 | 件数 |
|---|---:|
| SHA-256で一意な全case | 1 |
| 未分類 | 1 |

版名は根拠がある場合だけ使用します。
未分類1件は既知ファミリへ無理に帰属させていません。
""",
        encoding="utf-8",
    )

    result = inventory.sync_documented_case_counts(tmp_path, _counts(), write=True)

    assert result["write_performed"] is True
    assert "含む12件のSHA-256 case" in (tmp_path / "README.md").read_text(encoding="utf-8")
    rendered = (results / "README.md").read_text(encoding="utf-8")
    assert "| SHA-256で一意な全case | 12 |" in rendered
    assert "| 未分類case | 2 |" in rendered
    assert "未分類2件は" in rendered
    assert inventory.sync_documented_case_counts(tmp_path, _counts())["mismatches"] == []


def test_sync_checksum_manifests_detects_and_repairs_stale_file(tmp_path: Path) -> None:
    case = tmp_path / "analysis-results" / "case"
    case.mkdir(parents=True)
    (case / "report.json").write_text("{}\n", encoding="utf-8")
    manifest = case / "manifest.sha256"
    manifest.write_text("stale\n", encoding="utf-8")

    dry_run = inventory.sync_checksum_manifests(tmp_path)
    assert dry_run["mismatches"] == ["analysis-results/case/manifest.sha256"]
    inventory.sync_checksum_manifests(tmp_path, write=True)
    assert inventory.sync_checksum_manifests(tmp_path)["mismatches"] == []
    assert "report.json" in manifest.read_text(encoding="utf-8")