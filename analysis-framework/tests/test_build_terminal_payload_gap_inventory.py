"""終端ペイロード未取得台帳の統合判定と決定性を検証する。"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
sys.path.insert(0, str(COMMON))

import build_terminal_payload_gap_inventory as gaps


def _sha(character: str) -> str:
    return character * 64


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _case_path(root: Path, family: str, sha256: str) -> Path:
    return (
        root
        / "analysis-results"
        / "malware"
        / family
        / "versions"
        / "unknown"
        / "cases"
        / sha256
    )


def _fixture_repository(root: Path) -> dict[str, str]:
    hashes = {name: _sha(value) for name, value in zip("abcdefgx", "12345678")}
    families = {
        "a": "alpha",
        "b": "beta",
        "c": "gamma",
        "d": "delta",
        "e": "epsilon",
        "f": "zeta",
        "g": "eta",
    }
    catalog = {}
    for name, family in families.items():
        sha256 = hashes[name]
        canonical = _case_path(root, family, sha256).relative_to(root).as_posix()
        catalog[sha256] = {
            "case_id": f"sha256:{sha256}",
            "canonical_path": canonical,
            "case_kind": "malware",
            "family": family,
            "version_key": "unknown",
        }
        _case_path(root, family, sha256).mkdir(parents=True, exist_ok=True)
    _write_json(
        root / "analysis-results" / "catalog" / "cases.json",
        {"schema_version": 1, "cases": catalog},
    )
    inventory = root / "analysis-framework" / "inventories" / "static-hard-cases.yaml"
    inventory.parent.mkdir(parents=True, exist_ok=True)
    inventory.write_text(
        f"""schema_version: 1
cases:
  - sha256: {hashes['a']}
    family: alpha
    category: protected
    priority: P1
    blockers: [terminal_layer_not_recovered]
    expected_children: [{hashes['x']}]
groups:
  - id: beta_group
    family: beta
    category: encrypted
    priority: P0
    blockers: [payload_decoder_not_recovered]
    hashes: [{hashes['b']}]
excluded_cases:
  reason: terminal bytes absent
  hashes: [{hashes['c']}]
""",
        encoding="utf-8",
    )
    _write_json(
        _case_path(root, "delta", hashes["d"]) / "report.json",
        {
            "classification": {"terminal_family_confirmed": False},
            "case_state": {
                "status": "partial",
                "complete": False,
                "blockers": ["terminal_managed_resource_unresolved"],
            },
        },
    )
    epsilon = _case_path(root, "epsilon", hashes["e"])
    (epsilon / "README.md").write_text(
        "# 解析\n\n最終payloadは保護層のため未取得です。\n", encoding="utf-8"
    )
    _write_json(
        epsilon / "metadata.json",
        {"source": {"first_seen": "2026-08-01 12:34:56"}},
    )
    zeta = _case_path(root, "zeta", hashes["f"])
    (zeta / "FEATURES.md").write_text(
        "- terminal payload not recovered\n", encoding="utf-8"
    )
    _write_json(
        zeta / "report.json",
        {
            "classification": {"terminal_family_confirmed": True},
            "case_state": {"status": "complete", "complete": True, "blockers": []},
        },
    )
    eta = _case_path(root, "eta", hashes["g"])
    (eta / "README.md").write_text(
        "確認したIPはペイロード配布先です。最終C2は未回収です。\n",
        encoding="utf-8",
    )
    (eta / "generic-triage.json").write_text(
        '"packed_or_protected_inner_payload_not_recovered"\n', encoding="utf-8"
    )
    return hashes


def test_build_inventory_merges_reviewed_report_and_document_sources(
    tmp_path: Path,
) -> None:
    hashes = _fixture_repository(tmp_path)

    inventory = gaps.build_inventory(tmp_path)
    cases = {item["sha256"]: item for item in inventory["cases"]}

    assert set(cases) == {hashes[name] for name in "abcde"}
    assert hashes["x"] not in cases
    assert cases[hashes["a"]]["state"] == "curated_recovery_backlog"
    assert cases[hashes["b"]]["priority"] == "P0"
    assert cases[hashes["c"]]["state"] == "source_material_absent"
    assert cases[hashes["d"]]["state"] == "explicit_unrecovered"
    assert cases[hashes["e"]]["observation_date"] == "2026-08-01"
    assert inventory["scope"]["gap_case_count"] == 5
    assert inventory["scope"]["structured_terminal_completion_count"] == 1


def test_terminal_completion_is_independent_from_c2_case_completion(
    tmp_path: Path,
) -> None:
    """partial caseでも明示的terminal復元を認め、family未確認はfail closedにする。"""

    _fixture_repository(tmp_path)
    catalog_path = tmp_path / "analysis-results" / "catalog" / "cases.json"
    catalog_document = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog = catalog_document["cases"]
    scenarios = {
        "a": {"terminal": True, "manual": True, "c2": False},
        "b": {"terminal": True, "manual": False, "c2": True},
        "c": {"terminal": None, "manual": True, "c2": True},
        "d": {"terminal": False, "manual": True, "c2": True},
    }
    scenario_hashes: dict[str, str] = {}
    for marker, scenario in scenarios.items():
        digest = _sha(marker)
        scenario_hashes[marker] = digest
        family = f"scenario-{marker}"
        case_dir = _case_path(tmp_path, family, digest)
        case_dir.mkdir(parents=True)
        canonical = case_dir.relative_to(tmp_path).as_posix()
        catalog[digest] = {
            "case_id": f"sha256:{digest}",
            "canonical_path": canonical,
            "case_kind": "malware",
            "family": family,
            "version_key": "unknown",
        }
        classification = {}
        if scenario["terminal"] is not None:
            classification["terminal_family_confirmed"] = scenario["terminal"]
        report = {
            "classification": classification,
            "case_state": {
                "status": "partial",
                "complete": False,
                "blockers": ["c2_protocol_confirmation_pending"],
            },
        }
        if scenario["manual"]:
            report["manual_deep_analysis"] = {"terminal_payload_gap": "closed"}
        _write_json(case_dir / "report.json", report)
        if scenario["c2"]:
            _write_json(
                case_dir / "c2-analysis.json",
                {
                    "terminal_payload": {
                        "reached": True,
                        "status": "recovered",
                    }
                },
            )

    resolved = gaps._structured_terminal_completions(tmp_path, catalog)

    assert scenario_hashes["a"] in resolved
    assert scenario_hashes["b"] in resolved
    assert scenario_hashes["c"] not in resolved
    assert scenario_hashes["d"] not in resolved


def test_document_match_requires_same_sentence_payload_gap() -> None:
    assert gaps._line_is_explicit_gap("最終payloadは未取得です。")
    assert gaps._line_is_explicit_gap("未復元保護層または別payloadを一般化しない。")
    assert not gaps._line_is_explicit_gap(
        "確認したIPはペイロード配布先です。最終C2は未回収です。"
    )
    assert not gaps._line_is_explicit_gap("最終payloadは未復元ではなく、復元済みです。")


def test_render_and_sync_are_deterministic(tmp_path: Path) -> None:
    _fixture_repository(tmp_path)
    output = Path("intelligence/terminal-payload-recovery")

    first = gaps.sync_outputs(tmp_path, output)
    assert len(first["mismatches"]) == 4
    written = gaps.sync_outputs(tmp_path, output, write=True)
    assert written["write_performed"] is True
    assert gaps.sync_outputs(tmp_path, output)["mismatches"] == []

    readme = (tmp_path / output / "README.md").read_text(encoding="utf-8")
    csv_text = (tmp_path / output / "inventory.csv").read_text(encoding="utf-8")
    assert "終端ペイロード未取得ケース" in readme
    assert "ファミリー" in csv_text


def test_invalid_curated_hash_fails_closed(tmp_path: Path) -> None:
    _fixture_repository(tmp_path)
    inventory = tmp_path / "analysis-framework" / "inventories" / "static-hard-cases.yaml"
    inventory.write_text(
        "cases:\n  - sha256: invalid\n    family: alpha\n    priority: P0\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="SHA-256が不正"):
        gaps.build_inventory(tmp_path)
