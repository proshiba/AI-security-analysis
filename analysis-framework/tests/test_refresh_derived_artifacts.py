"""派生成果物の明示書込み境界と一括更新順序を検証する。"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import pytest


FRAMEWORK = Path(__file__).parents[1]
COMMON = FRAMEWORK / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from analysis_contract import seal_report  # noqa: E402
import correlate_campaigns as campaign_writer  # noqa: E402
from generate_ioc_lists import generate as generate_iocs  # noqa: E402
import refresh_derived_artifacts as refresher  # noqa: E402


def _minimal_ioc_repository(repository: Path) -> Path:
    digest = "a" * 64
    case = (
        repository
        / "analysis-results"
        / "malware"
        / "example"
        / "versions"
        / "unknown"
        / "cases"
        / digest
    )
    case.mkdir(parents=True)
    (case / "README.md").write_text(
        "# テスト\n\n## C2\n\n- `c2.example:443`\n",
        encoding="utf-8",
    )
    (repository / "analysis_history.yaml").write_text(
        "analyses: []\n",
        encoding="utf-8",
    )
    return case


def test_ioc_generator_is_read_only_until_write_is_explicit(tmp_path: Path) -> None:
    """既定dry-runとcheckがIOC成果物を作成しないことを保証する。"""

    case = _minimal_ioc_repository(tmp_path)

    dry_run = generate_iocs(tmp_path)
    assert dry_run["mismatches"]
    assert dry_run["write_performed"] is False
    assert not (case / "IOC-LIST.md").exists()
    assert not (tmp_path / "analysis-results" / "IOC-INDEX.md").exists()

    checked = generate_iocs(tmp_path, check=True)
    assert checked["check_failed"] is True
    assert not (case / "IOC-LIST.md").exists()

    written = generate_iocs(tmp_path, write=True)
    assert written["write_performed"] is True
    assert (case / "IOC-LIST.md").is_file()
    assert generate_iocs(tmp_path, check=True)["check_failed"] is False


def test_ioc_write_rejects_unrelated_artifact_tampering(tmp_path: Path) -> None:
    """IOC更新前に他の追跡成果物を検証し、改変を再封印しない。"""

    case = _minimal_ioc_repository(tmp_path)
    stale = "古いIOC一覧\n"
    other = '{"safe": true}\n'
    (case / "IOC-LIST.md").write_text(stale, encoding="utf-8")
    (case / "analysis.json").write_text(other, encoding="utf-8")
    report = {
        "schema_version": 1,
        "artifact_sha256": {
            "IOC-LIST.md": hashlib.sha256(stale.encode("utf-8")).hexdigest(),
            "analysis.json": hashlib.sha256(other.encode("utf-8")).hexdigest(),
        },
    }
    seal_report(report)
    (case / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (case / "analysis.json").write_text('{"safe": false}\n', encoding="utf-8")

    with pytest.raises(ValueError, match="IOC以外"):
        generate_iocs(tmp_path, write=True)

    assert (case / "IOC-LIST.md").read_text(encoding="utf-8") == stale

def test_campaign_case_labels_require_explicit_scope(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """snapshot書込みだけでは既存caseラベルを変更しない。"""

    digest = "b" * 64
    case = (
        tmp_path
        / "analysis-results"
        / "malware"
        / "example"
        / "versions"
        / "unknown"
        / "cases"
        / digest
    )
    case.mkdir(parents=True)
    output = tmp_path / "analysis-results" / "research" / "campaigns" / "fixture"
    fingerprints = tmp_path / "analysis-framework" / "registry" / "fingerprints.json"
    rules = tmp_path / "analysis-framework" / "registry" / "rules.json"
    report = {
        "counts": {
            "cases": 1,
            "candidate_pairs": 0,
            "accepted_edges": 0,
            "campaign_candidates": 0,
            "labeled_cases": 0,
        },
        "campaigns": [],
        "labels": {},
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "network_contacted": False,
        },
    }
    monkeypatch.setattr(campaign_writer, "load_rules", lambda _path: {})
    monkeypatch.setattr(campaign_writer, "_history_by_sha", lambda _repository: {})
    monkeypatch.setattr(
        campaign_writer,
        "discover_case_directories",
        lambda _root: [case],
    )
    monkeypatch.setattr(
        campaign_writer,
        "build_case_profile",
        lambda _case, _history: {"sha256": digest},
    )
    monkeypatch.setattr(
        campaign_writer,
        "extract_campaign_evidence",
        lambda _case, _profile, _rules: {"sha256": digest},
    )
    monkeypatch.setattr(
        campaign_writer,
        "correlate_cases",
        lambda _evidence, _rules: report,
    )
    monkeypatch.setattr(
        campaign_writer,
        "build_fingerprints",
        lambda _report: {"schema_version": 1, "fingerprints": []},
    )

    snapshot = campaign_writer.generate(
        tmp_path,
        output_root=output,
        rules_path=rules,
        fingerprints_path=fingerprints,
        write=True,
    )
    assert snapshot["case_labels_in_scope"] is False
    assert (output / "campaign-labels.json").is_file()
    assert not (case / "campaign-labels.json").exists()

    scoped = campaign_writer.generate(
        tmp_path,
        output_root=output,
        rules_path=rules,
        fingerprints_path=fingerprints,
        write=True,
        case_labels=True,
    )
    assert scoped["case_labels_in_scope"] is True
    payload = json.loads((case / "campaign-labels.json").read_text(encoding="utf-8"))
    assert payload["status"] == "no_strong_match"

    label_path = case / "campaign-labels.json"
    before = label_path.read_bytes()
    other_path = case / "analysis.json"
    other_path.write_text('{"safe": true}\n', encoding="utf-8")
    sealed = {
        "schema_version": 1,
        "artifact_sha256": {
            "campaign-labels.json": hashlib.sha256(before).hexdigest(),
            "analysis.json": hashlib.sha256(other_path.read_bytes()).hexdigest(),
        },
    }
    seal_report(sealed)
    (case / "report.json").write_text(
        json.dumps(sealed, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    other_path.write_text('{"safe": false}\n', encoding="utf-8")
    report["labels"] = {digest: [{"campaign_id": "changed"}]}

    with pytest.raises(ValueError, match="campaign label以外"):
        campaign_writer.generate(
            tmp_path,
            output_root=output,
            rules_path=rules,
            fingerprints_path=fingerprints,
            write=True,
            case_labels=True,
        )

    assert label_path.read_bytes() == before


def test_refresh_writes_in_dependency_order_and_rechecks(monkeypatch, tmp_path: Path) -> None:
    """campaign、IOC、類似性の順で更新し、同じ順序で再検証する。"""

    calls: list[tuple[str, bool, bool]] = []

    def result(name: str, write: bool, check: bool) -> dict:
        calls.append((name, write, check))
        return {
            "mismatches": ["fixture"] if write else [],
            "write_performed": write,
            "check_failed": False,
        }

    monkeypatch.setattr(
        refresher,
        "generate_campaigns",
        lambda _repository, **kwargs: result(
            "campaigns",
            bool(kwargs.get("write")),
            bool(kwargs.get("check")),
        ),
    )
    monkeypatch.setattr(
        refresher,
        "generate_ioc_lists",
        lambda _repository, **kwargs: result(
            "iocs",
            bool(kwargs.get("write")),
            bool(kwargs.get("check")),
        ),
    )
    monkeypatch.setattr(
        refresher,
        "generate_code_similarity",
        lambda _repository, **kwargs: result(
            "code_similarity",
            bool(kwargs.get("write")),
            bool(kwargs.get("check")),
        ),
    )

    report = refresher.refresh(
        tmp_path,
        campaign_output_root=tmp_path / "campaigns",
        rules_path=tmp_path / "rules.json",
        fingerprints_path=tmp_path / "fingerprints.json",
        similarity_json=tmp_path / "similarity.json",
        similarity_markdown=tmp_path / "similarity.md",
        write=True,
        case_labels=True,
    )

    assert calls == [
        ("campaigns", True, False),
        ("iocs", True, False),
        ("code_similarity", True, False),
        ("campaigns", False, True),
        ("iocs", False, True),
        ("code_similarity", False, True),
    ]
    assert report["mode"] == "write"
    assert report["verification"] is not None
    assert report["check_failed"] is False
    assert report["safety"]["network_contacted"] is False
