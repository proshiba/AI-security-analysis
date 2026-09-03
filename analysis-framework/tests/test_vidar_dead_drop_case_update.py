from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

REPOSITORY = Path(__file__).parents[2]
VIDAR = Path(__file__).parents[1] / "malware" / "vidar"
COMMON = Path(__file__).parents[1] / "common"
for path in (VIDAR, COMMON):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import dead_drop_case_update as updater  # noqa: E402
from analysis_contract import case_integrity_errors  # noqa: E402

SAMPLE = "0030c014ec4fae311492a87011f565f9ff3b1881137dda152953c6fe718e33e0"
SOURCE_CASE = (
    REPOSITORY
    / "analysis-results"
    / "malware"
    / "vidar"
    / "versions"
    / "unknown"
    / "cases"
    / SAMPLE
)
COLLECTION = "malwarebazaar-windows-20260902-0050"


@pytest.fixture
def short_tmp_path() -> Path:
    """Windows legacy path上限内でcanonical case layoutを組み立てる。"""

    parent = Path.home() / ".vidar-updater-tests"
    parent.mkdir(exist_ok=True)
    path = Path(tempfile.mkdtemp(prefix="v-", dir=parent))
    try:
        yield path
    finally:
        resolved = path.resolve()
        if resolved.parent == parent.resolve() and resolved.name.startswith("v-"):
            shutil.rmtree(resolved)


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _base_correlation() -> dict:
    return {
        "schema_version": 1,
        "profile": updater.CORRELATION_PROFILE,
        "sample_sha256": SAMPLE,
        "status": "inconclusive_snapshot_set",
        "final_c2_candidate": None,
        "final_c2_candidate_recovered": False,
        "c2_confirmed": False,
        "probable_c2": False,
        "confidence": 0.0,
        "corroborating_service_count": 0,
        "uncorroborated_final_c2_candidates": [
            {
                "endpoint": "single-source.example",
                "service_count": 1,
                "status": "tag_bound_decoded_requires_second_service",
            }
        ],
        "endpoint_resolution": {
            "method": None,
            "shared_service_response_decoded": False,
            "protocol_recovered": False,
            "protocol_status": "unresolved_static_protocol",
        },
        "decoder": {
            "profile": updater.VIDAR_DEAD_DROP_DECODER_PROFILE,
            "key_sha256": updater.VIDAR_DEAD_DROP_DECODER_KEY_SHA256,
            "config_tag_binding_required": True,
            "minimum_corroborating_services": 2,
            "raw_key_published": False,
            "raw_ciphertext_published": False,
        },
        "observations": [
            {
                "service": "telegram",
                "captured_at": "2026-09-02T20:29:44Z",
                "body_size": 128,
                "body_sha256": "1" * 64,
                "candidate_count": 0,
                "encoded_marker_count": 1,
                "tag_bound_marker_count": 1,
                "decoded_candidate_count": 1,
                "decoded_ciphertext_sha256": "2" * 64,
            }
        ],
        "snapshot_provenance": {
            "capture_mode": "bounded_opt_in_network_capture",
            "network_contacted_during_capture": True,
            "receipt_validation": "internally_verified_private_capture_receipt",
            "external_authenticity_established": False,
        },
        "safety": {
            "network_contacted": False,
            "sample_executed": False,
            "tool_published_raw_response": False,
            "tool_managed_output_repository_publication": False,
            "shared_service_is_c2": False,
            "active_probe_required": False,
        },
    }


def _correlated() -> dict:
    value = _base_correlation()
    value.update(
        {
            "status": "decoded_correlated_final_c2_candidate",
            "final_c2_candidate": "correlated.example:443",
            "final_c2_candidate_recovered": True,
            "probable_c2": True,
            "confidence": 0.95,
            "corroborating_service_count": 2,
            "uncorroborated_final_c2_candidates": [],
        }
    )
    value["endpoint_resolution"].update(
        {
            "method": "tag_bound_enc_decoder_two_service_correlation",
            "shared_service_response_decoded": True,
        }
    )
    value["observations"].append(
        {
            "service": "epic_games",
            "captured_at": "2026-09-02T20:29:45Z",
            "body_size": 96,
            "body_sha256": "3" * 64,
            "candidate_count": 0,
            "encoded_marker_count": 1,
            "tag_bound_marker_count": 1,
            "decoded_candidate_count": 1,
            "decoded_ciphertext_sha256": "2" * 64,
        }
    )
    return value


def _repository_fixture(tmp_path: Path, correlation: dict) -> tuple[Path, Path, Path]:
    repository = tmp_path / "repository"
    case = (
        repository
        / "analysis-results"
        / "malware"
        / "vidar"
        / "versions"
        / "unknown"
        / "cases"
        / SAMPLE
    )
    shutil.copytree(SOURCE_CASE, case)
    metadata_path = case / "metadata.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["collections"] = [COLLECTION]
    _write_json(metadata_path, metadata)

    # C2 validatorは自動化pathがrepository内の通常fileとして存在することも確認する。
    c2 = json.loads((case / "c2-analysis.json").read_text(encoding="utf-8"))
    automation_paths = set((c2.get("automation") or {}).get("handlers") or [])
    automation_paths.update((c2.get("automation") or {}).get("tests") or [])
    automation_paths.update(
        {
            "analysis-framework/malware/vidar/dead_drop_capture.py",
            "analysis-framework/malware/vidar/dead_drop_snapshot.py",
            "analysis-framework/malware/vidar/dead_drop_case_update.py",
            "analysis-framework/tests/test_vidar_dead_drop_capture.py",
            "analysis-framework/tests/test_vidar_dead_drop_case_update.py",
        }
    )
    for relative in automation_paths:
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("# test fixture\n", encoding="utf-8")

    case_record = {
        "attribution_basis": "one_shot_static_detector",
        "c2_analysis_complete": False,
        "c2_analysis_finding_count": 9,
        "c2_analysis_outcome": "unresolved",
        "case_path": updater._expected_case_relative(SAMPLE),
        "case_state": "partial",
        "confirmed_static_c2_observations": 0,
        "confirmed_static_management_observations": 0,
        "confirmed_static_network_observations": 0,
        "family": "vidar",
        "handler_failures": 0,
        "handler_successes": 1,
        "publication_stage": "partial_followup_required",
        "sha256": SAMPLE,
        "static_config_recovered": True,
    }
    collection = repository / "analysis-results" / "collections" / COLLECTION
    _write_json(
        collection / "manifest.json",
        {
            "schema_version": 1,
            "collection_id": COLLECTION,
            "cases": [{"case_id": f"sha256:{SAMPLE}"}],
            "analysis_complete": False,
            "complete": False,
            "publication_stage": "partial_followup_required",
            "case_state_counts": {"partial": 1},
            "case_blocker_counts": {"orchestration:network": 1},
        },
    )
    _write_json(
        collection / "publication-summary.json",
        {
            "schema_version": 1,
            "cases": [case_record],
            "samples_executed": False,
            "network_contacted": False,
            "analysis_complete": False,
            "publication_stage": "partial_followup_required",
            "case_state_counts": {"partial": 1},
            "case_blocker_counts": {"orchestration:network": 1},
        },
    )
    source_record = dict(case_record)
    source_record.pop("case_state")
    source_record["publication_stage"] = "analysis_followup_pending"
    _write_json(
        collection / "sources" / "vidar" / "summary.json",
        {
            "schema_version": 1,
            "family": "vidar",
            "count": 1,
            "cases": [source_record],
            "sample_executed": False,
            "network_contacted": False,
        },
    )
    _write_json(
        repository / "analysis-results" / "catalog" / "cases.json",
        {
            "schema_version": 1,
            "cases": {
                SAMPLE: {
                    "canonical_path": updater._expected_case_relative(SAMPLE),
                    "case_id": f"sha256:{SAMPLE}",
                    "case_kind": "malware",
                    "family": "vidar",
                    "version_key": "unknown",
                }
            },
        },
    )
    relative = case.relative_to(repository / "analysis-results").as_posix()
    (repository / "analysis-results" / "IOC-INDEX.md").write_text(
        "\n".join(
            [
                "# IOC 一覧索引",
                "",
                "| 解析 (Analysis) | IOC 一覧 | 件数 (Entries) |",
                "|---|---|---:|",
                f"| `{relative}` | [IOC-LIST.md]({relative}/IOC-LIST.md) | 1 |",
                "",
            ]
        ),
        encoding="utf-8",
    )
    correlation_path = tmp_path / "correlation.json"
    _write_json(correlation_path, correlation)
    return repository, case, correlation_path


def _assert_integrity(case: Path) -> dict:
    report = json.loads((case / "report.json").read_text(encoding="utf-8"))
    assert case_integrity_errors(
        case,
        report,
        expected_digest=SAMPLE,
        require_resumable=False,
    ) == []
    return report


def test_single_source_apply_is_successful_partial_and_resealed(short_tmp_path: Path) -> None:
    repository, case, correlation = _repository_fixture(short_tmp_path, _base_correlation())

    result = updater.apply_case_evidence(
        case,
        correlation,
        epic_http_status=403,
        repository=repository,
    )

    assert result["status"] == "single_service_unresolved"
    assert result["protocol_recovered"] is False
    assert result["decoded_endpoint_contacted"] is False
    report = _assert_integrity(case)
    for relative in (
        "README.md",
        "IOC-LIST.md",
        updater.PUBLIC_CORRELATION_NAME,
        updater.PUBLIC_REPORT_NAME,
    ):
        assert relative in report["artifact_sha256"]
    orchestration = json.loads((case / "orchestration.json").read_text(encoding="utf-8"))
    assert orchestration["status"] == "partial"
    assert "network" in orchestration["blockers"]
    assert orchestration["automation"]["decoded_endpoint_contacted"] is False
    c2 = json.loads((case / "c2-analysis.json").read_text(encoding="utf-8"))
    assert c2["c2"]["outcome"] == "unresolved"
    assert c2["c2"]["protocol"]["status"] == "unresolved"
    assert c2["c2"]["endpoints"][0]["role"] == "decoded_final_c2_candidate_unconfirmed"
    assert c2["c2"]["endpoints"][0]["contacted"] is False
    assert "single-source.example" not in (case / "IOC-LIST.md").read_text(encoding="utf-8")
    public = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (case / updater.PUBLIC_CORRELATION_NAME, case / updater.PUBLIC_REPORT_NAME)
    )
    assert "ENC:00" not in public
    assert "hash_id=" not in public
    assert updater._transaction_directory(case).exists() is False


def test_two_source_apply_keeps_protocol_and_case_partial(short_tmp_path: Path) -> None:
    repository, case, correlation = _repository_fixture(short_tmp_path, _correlated())

    result = updater.apply_case_evidence(case, correlation, repository=repository)

    assert result["status"] == "two_service_candidate_protocol_unresolved"
    _assert_integrity(case)
    orchestration = json.loads((case / "orchestration.json").read_text(encoding="utf-8"))
    assert orchestration["status"] == "partial"
    assert orchestration["quality_gates"]["network"]["satisfied"] is False
    assert "network" in orchestration["blockers"]
    c2 = json.loads((case / "c2-analysis.json").read_text(encoding="utf-8"))
    assert c2["c2"]["outcome"] == "unresolved"
    assert c2["c2"]["protocol"]["status"] == "unresolved"
    assert c2["c2"]["endpoints"] == [
        {
            "value": "correlated.example:443",
            "role": "probable_final_c2_candidate",
            "source": updater.CORRELATION_PROFILE,
            "confidence": "two_shared_service_tag_and_cipher_correlation",
            "contacted": False,
        }
    ]


def test_validator_rejects_extra_raw_field_and_mismatched_two_source_cipher() -> None:
    raw = _base_correlation()
    raw["raw_response"] = "ENC:deadbeef"
    with pytest.raises(updater.VidarDeadDropCaseUpdateError):
        updater.validate_public_correlation(raw, SAMPLE)

    mismatch = _correlated()
    mismatch["observations"][1]["decoded_ciphertext_sha256"] = "4" * 64
    with pytest.raises(updater.VidarDeadDropCaseUpdateError, match="相関service/method"):
        updater.validate_public_correlation(mismatch, SAMPLE)


def test_output_hardlink_is_rejected(short_tmp_path: Path) -> None:
    repository, case, correlation = _repository_fixture(short_tmp_path, _base_correlation())
    readme = case / "README.md"
    other = case / "README-hardlink.md"
    os.link(readme, other)
    try:
        with pytest.raises(updater.VidarDeadDropCaseUpdateError, match="単一link"):
            updater.apply_case_evidence(case, correlation, repository=repository)
    finally:
        other.unlink()


def test_interrupted_commit_is_rolled_back_on_next_run(
    short_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, case, correlation = _repository_fixture(short_tmp_path, _base_correlation())
    original_commit = updater._commit_transaction

    def interrupt_after_one_changed_file(prepared, _verify_callback):
        for entry in prepared.journal["entries"]:
            target = prepared.repository / entry["target"]
            original = prepared.originals[target]
            planned = updater._read_transaction_blob(prepared.directory, entry, "planned")
            if original.data != planned:
                updater._atomic_replace_bytes(
                    target,
                    planned,
                    original,
                    temporary_path=prepared.repository / entry["temporary"],
                )
                raise SystemExit("simulated process interruption")
        raise AssertionError("changed transaction entryがありません")

    with monkeypatch.context() as scoped:
        scoped.setattr(updater, "_commit_transaction", interrupt_after_one_changed_file)
        with pytest.raises(SystemExit, match="simulated process interruption"):
            updater.apply_case_evidence(case, correlation, repository=repository)

    assert updater._transaction_directory(case).is_dir()
    result = updater.apply_case_evidence(case, correlation, repository=repository)
    assert result["recovered_interrupted_transaction"] == "rolled_back_prepared"
    assert updater._transaction_directory(case).exists() is False
    _assert_integrity(case)
    assert updater._commit_transaction is original_commit


def test_cli_returns_zero_for_valid_single_source_partial(short_tmp_path: Path) -> None:
    repository, case, correlation = _repository_fixture(short_tmp_path, _base_correlation())
    assert (
        updater.main(
            [
                "--repository",
                str(repository),
                "--case-directory",
                str(case),
                "--correlation",
                str(correlation),
                "--epic-http-status",
                "403",
            ]
        )
        == 0
    )


def test_verified_two_source_commit_rolls_forward_after_interruption(
    short_tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository, case, correlation = _repository_fixture(short_tmp_path, _correlated())

    def interrupt_after_verified_marker(prepared, verify_callback):
        for entry in prepared.journal["entries"]:
            target = prepared.repository / entry["target"]
            updater._atomic_replace_bytes(
                target,
                updater._read_transaction_blob(prepared.directory, entry, "planned"),
                prepared.originals[target],
                temporary_path=prepared.repository / entry["temporary"],
            )
        verify_callback()
        updater._set_transaction_verified(prepared)
        raise SystemExit("simulated exit after verified marker")

    with monkeypatch.context() as scoped:
        scoped.setattr(updater, "_commit_transaction", interrupt_after_verified_marker)
        with pytest.raises(SystemExit, match="verified marker"):
            updater.apply_case_evidence(case, correlation, repository=repository)

    assert updater._transaction_directory(case).is_dir()
    result = updater.apply_case_evidence(case, correlation, repository=repository)
    assert result["recovered_interrupted_transaction"] == "rolled_forward_verified"
    assert result["status"] == "two_service_candidate_protocol_unresolved"
    assert updater._transaction_directory(case).exists() is False
    _assert_integrity(case)
