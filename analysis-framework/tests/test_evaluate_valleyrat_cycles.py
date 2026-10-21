"""ValleyRAT 20件cycle評価の事前登録、厳格gate、秘匿境界を検証する。"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
COMMON = ROOT / "analysis-framework" / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import evaluate_valleyrat_cycles as cycles


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _identities(prefix: str) -> list[str]:
    return [_digest(f"{prefix}:{index:02d}") for index in range(cycles.COHORT_SIZE)]


def _selection(
    identities: list[str],
    commitment: str | None = None,
    *,
    excluded: list[str] | None = None,
) -> dict[str, object]:
    excluded = excluded or []
    return {
        "identities": tuple(identities),
        "selection_commitment_sha256": commitment or _digest("selection:" + identities[0]),
        "identity_set_sha256": cycles._identity_set_sha256(identities),
        "excluded_hashes": len(excluded),
        "excluded_hashes_sha256": cycles._exclusion_set_sha256(excluded),
    }


def _completed_selection(
    identities: list[str],
    *,
    excluded: list[str] | None = None,
) -> dict[str, object]:
    selection = _selection(identities, excluded=excluded)
    selection["download_contract_verified"] = True
    selection["archive_encryption_and_member_identity_verified"] = True
    selection["manifest_semantic_sha256"] = _digest("completed-manifest:" + identities[0])
    return selection


def _selection_manifest(
    identities: list[str],
    *,
    complete: bool,
    excluded: list[str] | None = None,
) -> dict[str, object]:
    excluded = excluded or []
    metadata = [
        {
            "sha256_hash": digest,
            "signature": cycles.PROVIDER_SIGNATURE,
            "first_seen": f"2026-10-{index + 1:02d} 00:00:00",
        }
        for index, digest in enumerate(identities)
    ]
    selection_fields: dict[str, object] = {
        "schema_version": 1,
        "source": "MalwareBazaar Community API",
        "selection_mode": "signature_newest",
        "signature": cycles.PROVIDER_SIGNATURE,
        "query_limit": 100,
        "selected_at": "2026-10-19T00:00:00+00:00",
        "requested": cycles.COHORT_SIZE,
        "excluded_hashes": len(excluded),
        "excluded_hashes_sha256": cycles._canonical_sha256(sorted(excluded)),
        "selected_hashes": identities,
        "selected_metadata": metadata,
        "max_download_bytes": 64 * 1024 * 1024,
        "max_total_download_bytes": cycles.COHORT_SIZE * 64 * 1024 * 1024,
        "minimum_free_bytes": 1024,
        "archives_remain_encrypted": True,
        "samples_executed": False,
    }
    manifest = {
        **selection_fields,
        "observed_download_bytes": 0 if not complete else cycles.COHORT_SIZE,
        "selection_only": not complete,
        "downloaded": cycles.COHORT_SIZE if complete else 0,
        "pending": 0,
        "complete": complete,
        "retry_queue": [],
        "network_contacted_for_repository_download_only": True,
        "items": (
            [
                {
                    "sha256": digest,
                    "zip_sha256": _digest(f"archive:{digest}"),
                    "zip_size": 1,
                    "member_sha256": digest,
                    "member_size": 1,
                    "encrypted": True,
                    "encryption_verified": True,
                    "encryption_scheme": "winzip-aes-128",
                    "aes_strength_bits": 128,
                    "member_sha256_verified": True,
                }
                for digest in identities
            ]
            if complete
            else []
        ),
    }
    manifest["selection_commitment_sha256"] = cycles.malwarebazaar_batch._signature_selection_commitment(manifest)
    return manifest


def _evidence(
    digest: str,
    *,
    successful: bool,
) -> cycles.strict_holdout._CaseEvidence:
    return cycles.strict_holdout._CaseEvidence(
        digest=digest,
        exact_axes=(),
        logic_fingerprints=frozenset(),
        profile_axes=frozenset(),
        family_confirmed=successful,
        family_failure_reason=None if successful else "family_not_resolved",
        c2_config_confirmed=successful,
        c2_failure_reason=None if successful else "confirmed_config_missing",
        failure_category=None if successful else "family_unresolved",
        operator_expected_family_scope=True,
        exact_sha256_pinned=True,
        source_sha256_pinned=True,
        artifact_commitment_verified=True,
    )


def _corpus_summary(label: str) -> dict[str, object]:
    return {
        "input_commitment": {
            "aggregate_sha256": _digest(f"input:{label}"),
            "private_path": f"C:/private/{label}",
        },
        "counts": {
            "batch_errors": 0,
            "invalid_unique_cases": 0,
            "conflicting_case_sha256": 0,
        },
    }


def _install_evidence(
    monkeypatch: pytest.MonkeyPatch,
    identities: list[str],
    successes: int,
    *,
    label: str,
    include: int = cycles.COHORT_SIZE,
) -> None:
    cases = [_evidence(digest, successful=index < successes) for index, digest in enumerate(identities[:include])]
    monkeypatch.setattr(
        cycles.strict_holdout,
        "_collect_case_evidence",
        lambda _paths: (cases, _corpus_summary(label)),
    )


def _registered_state(identities: list[str]) -> dict[str, object]:
    state, changed = cycles.register_next_holdout(
        None,
        _selection(identities),
        baseline_identities=[],
    )
    assert changed is True
    return state


def _with_holdout_result(
    state: dict[str, object],
    *,
    status: str = "failed",
) -> dict[str, object]:
    """pathに依存せず、extension境界用の既評価stateを構築する。"""

    cycle = state["cycles"][-1]
    observed = cycles.REQUIRED_JOINT_SUCCESSES if status == "passed" else 0
    record = {
        "kind": "holdout",
        "ordinal": 1,
        "counts_for_target_gate": True,
        "input_commitment_sha256": _digest(f"input:{cycle['cycle_number']}:{status}"),
        "evaluation_summary_sha256": _digest(f"summary:{cycle['cycle_number']}:{status}"),
        "observed_joint_successes": observed,
        "input_integrity_clean": True,
        "target_gate_status": status,
    }
    cycle["holdout_run_registration"] = {
        "kind": "legacy_evaluated_holdout",
        "input_commitment_sha256": record["input_commitment_sha256"],
        "evaluation_summary_sha256": record["evaluation_summary_sha256"],
        "migration_commitment_sha256": cycles._canonical_sha256(
            {
                "domain": cycles.CONTRACT_VERSION,
                "kind": "legacy_evaluated_holdout",
                "cycle_number": cycle["cycle_number"],
                "input_commitment_sha256": record["input_commitment_sha256"],
                "evaluation_summary_sha256": record["evaluation_summary_sha256"],
            }
        ),
    }
    cycle["holdout_evaluation"] = record
    return cycles._validated_state(cycles._seal_state(state))


def _started_state(identities: list[str], run: Path) -> dict[str, object]:
    state = _registered_state(identities)
    state, changed = cycles.pre_register_holdout_run(state, [run])
    assert changed is True
    return state


def _state_with_pending_third_cycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[dict[str, object], list[str], list[str], list[str], list[str]]:
    """cycle 2に既存開発記録があり、cycle 3が未評価のstateを作る。"""

    first = _identities("historical-development-first")
    second = _identities("historical-development-second")
    third = _identities("historical-development-third")
    state = _with_holdout_result(_registered_state(first))
    state, changed = cycles.register_next_holdout(
        state,
        _selection(second, excluded=first),
    )
    assert changed is True
    state = _with_holdout_result(state)

    _install_evidence(monkeypatch, second, 5, label="second-development-before-third")
    state, _summary, changed = cycles.evaluate_current_cycle(
        state,
        [tmp_path / "second-development-before-third"],
        evaluation_kind="development_reanalysis",
        completed_selection=_completed_selection(second, excluded=first),
    )
    assert changed is True

    extra = _digest("historical-development-extra-known")
    effective = sorted({*first, *second, extra})
    state, _audit, changed = cycles.extend_exclusions(state, effective)
    assert changed is True
    state, changed = cycles.register_next_holdout(
        state,
        _selection(third, excluded=effective),
    )
    assert changed is True
    return state, first, second, third, effective


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _legacy_from_v2(state: dict[str, object]) -> dict[str, object]:
    """テスト用にschema v2のcycle/evaluationを真正なschema v1 chainへ変換する。"""

    legacy: dict[str, object] = {
        "schema_version": cycles.LEGACY_STATE_SCHEMA_VERSION,
        "contract_version": cycles.CONTRACT_VERSION,
        "visibility": dict(cycles.VISIBILITY),
        "target": dict(cycles.TARGET),
        "cycles": [],
    }
    legacy = cycles._seal_state(legacy)
    for source_cycle in state["cycles"]:
        selection = source_cycle["selection"]
        previous = legacy["state_semantic_sha256"]
        cycle_number = len(legacy["cycles"]) + 1
        legacy_cycle = {
            "cycle_number": cycle_number,
            "selection": {
                "identity_type": "sha256",
                "identity_count": cycles.COHORT_SIZE,
                "identities": list(selection["identities"]),
                "identity_set_sha256": selection["identity_set_sha256"],
                "selection_commitment_sha256": selection["selection_commitment_sha256"],
            },
            "registration": {
                "kind": "new_unused_holdout",
                "counts_for_target_gate": True,
                "previous_state_semantic_sha256": previous,
                "registration_commitment_sha256": cycles._legacy_registration_commitment(
                    cycle_number=cycle_number,
                    selection_commitment_sha256=selection["selection_commitment_sha256"],
                    identity_set_sha256=selection["identity_set_sha256"],
                    previous_state_semantic_sha256=previous,
                ),
            },
            "holdout_evaluation": source_cycle["holdout_evaluation"],
            "development_reanalyses": source_cycle["development_reanalyses"],
        }
        legacy["cycles"].append(legacy_cycle)
        legacy = cycles._seal_state(legacy)
    return legacy


def test_seven_of_twenty_is_the_strict_joint_gate_and_public_output_is_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """7件のfamily+C2同時成功だけが33%要件を満たし、秘密値を公開しない。"""

    identities = _identities("cycle-one")
    run = tmp_path / "private-run"
    state = _started_state(identities, run)
    _install_evidence(monkeypatch, identities, 7, label="private-run-one")

    updated, summary, changed = cycles.evaluate_current_cycle(
        state,
        [run],
        evaluation_kind="holdout",
        completed_selection=_completed_selection(identities),
    )

    assert changed is True
    assert updated["cycles"][0]["holdout_evaluation"]["observed_joint_successes"] == 7
    assert summary["metrics"]["joint_success"] == {
        "numerator": 7,
        "denominator": 20,
        "percentage": 35.0,
        "denominator_basis": "pre_registered_cycle_selection",
    }
    assert summary["target_gate"]["status"] == "passed"
    assert summary["state_transition"]["next_action"] == "stop_target_met"
    rendered = json.dumps(summary, ensure_ascii=False, sort_keys=True)
    assert all(digest not in rendered for digest in identities)
    assert "C:/private" not in rendered
    assert "PRIVATE-RUN" not in rendered
    assert summary["safety"]["network_values_included"] is False
    assert summary["cycle"]["completed_download_manifest_verified"] is True
    assert summary["cycle"]["exact_baseline_exclusion_sealed"] is True
    assert summary["cycle"]["cumulative_exclusion_verified"] is True
    assert summary["cycle"]["holdout_run_path_and_code_commitment_verified"] is True
    assert summary["safety"]["archive_encryption_and_member_identity_verified"] is True
    assert summary["safety"]["provider_archive_encryption_scheme"] == "winzip-aes-128"
    assert summary["safety"]["provider_archive_aes_strength_bits"] == 128


def test_six_of_twenty_fails_and_development_reanalysis_never_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同一20件の改善後再解析は診断できても、holdout gateを上書きしない。"""

    identities = _identities("development")
    initial_run = tmp_path / "initial"
    improved_run = tmp_path / "improved"
    state = _started_state(identities, initial_run)
    _install_evidence(monkeypatch, identities, 6, label="initial")
    state, initial, _changed = cycles.evaluate_current_cycle(
        state,
        [initial_run],
        evaluation_kind="holdout",
        completed_selection=_completed_selection(identities),
    )
    assert initial["target_gate"]["status"] == "failed"

    _install_evidence(monkeypatch, identities, 20, label="improved")
    state, diagnostic, changed = cycles.evaluate_current_cycle(
        state,
        [improved_run],
        evaluation_kind="development_reanalysis",
        completed_selection=_completed_selection(identities),
    )

    assert changed is True
    assert diagnostic["metrics"]["joint_success"]["numerator"] == 20
    assert diagnostic["target_gate"]["diagnostic_threshold_met"] is True
    assert diagnostic["target_gate"]["eligible_evaluation"] is False
    assert diagnostic["target_gate"]["status"] == "not_applicable_development_reanalysis"
    assert state["cycles"][0]["holdout_evaluation"]["observed_joint_successes"] == 6


def test_development_reanalysis_is_appended_to_unique_prior_evaluated_cycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """cycle 3登録後もcycle 2へ追記し、公式commitmentとgateを変更しない。"""

    state, first, second, _third, _effective = _state_with_pending_third_cycle(tmp_path, monkeypatch)
    original_seal = state["state_semantic_sha256"]
    original_extension = copy.deepcopy(state["exclusion_extensions"])
    original_third_registration = copy.deepcopy(state["cycles"][2]["registration"])
    original_holdout_records = [copy.deepcopy(cycle["holdout_evaluation"]) for cycle in state["cycles"]]

    _install_evidence(monkeypatch, second, 9, label="second-development-after-third")
    updated, summary, changed = cycles.evaluate_current_cycle(
        state,
        [tmp_path / "second-development-after-third"],
        evaluation_kind="development_reanalysis",
        completed_selection=_completed_selection(second, excluded=first),
    )

    assert changed is True
    assert summary["cycle"]["cycle_number"] == 2
    assert summary["target_gate"]["eligible_evaluation"] is False
    assert summary["target_gate"]["status"] == "not_applicable_development_reanalysis"
    assert len(updated["cycles"][1]["development_reanalyses"]) == 2
    assert updated["cycles"][1]["development_reanalyses"][1]["ordinal"] == 2
    assert updated["cycles"][1][cycles.DEVELOPMENT_CHAIN_COUNT_FIELD] == 1
    assert updated["cycles"][2]["development_reanalyses"] == []
    assert updated["cycles"][2]["holdout_evaluation"] is None
    assert updated["cycles"][2]["registration"] == original_third_registration
    assert updated["exclusion_extensions"] == original_extension
    assert [cycle["holdout_evaluation"] for cycle in updated["cycles"]] == original_holdout_records
    assert updated["state_semantic_sha256"] != original_seal
    assert cycles._validated_state(updated) == updated
    for invalid_count in (0, 2):
        tampered = copy.deepcopy(updated)
        tampered["cycles"][1][cycles.DEVELOPMENT_CHAIN_COUNT_FIELD] = invalid_count
        tampered = cycles._seal_state(tampered)
        with pytest.raises(cycles.CycleEvaluationError) as invalid_boundary:
            cycles._validated_state(tampered)
        assert invalid_boundary.value.code in {
            "state_development_chain_count_invalid",
            "state_exclusion_extension_commitment_mismatch",
            "state_registration_commitment_mismatch",
        }

    repeated, repeated_summary, repeated_changed = cycles.evaluate_current_cycle(
        updated,
        [tmp_path / "second-development-after-third"],
        evaluation_kind="development_reanalysis",
        completed_selection=_completed_selection(second, excluded=first),
    )
    assert repeated_changed is False
    assert repeated == updated
    assert repeated_summary == summary

    started, started_changed = cycles.pre_register_holdout_run(updated, [tmp_path / "third-holdout-run"])
    assert started_changed is True
    assert started["cycles"][2]["holdout_run_registration"]["kind"] == "first_holdout_run_precommitment"
    assert started["cycles"][2]["registration"] == original_third_registration
    assert cycles._validated_state(started) == started


def test_development_chain_boundary_without_downstream_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """後続commitmentがない最新cycleへ境界fieldを注入できない。"""

    identities = _identities("orphaned-development-boundary")
    state = _with_holdout_result(_registered_state(identities))
    _install_evidence(monkeypatch, identities, 5, label="orphaned-development")
    state, _summary, changed = cycles.evaluate_current_cycle(
        state,
        [tmp_path / "orphaned-development"],
        evaluation_kind="development_reanalysis",
        completed_selection=_completed_selection(identities),
    )
    assert changed is True

    for boundary in (0, len(state["cycles"][0]["development_reanalyses"])):
        tampered = copy.deepcopy(state)
        tampered["cycles"][0][cycles.DEVELOPMENT_CHAIN_COUNT_FIELD] = boundary
        tampered = cycles._seal_state(tampered)
        with pytest.raises(cycles.CycleEvaluationError) as captured:
            cycles._validated_state(tampered)
        assert captured.value.code == "state_development_chain_count_invalid"


def test_revoke_removes_orphaned_boundary_before_replacement_registration(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """取消後の追加診断をreplacement cycleの公式chainへ含める。"""

    first = _identities("revoke-development-first")
    cancelled = _identities("revoke-development-cancelled")
    replacement = _identities("revoke-development-replacement")
    state = _with_holdout_result(_registered_state(first))

    _install_evidence(monkeypatch, first, 3, label="development-before-cancelled-cycle")
    state, _summary, changed = cycles.evaluate_current_cycle(
        state,
        [tmp_path / "development-before-cancelled-cycle"],
        evaluation_kind="development_reanalysis",
        completed_selection=_completed_selection(first),
    )
    assert changed is True
    state, changed = cycles.register_next_holdout(
        state,
        _selection(cancelled, excluded=first),
    )
    assert changed is True

    _install_evidence(monkeypatch, first, 4, label="development-after-cancelled-cycle")
    state, _summary, changed = cycles.evaluate_current_cycle(
        state,
        [tmp_path / "development-after-cancelled-cycle"],
        evaluation_kind="development_reanalysis",
        completed_selection=_completed_selection(first),
    )
    assert changed is True
    assert state["cycles"][0][cycles.DEVELOPMENT_CHAIN_COUNT_FIELD] == 1

    state, _audit = cycles.revoke_latest_unevaluated(state)
    assert cycles.DEVELOPMENT_CHAIN_COUNT_FIELD not in state["cycles"][0]

    _install_evidence(monkeypatch, first, 5, label="development-after-revocation")
    state, _summary, changed = cycles.evaluate_current_cycle(
        state,
        [tmp_path / "development-after-revocation"],
        evaluation_kind="development_reanalysis",
        completed_selection=_completed_selection(first),
    )
    assert changed is True
    assert cycles.DEVELOPMENT_CHAIN_COUNT_FIELD not in state["cycles"][0]

    effective = sorted({*first, *cancelled})
    state, _extension_audit, changed = cycles.extend_exclusions(state, effective)
    assert changed is True
    state, changed = cycles.register_next_holdout(
        state,
        _selection(replacement, excluded=effective),
    )
    assert changed is True
    assert cycles._validated_state(state) == state

    tampered = copy.deepcopy(state)
    tampered["cycles"][0]["development_reanalyses"][-1]["input_commitment_sha256"] = _digest(
        "tampered-after-revocation"
    )
    tampered = cycles._seal_state(tampered)
    with pytest.raises(cycles.CycleEvaluationError) as captured:
        cycles._validated_state(tampered)
    assert captured.value.code == "state_exclusion_extension_commitment_mismatch"


def test_revoke_preserves_boundary_required_by_existing_extension(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """取消後も既存extensionが参照する真正な過去境界は保持する。"""

    state, first, second, _third, _effective = _state_with_pending_third_cycle(tmp_path, monkeypatch)
    _install_evidence(monkeypatch, second, 9, label="development-after-third-registration")
    state, _summary, changed = cycles.evaluate_current_cycle(
        state,
        [tmp_path / "development-after-third-registration"],
        evaluation_kind="development_reanalysis",
        completed_selection=_completed_selection(second, excluded=first),
    )
    assert changed is True
    assert state["cycles"][1][cycles.DEVELOPMENT_CHAIN_COUNT_FIELD] == 1

    state, _audit = cycles.revoke_latest_unevaluated(state)
    assert state["cycles"][1][cycles.DEVELOPMENT_CHAIN_COUNT_FIELD] == 1
    assert cycles._validated_state(state) == state


def test_holdout_evaluation_remains_limited_to_latest_cycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """過去cycleのmanifestをholdoutとして再指定しても最新cycleへ誤適用しない。"""

    state, first, second, _third, _effective = _state_with_pending_third_cycle(tmp_path, monkeypatch)
    with pytest.raises(cycles.CycleEvaluationError) as captured:
        cycles.evaluate_current_cycle(
            state,
            [tmp_path / "past-holdout"],
            evaluation_kind="holdout",
            completed_selection=_completed_selection(second, excluded=first),
        )
    assert captured.value.code == "selection_registration_mismatch"


def test_development_reanalysis_rejects_pending_future_cycle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """事前登録済みでも未評価の将来cycleを開発用評価へ流用しない。"""

    state, _first, _second, third, effective = _state_with_pending_third_cycle(tmp_path, monkeypatch)
    with pytest.raises(cycles.CycleEvaluationError) as captured:
        cycles.evaluate_current_cycle(
            state,
            [tmp_path / "pending-future"],
            evaluation_kind="development_reanalysis",
            completed_selection=_completed_selection(third, excluded=effective),
        )
    assert captured.value.code == "development_before_holdout"


def test_development_reanalysis_requires_exact_registered_identity_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """commitmentだけを流用した別identity集合を一致cycleとして受理しない。"""

    state, first, second, _third, _effective = _state_with_pending_third_cycle(tmp_path, monkeypatch)
    mismatched = _completed_selection(second, excluded=first)
    mismatched["identities"] = tuple(_identities("different-development-identities"))
    with pytest.raises(cycles.CycleEvaluationError) as captured:
        cycles.evaluate_current_cycle(
            state,
            [tmp_path / "identity-mismatch"],
            evaluation_kind="development_reanalysis",
            completed_selection=mismatched,
        )
    assert captured.value.code == "selection_registration_mismatch"


def test_development_reanalysis_rejects_ambiguous_cycle_resolution() -> None:
    """一致候補が複数なら任意のcycleを選ばずfail-closedにする。"""

    identities = _identities("ambiguous-development")
    state = _with_holdout_result(_registered_state(identities))
    duplicate = copy.deepcopy(state["cycles"][0])
    with pytest.raises(cycles.CycleEvaluationError) as captured:
        cycles._resolve_evaluation_cycle(
            {"cycles": [state["cycles"][0], duplicate]},
            evaluation_kind="development_reanalysis",
            completed_selection=_completed_selection(identities),
        )
    assert captured.value.code == "selection_registration_ambiguous"


def test_missing_registered_case_fails_integrity_and_is_accounted_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """選定20件の欠落を成功母数から落とさず、未完了として1件だけ分類する。"""

    identities = _identities("missing")
    run = tmp_path / "incomplete"
    state = _started_state(identities, run)
    _install_evidence(
        monkeypatch,
        identities,
        7,
        label="nineteen-only",
        include=19,
    )

    _updated, summary, _changed = cycles.evaluate_current_cycle(
        state,
        [run],
        evaluation_kind="holdout",
        completed_selection=_completed_selection(identities),
    )

    assert summary["metrics"]["joint_success"]["numerator"] == 7
    assert summary["input"]["matched_sealed_cases"] == 19
    assert summary["input"]["missing_selected_cases"] == 1
    assert summary["input"]["input_integrity_clean"] is False
    assert summary["failure_category_counts"]["analysis_incomplete_or_limit"] == 1
    assert sum(summary["failure_category_counts"].values()) == 13
    assert summary["safety"]["matched_sealed_report_safety_flags_verified"] is True
    assert summary["safety"]["sealed_report_safety_flags_verified"] is False
    assert summary["target_gate"]["status"] == "failed"
    assert "input_integrity_not_clean" in summary["target_gate"]["reason_codes"]


def test_next_cycle_must_be_disjoint_and_five_cycles_is_absolute_maximum(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """失敗後だけ未使用集合を追加でき、重複と6回目を拒否する。"""

    state: dict[str, object] | None = None
    first = _identities("limit-1")
    for cycle_number in range(1, cycles.MAXIMUM_HOLDOUT_CYCLES + 1):
        identities = first if cycle_number == 1 else _identities(f"limit-{cycle_number}")
        excluded = (
            []
            if state is None
            else sorted(digest for cycle in state["cycles"] for digest in cycle["selection"]["identities"])
        )
        state, changed = cycles.register_next_holdout(
            state,
            _selection(identities, excluded=excluded),
            baseline_identities=[] if state is None else None,
        )
        assert changed is True
        run = tmp_path / f"failed-{cycle_number}"
        state, started = cycles.pre_register_holdout_run(state, [run])
        assert started is True
        _install_evidence(
            monkeypatch,
            identities,
            0,
            label=f"failed-{cycle_number}",
        )
        state, summary, _changed = cycles.evaluate_current_cycle(
            state,
            [run],
            evaluation_kind="holdout",
            completed_selection=_completed_selection(identities, excluded=excluded),
        )
        assert summary["target_gate"]["status"] == "failed"
        if cycle_number == 1:
            with pytest.raises(cycles.CycleEvaluationError) as reused:
                cycles.register_next_holdout(
                    state,
                    _selection(first, _digest("different"), excluded=sorted(set(excluded).union(identities))),
                )
            assert reused.value.code == "holdout_identity_in_required_exclusion"

    with pytest.raises(cycles.CycleEvaluationError) as exhausted:
        cycles.register_next_holdout(
            state,
            _selection(
                _identities("limit-6"),
                excluded=sorted(digest for cycle in state["cycles"] for digest in cycle["selection"]["identities"]),
            ),
        )
    assert exhausted.value.code == "maximum_cycles_reached"


def test_development_reanalysis_requires_initial_holdout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """事前登録直後の同一集合再解析を、初回holdoutの代用品にしない。"""

    identities = _identities("premature-development")
    state = _registered_state(identities)
    _install_evidence(monkeypatch, identities, 20, label="premature")
    with pytest.raises(cycles.CycleEvaluationError) as captured:
        cycles.evaluate_current_cycle(
            state,
            [Path("PREMATURE")],
            evaluation_kind="development_reanalysis",
            completed_selection=_completed_selection(identities),
        )
    assert captured.value.code == "development_before_holdout"


def test_evaluation_requires_the_same_completed_download_manifest() -> None:
    """selection-only状態や別集合をsealed成果物の評価へ使用できない。"""

    identities = _identities("completed-selection")
    state = _registered_state(identities)
    with pytest.raises(cycles.CycleEvaluationError) as incomplete:
        cycles.evaluate_current_cycle(
            state,
            [Path("INCOMPLETE-DOWNLOAD")],
            evaluation_kind="holdout",
            completed_selection=_selection(identities),
        )
    assert incomplete.value.code == "completed_selection_not_verified"

    with pytest.raises(cycles.CycleEvaluationError) as different:
        cycles.evaluate_current_cycle(
            state,
            [Path("DIFFERENT-SELECTION")],
            evaluation_kind="holdout",
            completed_selection=_completed_selection(_identities("other-selection")),
        )
    assert different.value.code == "selection_registration_mismatch"


def test_selection_manifest_is_committed_before_analysis_and_reused_for_evaluation(
    tmp_path: Path,
) -> None:
    """selection-onlyと取得完了manifestが同じcommitmentと20件を保持する。"""

    identities = _identities("manifest")
    path = tmp_path / "manifest.json"
    selected = _selection_manifest(identities, complete=False)
    _write_json(path, selected)
    registered = cycles._validated_selection_manifest(path, phase="registration")
    assert registered["identities"] == tuple(identities)

    completed = _selection_manifest(identities, complete=True)
    assert completed["selection_commitment_sha256"] == selected["selection_commitment_sha256"]
    _write_json(path, completed)
    evaluated = cycles._validated_selection_manifest(path, phase="evaluation")
    assert evaluated["identities"] == registered["identities"]
    assert evaluated["selection_commitment_sha256"] == registered["selection_commitment_sha256"]
    assert evaluated["download_contract_verified"] is True
    assert evaluated["archive_encryption_and_member_identity_verified"] is True
    assert registered["download_contract_verified"] is False

    wrong_provider_strength = _selection_manifest(identities, complete=True)
    wrong_provider_strength["items"][0]["encryption_scheme"] = "winzip-aes-256"
    wrong_provider_strength["items"][0]["aes_strength_bits"] = 256
    _write_json(path, wrong_provider_strength)
    with pytest.raises(cycles.CycleEvaluationError) as wrong_encryption:
        cycles._validated_selection_manifest(path, phase="evaluation")
    assert wrong_encryption.value.code == "selection_download_item_integrity_invalid"


def test_selection_manifest_accepts_official_signature_query_depth(
    tmp_path: Path,
) -> None:
    """固定取得20件と独立して、署名検索範囲1,000件を受理する。"""

    identities = _identities("signature-query-depth")
    path = tmp_path / "manifest.json"
    manifest = _selection_manifest(identities, complete=False)
    manifest["query_limit"] = 1000
    manifest["selection_commitment_sha256"] = cycles.malwarebazaar_batch._signature_selection_commitment(manifest)
    _write_json(path, manifest)
    validated = cycles._validated_selection_manifest(path, phase="registration")
    assert validated["identities"] == tuple(identities)

    manifest["query_limit"] = 1001
    manifest["selection_commitment_sha256"] = cycles.malwarebazaar_batch._signature_selection_commitment(manifest)
    _write_json(path, manifest)
    with pytest.raises(cycles.CycleEvaluationError) as too_deep:
        cycles._validated_selection_manifest(path, phase="registration")
    assert too_deep.value.code == "selection_manifest_query_limit_invalid"


def test_register_cli_keeps_sample_identities_out_of_stdout(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLIはprivate stateにだけSHA-256を保存し、標準出力へ反射しない。"""

    identities = _identities("register-cli")
    manifest_path = tmp_path / "manifest.json"
    baseline_path = tmp_path / "baseline.json"
    state_path = tmp_path / "cycles.json"
    _write_json(baseline_path, {"identities": []})
    _write_json(
        manifest_path,
        _selection_manifest(identities, complete=False),
    )

    assert (
        cycles.main(
            [
                "register",
                "--state",
                str(state_path),
                "--selection-manifest",
                str(manifest_path),
                "--baseline-manifest",
                str(baseline_path),
            ]
        )
        == 0
    )
    public = capsys.readouterr().out
    private = state_path.read_text(encoding="utf-8")
    assert all(digest not in public for digest in identities)
    assert all(digest in private for digest in identities)
    assert json.loads(public)["sample_identifiers_included"] is False


def test_selection_commitment_tamper_and_non_twenty_cohort_are_rejected(
    tmp_path: Path,
) -> None:
    """事前登録後のmetadata差替えと20件未満の選定を拒否する。"""

    identities = _identities("tamper")
    path = tmp_path / "manifest.json"
    manifest = _selection_manifest(identities, complete=False)
    manifest["selected_metadata"][0]["signature"] = "swapped"
    _write_json(path, manifest)
    with pytest.raises(cycles.CycleEvaluationError) as tampered:
        cycles._validated_selection_manifest(path, phase="registration")
    assert tampered.value.code == "selection_commitment_mismatch"

    short = _selection_manifest(identities, complete=False)
    short["selected_hashes"] = identities[:-1]
    short["selected_metadata"] = short["selected_metadata"][:-1]
    short["selection_commitment_sha256"] = cycles.malwarebazaar_batch._signature_selection_commitment(short)
    _write_json(path, short)
    with pytest.raises(cycles.CycleEvaluationError) as not_twenty:
        cycles._validated_selection_manifest(path, phase="registration")
    assert not_twenty.value.code == "selection_manifest_identity_set_invalid"

    invalid_quota = _selection_manifest(identities, complete=False)
    invalid_quota["max_total_download_bytes"] = 0
    invalid_quota["selection_commitment_sha256"] = cycles.malwarebazaar_batch._signature_selection_commitment(
        invalid_quota
    )
    _write_json(path, invalid_quota)
    with pytest.raises(cycles.CycleEvaluationError) as quota:
        cycles._validated_selection_manifest(path, phase="registration")
    assert quota.value.code == "selection_manifest_quota_contract_invalid"


def test_private_state_cannot_be_written_inside_repository() -> None:
    """sample SHA-256を持つstateのrepository内保存をfail-closedにする。"""

    path = ROOT / "analysis-results" / "forbidden-cycle-state.json"
    with pytest.raises(cycles.CycleEvaluationError) as captured:
        cycles._validate_private_state_path(path)
    assert captured.value.code == "private_state_inside_repository"

    with pytest.raises(cycles.CycleEvaluationError) as private_input:
        cycles._validate_private_artifact_path(
            ROOT / "analysis-results" / "private-run",
            code="sealed_run_inside_repository",
        )
    assert private_input.value.code == "sealed_run_inside_repository"


def test_holdout_evaluation_is_idempotent_but_cannot_be_overwritten(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """同じ成果物の再実行だけを許可し、別成果物による初回結果改変を拒否する。"""

    identities = _identities("idempotent")
    first_run = tmp_path / "first"
    replacement_run = tmp_path / "replacement"
    state = _started_state(identities, first_run)
    _install_evidence(monkeypatch, identities, 7, label="first")
    state, first, changed = cycles.evaluate_current_cycle(
        state,
        [first_run],
        evaluation_kind="holdout",
        completed_selection=_completed_selection(identities),
    )
    assert changed is True

    state_again, second, changed = cycles.evaluate_current_cycle(
        state,
        [first_run],
        evaluation_kind="holdout",
        completed_selection=_completed_selection(identities),
    )
    assert changed is False and state_again == state and second == first

    changed_manifest = _completed_selection(identities)
    changed_manifest["manifest_semantic_sha256"] = _digest("changed-manifest")
    with pytest.raises(cycles.CycleEvaluationError) as manifest_replacement:
        cycles.evaluate_current_cycle(
            state,
            [first_run],
            evaluation_kind="holdout",
            completed_selection=changed_manifest,
        )
    assert manifest_replacement.value.code == "holdout_already_evaluated"

    _install_evidence(monkeypatch, identities, 8, label="replacement")
    with pytest.raises(cycles.CycleEvaluationError) as replacement:
        cycles.evaluate_current_cycle(
            state,
            [replacement_run],
            evaluation_kind="holdout",
            completed_selection=_completed_selection(identities),
        )
    assert replacement.value.code == "holdout_run_precommitment_mismatch"


def test_resealed_state_cannot_claim_a_gate_inconsistent_with_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """単なるJSON再sealで6/20を合格へ書き換える操作を拒否する。"""

    identities = _identities("semantic-tamper")
    run = tmp_path / "semantic-tamper"
    state = _started_state(identities, run)
    _install_evidence(monkeypatch, identities, 6, label="semantic-tamper")
    state, _summary, _changed = cycles.evaluate_current_cycle(
        state,
        [run],
        evaluation_kind="holdout",
        completed_selection=_completed_selection(identities),
    )
    state["cycles"][0]["holdout_evaluation"]["target_gate_status"] = "passed"
    tampered = cycles._seal_state(state)

    with pytest.raises(cycles.CycleEvaluationError) as captured:
        cycles._validated_state(tampered)
    assert captured.value.code == "state_holdout_gate_semantics_invalid"


def test_sealed_corpus_commitment_is_required(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """入力commitmentが欠落した成果物を固定hashとして受理しない。"""

    identities = _identities("missing-commitment")
    run = tmp_path / "missing-commitment"
    state = _started_state(identities, run)
    cases = [_evidence(digest, successful=True) for digest in identities]
    summary = _corpus_summary("missing-commitment")
    del summary["input_commitment"]
    monkeypatch.setattr(
        cycles.strict_holdout,
        "_collect_case_evidence",
        lambda _paths: (cases, summary),
    )

    with pytest.raises(cycles.CycleEvaluationError) as captured:
        cycles.evaluate_current_cycle(
            state,
            [run],
            evaluation_kind="holdout",
            completed_selection=_completed_selection(identities),
        )
    assert captured.value.code == "sealed_corpus_commitment_invalid"


def test_baseline_and_all_prior_cycles_are_required_in_next_exclusion(tmp_path: Path) -> None:
    """cycle 2はexact baselineとcycle 1選定の和集合を除外し、既知重複を拒否する。"""

    baseline = [_digest("baseline-one"), _digest("baseline-two")]
    first = _identities("cumulative-one")
    state, _changed = cycles.register_next_holdout(
        None,
        _selection(first, excluded=baseline),
        baseline_identities=baseline,
    )
    state, _started = cycles.pre_register_holdout_run(state, [tmp_path / "cumulative-one"])
    holdout = {
        "kind": "holdout",
        "ordinal": 1,
        "counts_for_target_gate": True,
        "input_commitment_sha256": _digest("input-cumulative"),
        "evaluation_summary_sha256": _digest("summary-cumulative"),
        "observed_joint_successes": 0,
        "input_integrity_clean": True,
        "target_gate_status": "failed",
    }
    state["cycles"][0]["holdout_evaluation"] = holdout
    state = cycles._validated_state(cycles._seal_state(state))
    required = sorted(set(baseline).union(first))

    with pytest.raises(cycles.CycleEvaluationError) as omitted:
        cycles.register_next_holdout(
            state,
            _selection(_identities("cumulative-two"), excluded=first),
        )
    assert omitted.value.code == "selection_cumulative_exclusion_mismatch"

    duplicate = [baseline[0], *_identities("cumulative-duplicate")[:19]]
    with pytest.raises(cycles.CycleEvaluationError) as reused:
        cycles.register_next_holdout(
            state,
            _selection(duplicate, excluded=required),
        )
    assert reused.value.code == "holdout_identity_in_required_exclusion"


def test_holdout_run_must_be_precommitted_before_output_exists(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """初回holdoutは未作成pathとcode treeを先に封印し、別runを拒否する。"""

    identities = _identities("run-precommit")
    state = _registered_state(identities)
    with pytest.raises(cycles.CycleEvaluationError) as missing:
        cycles._verify_holdout_run_precommitment(state["cycles"][0], [tmp_path / "run"])
    assert missing.value.code == "holdout_run_not_pre_registered"

    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(cycles.CycleEvaluationError) as late:
        cycles.pre_register_holdout_run(state, [existing])
    assert late.value.code == "holdout_run_path_already_exists"

    planned = tmp_path / "planned"
    state, changed = cycles.pre_register_holdout_run(state, [planned])
    assert changed is True
    cycles._verify_holdout_run_precommitment(state["cycles"][0], [planned])
    with pytest.raises(cycles.CycleEvaluationError) as swapped:
        cycles._verify_holdout_run_precommitment(state["cycles"][0], [tmp_path / "other"])
    assert swapped.value.code == "holdout_run_precommitment_mismatch"
    monkeypatch.setattr(cycles, "_analysis_code_tree_sha256", lambda: _digest("changed-code"))
    with pytest.raises(cycles.CycleEvaluationError) as changed_code:
        cycles._verify_holdout_run_precommitment(state["cycles"][0], [planned])
    assert changed_code.value.code == "holdout_analysis_code_changed"


def test_legacy_cycle_one_migrates_but_baseline_duplicate_cycle_two_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """既評価Cycle 1を保持し、旧stateで見えなかったbaseline重複Cycle 2は受理しない。"""

    baseline = [_digest("legacy-baseline")]
    first = _identities("legacy-cycle-one")
    state, _changed = cycles.register_next_holdout(
        None,
        _selection(first, excluded=baseline),
        baseline_identities=baseline,
    )
    run = tmp_path / "legacy-first"
    state, _started = cycles.pre_register_holdout_run(state, [run])
    _install_evidence(monkeypatch, first, 0, label="legacy-first")
    state, _summary, _changed = cycles.evaluate_current_cycle(
        state,
        [run],
        evaluation_kind="holdout",
        completed_selection=_completed_selection(first, excluded=baseline),
    )
    legacy = _legacy_from_v2(state)
    migrated = cycles.migrate_legacy_state(
        legacy,
        [_selection(first, excluded=baseline)],
        baseline,
    )
    assert migrated["schema_version"] == cycles.STATE_SCHEMA_VERSION
    assert migrated["cycles"][0]["holdout_run_registration"]["kind"] == "legacy_evaluated_holdout"
    assert migrated["cycles"][0]["holdout_evaluation"] == state["cycles"][0]["holdout_evaluation"]

    second = [baseline[0], *_identities("legacy-cycle-two")[:19]]
    previous = legacy["state_semantic_sha256"]
    second_selection = _selection(second, excluded=sorted(set(baseline).union(first)))
    legacy["cycles"].append(
        {
            "cycle_number": 2,
            "selection": {
                "identity_type": "sha256",
                "identity_count": cycles.COHORT_SIZE,
                "identities": sorted(second),
                "identity_set_sha256": second_selection["identity_set_sha256"],
                "selection_commitment_sha256": second_selection["selection_commitment_sha256"],
            },
            "registration": {
                "kind": "new_unused_holdout",
                "counts_for_target_gate": True,
                "previous_state_semantic_sha256": previous,
                "registration_commitment_sha256": cycles._legacy_registration_commitment(
                    cycle_number=2,
                    selection_commitment_sha256=second_selection["selection_commitment_sha256"],
                    identity_set_sha256=second_selection["identity_set_sha256"],
                    previous_state_semantic_sha256=previous,
                ),
            },
            "holdout_evaluation": None,
            "development_reanalyses": [],
        }
    )
    legacy = cycles._seal_state(legacy)
    with pytest.raises(cycles.CycleEvaluationError) as duplicate:
        cycles.migrate_legacy_state(
            legacy,
            [
                _selection(first, excluded=baseline),
                second_selection,
            ],
            baseline,
        )
    assert duplicate.value.code == "holdout_identity_in_required_exclusion"


def test_latest_unevaluated_cycle_can_be_revoked_with_redacted_audit(tmp_path: Path) -> None:
    """最新未評価cycleだけを取消し、state手編集なしでcommitment監査を残す。"""

    identities = _identities("revoke-latest")
    state = _registered_state(identities)
    state, _changed = cycles.pre_register_holdout_run(state, [tmp_path / "revoke-run"])
    updated, audit = cycles.revoke_latest_unevaluated(state)
    assert updated["cycles"] == []
    assert audit["kind"] == "latest_unevaluated_holdout_revocation"
    assert audit["holdout_run_was_pre_registered"] is True
    assert audit["sample_identifiers_included"] is False
    rendered = json.dumps(audit, sort_keys=True)
    assert all(digest not in rendered for digest in identities)
    assert audit["after_state_semantic_sha256"] == updated["state_semantic_sha256"]


def test_cancelled_cycle_can_be_sealed_into_monotonic_extension_before_next_cycle() -> None:
    """取消Cycleの20件を含む全既知集合を追加し、履歴を変えず次選定へ強制する。"""

    baseline = [_digest("epoch-baseline-one"), _digest("epoch-baseline-two")]
    first = _identities("epoch-cycle-one")
    state, _changed = cycles.register_next_holdout(
        None,
        _selection(first, excluded=baseline),
        baseline_identities=baseline,
    )
    state = _with_holdout_result(state)
    cancelled = _identities("epoch-cancelled-cycle-two")
    historical_required = sorted(set(baseline).union(first))
    state, _changed = cycles.register_next_holdout(
        state,
        _selection(cancelled, excluded=historical_required),
    )
    state, revocation = cycles.revoke_latest_unevaluated(state)
    assert revocation["cancelled_cycle_number"] == 2

    newly_known = [_digest(f"epoch-newly-known:{index}") for index in range(7)]
    effective = sorted(set(historical_required).union(cancelled, newly_known))
    state, audit, changed = cycles.extend_exclusions(state, effective)
    assert changed is True
    assert audit["status"] == "extended"
    assert audit["sample_identifiers_included"] is False
    extension = state["exclusion_extensions"][0]
    assert extension["after_cycle_count"] == 1
    assert extension["effective_identities"] == effective
    assert set(cancelled).issubset(extension["added_identities"])
    assert state["cycles"][0]["selection"]["excluded_hashes"] == len(baseline)
    assert state["cycles"][0]["selection"]["exclusion_extension_count"] == 0

    with pytest.raises(cycles.CycleEvaluationError) as omitted:
        cycles.register_next_holdout(
            state,
            _selection(_identities("epoch-omitted"), excluded=effective[:-1]),
        )
    assert omitted.value.code == "selection_cumulative_exclusion_mismatch"

    next_state, registered = cycles.register_next_holdout(
        state,
        _selection(_identities("epoch-valid-next"), excluded=effective),
    )
    assert registered is True
    assert next_state["cycles"][1]["selection"]["exclusion_extension_count"] == 1


def test_exclusion_extension_is_monotonic_idempotent_and_redacted() -> None:
    """集合削除を拒否し、同じfull setはrecordを増やさず監査だけを返す。"""

    identities = _identities("epoch-idempotent")
    state = _with_holdout_result(_registered_state(identities))
    added = [_digest("epoch-extra-one"), _digest("epoch-extra-two")]
    effective = sorted(set(identities).union(added))
    state, audit, changed = cycles.extend_exclusions(state, effective)
    assert changed is True
    assert audit["added_identity_count"] == len(added)

    unchanged, repeated_audit, repeated = cycles.extend_exclusions(state, effective)
    assert repeated is False
    assert unchanged == state
    assert repeated_audit["status"] == "already_current"
    assert repeated_audit["extension_commitment_sha256"] is None
    rendered = json.dumps([audit, repeated_audit], sort_keys=True)
    assert all(identity not in rendered for identity in effective)

    with pytest.raises(cycles.CycleEvaluationError) as removed:
        cycles.extend_exclusions(state, effective[1:])
    assert removed.value.code == "exclusion_extension_not_monotonic"


def test_exclusion_extension_requires_a_closed_failed_cycle() -> None:
    """未評価cycleと合格cycleの後には次cycle用extensionを作成しない。"""

    pending_identities = _identities("epoch-pending")
    pending = _registered_state(pending_identities)
    with pytest.raises(cycles.CycleEvaluationError) as not_evaluated:
        cycles.extend_exclusions(
            pending,
            sorted(set(pending_identities).union({_digest("pending-extra")})),
        )
    assert not_evaluated.value.code == "exclusion_extension_pending_cycle"

    passed_identities = _identities("epoch-passed")
    passed = _with_holdout_result(_registered_state(passed_identities), status="passed")
    with pytest.raises(cycles.CycleEvaluationError) as target_met:
        cycles.extend_exclusions(
            passed,
            sorted(set(passed_identities).union({_digest("passed-extra")})),
        )
    assert target_met.value.code == "exclusion_extension_target_already_met"


def test_extension_chain_tamper_is_rejected() -> None:
    """extensionのidentity集計を再sealしても改変として拒否する。"""

    identities = _identities("epoch-tamper")
    state = _with_holdout_result(_registered_state(identities))
    effective = sorted(set(identities).union({_digest("epoch-tamper-extra")}))
    state, _audit, _changed = cycles.extend_exclusions(state, effective)

    tampered = json.loads(json.dumps(state))
    tampered["exclusion_extensions"][0]["added_identity_count"] += 1
    tampered = cycles._seal_state(tampered)
    with pytest.raises(cycles.CycleEvaluationError) as invalid:
        cycles._validated_state(tampered)
    assert invalid.value.code == "state_exclusion_extension_identity_invalid"


def test_extend_exclusions_cli_writes_redacted_audit_without_state_editing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """CLIはprivate full setをstateへ封印し、stdout/auditへidentityを出さない。"""

    identities = _identities("epoch-cli")
    state = _with_holdout_result(_registered_state(identities))
    extra = _digest("epoch-cli-extra")
    effective = sorted(set(identities).union({extra}))
    state_path = tmp_path / "cycle-state.json"
    manifest_path = tmp_path / "known-identities.json"
    audit_path = tmp_path / "extension-audit.json"
    cycles._write_state(state_path, state)
    _write_json(
        manifest_path,
        {
            "identity_type": "sha256",
            "identity_count": len(effective),
            "identities": effective,
            "excluded_hashes_sha256": cycles._exclusion_set_sha256(effective),
        },
    )

    result = cycles.main(
        [
            "extend-exclusions",
            "--state",
            str(state_path),
            "--exclusion-manifest",
            str(manifest_path),
            "--audit-output",
            str(audit_path),
        ]
    )
    assert result == 0
    stdout = capsys.readouterr().out
    assert "exclusions_extended" in stdout
    assert all(identity not in stdout for identity in effective)
    persisted = cycles.load_state(state_path)
    assert persisted["exclusion_extensions"][0]["effective_identities"] == effective
    audit_text = audit_path.read_text(encoding="utf-8")
    assert all(identity not in audit_text for identity in effective)


def test_extension_input_requires_exact_count_and_digest(tmp_path: Path) -> None:
    """extension CLIへ曖昧なmanifestや改変済みhash-listを渡せない。"""

    identities = sorted([_digest("strict-extension-one"), _digest("strict-extension-two")])
    malformed = tmp_path / "malformed-extension.json"
    _write_json(
        malformed,
        {
            "identity_type": "sha256",
            "identity_count": len(identities) + 1,
            "identities": identities,
            "excluded_hashes_sha256": cycles._exclusion_set_sha256(identities),
        },
    )
    with pytest.raises(cycles.CycleEvaluationError) as invalid:
        cycles._exact_exclusion_hashes_from_files([malformed])
    assert invalid.value.code == "exclusion_manifest_contract_invalid"


def test_legacy_5338_baseline_can_extend_to_6868_before_next_selection() -> None:
    """実運用と同じ件数でmigration、取消20件の追加、次cycle登録を検証する。"""

    baseline = [_digest(f"historical-baseline:{index:04d}") for index in range(5338)]
    first = _identities("historical-cycle-one")
    first_selection = _selection(first, excluded=baseline)
    original, _changed = cycles.register_next_holdout(
        None,
        first_selection,
        baseline_identities=baseline,
    )
    original = _with_holdout_result(original)
    migrated = cycles.migrate_legacy_state(
        _legacy_from_v2(original),
        [first_selection],
        baseline,
    )
    assert migrated["baseline_exclusion"]["identity_count"] == 5338

    cancelled = _identities("historical-cancelled-cycle-two")
    newly_known = [_digest(f"historical-newly-known:{index:04d}") for index in range(1490)]
    effective = sorted(set(baseline).union(first, cancelled, newly_known))
    assert len(effective) == 6868
    migrated, audit, changed = cycles.extend_exclusions(migrated, effective)
    assert changed is True
    assert audit["effective_identity_count"] == 6868
    assert set(cancelled).issubset(migrated["exclusion_extensions"][0]["added_identities"])

    next_state, registered = cycles.register_next_holdout(
        migrated,
        _selection(_identities("historical-valid-cycle-two"), excluded=effective),
    )
    assert registered is True
    assert next_state["cycles"][1]["selection"]["excluded_hashes"] == 6868
