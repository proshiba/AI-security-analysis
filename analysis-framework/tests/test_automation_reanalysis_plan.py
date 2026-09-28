"""読取専用再解析plannerのidentity・drift・修復分離・有界計画を合成metadataで検証する。"""

from __future__ import annotations

import copy
from collections import Counter
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import automation_failure_inventory as audit
import automation_reanalysis_plan as planner
import c2_analysis_contract

# pytestのimportlib modeでも、固定された同一directoryの合成fixtureだけを読み込む。
# bare sibling importや同名module探索へ依存せず、test directoryの追加も要求しない。
_fixture_spec = importlib.util.spec_from_file_location(
    "_daily_automation_failure_inventory_fixtures_v1",
    Path(__file__).with_name("test_automation_failure_inventory.py"),
)
assert _fixture_spec is not None and _fixture_spec.loader is not None
_fixture_module = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(_fixture_module)
_fixture, _update_report, _write = (
    _fixture_module._fixture, _fixture_module._update_report, _fixture_module._write
)


def _inputs(root: Path):
    case = _fixture(root)
    digest = "a" * 64
    c2 = c2_analysis_contract.build_unresolved_contract(digest, "fixture")
    artifact = _write(case / "c2-analysis.json", c2)
    _update_report(case, lambda report: report["artifact_sha256"].update({"c2-analysis.json": artifact}))
    value = audit._inventory(root)
    catalog = json.loads((root / "analysis-results/catalog/cases.json").read_text(encoding="utf-8"))
    return case, value, catalog


def _commit(value):
    value["inventory_sha256"] = audit._hash({k: v for k, v in value.items() if k != "inventory_sha256"})
    return value


def _plan(value, catalog, current=None, **kwargs):
    return planner.build_plan(value, current or value, catalog, catalog_sha256=value["catalog_sha256"], **kwargs)


def _scale_inputs(tmp_path: Path, count: int, repairs: int = 0):
    # 実検体・metadata fileを増やさず、公開schemaの合成recordだけをmemory上に構成する。
    _case, value, _catalog = _inputs(tmp_path)
    template = value["cases"][0]
    records, identities = [], {}
    for index in range(count):
        digest = f"{index:064x}"
        row = copy.deepcopy(template)
        row["sha256"] = digest
        row["fingerprints"]["input"] = digest
        if index < repairs:
            row.update(record_valid=False, metadata_findings=["report_missing"], blockers=[],
                improvement_actions=[], recorded_case_state="unknown", c2_recorded_outcome="unknown",
                c2_metadata_contract_complete=False, url_role_counts={})
            row["config"] = {"status": "unknown", "required": None,
                "recorded_confirmed": False, "candidate_recorded": False}
            row["fingerprints"] = dict.fromkeys(planner.FINGERPRINTS)
        records.append(row)
        identities[digest] = {"case_id": "sha256:" + digest, "case_kind": "malware", "family": "fixture",
            "version_key": "unknown", "attribution_status": "resolved",
            "canonical_path": f"analysis-results/malware/fixture/versions/unknown/cases/{digest}"}
    catalog = {"schema_version": 1, "cases": identities}
    value.update(cases=records, catalog_sha256=audit._hash(catalog), coverage=audit._rates(records),
        recorded_case_state_counts=dict(Counter(row["recorded_case_state"] for row in records)),
        metadata_finding_case_counts=dict(Counter(code for row in records for code in row["metadata_findings"])),
        blocker_case_counts=dict(Counter(code for row in records for code in row["blockers"])),
        improvement_priorities=[{"action_id": action, "affected_cases": amount} for action, amount in
            sorted(Counter(action for row in records for action in row["improvement_actions"]).items(),
                key=lambda pair: (-pair[1], pair[0]))],
        family_coverage={"fixture": audit._rates(records)},
        change_decision_counts=dict(Counter(row["change_decision"] for row in records)),
        url_role_counts=dict(sum((Counter(row["url_role_counts"]) for row in records), Counter())))
    return _commit(value), catalog


def test_valid_static_candidate_is_review_only_and_privacy_safe(tmp_path: Path) -> None:
    _case, value, catalog = _inputs(tmp_path)
    result = _plan(value, catalog)
    assert result["candidate_count"] == 1 and result["repair_record_count"] == 0
    candidate = result["job_candidates"][0]
    assert candidate["minimum_next_action"] == "configuration_and_c2_static_recovery"
    assert candidate["decision"] == "successor_review_required"
    assert candidate["same_workflow_resume_allowed"] is False
    assert candidate["automatic_retry_allowed"] is False
    assert candidate["human_review_required"] is True
    text = json.dumps(result)
    assert "SECRET" not in text and "secret.example" not in text
    assert "canonical_path" not in text and "sample_path" not in text
    assert result["plan_sha256"] == audit._hash({k: v for k, v in result.items() if k != "plan_sha256"})


def test_metadata_missing_goes_to_repair_not_extraction(tmp_path: Path) -> None:
    case, _value, catalog = _inputs(tmp_path)
    (case / "report.json").unlink()
    value = audit._inventory(tmp_path)
    result = _plan(value, catalog)
    assert result["candidate_count"] == 0
    repair = result["metadata_repairs"][0]
    assert repair["analysis_job_candidate"] is False
    assert "record_invalid_or_legacy" in repair["reason_codes"]


def test_unknown_blocker_is_manual_repair(tmp_path: Path) -> None:
    case, _value, catalog = _inputs(tmp_path)
    _update_report(case, lambda report: report["case_state"].update(blockers=["unknown_secret_blocker"]))
    value = audit._inventory(tmp_path)
    result = _plan(value, catalog)
    assert result["candidate_count"] == 0
    assert "unregistered_blocker_review_required" in result["metadata_repairs"][0]["reason_codes"]
    assert "unknown_secret_blocker" not in json.dumps(result)


@pytest.mark.parametrize("dimension", ["input", "evidence", "implementation_contract"])
def test_snapshot_drift_fails_closed_even_with_valid_self_hash(tmp_path: Path, dimension: str) -> None:
    _case, value, catalog = _inputs(tmp_path)
    changed = copy.deepcopy(value)
    changed["cases"][0]["fingerprints"][dimension] = "e" * 64
    _commit(changed)
    with pytest.raises(planner.ReanalysisPlanError, match="inventory_evidence_drift"):
        _plan(changed, catalog, current=value)


def test_recorded_implementation_change_never_enables_old_contract_resume(tmp_path: Path) -> None:
    _case, value, catalog = _inputs(tmp_path)
    changed = copy.deepcopy(value)
    changed["cases"][0]["change_decision"] = "successor_review_required"
    changed["cases"][0]["changed_dimensions"] = ["implementation_contract"]
    _commit(changed)
    result = _plan(changed, catalog, current=value)
    assert result["job_candidates"][0]["same_workflow_resume_allowed"] is False
    assert result["job_candidates"][0]["decision"] == "successor_review_required"


@pytest.mark.parametrize("mutation,code", [
    (lambda v: v.update(schema_version=True), "inventory_schema_invalid"),
    (lambda v: v.update(automatic_dispatch_allowed=True), "inventory_safety_invalid"),
    (lambda v: v.update(raw_payload="SECRET"), "inventory_schema_invalid"),
    (lambda v: v["cases"][0].update(record_valid=1), "inventory_case_safety_invalid"),
    (lambda v: v["cases"].append(copy.deepcopy(v["cases"][0])), "inventory_duplicate_case"),
])
def test_invalid_schema_and_unsafe_flags_are_fixed_errors(tmp_path: Path, mutation, code: str) -> None:
    _case, value, catalog = _inputs(tmp_path)
    mutation(value)
    _commit(value)
    with pytest.raises(planner.ReanalysisPlanError, match=code):
        _plan(value, catalog)


def test_bad_self_hash_is_rejected(tmp_path: Path) -> None:
    _case, value, catalog = _inputs(tmp_path)
    value["inventory_sha256"] = "e" * 64
    with pytest.raises(planner.ReanalysisPlanError, match="inventory_commitment_invalid"):
        _plan(value, catalog)


@pytest.mark.parametrize("part", ["case_id", "canonical_path", "family"])
def test_catalog_identity_cannot_be_substituted(tmp_path: Path, part: str) -> None:
    _case, value, catalog = _inputs(tmp_path)
    next(iter(catalog["cases"].values()))[part] = "../../SECRET"
    with pytest.raises(planner.ReanalysisPlanError, match="catalog_identity_invalid"):
        _plan(value, catalog)


def test_catalog_commitment_mismatch_is_rejected(tmp_path: Path) -> None:
    _case, value, catalog = _inputs(tmp_path)
    with pytest.raises(planner.ReanalysisPlanError, match="catalog_commitment_mismatch"):
        planner.build_plan(value, value, catalog, catalog_sha256="e" * 64)


def test_forged_action_cannot_replace_registry_policy(tmp_path: Path) -> None:
    _case, value, catalog = _inputs(tmp_path)
    value["cases"][0]["improvement_actions"] = ["execute_arbitrary_command"]
    _commit(value)
    with pytest.raises(planner.ReanalysisPlanError, match="remediation_registry_projection_mismatch"):
        _plan(value, catalog)


@pytest.mark.parametrize("kwargs", [{"max_candidates": 0}, {"max_candidates": True},
    {"max_candidates": 65}, {"max_repairs": 129}, {"max_repairs": 1.0}])
def test_plan_bounds_are_exact_and_hard(tmp_path: Path, kwargs: dict) -> None:
    _case, value, catalog = _inputs(tmp_path)
    with pytest.raises(planner.ReanalysisPlanError, match="plan_limits_invalid"):
        _plan(value, catalog, **kwargs)


def test_top_summary_cannot_lie_about_current_evidence(tmp_path: Path) -> None:
    _case, value, catalog = _inputs(tmp_path)
    forged = copy.deepcopy(value)
    forged["coverage"]["record_valid_cases"] = 999
    _commit(forged)
    with pytest.raises(planner.ReanalysisPlanError, match="inventory_summary_drift"):
        _plan(forged, catalog, current=value)


def test_isolated_help_and_cli_synthetic_roundtrip(tmp_path: Path) -> None:
    _case, value, _catalog = _inputs(tmp_path)
    source = tmp_path / "inventory.json"
    _write(source, value)
    command = [sys.executable, "-I", "-B", str(COMMON / "automation_reanalysis_plan.py")]
    help_result = subprocess.run(command + ["--help"], capture_output=True, timeout=30, check=False)
    assert help_result.returncode == 0
    result = subprocess.run(command + ["--repository", str(tmp_path), "--inventory", str(source)],
        capture_output=True, timeout=30, check=False)
    assert result.returncode == 0
    output = json.loads(result.stdout)
    assert output["candidate_count"] == 1 and output["job_execution_attempted"] is False


def test_cli_errors_do_not_echo_source_values(tmp_path: Path) -> None:
    _case, value, _catalog = _inputs(tmp_path)
    value["token"] = "UNPUBLISHABLE-SECRET"
    source = tmp_path / "invalid.json"
    _write(source, value)
    result = subprocess.run([sys.executable, "-I", "-B", str(COMMON / "automation_reanalysis_plan.py"),
        "--inventory", str(source), "--repository", str(tmp_path)], capture_output=True, timeout=30, check=False)
    assert result.returncode == 2
    assert b"UNPUBLISHABLE-SECRET" not in result.stderr
    assert json.loads(result.stderr)["error"] == "inventory_schema_invalid"


def test_bounded_candidate_output_retains_omission_commitment(tmp_path: Path) -> None:
    _case, value, catalog = _inputs(tmp_path)
    digest = "b" * 64
    second = copy.deepcopy(value["cases"][0])
    second["sha256"] = digest
    second["fingerprints"]["input"] = "c" * 64
    value["cases"].append(second)
    identity = copy.deepcopy(next(iter(catalog["cases"].values())))
    identity["case_id"] = "sha256:" + digest
    identity["canonical_path"] = identity["canonical_path"].rsplit("/", 1)[0] + "/" + digest
    catalog["cases"][digest] = identity
    value["catalog_sha256"] = audit._hash(catalog)
    value["coverage"] = audit._rates(value["cases"])
    _commit(value)
    result = _plan(value, catalog, max_candidates=1)
    assert result["candidate_count"] == 2
    assert len(result["job_candidates"]) == 1
    assert result["omissions"]["candidate_count"] == 1
    assert audit.SHA.fullmatch(result["omissions"]["candidate_sha256"])
    assert result["automatic_dispatch_allowed"] is False
    assert result == _plan(value, catalog, max_candidates=1)


@pytest.mark.parametrize("value,code", [(float("nan"), "input_nonfinite_number"),
    (float("inf"), "input_nonfinite_number"), (1 << 200, "input_integer_limit"),
    ("\ud800", "input_text_invalid")])
def test_pure_api_structure_guard_uses_fixed_errors(value, code: str) -> None:
    with pytest.raises(planner.ReanalysisPlanError, match=code):
        planner._bounded_shape({"fixture": value})


def test_catalog_kind_with_unexpected_type_is_fixed_error(tmp_path: Path) -> None:
    _case, value, catalog = _inputs(tmp_path)
    next(iter(catalog["cases"].values()))["case_kind"] = {"secret": "value"}
    with pytest.raises(planner.ReanalysisPlanError, match="catalog_identity_invalid"):
        _plan(value, catalog)


def test_old_inventory_unknown_schema_is_never_a_job(tmp_path: Path) -> None:
    _case, value, catalog = _inputs(tmp_path)
    value["schema_version"] = 99
    _commit(value)
    with pytest.raises(planner.ReanalysisPlanError, match="inventory_schema_invalid"):
        _plan(value, catalog)


def test_unsafe_limit_in_inventory_is_rejected_before_planning(tmp_path: Path) -> None:
    _case, value, catalog = _inputs(tmp_path)
    value["limits"]["wall_seconds"] = float("nan")
    with pytest.raises(planner.ReanalysisPlanError, match="input_nonfinite_number"):
        _plan(value, catalog)


@pytest.mark.parametrize("roles", [{"secret_role": 1}, {"c2": True}, {"c2": -1}, {"c2": 1.0}, []])
def test_case_url_role_schema_never_accepts_unknown_or_noninteger_counts(tmp_path: Path, roles) -> None:
    _case, value, catalog = _inputs(tmp_path)
    value["cases"][0]["url_role_counts"] = roles
    _commit(value)
    with pytest.raises(planner.ReanalysisPlanError, match="inventory_url_role_counts_invalid"):
        _plan(value, catalog)


@pytest.mark.parametrize("count", [4017, 10000])
def test_scale_profiles_keep_candidate_and_repair_caps_and_commitments(tmp_path: Path, count: int) -> None:
    repairs = count // 4
    value, catalog = _scale_inputs(tmp_path, count, repairs)
    result = _plan(value, catalog)
    assert result["candidate_count"] == count - repairs
    assert result["repair_record_count"] == repairs
    assert len(result["job_candidates"]) == 64 and len(result["metadata_repairs"]) == 128
    assert result["omissions"]["candidate_count"] == count - repairs - 64
    assert result["omissions"]["repair_count"] == repairs - 128
    assert audit.SHA.fullmatch(result["omissions"]["candidate_sha256"])
    assert audit.SHA.fullmatch(result["omissions"]["repair_sha256"])
    assert result["analysis_success_rate_measured"] is False
    assert len(json.dumps(result).encode("utf-8")) <= planner.MAX_OUTPUT_BYTES


def test_omission_commitments_equal_full_omitted_rows_and_detect_change(tmp_path: Path) -> None:
    value, catalog = _scale_inputs(tmp_path, 5, repairs=2)
    full = _plan(value, catalog)
    bounded = _plan(value, catalog, max_candidates=1, max_repairs=1)
    assert bounded["omissions"]["candidate_sha256"] == audit._hash(full["job_candidates"][1:])
    assert bounded["omissions"]["repair_sha256"] == audit._hash(full["metadata_repairs"][1:])
    value["cases"][-1]["fingerprints"]["evidence"] = "e" * 64
    value["cases"][1]["changed_dimensions"] = ["evidence"]
    _commit(value)
    changed = _plan(value, catalog, max_candidates=1, max_repairs=1)
    assert changed["job_candidates"] == bounded["job_candidates"]
    assert changed["metadata_repairs"] == bounded["metadata_repairs"]
    assert changed["omissions"]["candidate_sha256"] != bounded["omissions"]["candidate_sha256"]
    assert changed["omissions"]["repair_sha256"] != bounded["omissions"]["repair_sha256"]


def test_input_snapshot_accepts_10000_case_inventory_above_old_8mib_and_reverifies(tmp_path: Path) -> None:
    value, _catalog = _scale_inputs(tmp_path, 10000)
    source = tmp_path / "synthetic-scale.json"
    _write(source, value)
    size = source.stat().st_size
    assert audit.MAX_FILE_BYTES < size <= planner.MAX_INPUT_BYTES
    snapshot = planner._InputSnapshot(source)
    loaded = snapshot.read()
    assert len(loaded["cases"]) == 10000
    planner._validate_inventory(loaded)
    assert snapshot.guard.files == 1 and snapshot.guard.used == size
    snapshot.verify()
    assert snapshot.guard.files == 2 and snapshot.guard.used == 2 * size
    with pytest.raises(planner.ReanalysisPlanError, match="input_snapshot_read_count_limit"):
        snapshot.verify()


@pytest.mark.parametrize("excess", [0, 1])
def test_cli_dedicated_input_byte_boundary_is_32mib_not_8mib(tmp_path: Path, excess: int) -> None:
    # schema不適合の合成objectを最大sizeへspace paddingし、reader quotaを先に検証する。
    source = tmp_path / "synthetic-byte-boundary.json"
    source.write_bytes(b"{}" + b" " * (planner.MAX_INPUT_BYTES + excess - 2))
    result = subprocess.run([sys.executable, "-I", "-B", str(COMMON / "automation_reanalysis_plan.py"),
        "--inventory", str(source), "--repository", str(tmp_path)], capture_output=True, timeout=45, check=False)
    assert result.returncode == 2
    expected = "inventory_schema_invalid" if excess == 0 else "input_snapshot_bytes_limit"
    assert json.loads(result.stderr)["error"] == expected


def test_exact_32mib_snapshot_reverification_has_64mib_cumulative_cap(tmp_path: Path) -> None:
    source = tmp_path / "synthetic-exact-cap.json"
    source.write_bytes(b"{}" + b" " * (planner.MAX_INPUT_BYTES - 2))
    snapshot = planner._InputSnapshot(source)
    assert snapshot.read() == {}
    snapshot.verify()
    assert snapshot.guard.files == 2 and snapshot.guard.used == 64 * 1024 * 1024
    with pytest.raises(planner.ReanalysisPlanError, match="input_snapshot_read_count_limit"):
        snapshot.verify()


def test_preallocation_tokens_reject_2million_boundary_before_decoder(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "synthetic-node-boundary.json"
    # root、key、listと2,000,000 primitivesにより、bytes cap未満でもtoken capを超える。
    source.write_bytes(b'{"synthetic":[' + b"0," * (planner.MAX_INPUT_NODES - 1) + b"0]}")
    def forbidden_decoder(*_args, **_kwargs):
        raise AssertionError("上限超過文書をdecoderへ渡してはいけません")
    monkeypatch.setattr(planner.json, "loads", forbidden_decoder)
    with pytest.raises(planner.ReanalysisPlanError, match="input_preallocation_token_limit"):
        planner._InputSnapshot(source).read()


def test_cli_preallocation_nodes_reject_before_schema_or_repository_access(tmp_path: Path) -> None:
    source = tmp_path / "synthetic-cli-node-boundary.json"
    source.write_bytes(b'{"synthetic":[' + b"0," * (planner.MAX_INPUT_NODES - 1) + b"0]}")
    result = subprocess.run([sys.executable, "-I", "-B", str(COMMON / "automation_reanalysis_plan.py"),
        "--inventory", str(source), "--repository", str(tmp_path)], capture_output=True, timeout=45, check=False)
    assert result.returncode == 2
    assert json.loads(result.stderr)["error"] == "input_preallocation_token_limit"


def test_aggregate_and_per_case_node_profiles_are_independently_enforced(tmp_path: Path) -> None:
    _case, value, catalog = _inputs(tmp_path)
    row = value["cases"][0]
    row["url_role_counts"] = {"fixture": [0] * planner.MAX_CASE_NODES}
    _commit(value)
    with pytest.raises(planner.ReanalysisPlanError, match="input_structure_limit"):
        _plan(value, catalog)
    # case毎の小さな木を束ねても、aggregate200万nodeを超えるinputは通さない。
    with pytest.raises(planner.ReanalysisPlanError, match="input_structure_limit"):
        planner._bounded_shape([[0] * 20000] * 100)


@pytest.mark.parametrize("kwargs", [{"max_nodes": True}, {"max_nodes": 2_000_001},
    {"max_text_bytes": 32 * 1024 * 1024 + 1}, {"max_text_bytes": float("nan")}])
def test_private_structure_profile_cannot_raise_hard_limits(kwargs: dict) -> None:
    with pytest.raises(planner.ReanalysisPlanError, match="input_structure_profile_invalid"):
        planner._bounded_shape({}, **kwargs)


@pytest.mark.parametrize("raw,code", [(b'{"same":1,"same":2}', "input_json_invalid"),
    (b'{"value":1e999}', "input_nonfinite_number"),
    (b'{"value":NaN}', "input_json_invalid"),
    (b'{"value":"\\ud800"}', "input_text_invalid")])
def test_snapshot_decoder_fails_closed_with_fixed_errors(tmp_path: Path, raw: bytes, code: str) -> None:
    source = tmp_path / "synthetic-invalid-json.json"
    source.write_bytes(raw)
    with pytest.raises(planner.ReanalysisPlanError, match=code):
        planner._InputSnapshot(source).read()


def test_snapshot_reverification_rejects_input_drift(tmp_path: Path) -> None:
    source = tmp_path / "synthetic-drift.json"
    source.write_bytes(b'{"before":true}')
    snapshot = planner._InputSnapshot(source)
    snapshot.read()
    source.write_bytes(b'{"before":null}')
    with pytest.raises(planner.ReanalysisPlanError, match="input_snapshot_changed"):
        snapshot.verify()


def test_snapshot_rejects_hardlinked_source(tmp_path: Path) -> None:
    source = tmp_path / "synthetic-original.json"
    source.write_bytes(b"{}")
    linked = tmp_path / "synthetic-hardlink.json"
    os.link(source, linked)
    with pytest.raises(planner.ReanalysisPlanError, match="input_snapshot_file_unsafe"):
        planner._InputSnapshot(linked).read()


@pytest.mark.parametrize("endpoints", [[None], [1], [None, None]])
def test_producer_unknown_url_structure_is_metadata_repair(short_tmp: Path, endpoints) -> None:
    """producer既存enumを受けても、構造不明を抽出job候補へ流さない。"""
    case, _value, catalog = _inputs(short_tmp)
    path = case / "orchestration.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    value["outputs"]["network_endpoints"] = endpoints
    digest = _write(path, value)
    _update_report(case, lambda report: report["artifact_sha256"].update({"orchestration.json": digest}))
    current = audit._inventory(short_tmp)
    result = _plan(current, catalog)
    assert result["candidate_count"] == 0 and result["repair_record_count"] == 1
    repair = result["metadata_repairs"][0]
    assert repair["reason_codes"] == ["url_endpoint_structure_unknown"]
    assert repair["analysis_job_candidate"] is repair["automatic_dispatch_allowed"] is False


@pytest.mark.parametrize("count", [True, -1, "1", 1.0, 200_001])
def test_unknown_url_structure_count_stays_exact_bounded(short_tmp: Path, count) -> None:
    """追加既知enumもbool、文字列、負数、上限超過を受理しない。"""
    _case, value, catalog = _inputs(short_tmp)
    value["cases"][0]["url_role_counts"] = {"unknown_structure": count}
    _commit(value)
    with pytest.raises(planner.ReanalysisPlanError, match="inventory_url_role_counts_invalid"):
        _plan(value, catalog)


@pytest.mark.parametrize("kind", ["dict", "string_key", "collision_key", "sha"])
def test_pure_api_unknown_objects_rejected_without_callbacks(short_tmp: Path, kind: str) -> None:
    """通常JSON型以外を、反復・hash・比較・encodeより前に拒否する。"""
    _case, value, catalog = _inputs(short_tmp)
    class UnknownDict(dict):
        def __iter__(self):
            raise AssertionError("unknown_iteration_called")
    class UnknownString(str):
        armed = False
        def __hash__(self):
            if self.armed:
                raise AssertionError("unknown_hash_called")
            return str.__hash__(self)
        def __eq__(self, other):
            if self.armed:
                raise AssertionError("unknown_comparison_called")
            return str.__eq__(self, other)
        def encode(self, *args, **kwargs):
            raise AssertionError("unknown_encode_called")
    class UnknownCollision:
        armed = False
        def __hash__(self):
            return hash("schema_version")
        def __eq__(self, other):
            if self.armed:
                raise AssertionError("unknown_collision_comparison_called")
            return False
    if kind == "dict":
        with pytest.raises(planner.ReanalysisPlanError, match="inventory_schema_invalid"):
            planner._validate_inventory(UnknownDict(value))
    elif kind in {"string_key", "collision_key"}:
        key = UnknownString("unknown") if kind == "string_key" else UnknownCollision()
        value[key] = None
        key.armed = True
        with pytest.raises(planner.ReanalysisPlanError, match="input_key_invalid"):
            planner._validate_inventory(value)
    else:
        digest = UnknownString(value["catalog_sha256"])
        digest.armed = True
        with pytest.raises(planner.ReanalysisPlanError, match="catalog_commitment_invalid"):
            planner.build_plan(value, value, catalog, catalog_sha256=digest)


@pytest.mark.parametrize("missing", ["schema_version", "cases", "inventory_sha256"])
def test_pure_api_missing_top_key_keeps_fixed_error(short_tmp: Path, missing: str) -> None:
    """早期型走査後も欠落fieldの固定error契約を維持する。"""
    _case, value, _catalog = _inputs(short_tmp)
    del value[missing]
    with pytest.raises(planner.ReanalysisPlanError, match="inventory_schema_invalid"):
        planner._validate_inventory(value)
