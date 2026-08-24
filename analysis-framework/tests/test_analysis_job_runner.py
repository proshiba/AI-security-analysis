"""script-only静的解析ジョブrunnerの安全境界を検証する。"""

from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import platform
import stat
import subprocess
import sys
import threading
import time
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_job_runner as runner  # noqa: E402


def request_value(job_id: str = "job-001", **options: Any) -> dict[str, Any]:
    """テスト用の最小要求を返す。"""

    return {
        "schema_version": 1,
        "job_id": job_id,
        "inputs": ["set/sample.bin"],
        "options": options,
    }


def make_roots(tmp_path: Path, *, data: bytes = b"MZ synthetic static bytes") -> tuple[Path, Path]:
    """相互に分離した入力rootとjob rootを作る。"""

    input_root = tmp_path / "inputs"
    jobs_root = tmp_path / "jobs"
    sample = input_root / "set" / "sample.bin"
    sample.parent.mkdir(parents=True)
    sample.write_bytes(data)
    jobs_root.mkdir()
    return input_root, jobs_root


def make_trusted_tool_configuration(
    tmp_path: Path,
    *,
    upx_bytes: bytes = b"synthetic pinned UPX executable",
    sevenzip_bytes: bytes | None = None,
) -> tuple[runner.TrustedToolConfiguration, Path, Path]:
    """repository・input・job root外にtest用operator manifestを作る。"""

    operator_root = tmp_path / "operator-static-tools"
    operator_root.mkdir(exist_ok=True)
    upx = operator_root / ("upx.exe" if os.name == "nt" else "upx")
    upx.write_bytes(upx_bytes)
    sevenzip: Path | None = None
    if sevenzip_bytes is not None:
        sevenzip = operator_root / ("7zz.exe" if os.name == "nt" else "7zz")
        sevenzip.write_bytes(sevenzip_bytes)

    def record(path: Path | None) -> dict[str, Any] | None:
        if path is None:
            return None
        payload = path.read_bytes()
        return {
            "path": str(path.resolve()),
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        }

    manifest = operator_root / "trusted-static-tools.json"
    manifest.write_bytes(
        json.dumps(
            {
                "schema_version": 1,
                "profile_id": "test-pinned-tools",
                "platform": {
                    "sys_platform": sys.platform.casefold(),
                    "machine": platform.machine().casefold(),
                },
                "tools": {
                    "upx": record(upx),
                    "sevenzip": record(sevenzip),
                },
            },
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    configuration = runner.TrustedToolConfiguration(
        manifest_path=manifest,
        manifest_sha256=hashlib.sha256(manifest.read_bytes()).hexdigest(),
    )
    return configuration, manifest, upx


def write_summary(
    output: Path,
    *,
    network_contacted: bool = False,
    ai_used: bool = False,
    count_overrides: dict[str, int] | None = None,
) -> None:
    """analyze_sample.pyの最小安全summaryを作る。"""

    output.mkdir(parents=True, exist_ok=True)
    counts = {
        "input_files": 1,
        "analyzed": 1,
        "duplicates": 0,
        "errors": 0,
        "identified": 0,
        "unknown_or_ambiguous": 1,
        "automation_resolved": 0,
        "automation_partial": 0,
        "automation_unknown": 1,
        "candidate_handler_attempts": 0,
        "handler_successes": 0,
        "handler_failures": 0,
        "handler_no_evidence": 0,
        "handler_ambiguous": 0,
        "handler_incompatible": 0,
        "analysis_stage_failures": 0,
        "analysis_stage_partial": 0,
        "complete": 1,
        "triaged_unknown": 0,
        "partial": 0,
        "failed": 0,
        "resumed": 0,
    }
    counts.update(count_overrides or {})
    root_sha256 = "a" * 64
    follow_on = {
        "schema_version": 1,
        "status": "no_retained_payloads",
        "analysis_contract_sha256": "c" * 64,
        "limits": {
            "maximum_artifacts": runner.MAX_FOLLOW_ON_ARTIFACTS,
            "maximum_edges": runner.MAX_FOLLOW_ON_EDGES,
            "maximum_depth": runner.MAX_FOLLOW_ON_DEPTH,
            "maximum_total_bytes": runner.MAX_FOLLOW_ON_TOTAL_BYTES,
            "maximum_payload_size": runner.MAX_FOLLOW_ON_PAYLOAD_SIZE,
            "maximum_wall_seconds": runner.MAX_FOLLOW_ON_WALL_SECONDS,
            "maximum_child_seconds": runner.MAX_FOLLOW_ON_CHILD_SECONDS,
            "maximum_omitted_metadata": runner.MAX_FOLLOW_ON_OMITTED_METADATA,
        },
        "roots": [root_sha256],
        "nodes": [{"sha256": root_sha256, "depth": 0, "state": "root"}],
        "edges": [],
        "omitted_metadata": [],
        "omitted_metadata_commitments": [],
        "errors": [],
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
        "queued_artifact_count": 0,
        "queued_total_bytes": 0,
        "verified_read_count": 0,
        "verified_read_bytes": 0,
        "parent_promotion_enabled": True,
        "promoted_parent_sha256": [],
        "wall_clock_exhausted": False,
    }
    follow_on_raw = (json.dumps(follow_on, sort_keys=True) + "\n").encode("utf-8")
    (output / "follow-on-analysis.json").write_bytes(follow_on_raw)
    (output / "summary.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "counts": counts,
                "catalog": {},
                "analysis_contract": {},
                "requirements_policy": {},
                "settings": {},
                "cases": [{"sha256": root_sha256}] * counts["analyzed"],
                "duplicates": [
                    {
                        "source_name": f"duplicate-{index}.bin",
                        "sha256": root_sha256,
                    }
                    for index in range(counts["duplicates"])
                ],
                "errors": [
                    {
                        "source_name": f"error-{index}.bin",
                        "error": "ValueError: synthetic input error",
                    }
                    for index in range(counts["errors"])
                ],
                "derived_cases": [],
                "derived_counts": {
                    "analyzed": 0,
                    "identified": 0,
                    "unknown_or_ambiguous": 0,
                    "complete": 0,
                    "triaged_unknown": 0,
                    "partial": 0,
                    "failed": 0,
                    "resumed": 0,
                },
                "follow_on_analysis_contract": {
                    "schema_version": 1,
                    "sha256": "c" * 64,
                },
                "follow_on_analysis": {
                    "artifact": "follow-on-analysis.json",
                    "sha256": hashlib.sha256(follow_on_raw).hexdigest(),
                    "status": "no_retained_payloads",
                    "node_count": 1,
                    "edge_count": 0,
                    "error_count": 0,
                },
                "executed_sample": False,
                "network_contacted": network_contacted,
                "ai_used": ai_used,
            }
        ),
        encoding="utf-8",
    )


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_validated_daily_static_bundle_is_path_free_and_deterministic(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64

    def validate(_path: Path, **kwargs: Any) -> tuple[dict[str, Any], dict[str, int]]:
        capture = kwargs["_daily_static_capture"]
        capture.cases[digest] = {
            "generic-triage.json": b'{"schema_version":1}\n',
            "static-logic.json": b'{"schema_version":1}\n',
        }
        capture.total_bytes = sum(len(value) for value in capture.cases[digest].values())
        return {"cases": [{"sha256": digest}], "derived_cases": []}, {"analyzed": 1}

    monkeypatch.setattr(runner, "_validated_summary", validate)
    bundle = runner.validated_daily_static_bundle(
        tmp_path / "summary.json",
        expected_input_files=1,
        expected_analysis_contract={},
        expected_follow_on_contract={},
        expected_options={},
        expected_input_manifest=(),
    )

    assert bundle.counts == {"analyzed": 1}
    assert tuple(case.sha256 for case in bundle.cases) == (digest,)
    assert "path" not in repr(bundle)
    assert bundle.case_artifact_commitment_sha256 == runner.hashlib.sha256(
        runner.json.dumps(
            [
                {
                    "sha256": digest,
                    "generic_triage": {
                        "size": len(bundle.cases[0].generic_triage),
                        "sha256": bundle.cases[0].generic_triage_sha256,
                    },
                    "static_logic": {
                        "size": len(bundle.cases[0].static_logic),
                        "sha256": bundle.cases[0].static_logic_sha256,
                    },
                }
            ],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def test_validated_daily_static_bundle_rejects_capture_aggregate_over_limit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    digest = "a" * 64

    def validate(_path: Path, **kwargs: Any) -> tuple[dict[str, Any], dict[str, int]]:
        capture = kwargs["_daily_static_capture"]
        capture.cases[digest] = {
            "generic-triage.json": b"{}",
            "static-logic.json": b"{}",
        }
        capture.total_bytes = 2
        return {"cases": [{"sha256": digest}], "derived_cases": []}, {}

    monkeypatch.setattr(runner, "_validated_summary", validate)
    monkeypatch.setattr(runner, "MAX_DAILY_STATIC_CAPTURE_TOTAL_BYTES", 1)

    with pytest.raises(runner.JobContractError) as caught:
        runner.validated_daily_static_bundle(
            tmp_path / "summary.json",
            expected_input_files=1,
            expected_analysis_contract={},
            expected_follow_on_contract={},
            expected_options={},
            expected_input_manifest=(),
        )

    assert caught.value.code == "summary_invalid"


def replace_follow_on(output: Path, value: dict[str, Any]) -> None:
    """follow-on graphとsummary参照を同じbytesへ更新する。"""

    raw = (json.dumps(value, sort_keys=True) + "\n").encode("utf-8")
    (output / "follow-on-analysis.json").write_bytes(raw)
    summary = load_json(output / "summary.json")
    summary["follow_on_analysis"] = {
        "artifact": "follow-on-analysis.json",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "status": value["status"],
        "node_count": len(value["nodes"]),
        "edge_count": len(value["edges"]),
        "error_count": len(value["errors"]),
    }
    (output / "summary.json").write_text(json.dumps(summary), encoding="utf-8")


def test_derived_summary_is_validated_separately(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    write_summary(output)
    summary = load_json(output / "summary.json")
    root_sha256 = "a" * 64
    child_sha256 = "b" * 64
    summary["derived_cases"] = [
        {
            "sha256": child_sha256,
            "source_name": f"follow-on-{child_sha256[:16]}.bin",
            "family": "unknown",
            "selected_family": None,
            "selected_families": [],
            "automation_family": None,
            "automation_state": "unknown",
            "candidate_handler_attempts": 0,
            "ai_used": False,
            "campaign": "unknown",
            "handler_succeeded": 0,
            "handler_failed": 0,
            "handler_no_evidence": 0,
            "handler_ambiguous": 0,
            "handler_incompatible": 0,
            "analysis_stage_failed": False,
            "analysis_stage_partial": False,
            "case_state": "complete",
            "report": f"cases/{child_sha256}/report.json",
            "resumed": False,
            "case_origin": "derived_follow_on",
            "follow_on_depth": 1,
            "parent_sha256": [root_sha256],
        }
    ]
    summary["derived_counts"]["analyzed"] = 1
    summary["derived_counts"]["unknown_or_ambiguous"] = 1
    summary["derived_counts"]["complete"] = 1
    follow_on = {
        "schema_version": 1,
        "status": "complete",
        "analysis_contract_sha256": "c" * 64,
        "limits": {
            "maximum_artifacts": runner.MAX_FOLLOW_ON_ARTIFACTS,
            "maximum_edges": runner.MAX_FOLLOW_ON_EDGES,
            "maximum_depth": runner.MAX_FOLLOW_ON_DEPTH,
            "maximum_total_bytes": runner.MAX_FOLLOW_ON_TOTAL_BYTES,
            "maximum_payload_size": runner.MAX_FOLLOW_ON_PAYLOAD_SIZE,
            "maximum_wall_seconds": runner.MAX_FOLLOW_ON_WALL_SECONDS,
            "maximum_child_seconds": runner.MAX_FOLLOW_ON_CHILD_SECONDS,
            "maximum_omitted_metadata": runner.MAX_FOLLOW_ON_OMITTED_METADATA,
        },
        "wall_clock_exhausted": False,
        "roots": [root_sha256],
        "nodes": [
            {"sha256": root_sha256, "depth": 0, "state": "root"},
            {
                "sha256": child_sha256,
                "depth": 1,
                "state": "analyzed",
                "case_state": "complete",
                "size": 10,
                "family_hint_count": 0,
                "family_hint_root_sha256": None,
                "family_hint_lineage_depth": None,
            },
        ],
        "edges": [
            {
                "parent_sha256": root_sha256,
                "child_sha256": child_sha256,
                "depth": 1,
                "path": "p/child.bin",
                "role": "terminal_payload",
                "kind": "pe",
                "size": 10,
                "status": "child_complete",
            }
        ],
        "omitted_metadata": [],
        "omitted_metadata_commitments": [],
        "errors": [],
        "executed_sample": False,
        "network_contacted": False,
        "ai_used": False,
        "queued_artifact_count": 1,
        "queued_total_bytes": 10,
        "verified_read_count": 1,
        "verified_read_bytes": 10,
        "parent_promotion_enabled": True,
        "promoted_parent_sha256": [],
    }
    raw = (json.dumps(follow_on, sort_keys=True) + "\n").encode("utf-8")
    (output / "follow-on-analysis.json").write_bytes(raw)
    summary["follow_on_analysis"] = {
        "artifact": "follow-on-analysis.json",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "status": "complete",
        "node_count": 2,
        "edge_count": 1,
        "error_count": 0,
    }
    case_dir = output / "cases" / child_sha256
    case_dir.mkdir(parents=True)
    report = {
        "schema_version": 1,
        "sample": {
            "sha256": child_sha256,
            "source_name": f"follow-on-{child_sha256[:16]}.bin",
        },
        "analysis_contract": {"schema_version": 1, "sha256": "c" * 64},
        "classification": {
            "family": "unknown",
            "selected_family": None,
            "selected_families": [],
            "campaign": "unknown",
        },
        "case_state": {"status": "complete"},
        "follow_on_lineage": {
            "schema_version": 1,
            "depth": 1,
            "parent_sha256": root_sha256,
            "root_kind": "retained_terminal_or_final_payload",
        },
        "handler_executions": [],
        "generic_triage": "complete",
    }
    (case_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
    (case_dir / "orchestration.json").write_text(
        json.dumps(
            {
                "status": "complete",
                "blockers": [],
                "family_resolution": {"status": "unresolved", "family": None},
            }
        ),
        encoding="utf-8",
    )
    (case_dir / "candidate-handler-assessment.json").write_text(
        json.dumps({"planned_attempt_count": 0}),
        encoding="utf-8",
    )
    monkeypatch.setattr(runner, "case_integrity_errors", lambda *_args, **_kwargs: [])
    (output / "summary.json").write_text(json.dumps(summary), encoding="utf-8")

    validated, counts = runner._validated_summary(
        output / "summary.json",
        expected_input_files=1,
    )

    assert counts["analyzed"] == 1
    assert len(validated["derived_cases"]) == 1

    hinted = deepcopy(follow_on)
    hinted["nodes"][1].update(
        {
            "family_hint_count": 1,
            "family_hint_root_sha256": root_sha256,
            "family_hint_lineage_depth": 1,
        }
    )
    replace_follow_on(output, hinted)
    validated, counts = runner._validated_summary(
        output / "summary.json",
        expected_input_files=1,
    )
    for field, invalid in (
        ("family_hint_count", True),
        ("family_hint_root_sha256", child_sha256),
        ("family_hint_lineage_depth", runner.MAX_FAMILY_HINT_LINEAGE_DEPTH + 1),
    ):
        forged_hint = deepcopy(hinted)
        forged_hint["nodes"][1][field] = invalid
        replace_follow_on(output, forged_hint)
        with pytest.raises(runner.JobContractError) as caught:
            runner._validated_summary(output / "summary.json", expected_input_files=1)
        assert caught.value.code == "summary_invalid"
    replace_follow_on(output, hinted)
    validated, counts = runner._validated_summary(
        output / "summary.json",
        expected_input_files=1,
    )

    omitted = json.loads(json.dumps(validated))
    omitted["derived_cases"] = []
    for key in omitted["derived_counts"]:
        omitted["derived_counts"][key] = 0
    (output / "summary.json").write_text(json.dumps(omitted), encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_count_mismatch"
    (output / "summary.json").write_text(json.dumps(validated), encoding="utf-8")

    monkeypatch.setattr(
        runner,
        "case_integrity_errors",
        lambda *_args, **_kwargs: ["artifact_hash_mismatch"],
    )
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"

    monkeypatch.setattr(runner, "case_integrity_errors", lambda *_args, **_kwargs: [])

    report["follow_on_lineage"]["parent_sha256"] = "d" * 64
    (case_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"
    report["follow_on_lineage"]["parent_sha256"] = root_sha256
    (case_dir / "report.json").write_text(json.dumps(report), encoding="utf-8")

    validated["derived_cases"][0]["follow_on_depth"] = 2
    (output / "summary.json").write_text(json.dumps(validated), encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"


def test_follow_on_artifact_hash_tamper_is_rejected(tmp_path: Path) -> None:
    """summary確定後のgraph差替えをSHA-256で拒否する。"""

    output = tmp_path / "output"
    write_summary(output)
    with (output / "follow-on-analysis.json").open("ab") as stream:
        stream.write(b" ")

    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"


def test_follow_on_contract_and_limits_are_anchored(tmp_path: Path) -> None:
    output = tmp_path / "output"
    write_summary(output)

    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(
            output / "summary.json",
            expected_input_files=1,
            expected_follow_on_contract={
                "schema_version": 1,
                "sha256": "d" * 64,
            },
        )
    assert caught.value.code == "summary_invalid"

    follow_on = load_json(output / "follow-on-analysis.json")
    follow_on["limits"]["maximum_edges"] += 1
    raw = (json.dumps(follow_on, sort_keys=True) + "\n").encode("utf-8")
    (output / "follow-on-analysis.json").write_bytes(raw)
    summary = load_json(output / "summary.json")
    summary["follow_on_analysis"]["sha256"] = hashlib.sha256(raw).hexdigest()
    (output / "summary.json").write_text(json.dumps(summary), encoding="utf-8")

    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"


def test_root_contract_is_anchored_to_current_request_and_code(tmp_path: Path) -> None:
    output = tmp_path / "output"
    write_summary(output)
    summary = load_json(output / "summary.json")
    contract = {"schema_version": 1, "sha256": "d" * 64}
    summary["analysis_contract"] = contract
    (output / "summary.json").write_text(json.dumps(summary), encoding="utf-8")

    runner._validated_summary(
        output / "summary.json",
        expected_input_files=1,
        expected_analysis_contract=contract,
    )
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(
            output / "summary.json",
            expected_input_files=1,
            expected_analysis_contract={"schema_version": 1, "sha256": "e" * 64},
        )
    assert caught.value.code == "summary_invalid"


def test_summary_count_key_sets_are_exact(tmp_path: Path) -> None:
    output = tmp_path / "output"
    write_summary(output)
    summary = load_json(output / "summary.json")
    summary["counts"].pop("handler_successes")
    (output / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"

    write_summary(output)
    summary = load_json(output / "summary.json")
    summary["counts"]["unexpected"] = 0
    (output / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"

    write_summary(output)
    summary = load_json(output / "summary.json")
    summary["derived_counts"]["unexpected"] = 0
    (output / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"


def test_summary_follow_on_and_node_key_sets_are_exact(tmp_path: Path) -> None:
    """producerが生成しないfieldは各公開schemaで拒否する。"""

    output = tmp_path / "output"
    write_summary(output)
    summary = load_json(output / "summary.json")
    summary["unexpected"] = "must-fail"
    (output / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"

    write_summary(output)
    follow_on = load_json(output / "follow-on-analysis.json")
    follow_on["unexpected"] = "must-fail"
    replace_follow_on(output, follow_on)
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"

    write_summary(output)
    follow_on = load_json(output / "follow-on-analysis.json")
    follow_on["nodes"][0]["unexpected"] = "must-fail"
    replace_follow_on(output, follow_on)
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"


def test_public_run_job_has_no_process_injection_seam() -> None:
    """WebUI向けproduction APIから任意callableを注入できない。"""

    assert "run_process" not in inspect.signature(runner.run_job).parameters
    assert "run_process" in inspect.signature(runner._run_job_for_test).parameters


def test_public_run_job_revalidates_manually_constructed_request(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    malicious = runner.JobRequest(
        job_id="../escape",
        inputs=("set/sample.bin",),
        family_hint_manifest=None,
        options=dict(runner.DEFAULT_OPTIONS),
    )

    with pytest.raises(runner.JobContractError) as caught:
        runner.run_job(
            malicious,
            input_root=input_root,
            jobs_root=jobs_root,
            timeout_seconds=60,
        )
    assert caught.value.code == "invalid_job_id"
    assert not (tmp_path / "escape").exists()

    forbidden = runner.JobRequest(
        job_id="job-manual-forbidden",
        inputs=("set/sample.bin",),
        family_hint_manifest=None,
        options={**runner.DEFAULT_OPTIONS, "allow_network": True},
    )
    with pytest.raises(runner.JobContractError) as caught:
        runner.run_job(
            forbidden,
            input_root=input_root,
            jobs_root=jobs_root,
            timeout_seconds=60,
        )
    assert caught.value.code == "network_or_privileged_option_forbidden"
    assert not (jobs_root / "job-manual-forbidden").exists()


def test_public_validate_job_revalidates_manually_constructed_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Python APIでloaderを迂回しても受付前検証が不正requestを拒否する。"""

    input_root, jobs_root = make_roots(tmp_path)
    malicious = runner.JobRequest(
        job_id="../escape",
        inputs=("set/sample.bin",),
        family_hint_manifest=None,
        options=dict(runner.DEFAULT_OPTIONS),
    )
    runtime_called = False

    def unexpected_runtime() -> dict[str, object]:
        nonlocal runtime_called
        runtime_called = True
        return {}

    monkeypatch.setattr(runner, "validate_analyzer_runtime", unexpected_runtime)
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_job(
            malicious,
            input_root=input_root,
            jobs_root=jobs_root,
        )
    assert caught.value.code == "invalid_job_id"
    assert runtime_called is False
    assert not (tmp_path / "escape").exists()

    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_job(  # type: ignore[arg-type]
            object(),
            input_root=input_root,
            jobs_root=jobs_root,
        )
    assert caught.value.code == "invalid_request_type"
    assert runtime_called is False


def test_duplicate_error_schema_and_input_manifest_are_exact() -> None:
    root = "a" * 64
    summary = {
        "cases": [{"source_name": "sample.bin", "sha256": root}],
        "duplicates": [{"source_name": "copy.bin", "sha256": root}],
        "errors": [],
    }
    manifest = [
        runner.ExpectedInputUnit("sample.bin", "sample.bin", root, True),
        runner.ExpectedInputUnit("copy.bin", "copy.bin", root, True),
    ]
    runner._validate_summary_input_records(
        summary,
        root_hashes={root},
        expected_input_manifest=manifest,
    )

    forged = deepcopy(summary)
    forged["duplicates"][0]["sha256"] = "b" * 64
    with pytest.raises(runner.JobContractError):
        runner._validate_summary_input_records(
            forged,
            root_hashes={root},
            expected_input_manifest=manifest,
        )

    malformed = deepcopy(summary)
    malformed["duplicates"][0]["extra"] = True
    with pytest.raises(runner.JobContractError):
        runner._validate_summary_input_records(
            malformed,
            root_hashes={root},
            expected_input_manifest=manifest,
        )

    unsafe_error = {
        "cases": [],
        "duplicates": [],
        "errors": [{"source_name": "bad\nname.bin", "error": "failure"}],
    }
    with pytest.raises(runner.JobContractError):
        runner._validate_summary_input_records(
            unsafe_error,
            root_hashes=set(),
            expected_input_manifest=None,
        )

    all_duplicate = {
        "cases": [],
        "duplicates": [{"source_name": "copy.bin", "sha256": root}],
        "errors": [],
    }
    with pytest.raises(runner.JobContractError):
        runner._validate_summary_input_records(
            all_duplicate,
            root_hashes=set(),
            expected_input_manifest=None,
        )


def test_follow_on_omission_requires_exact_partial_marker_and_deadline(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    write_summary(output)
    root = "a" * 64
    child = "b" * 64
    marker = f"{root}:verified_output_edge_limit"
    graph = load_json(output / "follow-on-analysis.json")
    graph.update(
        {
            "status": "partial",
            "errors": [marker],
            "omitted_metadata": [
                {
                    "parent_sha256": root,
                    "sha256": child,
                    "size": 10,
                    "path": "p/child.bin",
                    "role": "terminal_payload",
                    "kind": "pe",
                    "reason": "verified_output_edge_limit",
                }
            ],
        }
    )
    replace_follow_on(output, graph)
    runner._validated_summary(output / "summary.json", expected_input_files=1)

    missing_marker = deepcopy(graph)
    missing_marker["errors"] = []
    replace_follow_on(output, missing_marker)
    with pytest.raises(runner.JobContractError):
        runner._validated_summary(output / "summary.json", expected_input_files=1)

    wrong_status = deepcopy(graph)
    wrong_status["status"] = "complete"
    replace_follow_on(output, wrong_status)
    with pytest.raises(runner.JobContractError):
        runner._validated_summary(output / "summary.json", expected_input_files=1)

    deadline = deepcopy(graph)
    reason = "verified_output_read_wall_clock_limit"
    deadline["errors"] = [f"{root}:{reason}"]
    deadline["omitted_metadata"][0]["reason"] = reason
    deadline["wall_clock_exhausted"] = False
    replace_follow_on(output, deadline)
    with pytest.raises(runner.JobContractError):
        runner._validated_summary(output / "summary.json", expected_input_files=1)

    extra_key = deepcopy(graph)
    extra_key["omitted_metadata"][0]["extra"] = True
    replace_follow_on(output, extra_key)
    with pytest.raises(runner.JobContractError):
        runner._validated_summary(output / "summary.json", expected_input_files=1)


def test_follow_on_total_queue_bytes_over_hard_limit_is_rejected(tmp_path: Path) -> None:
    output = tmp_path / "output"
    write_summary(output)
    graph = load_json(output / "follow-on-analysis.json")
    root = "a" * 64
    children = ["b" * 64, "c" * 64, "d" * 64]
    size = runner.MAX_FOLLOW_ON_PAYLOAD_SIZE
    graph.update(
        {
            "status": "partial",
            "nodes": [
                {"sha256": root, "depth": 0, "state": "root"},
                *[
                    {
                        "sha256": digest,
                        "depth": 1,
                        "state": "timeout",
                        "size": size,
                        "family_hint_count": 0,
                        "family_hint_root_sha256": None,
                        "family_hint_lineage_depth": None,
                    }
                    for digest in children
                ],
            ],
            "edges": [
                {
                    "parent_sha256": root,
                    "child_sha256": digest,
                    "depth": 1,
                    "path": f"p/{digest}.bin",
                    "role": "terminal_payload",
                    "kind": "pe",
                    "size": size,
                    "status": "child_incomplete",
                }
                for digest in children
            ],
            "queued_artifact_count": len(children),
            "queued_total_bytes": len(children) * size,
            "verified_read_count": len(children),
            "verified_read_bytes": len(children) * size,
        }
    )
    replace_follow_on(output, graph)

    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"


def test_complete_edge_cannot_point_to_failed_node(tmp_path: Path) -> None:
    output = tmp_path / "output"
    write_summary(output)
    graph = load_json(output / "follow-on-analysis.json")
    root = "a" * 64
    child = "b" * 64
    graph.update(
        {
            "status": "partial",
            "nodes": [
                {"sha256": root, "depth": 0, "state": "root"},
                {
                    "sha256": child,
                    "depth": 1,
                    "state": "failed",
                    "size": 10,
                    "error_type": "ValueError",
                    "family_hint_count": 0,
                    "family_hint_root_sha256": None,
                    "family_hint_lineage_depth": None,
                },
            ],
            "edges": [
                {
                    "parent_sha256": root,
                    "child_sha256": child,
                    "depth": 1,
                    "path": "p/child.bin",
                    "role": "terminal_payload",
                    "kind": "pe",
                    "size": 10,
                    "status": "child_complete",
                }
            ],
            "queued_artifact_count": 1,
            "queued_total_bytes": 10,
            "verified_read_count": 1,
            "verified_read_bytes": 10,
        }
    )
    replace_follow_on(output, graph)

    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(output / "summary.json", expected_input_files=1)
    assert caught.value.code == "summary_invalid"


def test_shared_complete_edge_can_reuse_only_a_complete_root(tmp_path: Path) -> None:
    output = tmp_path / "output"
    write_summary(output)
    first_root = "a" * 64
    other_root = "b" * 64
    graph = load_json(output / "follow-on-analysis.json")
    graph.update(
        {
            "status": "complete",
            "roots": [first_root, other_root],
            "nodes": [
                {"sha256": first_root, "depth": 0, "state": "root"},
                {"sha256": other_root, "depth": 0, "state": "root"},
            ],
            "edges": [
                {
                    "parent_sha256": first_root,
                    "child_sha256": other_root,
                    "depth": 1,
                    "path": "p/other-root.bin",
                    "role": "terminal_payload",
                    "kind": "pe",
                    "size": 10,
                    "status": "shared_sha256_reused_complete",
                }
            ],
            "queued_artifact_count": 0,
            "queued_total_bytes": 0,
            "verified_read_count": 1,
            "verified_read_bytes": 10,
        }
    )
    replace_follow_on(output, graph)

    validated = runner._validated_follow_on_artifact(
        output / "summary.json",
        load_json(output / "summary.json"),
    )
    depths = validated.pop("_validated_node_depths")
    validated.pop("_validated_node_states")
    validated.pop("_validated_node_case_states")
    runner._validate_root_reused_edges(
        validated,
        node_depths=depths,
        root_states={first_root: "partial", other_root: "complete"},
    )
    with pytest.raises(runner.JobContractError):
        runner._validate_root_reused_edges(
            validated,
            node_depths=depths,
            root_states={first_root: "partial", other_root: "partial"},
        )


def test_follow_on_edge_is_rehashed_against_parent_wrapper(tmp_path: Path) -> None:
    output = tmp_path / "output"
    parent = "a" * 64
    payload = b"MZ retained payload"
    child = hashlib.sha256(payload).hexdigest()
    case_dir = output / "cases" / parent
    payload_path = case_dir / "p" / "child.bin"
    payload_path.parent.mkdir(parents=True)
    payload_path.write_bytes(payload)
    wrapper = {
        "verified_binary_outputs": [
            {
                "role": "terminal_payload",
                "kind": "pe",
                "path": "p/child.bin",
                "sha256": child,
                "size": len(payload),
                "verification": {
                    "status": "artifact_hash_verified",
                    "sha256_matches": True,
                    "size_matches": True,
                },
            }
        ],
        "verified_binary_output_audit": {
            "schema_version": 1,
            "maximum_outputs": 64,
            "maximum_total_size": 256 * 1024 * 1024,
            "binary_values_seen": 1,
            "binary_bytes_seen": len(payload),
            "traversal_items": 1,
            "observed_output_count": 1,
            "retained_output_count": 1,
            "retained_for_follow_on_analysis": True,
            "follow_on_analysis_complete": False,
            "observation_scope": "parent_rehashed_case_artifact",
            "truncated": False,
            "reasons": [],
        },
    }
    (case_dir / "handler.json").write_text(json.dumps(wrapper), encoding="utf-8")
    (case_dir / "candidate-handler-assessment.json").write_text(
        json.dumps({"families": []}),
        encoding="utf-8",
    )
    report = {"handler_executions": [{"result": "handler.json"}]}
    follow_on = {
        "verified_read_count": 1,
        "verified_read_bytes": len(payload),
        "omitted_metadata": [],
        "edges": [
            {
                "parent_sha256": parent,
                "child_sha256": child,
                "depth": 1,
                "path": "p/child.bin",
                "role": "terminal_payload",
                "kind": "pe",
                "size": len(payload),
                "status": "child_complete",
            }
        ],
    }

    runner._validate_follow_on_edge_provenance(
        output / "summary.json",
        follow_on=follow_on,
        validated_case_reports={parent: report},
    )
    bounded_omission = {
        **follow_on,
        "verified_read_count": 0,
        "verified_read_bytes": 0,
        "edges": [],
        "omitted_metadata": [
            {
                "parent_sha256": parent,
                "sha256": child,
                "size": len(payload),
                "path": "p/child.bin",
                "role": "terminal_payload",
                "kind": "pe",
                "reason": "verified_output_edge_limit",
            }
        ],
    }
    runner._validate_follow_on_edge_provenance(
        output / "summary.json",
        follow_on=bounded_omission,
        validated_case_reports={parent: report},
    )
    omitted = {**follow_on, "verified_read_count": 0, "verified_read_bytes": 0, "edges": []}
    with pytest.raises(runner.JobContractError) as caught:
        runner._validate_follow_on_edge_provenance(
            output / "summary.json",
            follow_on=omitted,
            validated_case_reports={parent: report},
        )
    assert caught.value.code == "summary_invalid"
    payload_path.write_bytes(b"NZ retained payload")
    with pytest.raises(runner.JobContractError) as caught:
        runner._validate_follow_on_edge_provenance(
            output / "summary.json",
            follow_on=follow_on,
            validated_case_reports={parent: report},
        )
    assert caught.value.code == "summary_invalid"


def test_parent_promotion_proof_requires_exact_complete_parent_and_child_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    parent = "a" * 64
    child = "b" * 64
    semantic = "c" * 64
    child_proof = {
        "sha256": child,
        "analysis_contract_sha256": "d" * 64,
        "report_semantic_sha256": semantic,
    }
    wrapper = {
        "result": {
            "decoded_config_recovered": True,
            "configuration": {"host": "example.invalid"},
        },
        "verified_binary_outputs": [
            {
                "role": "terminal_payload",
                "kind": "pe",
                "path": "p/child.bin",
                "sha256": child,
                "size": 1,
                "verification": {
                    "status": "artifact_hash_verified",
                    "sha256_matches": True,
                    "size_matches": True,
                },
            }
        ],
        "verified_binary_output_audit": {
            "schema_version": 1,
            "maximum_outputs": 64,
            "maximum_total_size": 256 * 1024 * 1024,
            "binary_values_seen": 1,
            "binary_bytes_seen": 1,
            "traversal_items": 1,
            "observed_output_count": 1,
            "retained_output_count": 1,
            "retained_for_follow_on_analysis": True,
            "follow_on_analysis_complete": True,
            "observation_scope": "parent_rehashed_case_artifact",
            "truncated": False,
            "reasons": [],
        },
        "follow_on_analysis_proof": {
            "schema_version": 1,
            "status": "all_retained_payloads_strict_complete",
            "children": [child_proof],
        },
    }
    record = {
        "source": "selected_family_analysis",
        "family": "valleyrat",
        "handler_id": "test-valleyrat",
        "status": "succeeded",
        "selected_layer_sha256": "e" * 64,
        "result": wrapper,
        "verified_binary_outputs": wrapper["verified_binary_outputs"],
        "verified_binary_output_audit": wrapper["verified_binary_output_audit"],
    }
    quality = runner.orchestration_outcome._execution_quality(record)  # noqa: SLF001
    record["selected_evidence"] = {
        "sufficient": True,
        "tier": quality["tier"],
        "score": quality["score"],
    }
    recomputed_outputs = runner.orchestration_outcome.summarize_handler_outputs(
        [record],
        family_filter="valleyrat",
    )
    monkeypatch.setattr(
        runner,
        "_validated_case_handler_records",
        lambda *_args, **_kwargs: [record],
    )
    for digest, outcome in {
        parent: {
            "status": "complete",
            "blockers": [],
            "family_resolution": {"status": "resolved", "family": "valleyrat"},
            "outputs": recomputed_outputs,
        },
        child: {"status": "complete", "blockers": []},
    }.items():
        case_dir = output / "cases" / digest
        case_dir.mkdir(parents=True)
        (case_dir / "orchestration.json").write_text(json.dumps(outcome), encoding="utf-8")
    reports = {
        parent: {
            "case_state": {"status": "complete"},
            "follow_on_promotion": {
                "schema_version": 1,
                "status": "verified_children_linked",
                "child_analysis_contract_sha256": "d" * 64,
                "children": [child_proof],
            },
        },
        child: {
            "case_state": {"status": "complete"},
            "report_semantic_sha256": semantic,
        },
    }
    follow_on = {
        "promoted_parent_sha256": [parent],
        "edges": [
            {
                "parent_sha256": parent,
                "child_sha256": child,
                "status": "child_complete",
            }
        ],
    }
    contract = {"sha256": "d" * 64}

    runner._validate_parent_promotion_proofs(
        output / "summary.json",
        follow_on=follow_on,
        follow_on_contract=contract,
        validated_case_reports=reports,
        node_case_states={child: "complete"},
    )

    omitted = deepcopy(follow_on)
    omitted["promoted_parent_sha256"] = []
    with pytest.raises(runner.JobContractError):
        runner._validate_parent_promotion_proofs(
            output / "summary.json",
            follow_on=omitted,
            follow_on_contract=contract,
            validated_case_reports=reports,
            node_case_states={child: "complete"},
        )

    incomplete_child = deepcopy(reports)
    incomplete_child[child]["case_state"]["status"] = "partial"
    with pytest.raises(runner.JobContractError):
        runner._validate_parent_promotion_proofs(
            output / "summary.json",
            follow_on=follow_on,
            follow_on_contract=contract,
            validated_case_reports=incomplete_child,
            node_case_states={child: "partial"},
        )

    incomplete_parent = deepcopy(reports)
    incomplete_parent[parent]["case_state"]["status"] = "partial"
    with pytest.raises(runner.JobContractError):
        runner._validate_parent_promotion_proofs(
            output / "summary.json",
            follow_on=follow_on,
            follow_on_contract=contract,
            validated_case_reports=incomplete_parent,
            node_case_states={child: "complete"},
        )

    omitted_internal = deepcopy(record)
    omitted_internal["result"] = deepcopy(wrapper)
    omitted_internal["result"]["follow_on_analysis_proof"]["children"] = []
    monkeypatch.setattr(
        runner,
        "_validated_case_handler_records",
        lambda *_args, **_kwargs: [omitted_internal],
    )
    with pytest.raises(runner.JobContractError):
        runner._validate_parent_promotion_proofs(
            output / "summary.json",
            follow_on=follow_on,
            follow_on_contract=contract,
            validated_case_reports=reports,
            node_case_states={child: "complete"},
        )


def test_production_root_counts_and_follow_on_status_are_bound_to_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "output"
    write_summary(output)
    summary = load_json(output / "summary.json")
    root = "a" * 64
    root_case = {
        "sha256": root,
        "source_name": "sample.bin",
        "family": "unknown",
        "selected_family": None,
        "selected_families": [],
        "automation_family": None,
        "automation_state": "unknown",
        "candidate_handler_attempts": 0,
        "ai_used": False,
        "campaign": "unknown",
        "handler_succeeded": 0,
        "handler_failed": 0,
        "handler_no_evidence": 0,
        "handler_ambiguous": 0,
        "handler_incompatible": 0,
        "analysis_stage_failed": False,
        "analysis_stage_partial": False,
        "case_state": "complete",
        "report": f"cases/{root}/report.json",
        "resumed": False,
    }
    contract = {
        "schema_version": 1,
        "sha256": "d" * 64,
        "settings": {
            "assessment_only": False,
            "family_hint_manifest": None,
            "static_tools": {
                "upx": None,
                "sevenzip": None,
                "diec": None,
            },
        },
    }
    options = dict(runner.DEFAULT_OPTIONS)
    summary["analysis_contract"] = contract
    summary["settings"] = runner._expected_summary_settings(options, contract)
    summary["cases"] = [root_case]
    (output / "summary.json").write_text(json.dumps(summary), encoding="utf-8")
    monkeypatch.setattr(
        runner,
        "_validated_derived_case_report",
        lambda *_args, **_kwargs: {},
    )
    monkeypatch.setattr(runner, "_validate_follow_on_edge_provenance", lambda *_args, **_kwargs: None)

    runner._validated_summary(
        output / "summary.json",
        expected_input_files=1,
        expected_analysis_contract=contract,
        expected_options=options,
        verify_root_cases=True,
    )

    forged_settings = load_json(output / "summary.json")
    forged_settings["settings"]["max_files"] += 1
    (output / "summary.json").write_text(
        json.dumps(forged_settings),
        encoding="utf-8",
    )
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(
            output / "summary.json",
            expected_input_files=1,
            expected_analysis_contract=contract,
            expected_options=options,
            verify_root_cases=True,
        )
    assert caught.value.code == "summary_invalid"
    forged_settings["settings"] = runner._expected_summary_settings(options, contract)
    (output / "summary.json").write_text(
        json.dumps(forged_settings),
        encoding="utf-8",
    )

    forged = load_json(output / "summary.json")
    forged["cases"][0]["case_state"] = "partial"
    (output / "summary.json").write_text(json.dumps(forged), encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(
            output / "summary.json",
            expected_input_files=1,
            expected_analysis_contract=contract,
            expected_options=options,
            verify_root_cases=True,
        )
    assert caught.value.code == "summary_count_mismatch"

    forged["cases"][0]["case_state"] = "complete"
    (output / "summary.json").write_text(json.dumps(forged), encoding="utf-8")
    graph = load_json(output / "follow-on-analysis.json")
    graph.update({"status": "disabled_assessment_only", "nodes": [], "edges": []})
    replace_follow_on(output, graph)
    with pytest.raises(runner.JobContractError) as caught:
        runner._validated_summary(
            output / "summary.json",
            expected_input_files=1,
            expected_analysis_contract=contract,
            expected_options=options,
            verify_root_cases=True,
        )
    assert caught.value.code == "summary_invalid"


def test_request_defaults_are_normalized() -> None:
    request = runner.validate_request_object(request_value())

    assert request.job_id == "job-001"
    assert request.inputs == ("set/sample.bin",)
    assert request.options["archive_mode"] == "auto"
    assert request.options["minimum_confidence"] == "medium"
    assert request.options["max_files"] == runner.MAX_DISCOVERED_FILES
    assert request.options["family"] is None


def test_runtime_preflight_uses_same_interpreter_and_sanitized_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)

    runner.validate_analyzer_runtime.cache_clear()
    monkeypatch.setattr(runner, "run_bounded", fake_run)
    result = runner.validate_analyzer_runtime()
    runner.validate_analyzer_runtime.cache_clear()

    assert len(calls) == 2
    assert all(Path(argv[0]).resolve() == Path(sys.executable).resolve() for argv, _ in calls)
    assert all("-I" in argv for argv, _ in calls)
    assert all(kwargs["shell"] is False for _, kwargs in calls)
    assert all(kwargs["timeout"] == runner.RUNTIME_PREFLIGHT_TIMEOUT_SECONDS for _, kwargs in calls)
    assert all(kwargs["require_containment"] is True for _, kwargs in calls)
    assert all(
        kwargs["maximum_active_processes"] == runner.MAX_RUNTIME_PREFLIGHT_ACTIVE_PROCESSES for _, kwargs in calls
    )
    assert all(kwargs["maximum_memory_bytes"] == runner.MAX_RUNTIME_PREFLIGHT_MEMORY_BYTES for _, kwargs in calls)
    assert all(kwargs["env"]["PYTHONNOUSERSITE"] == "1" for _, kwargs in calls)
    assert all("VT_API_KEY" not in kwargs["env"] for _, kwargs in calls)
    assert result["analyzer_import_verified"] is True
    assert result["automatic_handler_catalog_discovered"] is True
    assert result["handler_dependencies_verified_on_demand"] is True
    assert result["nested_worker_runtime_verified"] is True


def test_runtime_preflight_rejects_user_site_only_dependencies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner.validate_analyzer_runtime.cache_clear()
    monkeypatch.setattr(
        runner,
        "run_bounded",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=1),
    )
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_analyzer_runtime()
    runner.validate_analyzer_runtime.cache_clear()
    assert caught.value.code == "runtime_dependency_unavailable"


def test_analysis_bundle_worker_is_isolated_bounded_and_private(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root, _ = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-bundle"))
    observed: dict[str, Any] = {}
    response = {
        "schema_version": 1,
        "root_analysis_contract": {"schema_version": 1, "sha256": "a" * 64},
        "follow_on_analysis_contract": {"schema_version": 1, "sha256": "b" * 64},
        "input_manifest": [
            {
                "source_name": "sample.bin",
                "unit_source_name": "sample.bin",
                "sha256": "c" * 64,
                "read_succeeded": True,
            }
        ],
    }

    def fake_bounded(command, **kwargs):
        observed["command"] = command
        observed["kwargs"] = kwargs
        return runner._BoundedProcessResult(
            args=command,
            returncode=0,
            stdout=json.dumps(response).encode("utf-8"),
            stderr=b"",
            stdout_truncated=False,
            stderr_truncated=False,
        )

    monkeypatch.setattr(runner, "_run_process_with_bounded_output", fake_bounded)
    root_contract, child_contract, manifest = runner.build_expected_analysis_bundle(
        request,
        [input_root / "set" / "sample.bin"],
        tmp_path / "analysis",
        family_hint_manifest=None,
    )

    command = observed["command"]
    kwargs = observed["kwargs"]
    private_request = json.loads(kwargs["stdin_payload"].decode("utf-8"))
    assert command[0] == str(Path(sys.executable).resolve())
    assert command[1:3] == ["-I", "-B"]
    assert "infected" not in command
    assert private_request["password"] == "infected"
    assert private_request["trusted_tools"] == {
        "upx": None,
        "sevenzip": None,
        "diec": None,
    }
    assert kwargs["shell"] is False
    assert kwargs["env"]["PYTHONNOUSERSITE"] == "1"
    assert kwargs["maximum_stdout_bytes"] == runner.MAX_INPUT_MANIFEST_RESPONSE_BYTES
    assert kwargs["maximum_active_processes"] == runner.MAX_INPUT_MANIFEST_ACTIVE_PROCESSES
    assert kwargs["maximum_memory_bytes"] == runner.MAX_INPUT_MANIFEST_MEMORY_BYTES
    assert kwargs["timeout"] == runner.INPUT_MANIFEST_TIMEOUT_SECONDS
    assert root_contract["sha256"] == "a" * 64
    assert child_contract["sha256"] == "b" * 64
    assert manifest == [runner.ExpectedInputUnit("sample.bin", "sample.bin", "c" * 64, True)]

    response["unexpected"] = True
    with pytest.raises(runner.JobContractError) as caught:
        runner.build_expected_analysis_bundle(
            request,
            [input_root / "set" / "sample.bin"],
            tmp_path / "analysis",
            family_hint_manifest=None,
        )
    assert caught.value.code == "input_manifest_failed"


@pytest.mark.parametrize(
    "forbidden",
    [
        "allow_network",
        "allow_live_c2_check",
        "allow_authentication",
        "collect_jarm",
        "password",
        "python",
        "output",
    ],
)
def test_network_live_and_privileged_options_are_rejected(forbidden: str) -> None:
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_request_object(request_value(**{forbidden: True}))

    assert caught.value.code == "network_or_privileged_option_forbidden"


def test_unknown_keys_and_duplicate_inputs_are_rejected() -> None:
    unknown = request_value()
    unknown["callback"] = "https://example.invalid/"
    with pytest.raises(runner.JobContractError, match="top-level"):
        runner.validate_request_object(unknown)

    duplicate = request_value()
    duplicate["inputs"] = ["set/sample.bin", "SET/SAMPLE.BIN"]
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_request_object(duplicate)
    assert caught.value.code == "duplicate_input"


def test_stdin_request_loader_is_bounded_and_strict() -> None:
    request = runner.load_job_request_from_stdin(io.BytesIO(json.dumps(request_value("job-stdin")).encode("utf-8")))
    assert request.job_id == "job-stdin"

    duplicate_key = b'{"schema_version":1,"job_id":"job-stdin","inputs":["set/sample.bin"],"options":{},"options":{}}'
    with pytest.raises(runner.JobContractError, match="重複"):
        runner.load_job_request_from_stdin(io.BytesIO(duplicate_key))

    with pytest.raises(runner.JobContractError) as caught:
        runner.load_job_request_from_stdin(io.BytesIO(b"x" * (runner.MAX_REQUEST_BYTES + 1)))
    assert caught.value.code == "json_size_out_of_bounds"


def test_validate_cli_uses_stdin_loader_for_dash(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request = runner.validate_request_object(request_value("job-stdin-cli"))
    observed: dict[str, Any] = {}

    monkeypatch.setattr(runner, "load_job_request_from_stdin", lambda: request)

    def fail_file_loader(_path: Path) -> runner.JobRequest:
        raise AssertionError("file loader must not be used for --request -")

    def fake_validate(
        supplied: runner.JobRequest,
        *,
        input_root: Path,
        jobs_root: Path,
        trusted_tool_configuration: runner.TrustedToolConfiguration | None,
    ) -> dict[str, Any]:
        observed.update(
            request=supplied,
            input_root=input_root,
            jobs_root=jobs_root,
            trusted_tool_configuration=trusted_tool_configuration,
        )
        return {"schema_version": 1, "valid": True}

    monkeypatch.setattr(runner, "load_job_request", fail_file_loader)
    monkeypatch.setattr(runner, "validate_job", fake_validate)
    assert (
        runner.main(
            [
                "validate",
                "--request",
                "-",
                "--input-root",
                "input-root",
                "--jobs-root",
                "jobs-root",
            ]
        )
        == 0
    )
    assert observed == {
        "request": request,
        "input_root": Path("input-root"),
        "jobs_root": Path("jobs-root"),
        "trusted_tool_configuration": None,
    }
    assert json.loads(capsys.readouterr().out)["valid"] is True


@pytest.mark.parametrize(
    "value",
    [
        "../sample.bin",
        "set/../sample.bin",
        "C:/sample.bin",
        "/sample.bin",
        "set\\sample.bin",
        "set//sample.bin",
        "set/CON.txt",
        "set/sample.bin.",
    ],
)
def test_ambiguous_or_escaping_input_paths_are_rejected(value: str) -> None:
    request = request_value()
    request["inputs"] = [value]
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_request_object(request)
    assert caught.value.code == "invalid_input_path"


def test_duplicate_json_keys_and_non_finite_numbers_are_rejected(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner.load_json_object_strict(duplicate, max_bytes=1024)
    assert caught.value.code == "duplicate_json_key"

    non_finite = tmp_path / "nan.json"
    non_finite.write_text('{"value":NaN}', encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner.load_json_object_strict(non_finite, max_bytes=1024)
    assert caught.value.code == "non_finite_json_number"

    exponent_overflow = tmp_path / "exponent-overflow.json"
    exponent_overflow.write_text('{"value":1e999}', encoding="utf-8")
    with pytest.raises(runner.JobContractError) as caught:
        runner.load_json_object_strict(exponent_overflow, max_bytes=1024)
    assert caught.value.code == "non_finite_json_number"


def test_atomic_json_refuses_non_finite_output(tmp_path: Path) -> None:
    destination = tmp_path / "result.json"
    with pytest.raises(ValueError):
        runner.atomic_json(destination, {"value": float("inf")})
    assert not destination.exists()


def test_strict_json_rejects_excessive_nesting(tmp_path: Path) -> None:
    nested = tmp_path / "nested.json"
    nested.write_bytes(b'{"value":' + (b"[" * 2_000) + b"0" + (b"]" * 2_000) + b"}")
    with pytest.raises(runner.JobContractError) as caught:
        runner.load_json_object_strict(nested, max_bytes=8_192)
    assert caught.value.code == "json_invalid"


def test_strict_json_rejects_excessive_integer_digits(tmp_path: Path) -> None:
    oversized = tmp_path / "oversized-integer.json"
    oversized.write_bytes(b'{"value":' + (b"9" * 500) + b"}")
    with pytest.raises(runner.JobContractError) as caught:
        runner.load_json_object_strict(oversized, max_bytes=8_192)
    assert caught.value.code == "json_invalid"


def test_strict_json_rejects_hardlinks(tmp_path: Path) -> None:
    original = tmp_path / "original.json"
    linked = tmp_path / "linked.json"
    original.write_text('{"schema_version":1}', encoding="utf-8")
    try:
        os.link(original, linked)
    except (OSError, NotImplementedError):
        pytest.skip("この環境ではhardlinkを作成できません")

    with pytest.raises(runner.JobContractError) as caught:
        runner.load_json_object_strict(linked, max_bytes=1024)

    assert caught.value.code == "json_hardlink_forbidden"


def test_input_tree_count_size_and_overlap_are_fail_closed(tmp_path: Path) -> None:
    input_root, _ = make_roots(tmp_path)
    (input_root / "set" / "second.bin").write_bytes(b"B")
    request = runner.validate_request_object(
        {
            "schema_version": 1,
            "job_id": "job-limits",
            "inputs": ["set"],
            "options": {"max_files": 1},
        }
    )
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_inputs(request, input_root.resolve())
    assert caught.value.code == "input_count_exceeded"

    overlap = runner.validate_request_object(
        {
            "schema_version": 1,
            "job_id": "job-overlap",
            "inputs": ["set", "set/sample.bin"],
        }
    )
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_inputs(overlap, input_root.resolve())
    assert caught.value.code == "overlapping_inputs"


def test_input_and_job_roots_must_be_separate(tmp_path: Path) -> None:
    input_root, _ = make_roots(tmp_path)
    nested_jobs = input_root / "jobs"

    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_roots(input_root, nested_jobs, create_jobs_root=False)
    assert caught.value.code == "root_overlap"
    assert not nested_jobs.exists()

    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_roots(input_root, nested_jobs, create_jobs_root=True)
    assert caught.value.code == "root_overlap"
    assert not nested_jobs.exists()


def test_symlink_input_is_rejected_when_supported(tmp_path: Path) -> None:
    input_root, _ = make_roots(tmp_path)
    target = input_root / "set" / "target.bin"
    target.write_bytes(b"target")
    link = input_root / "set" / "linked.bin"
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("この環境ではsymlinkを作成できません")
    request = runner.validate_request_object({"schema_version": 1, "job_id": "job-link", "inputs": ["set/linked.bin"]})

    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_inputs(request, input_root.resolve())
    assert caught.value.code == "input_reparse_forbidden"


def test_build_argv_uses_only_allowlisted_static_options(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(
        request_value(
            family="valleyrat",
            assessment_only=True,
            force_container_probe=True,
            retry_max_static_layers=128,
        )
    )
    inputs, _ = runner.validate_inputs(request, input_root.resolve())
    argv = runner.build_analyzer_argv(request, inputs, jobs_root / "output")

    assert argv[0] == str(Path(sys.executable).resolve())
    assert argv[1:3] == ["-I", "-B"]
    assert argv[3].endswith("analysis_job_runner.py") is False
    assert argv[3].endswith("analyze_sample.py")
    assert "--family" in argv
    assert "valleyrat" in argv
    assert "--assessment-only" in argv
    assert "--force-container-probe" in argv
    assert "--retry-max-static-layers" in argv
    assert not any("network" in item or "live" in item or "jarm" in item for item in argv)


def test_trusted_tool_manifest_is_pinned_snapshotted_and_forwarded(
    tmp_path: Path,
) -> None:
    """operator toolをjob-private snapshotへ固定し、元pathをargvへ出さない。"""

    input_root, jobs_root = make_roots(tmp_path)
    configuration, _manifest, source = make_trusted_tool_configuration(
        tmp_path,
        sevenzip_bytes=b"synthetic pinned 7zz executable",
    )
    policy = runner.load_trusted_tool_policy(
        configuration,
        forbidden_roots=(input_root.resolve(), jobs_root.resolve()),
    )
    job_dir = jobs_root / "manual-tool-snapshot"
    job_dir.mkdir()
    bundle = runner.stage_trusted_tool_bundle(policy, job_dir=job_dir)
    runner.verify_trusted_tool_bundle(bundle, job_dir=job_dir)

    request = runner.validate_request_object(request_value("job-tool-argv"))
    inputs, _ = runner.validate_inputs(request, input_root.resolve())
    argv = runner.build_analyzer_argv(
        request,
        inputs,
        job_dir / "analysis",
        trusted_tools=bundle,
    )

    forwarded_upx = Path(argv[argv.index("--upx") + 1])
    forwarded_7zz = Path(argv[argv.index("--sevenzip") + 1])
    assert forwarded_upx == bundle.tools["upx"].path
    assert forwarded_7zz == bundle.tools["sevenzip"].path
    assert forwarded_upx != source.resolve()
    assert "--diec" not in argv
    manifest_text = bundle.manifest_path.read_text(encoding="utf-8")
    assert str(source.resolve()) not in manifest_text
    assert bundle.provenance()["tools"] == bundle.identities()


def test_trusted_tool_manifest_and_binary_pins_fail_closed(tmp_path: Path) -> None:
    """manifest raw pinとbinary content pinの不一致を別々に拒否する。"""

    input_root, jobs_root = make_roots(tmp_path)
    configuration, manifest, source = make_trusted_tool_configuration(tmp_path)
    wrong_manifest_pin = runner.TrustedToolConfiguration(
        manifest_path=manifest,
        manifest_sha256="0" * 64,
    )
    with pytest.raises(runner.JobContractError) as captured:
        runner.load_trusted_tool_policy(
            wrong_manifest_pin,
            forbidden_roots=(input_root, jobs_root),
        )
    assert captured.value.code == "trusted_tool_manifest_pin_mismatch"

    source.write_bytes(b"changed after manifest was pinned")
    with pytest.raises(runner.JobContractError) as captured:
        runner.load_trusted_tool_policy(
            configuration,
            forbidden_roots=(input_root, jobs_root),
        )
    assert captured.value.code in {
        "trusted_tool_binary_invalid",
        "trusted_tool_binary_pin_mismatch",
    }


def test_trusted_tool_manifest_rejects_platform_and_unknown_tool_keys(
    tmp_path: Path,
) -> None:
    """host不一致とDIEC等の未許可toolをstrict schemaで拒否する。"""

    input_root, jobs_root = make_roots(tmp_path)
    configuration, manifest, _source = make_trusted_tool_configuration(tmp_path)
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["platform"]["machine"] = "definitely-not-this-host"
    manifest.write_text(json.dumps(document), encoding="utf-8")
    mismatch = runner.TrustedToolConfiguration(
        manifest,
        hashlib.sha256(manifest.read_bytes()).hexdigest(),
    )
    with pytest.raises(runner.JobContractError) as captured:
        runner.load_trusted_tool_policy(
            mismatch,
            forbidden_roots=(input_root, jobs_root),
        )
    assert captured.value.code == "trusted_tool_platform_mismatch"

    configuration, manifest, _source = make_trusted_tool_configuration(tmp_path)
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["tools"]["diec"] = None
    manifest.write_text(json.dumps(document), encoding="utf-8")
    unknown = runner.TrustedToolConfiguration(
        manifest,
        hashlib.sha256(manifest.read_bytes()).hexdigest(),
    )
    with pytest.raises(runner.JobContractError) as captured:
        runner.load_trusted_tool_policy(
            unknown,
            forbidden_roots=(input_root, jobs_root),
        )
    assert captured.value.code == "trusted_tool_manifest_invalid"


def test_trusted_tool_source_must_be_outside_input_job_and_repository_roots(
    tmp_path: Path,
) -> None:
    """検体側やjob側へ置かれた実行fileをoperator toolとして採用しない。"""

    input_root, jobs_root = make_roots(tmp_path)
    configuration, manifest, _source = make_trusted_tool_configuration(tmp_path)
    inside = input_root / "set" / "operator-upx.exe"
    inside.write_bytes(b"not an operator controlled binary")
    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["tools"]["upx"] = {
        "path": str(inside.resolve()),
        "size": inside.stat().st_size,
        "sha256": hashlib.sha256(inside.read_bytes()).hexdigest(),
    }
    manifest.write_text(json.dumps(document), encoding="utf-8")
    configuration = runner.TrustedToolConfiguration(
        manifest,
        hashlib.sha256(manifest.read_bytes()).hexdigest(),
    )
    with pytest.raises(runner.JobContractError) as captured:
        runner.load_trusted_tool_policy(
            configuration,
            forbidden_roots=(input_root, jobs_root),
        )
    assert captured.value.code == "trusted_tool_root_forbidden"


def test_trusted_tool_source_rejects_hardlink_and_duplicate_binary(
    tmp_path: Path,
) -> None:
    """tool sourceの複数linkと異なるtool IDによる同一binary共有を拒否する。"""

    input_root, jobs_root = make_roots(tmp_path)
    configuration, manifest, source = make_trusted_tool_configuration(tmp_path)
    alias = source.with_name("upx-hardlink-alias.exe")
    try:
        os.link(source, alias)
    except (NotImplementedError, OSError) as exc:
        pytest.skip(f"このfilesystemではhardlinkを作成できません: {exc}")
    with pytest.raises(runner.JobContractError) as captured:
        runner.load_trusted_tool_policy(
            configuration,
            forbidden_roots=(input_root, jobs_root),
        )
    assert captured.value.code == "trusted_tool_binary_invalid"
    alias.unlink()

    document = json.loads(manifest.read_text(encoding="utf-8"))
    document["tools"]["sevenzip"] = dict(document["tools"]["upx"])
    manifest.write_text(json.dumps(document), encoding="utf-8")
    duplicate = runner.TrustedToolConfiguration(
        manifest,
        hashlib.sha256(manifest.read_bytes()).hexdigest(),
    )
    with pytest.raises(runner.JobContractError) as captured:
        runner.load_trusted_tool_policy(
            duplicate,
            forbidden_roots=(input_root, jobs_root),
        )
    assert captured.value.code == "trusted_tool_duplicate_binary"


def test_trusted_tool_snapshot_detects_source_and_snapshot_changes(
    tmp_path: Path,
) -> None:
    """validation後のsource変更とsnapshot tree追加を検出する。"""

    input_root, jobs_root = make_roots(tmp_path)
    configuration, _manifest, source = make_trusted_tool_configuration(tmp_path)
    policy = runner.load_trusted_tool_policy(
        configuration,
        forbidden_roots=(input_root, jobs_root),
    )
    source.write_bytes(b"changed between policy validation and snapshot")
    failed_job = jobs_root / "failed-tool-snapshot"
    failed_job.mkdir()
    with pytest.raises(runner.JobContractError) as captured:
        runner.stage_trusted_tool_bundle(policy, job_dir=failed_job)
    assert captured.value.code == "trusted_tool_snapshot_failed"

    configuration, _manifest, _source = make_trusted_tool_configuration(tmp_path)
    policy = runner.load_trusted_tool_policy(
        configuration,
        forbidden_roots=(input_root, jobs_root),
    )
    job_dir = jobs_root / "changed-tool-snapshot"
    job_dir.mkdir()
    bundle = runner.stage_trusted_tool_bundle(policy, job_dir=job_dir)
    extra = job_dir / "contract-inputs" / "static-tools" / "unexpected.bin"
    extra.write_bytes(b"unexpected")
    with pytest.raises(runner.JobContractError) as captured:
        runner.verify_trusted_tool_bundle(bundle, job_dir=job_dir)
    assert captured.value.code == "trusted_tool_snapshot_changed"


def test_trusted_tool_cli_requires_manifest_and_pin_pair(tmp_path: Path) -> None:
    """operator CLI引数の片方だけを指定した場合はfail-closedにする。"""

    configuration, manifest, _source = make_trusted_tool_configuration(tmp_path)
    args = runner.build_parser().parse_args(
        [
            "validate",
            "--request",
            "request.json",
            "--input-root",
            "inputs",
            "--jobs-root",
            "jobs",
            "--trusted-tools-manifest",
            str(manifest),
        ]
    )
    with pytest.raises(runner.JobContractError) as captured:
        runner._trusted_tool_configuration_from_args(args)
    assert captured.value.code == "trusted_tool_configuration_incomplete"

    args.trusted_tools_manifest_sha256 = configuration.manifest_sha256
    assert runner._trusted_tool_configuration_from_args(args) == configuration


def test_family_hint_manifest_is_validated_separately_and_forwarded(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    manifest = input_root / "hints" / "job.json"
    manifest.parent.mkdir()
    manifest.write_text(
        json.dumps({"schema_version": 1, "samples": {"0" * 64: "valleyrat"}}),
        encoding="utf-8",
    )
    value = request_value("job-manifest")
    value["family_hint_manifest"] = "hints/job.json"
    request = runner.validate_request_object(value)
    inputs, _ = runner.validate_inputs(request, input_root.resolve())

    validated = runner.validate_family_hint_manifest(request, input_root.resolve(), inputs)
    argv = runner.build_analyzer_argv(
        request,
        inputs,
        jobs_root / "output",
        family_hint_manifest=validated,
    )

    assert validated == manifest.resolve()
    assert argv[argv.index("--family-hint-manifest") + 1] == str(manifest.resolve())
    assert "hints/job.json" not in [str(path) for path in inputs]


def test_family_hint_manifest_must_be_strict_json_and_not_overlap_inputs(tmp_path: Path) -> None:
    input_root, _ = make_roots(tmp_path)
    malformed = input_root / "malformed.json"
    malformed.write_text('{"schema_version":NaN}', encoding="utf-8")
    value = request_value("job-malformed-manifest")
    value["family_hint_manifest"] = "malformed.json"
    request = runner.validate_request_object(value)
    inputs, _ = runner.validate_inputs(request, input_root.resolve())
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_family_hint_manifest(request, input_root.resolve(), inputs)
    assert caught.value.code == "non_finite_json_number"

    inside = input_root / "set" / "hints.json"
    inside.write_text("{}", encoding="utf-8")
    overlapping = {
        "schema_version": 1,
        "job_id": "job-overlapping-manifest",
        "inputs": ["set"],
        "family_hint_manifest": "set/hints.json",
    }
    request = runner.validate_request_object(overlapping)
    inputs, _ = runner.validate_inputs(request, input_root.resolve())
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_family_hint_manifest(request, input_root.resolve(), inputs)
    assert caught.value.code == "manifest_overlaps_inputs"


def test_family_hint_manifest_size_and_direct_input_reuse_are_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    duplicate = request_value("job-duplicate-manifest")
    duplicate["family_hint_manifest"] = "set/sample.bin"
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_request_object(duplicate)
    assert caught.value.code == "manifest_is_input"

    input_root, _ = make_roots(tmp_path)
    manifest = input_root / "large.json"
    manifest.write_text('{"value":"larger than test cap"}', encoding="utf-8")
    value = request_value("job-large-manifest")
    value["family_hint_manifest"] = "large.json"
    request = runner.validate_request_object(value)
    inputs, _ = runner.validate_inputs(request, input_root.resolve())
    monkeypatch.setattr(runner, "MAX_FAMILY_HINT_MANIFEST_BYTES", 8)
    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_family_hint_manifest(request, input_root.resolve(), inputs)
    assert caught.value.code == "json_size_out_of_bounds"


def test_run_job_passes_only_an_immutable_job_local_manifest_copy(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    manifest = input_root / "hints.json"
    manifest.write_text(json.dumps({"schema_version": 1, "samples": {"0" * 64: "valleyrat"}}), encoding="utf-8")
    value = request_value("job-canonical-manifest")
    value["family_hint_manifest"] = "hints.json"
    request = runner.validate_request_object(value)
    observed: dict[str, Any] = {}

    def fake_run(argv: list[str], **_: Any) -> SimpleNamespace:
        staged = Path(argv[argv.index("--family-hint-manifest") + 1])
        observed["staged"] = staged
        observed["before"] = staged.read_bytes()
        manifest.write_text('{"changed":true}', encoding="utf-8")
        observed["after"] = staged.read_bytes()
        write_summary(Path(argv[argv.index("--output") + 1]))
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    assert exit_code == 0
    assert observed["staged"] != manifest.resolve()
    assert observed["staged"] == jobs_root / "job-canonical-manifest" / "contract-inputs" / "family-hint-manifest.json"
    assert observed["before"] == observed["after"]
    result = load_json(jobs_root / "job-canonical-manifest" / "result.json")
    assert result["artifacts"]["family_hint_manifest"] == "contract-inputs/family-hint-manifest.json"
    assert len(result["artifacts"]["family_hint_manifest_sha256"]) == 64


def test_child_environment_does_not_inherit_api_keys_or_python_injection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VT_API_KEY", "secret")
    monkeypatch.setenv("TRIAGE_API_KEY", "secret")
    monkeypatch.setenv("MAXMIND_LICENSE_KEY", "secret")
    monkeypatch.setenv("PYTHONPATH", "C:/untrusted")
    monkeypatch.setenv("PYTHONHOME", "C:/untrusted")
    monkeypatch.setenv("TEMP", "C:/untrusted-temp")
    monkeypatch.setenv("TMP", "C:/untrusted-tmp")
    monkeypatch.setenv("TMPDIR", "C:/untrusted-tmpdir")

    environment = runner.build_sanitized_environment()

    assert "VT_API_KEY" not in environment
    assert "TRIAGE_API_KEY" not in environment
    assert "MAXMIND_LICENSE_KEY" not in environment
    assert "PYTHONPATH" not in environment
    assert "PYTHONHOME" not in environment
    assert "TEMP" not in environment
    assert "TMP" not in environment
    assert "TMPDIR" not in environment
    assert environment["PYTHONNOUSERSITE"] == "1"


def test_complete_job_writes_atomic_machine_readable_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-complete"))
    captured: dict[str, Any] = {}
    monkeypatch.setenv("VT_API_KEY", "must-not-leak")

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        captured["argv"] = argv
        captured["kwargs"] = kwargs
        temporary_paths = {Path(kwargs["env"][name]) for name in ("TEMP", "TMP", "TMPDIR")}
        assert len(temporary_paths) == 1
        temporary_root = temporary_paths.pop()
        assert temporary_root.name == runner.PRIVATE_TEMP_DIRECTORY_NAME
        assert temporary_root.parent == Path(argv[argv.index("--output") + 1])
        transient = temporary_root / "transient.bin"
        transient.write_bytes(b"temporary sample-derived bytes")
        transient.unlink()
        output = Path(argv[argv.index("--output") + 1])
        write_summary(output)
        return SimpleNamespace(returncode=0, stdout=b'{"complete": 1}\n', stderr=b"")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    job_dir = jobs_root / "job-complete"
    assert exit_code == 0
    assert captured["kwargs"]["shell"] is False
    assert captured["kwargs"]["check"] is False
    assert captured["kwargs"]["cwd"] == runner.REPOSITORY_ROOT
    assert "VT_API_KEY" not in captured["kwargs"]["env"]
    assert load_json(job_dir / "status.json")["state"] == "completed"
    result = load_json(job_dir / "result.json")
    assert result["accepted"] is True
    assert result["analysis_state"] == "complete"
    assert result["safety"]["network_contacted"] is False
    assert result["safety"]["ai_used"] is False
    assert result["process"]["shell"] is False
    assert result["derived_counts"]["analyzed"] == 0
    assert result["follow_on_analysis"]["status"] == "no_retained_payloads"
    assert result["artifacts"]["follow_on_analysis"] == "analysis/follow-on-analysis.json"
    assert load_json(job_dir / "progress.json")["percent"] == 100
    assert not (job_dir / "analysis" / runner.PRIVATE_TEMP_DIRECTORY_NAME).exists()
    assert not list(job_dir.rglob("*.tmp"))

    snapshot = runner.read_job_snapshot(jobs_root, "job-complete")
    assert snapshot["status"]["terminal"] is True
    assert snapshot["result"]["accepted"] is True


def test_complete_job_records_trusted_tool_provenance(
    tmp_path: Path,
) -> None:
    """jobはsnapshotだけをanalyzerへ渡し、resultと公開schemaへprovenanceを残す。"""

    input_root, jobs_root = make_roots(tmp_path)
    configuration, _manifest, source = make_trusted_tool_configuration(tmp_path)
    request = runner.validate_request_object(request_value("job-trusted-tool"))
    observed: dict[str, Path] = {}

    def fake_run(argv: list[str], **_: Any) -> SimpleNamespace:
        observed["upx"] = Path(argv[argv.index("--upx") + 1])
        write_summary(Path(argv[argv.index("--output") + 1]))
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
        trusted_tool_configuration=configuration,
    )

    job_dir = jobs_root / "job-trusted-tool"
    result = load_json(job_dir / "result.json")
    assert exit_code == 0
    assert observed["upx"] != source.resolve()
    assert observed["upx"].is_relative_to(job_dir / "contract-inputs" / "static-tools")
    assert result["trusted_static_tools"]["profile_id"] == "test-pinned-tools"
    assert result["trusted_static_tools"]["tools"]["upx"]["sha256"] == (hashlib.sha256(source.read_bytes()).hexdigest())
    assert result["artifacts"]["trusted_static_tools_manifest"] == ("contract-inputs/trusted-static-tools.json")
    assert len(result["artifacts"]["trusted_static_tools_manifest_sha256"]) == 64
    snapshot = runner.read_job_snapshot(jobs_root, "job-trusted-tool")
    assert snapshot["result"]["trusted_static_tools"] == result["trusted_static_tools"]


def test_completed_job_rejects_residual_private_temp_entry(tmp_path: Path) -> None:
    """解析processが残した一時fileを公開成果物として黙認しない。"""

    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-private-temp-residual"))

    def fake_run(argv: list[str], **kwargs: Any) -> SimpleNamespace:
        output = Path(argv[argv.index("--output") + 1])
        write_summary(output)
        Path(kwargs["env"]["TEMP"]).joinpath("leftover.bin").write_bytes(b"payload")
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    job_dir = jobs_root / "job-private-temp-residual"
    assert exit_code == 2
    result = load_json(job_dir / "result.json")
    assert result["accepted"] is False
    assert result["error"]["code"] == "private_temp_not_empty"
    assert load_json(job_dir / "status.json")["state"] == "failed"


def test_private_temp_finalizer_rejects_hardlinked_entry(tmp_path: Path) -> None:
    """一時領域でもhardlinkをquota／tree検証より先へ通さない。"""

    analysis_output = tmp_path / "analysis"
    analysis_output.mkdir()
    binding = runner.prepare_job_private_temp(analysis_output)
    original = binding.path / "original.bin"
    linked = binding.path / "linked.bin"
    original.write_bytes(b"sample-derived")
    try:
        os.link(original, linked)
    except OSError as exc:
        pytest.skip(f"hardlinkを作成できない環境です: {exc}")

    with pytest.raises(runner.JobContractError) as caught:
        runner.finalize_job_private_temp(binding, analysis_output=analysis_output)

    assert caught.value.code == "analysis_output_hardlink_forbidden"


def test_malwarebazaar_mixed_directory_counts_only_zip_for_analyzer(tmp_path: Path) -> None:
    """README等も検証するがsummary期待件数にはZIPだけを使う。"""

    input_root, jobs_root = make_roots(tmp_path)
    (input_root / "set" / "sample.bin").unlink()
    (input_root / "set" / "one.zip").write_bytes(b"PK synthetic")
    (input_root / "set" / "README.txt").write_text("説明", encoding="utf-8")
    value = request_value("job-malwarebazaar", archive_mode="malwarebazaar")
    value["inputs"] = ["set"]
    request = runner.validate_request_object(value)

    def fake_run(argv: list[str], **_: Any) -> SimpleNamespace:
        write_summary(Path(argv[argv.index("--output") + 1]))
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    assert exit_code == 0
    result = load_json(jobs_root / "job-malwarebazaar" / "result.json")
    assert result["inputs"][0]["file_count"] == 2
    assert result["inputs"][0]["analyzer_file_count"] == 1
    assert result["counts"]["input_files"] == 1


def test_analyzer_partial_exit_is_preserved(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-partial"))

    def fake_run(argv: list[str], **_: Any) -> SimpleNamespace:
        write_summary(
            Path(argv[argv.index("--output") + 1]),
            count_overrides={"complete": 0, "partial": 1},
        )
        return SimpleNamespace(returncode=20, stdout=b"partial", stderr=b"")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    assert exit_code == 20
    assert load_json(jobs_root / "job-partial" / "status.json")["state"] == "completed_partial"
    assert load_json(jobs_root / "job-partial" / "result.json")["analysis_state"] == "partial"


def test_triaged_unknown_is_accepted_as_completed_partial(tmp_path: Path) -> None:
    """未分類triageの実行成功と解析完了を分離し、jobは受理済みpartialにする。"""

    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-triaged-unknown"))

    def fake_run(argv: list[str], **_: Any) -> SimpleNamespace:
        write_summary(
            Path(argv[argv.index("--output") + 1]),
            count_overrides={"complete": 0, "triaged_unknown": 1},
        )
        return SimpleNamespace(returncode=20, stdout=b"triaged", stderr=b"")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    result = load_json(jobs_root / "job-triaged-unknown" / "result.json")
    assert exit_code == 20
    assert result["accepted"] is True
    assert result["analysis_state"] == "partial"
    assert result["process"]["exit_code"] == 20
    assert load_json(jobs_root / "job-triaged-unknown" / "status.json")["state"] == ("completed_partial")


def test_analyzer_exit_code_must_match_validated_summary(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-exit-summary-mismatch"))

    def fake_run(argv: list[str], **_: Any) -> SimpleNamespace:
        write_summary(Path(argv[argv.index("--output") + 1]))
        return SimpleNamespace(returncode=20, stdout=b"", stderr=b"")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    result = load_json(jobs_root / "job-exit-summary-mismatch" / "result.json")
    assert exit_code == 2
    assert result["error"]["code"] == "analyzer_exit_summary_mismatch"


def test_summary_claiming_network_contact_is_rejected(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-network-claim"))

    def fake_run(argv: list[str], **_: Any) -> SimpleNamespace:
        write_summary(Path(argv[argv.index("--output") + 1]), network_contacted=True)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    result = load_json(jobs_root / "job-network-claim" / "result.json")
    assert exit_code == 2
    assert result["accepted"] is False
    assert result["error"]["code"] == "analyzer_safety_contract_failed"


def test_summary_claiming_ai_use_is_rejected(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-ai-claim"))

    def fake_run(argv: list[str], **_: Any) -> SimpleNamespace:
        write_summary(Path(argv[argv.index("--output") + 1]), ai_used=True)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    result = load_json(jobs_root / "job-ai-claim" / "result.json")
    assert exit_code == 2
    assert result["safety"]["ai_used"] is False
    assert result["error"]["code"] == "analyzer_safety_contract_failed"


def test_inconsistent_summary_counts_are_rejected(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-count-mismatch"))

    def fake_run(argv: list[str], **_: Any) -> SimpleNamespace:
        write_summary(
            Path(argv[argv.index("--output") + 1]),
            count_overrides={"input_files": 2},
        )
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    result = load_json(jobs_root / "job-count-mismatch" / "result.json")
    assert exit_code == 2
    assert result["error"]["code"] == "summary_count_mismatch"


def test_analysis_output_size_quota_is_enforced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-output-quota"))
    monkeypatch.setattr(runner, "MAX_ANALYSIS_OUTPUT_BYTES", 8)

    def fake_run(argv: list[str], **_: Any) -> SimpleNamespace:
        output = Path(argv[argv.index("--output") + 1])
        write_summary(output)
        return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    result = load_json(jobs_root / "job-output-quota" / "result.json")
    assert exit_code == 2
    assert result["error"]["code"] == "analysis_output_size_quota_exceeded"


def test_default_process_runner_drains_and_truncates_both_streams() -> None:
    size = runner.MAX_LOG_BYTES + 4096
    script = (
        "import sys;"
        f"sys.stdout.buffer.write(b'A'*{size});sys.stdout.buffer.flush();"
        f"sys.stderr.buffer.write(b'B'*{size});sys.stderr.buffer.flush()"
    )

    completed = runner._run_process_with_bounded_output(
        [sys.executable, "-c", script],
        cwd=runner.REPOSITORY_ROOT,
        env=runner.build_sanitized_environment(),
        shell=False,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=30,
    )

    assert completed.returncode == 0
    assert completed.stdout == b"A" * runner.MAX_LOG_BYTES
    assert completed.stderr == b"B" * runner.MAX_LOG_BYTES
    assert completed.stdout_truncated is True
    assert completed.stderr_truncated is True


def test_default_process_runner_closes_containment_after_normal_parent_exit(
    tmp_path: Path,
) -> None:
    """親が正常終了しても、Job／process group内の遅延子processを残さない。"""

    spawned = tmp_path / "child-spawned.txt"
    escaped = tmp_path / "child-escaped.txt"
    child_code = (
        "import pathlib,sys,time;time.sleep(0.75);pathlib.Path(sys.argv[1]).write_text('escaped',encoding='ascii')"
    )
    parent_code = (
        "import pathlib,subprocess,sys;"
        "child=subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);"
        "pathlib.Path(sys.argv[3]).write_text(str(child.pid),encoding='ascii')"
    )

    completed = runner._run_process_with_bounded_output(
        [sys.executable, "-c", parent_code, child_code, str(escaped), str(spawned)],
        cwd=runner.REPOSITORY_ROOT,
        env=runner.build_sanitized_environment(),
        shell=False,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        maximum_active_processes=4,
        maximum_memory_bytes=512 * 1024 * 1024,
    )

    assert completed.returncode == 0
    assert spawned.is_file()
    time.sleep(1.0)
    assert not escaped.exists()


def test_default_process_runner_terminates_owned_tree_on_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    aborted: list[bool] = []
    abort = runner.ProcessContainment.abort

    def recording_abort(containment: runner.ProcessContainment) -> None:
        aborted.append(True)
        abort(containment)

    monkeypatch.setattr(runner.ProcessContainment, "abort", recording_abort)
    with pytest.raises(subprocess.TimeoutExpired):
        runner._run_process_with_bounded_output(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=runner.REPOSITORY_ROOT,
            env=runner.build_sanitized_environment(),
            shell=False,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=0.1,
        )

    assert aborted == [True]


def test_default_process_runner_times_out_while_large_stdin_is_not_read() -> None:
    """pipe容量を超えるstdinをchildが読まなくてもwall-clock timeoutを適用する。"""

    started = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired) as caught:
        runner._run_process_with_bounded_output(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=runner.REPOSITORY_ROOT,
            env=runner.build_sanitized_environment(),
            shell=False,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=0.2,
            stdin_payload=b"X" * (2 * 1024 * 1024),
        )

    assert caught.value.timeout == 0.2
    assert time.monotonic() - started < 10


def test_default_process_runner_delivers_private_stdin_and_eof() -> None:
    """stdin writerはpayload全体とEOFを送り、従来のworker契約を維持する。"""

    payload = b"bounded private worker request"
    completed = runner._run_process_with_bounded_output(
        [
            sys.executable,
            "-c",
            ("import sys;payload=sys.stdin.buffer.read();sys.stdout.buffer.write(payload[::-1])"),
        ],
        cwd=runner.REPOSITORY_ROOT,
        env=runner.build_sanitized_environment(),
        shell=False,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        stdin_payload=payload,
    )

    assert completed.returncode == 0
    assert completed.stdout == payload[::-1]
    assert completed.stderr == b""
    assert completed.stdout_truncated is False
    assert completed.stderr_truncated is False


@pytest.mark.parametrize("failure_index", [1, 2, 3])
def test_default_process_runner_aborts_when_io_thread_start_fails(
    monkeypatch: pytest.MonkeyPatch,
    failure_index: int,
) -> None:
    """stdout、stderr、stdinの各thread初期化失敗でprocess treeを回収する。"""

    original_start = runner.threading.Thread.start
    original_abort = runner.ProcessContainment.abort
    starts = 0
    aborted: list[bool] = []

    def failing_start(thread: threading.Thread) -> None:
        nonlocal starts
        starts += 1
        if starts == failure_index:
            raise RuntimeError("synthetic thread start failure")
        original_start(thread)

    def recording_abort(containment: runner.ProcessContainment) -> None:
        aborted.append(True)
        original_abort(containment)

    monkeypatch.setattr(runner.threading.Thread, "start", failing_start)
    monkeypatch.setattr(runner.ProcessContainment, "abort", recording_abort)

    with pytest.raises(RuntimeError, match="synthetic thread start failure"):
        runner._run_process_with_bounded_output(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            cwd=runner.REPOSITORY_ROOT,
            env=runner.build_sanitized_environment(),
            shell=False,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            stdin_payload=b"request",
        )

    assert starts == failure_index
    assert aborted == [True]


def test_default_process_runner_stops_during_output_quota_excess(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "analysis"
    output.mkdir()
    monkeypatch.setattr(runner, "MAX_ANALYSIS_OUTPUT_BYTES", 1024)
    monkeypatch.setattr(runner, "MIN_FREE_DISK_RESERVE_BYTES", 1)
    monkeypatch.setattr(runner, "OUTPUT_MONITOR_INTERVAL_SECONDS", 0.05)
    script = (
        "from pathlib import Path;import sys,time;"
        "Path(sys.argv[1]).joinpath('large.bin').write_bytes(b'X'*8192);time.sleep(30)"
    )

    with pytest.raises(runner.JobContractError) as caught:
        runner._run_process_with_bounded_output(
            [sys.executable, "-c", script, str(output)],
            cwd=runner.REPOSITORY_ROOT,
            env=runner.build_sanitized_environment(),
            shell=False,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
            monitored_output=output,
        )

    assert caught.value.code == "analysis_output_size_quota_exceeded"


def _raise_transient_output_scan_failure(
    *,
    access_denied: bool = False,
    code: str = "analysis_output_reparse_forbidden",
) -> None:
    """削除済み一時directoryを列挙した実障害と同じcause chainを再現する。"""

    if access_denied:
        transient = PermissionError(13, "synthetic delete-pending directory", "handler-assessment-test")
        transient.winerror = 5
    else:
        transient = FileNotFoundError(2, "synthetic missing directory", "handler-assessment-test")
    try:
        raise transient
    except OSError as tree_changed:
        try:
            raise ValueError("case treeを安全に走査できません") from tree_changed
        except ValueError as scan_error:
            raise runner.JobContractError(
                code,
                "解析出力にreparse pointが含まれています",
            ) from scan_error


def test_live_output_scan_retries_only_transient_disappearance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """live treeから消えたentryは再試行し、安定snapshotだけを受理する。"""

    expected = {"entries": 0, "files": 0, "directories": 0, "total_bytes": 0}
    successful_attempts = 0

    def transient_then_stable(_path: Path) -> dict[str, int]:
        nonlocal successful_attempts
        successful_attempts += 1
        if successful_attempts == 1:
            _raise_transient_output_scan_failure()
        return expected

    monkeypatch.setattr(runner, "validate_analysis_output_tree", transient_then_stable)

    assert runner._validate_live_analysis_output_tree(tmp_path) == expected
    assert successful_attempts == 2

    access_denied_attempts = 0

    def access_denied_then_stable(_path: Path) -> dict[str, int]:
        nonlocal access_denied_attempts
        access_denied_attempts += 1
        if access_denied_attempts == 1:
            _raise_transient_output_scan_failure(access_denied=True)
        return expected

    monkeypatch.setattr(runner, "validate_analysis_output_tree", access_denied_then_stable)

    assert runner._validate_live_analysis_output_tree(tmp_path) == expected
    assert access_denied_attempts == 2

    exhausted_attempts = 0

    def always_transient(_path: Path) -> dict[str, int]:
        nonlocal exhausted_attempts
        exhausted_attempts += 1
        _raise_transient_output_scan_failure(access_denied=True)
        raise AssertionError("到達不能")

    monkeypatch.setattr(runner, "validate_analysis_output_tree", always_transient)
    with pytest.raises(runner.JobContractError) as caught:
        runner._validate_live_analysis_output_tree(tmp_path)

    assert caught.value.code == "analysis_output_changed_during_scan"
    assert str(caught.value) == "解析出力treeがlive検証中に継続して変更されました"
    assert exhausted_attempts == runner.MAX_LIVE_OUTPUT_SCAN_ATTEMPTS


def test_live_output_scan_never_retries_actual_reparse(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """実reparse検出はlive scanでも即時にfail-closedとする。"""

    attempts = 0

    def actual_reparse(_path: Path) -> dict[str, int]:
        nonlocal attempts
        attempts += 1
        try:
            raise ValueError("reparse pointを含むcase tree")
        except ValueError as scan_error:
            raise runner.JobContractError(
                "analysis_output_reparse_forbidden",
                "解析出力にreparse pointが含まれています",
            ) from scan_error

    monkeypatch.setattr(runner, "validate_analysis_output_tree", actual_reparse)
    with pytest.raises(runner.JobContractError) as caught:
        runner._validate_live_analysis_output_tree(tmp_path)

    assert caught.value.code == "analysis_output_reparse_forbidden"
    assert attempts == 1

    quota_attempts = 0

    def unrelated_quota_failure(_path: Path) -> dict[str, int]:
        nonlocal quota_attempts
        quota_attempts += 1
        _raise_transient_output_scan_failure(code="analysis_output_size_quota_exceeded")
        raise AssertionError("到達不能")

    monkeypatch.setattr(runner, "validate_analysis_output_tree", unrelated_quota_failure)
    with pytest.raises(runner.JobContractError) as unrelated:
        runner._validate_live_analysis_output_tree(tmp_path)

    assert unrelated.value.code == "analysis_output_size_quota_exceeded"
    assert quota_attempts == 1


def test_nonaccepted_exit_code_is_a_terminal_failure(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-failed"))

    def fake_run(*_: Any, **__: Any) -> SimpleNamespace:
        return SimpleNamespace(returncode=9, stdout=b"", stderr=b"failure")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    result = load_json(jobs_root / "job-failed" / "result.json")
    assert exit_code == 1
    assert result["error"]["code"] == "analyzer_exit_nonzero"
    assert result["process"]["exit_code"] == 9


def test_timeout_is_recorded_without_retry(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-timeout"))
    calls = 0

    def fake_run(*_: Any, **__: Any) -> SimpleNamespace:
        nonlocal calls
        calls += 1
        raise subprocess.TimeoutExpired(["python"], timeout=60, output=b"bounded", stderr=b"timeout")

    exit_code = runner._run_job_for_test(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
        run_process=fake_run,
    )

    result = load_json(jobs_root / "job-timeout" / "result.json")
    assert calls == 1
    assert exit_code == 124
    assert result["analysis_state"] == "timed_out"
    assert result["error"]["code"] == "analyzer_timeout"
    assert not (jobs_root / "job-timeout" / "analysis" / ".private-temp").exists()


def test_existing_job_id_is_never_reused(tmp_path: Path) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-existing"))
    (jobs_root / "job-existing").mkdir()

    with pytest.raises(runner.JobContractError) as caught:
        runner.run_job(request, input_root=input_root, jobs_root=jobs_root, timeout_seconds=60)
    assert caught.value.code == "job_already_exists"


def test_validate_job_performs_runtime_probe_without_job_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root, jobs_root = make_roots(tmp_path)
    request = runner.validate_request_object(request_value("job-validate"))
    monkeypatch.setattr(
        runner,
        "validate_analyzer_runtime",
        lambda: {
            "python_implementation": "cpython",
            "python_version": "3.13.0",
            "user_site_enabled": False,
            "analyzer_import_verified": True,
            "nested_worker_runtime_verified": True,
        },
    )

    result = runner.validate_job(request, input_root=input_root, jobs_root=jobs_root)

    assert result["valid"] is True
    assert result["network_or_live_options_allowed"] is False
    assert result["ai_used"] is False
    assert result["runtime"]["nested_worker_runtime_verified"] is True
    assert not (jobs_root / "job-validate").exists()


def test_real_analyzer_runs_with_sanitized_environment(tmp_path: Path) -> None:
    runner.validate_analyzer_runtime.cache_clear()
    try:
        runner.validate_analyzer_runtime()
    except runner.JobContractError as exc:
        pytest.skip(f"このinterpreterはsanitized runtime要件を満たしません: {exc.code}")
    input_root, jobs_root = make_roots(tmp_path, data=b"synthetic offline static analysis input")
    request = runner.validate_request_object(
        request_value(
            "job-real-smoke",
            archive_mode="raw",
            assessment_only=True,
            max_files=1,
            max_file_size=1024 * 1024,
            string_scan_limit=100,
            max_static_layers=4,
        )
    )

    exit_code = runner.run_job(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
    )

    assert exit_code in {0, 20}
    result = load_json(jobs_root / "job-real-smoke" / "result.json")
    assert result["accepted"] is True
    assert result["safety"]["summary_safety_contract_verified"] is True
    assert result["safety"]["ai_used"] is False
    assert (jobs_root / "job-real-smoke" / "analysis" / "summary.json").is_file()


def test_input_snapshot_rejects_original_hardlink(tmp_path: Path) -> None:
    input_root, _ = make_roots(tmp_path)
    source = input_root / "set" / "sample.bin"
    alias = input_root / "set" / "alias.bin"
    try:
        os.link(source, alias)
    except OSError as exc:
        pytest.skip(f"このfilesystemではhardlink testを実行できません: {exc}")
    request = runner.validate_request_object(request_value("job-hardlink"))

    with pytest.raises(runner.JobContractError) as caught:
        runner.validate_inputs(request, input_root.resolve())

    assert caught.value.code == "input_hardlink_forbidden"


@pytest.mark.parametrize("mutation", ["replace", "grow"])
def test_input_snapshot_rejects_change_after_validation(
    tmp_path: Path,
    mutation: str,
) -> None:
    input_root, _ = make_roots(tmp_path, data=b"original")
    request = runner.validate_request_object(request_value(f"job-changed-{mutation}"))
    _, records = runner.validate_inputs(request, input_root.resolve())
    source = input_root / "set" / "sample.bin"
    if mutation == "replace":
        replacement = source.with_suffix(".replacement")
        replacement.write_bytes(b"replaced")
        os.replace(replacement, source)
    else:
        source.write_bytes(b"original-and-grown")
    job_dir = tmp_path / "jobs" / request.job_id
    job_dir.mkdir(parents=True)

    with pytest.raises(runner.JobContractError) as caught:
        runner.stage_input_snapshots(
            request,
            records,
            input_root=input_root.resolve(),
            job_dir=job_dir,
        )

    assert caught.value.code == "input_changed_after_validation"


def test_input_snapshot_detects_snapshot_mutation(tmp_path: Path) -> None:
    input_root, _ = make_roots(tmp_path, data=b"immutable")
    request = runner.validate_request_object(request_value("job-snapshot-mutation"))
    _, records = runner.validate_inputs(request, input_root.resolve())
    job_dir = tmp_path / "jobs" / request.job_id
    job_dir.mkdir(parents=True)
    bundle = runner.stage_input_snapshots(
        request,
        records,
        input_root=input_root.resolve(),
        job_dir=job_dir,
    )
    snapshot = bundle.inputs[0].path
    os.chmod(snapshot, stat.S_IWRITE | stat.S_IREAD)
    snapshot.write_bytes(b"tampered!")

    with pytest.raises(runner.JobContractError) as caught:
        runner.verify_input_snapshot_bundle(bundle, job_dir=job_dir)

    assert caught.value.code == "input_snapshot_changed"


def test_input_snapshot_checks_required_capacity_before_copy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root, _ = make_roots(tmp_path, data=b"capacity")
    request = runner.validate_request_object(request_value("job-snapshot-capacity"))
    _, records = runner.validate_inputs(request, input_root.resolve())
    job_dir = tmp_path / "jobs" / request.job_id
    job_dir.mkdir(parents=True)
    required = sum(binding.information.st_size for record in records for binding in record.source_files)
    monkeypatch.setattr(
        runner.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(free=required + runner.MIN_FREE_DISK_RESERVE_BYTES - 1),
    )

    with pytest.raises(runner.JobContractError) as caught:
        runner.stage_input_snapshots(
            request,
            records,
            input_root=input_root.resolve(),
            job_dir=job_dir,
        )

    assert caught.value.code == "input_snapshot_disk_reserve_exceeded"
    assert not (job_dir / "contract-inputs" / "samples").exists()


def test_input_snapshot_flattens_same_names_without_collision(tmp_path: Path) -> None:
    input_root = tmp_path / "inputs"
    for directory, payload in (("a", b"A"), ("b", b"B")):
        path = input_root / "set" / directory / "same.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    value = request_value("job-same-names", archive_mode="raw")
    value["inputs"] = ["set"]
    request = runner.validate_request_object(value)
    job_dir = tmp_path / "jobs" / request.job_id
    job_dir.mkdir(parents=True)
    _, records = runner.validate_inputs(request, input_root.resolve())

    bundle = runner.stage_input_snapshots(
        request,
        records,
        input_root=input_root.resolve(),
        job_dir=job_dir,
    )

    assert [item.source_relative_path for item in bundle.inputs] == [
        "set/a/same.bin",
        "set/b/same.bin",
    ]
    assert [item.path.name for item in bundle.inputs] == ["same.bin", "same.bin"]
    assert bundle.inputs[0].path.parent != bundle.inputs[1].path.parent
    assert [item.path.parent.name for item in bundle.inputs] == ["000000", "000001"]
    runner.verify_input_snapshot_bundle(bundle, job_dir=job_dir)


def test_malwarebazaar_snapshot_filters_zip_and_preserves_collect_order(
    tmp_path: Path,
) -> None:
    input_root = tmp_path / "inputs"
    fixtures = {
        "set/z/last.zip": b"last",
        "set/a/first.ZIP": b"first",
        "set/a/ignored.txt": b"ignored",
    }
    for relative, payload in fixtures.items():
        path = input_root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    value = request_value("job-malwarebazaar-snapshot", archive_mode="malwarebazaar")
    value["inputs"] = ["set"]
    request = runner.validate_request_object(value)
    job_dir = tmp_path / "jobs" / request.job_id
    job_dir.mkdir(parents=True)
    _, records = runner.validate_inputs(request, input_root.resolve())

    bundle = runner.stage_input_snapshots(
        request,
        records,
        input_root=input_root.resolve(),
        job_dir=job_dir,
    )

    assert records[0].file_count == 3
    assert records[0].analyzer_file_count == 2
    assert [item.source_relative_path for item in bundle.inputs] == [
        "set/a/first.ZIP",
        "set/z/last.zip",
    ]
    assert [item.path.parent.name for item in bundle.inputs] == ["000000", "000001"]
    assert bundle.manifest_document["file_count"] == 2


def test_production_workers_receive_only_job_private_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_root, jobs_root = make_roots(tmp_path, data=b"production snapshot")
    request = runner.validate_request_object(request_value("job-production-snapshot"))
    captured: dict[str, list[Path]] = {}
    monkeypatch.setattr(runner, "validate_analyzer_runtime", lambda: {})

    def fake_bundle(
        _request: runner.JobRequest,
        inputs: list[Path],
        _analysis_output: Path,
        **_: Any,
    ) -> tuple[dict[str, Any], dict[str, Any], list[runner.ExpectedInputUnit]]:
        captured["bundle"] = list(inputs)
        digest = hashlib.sha256(inputs[0].read_bytes()).hexdigest()
        static_tools = {"upx": None, "sevenzip": None, "diec": None}
        return (
            {
                "schema_version": 1,
                "sha256": "a" * 64,
                "settings": {"static_tools": static_tools},
            },
            {
                "schema_version": 1,
                "sha256": "b" * 64,
                "settings": {"static_tools": static_tools},
            },
            [
                runner.ExpectedInputUnit(
                    source_name=inputs[0].name,
                    unit_source_name=inputs[0].name,
                    sha256=digest,
                    read_succeeded=True,
                )
            ],
        )

    def stop_before_analyzer(argv: list[str], **_: Any) -> SimpleNamespace:
        captured["analyzer"] = [Path(argv[index + 1]) for index, value in enumerate(argv) if value == "--input"]
        raise runner.JobContractError("test_stop_before_analyzer", "test stop")

    monkeypatch.setattr(runner, "build_expected_analysis_bundle", fake_bundle)
    monkeypatch.setattr(runner, "_run_process_with_bounded_output", stop_before_analyzer)

    exit_code = runner.run_job(
        request,
        input_root=input_root,
        jobs_root=jobs_root,
        timeout_seconds=60,
    )

    expected_root = jobs_root / request.job_id / "contract-inputs" / "samples"
    assert exit_code == 2
    assert captured["bundle"] == captured["analyzer"]
    assert all(path.is_relative_to(expected_root) for path in captured["bundle"])
    assert (input_root / "set" / "sample.bin").resolve() not in captured["bundle"]
    result = load_json(jobs_root / request.job_id / "result.json")
    assert result["error"]["code"] == "test_stop_before_analyzer"
