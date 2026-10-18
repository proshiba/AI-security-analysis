"""PureLogsの実detector・handler・one-shot接続を回帰検証する。"""

from __future__ import annotations

import base64
import hashlib
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMMON_ROOT = REPOSITORY_ROOT / "analysis-framework" / "common"
CLASSIFIERS_ROOT = REPOSITORY_ROOT / "analysis-framework" / "classifiers"
for import_root in (REPOSITORY_ROOT, COMMON_ROOT, CLASSIFIERS_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

import analyze_sample as one_shot
from handler_catalog import (
    assess_candidate_handlers,
    discover_handlers,
    preflight_handler_for_assessment,
)

REGISTRY = REPOSITORY_ROOT / "analysis-framework" / "registry" / "malware_types.json"
HANDLER_ID = "purelogs:extractors.purelogs.extractor.py:extract"


def _varint(value: int) -> bytes:
    """非負整数をprotobuf varintへ変換する。"""

    encoded = bytearray()
    while value > 0x7F:
        encoded.append((value & 0x7F) | 0x80)
        value >>= 7
    encoded.append(value)
    return bytes(encoded)


def _bytes_field(number: int, value: bytes) -> bytes:
    """protobufのlength-delimited fieldを作る。"""

    return _varint(number << 3 | 2) + _varint(len(value)) + value


def _integer_field(number: int, value: int) -> bytes:
    """protobufのvarint fieldを作る。"""

    return _varint(number << 3) + _varint(value)


def _purelogs_fixture() -> bytes:
    """実行能力を持たないPureLogs設定・protocol証拠を作る。"""

    config = (
        _bytes_field(1, b"logs.example.test")
        + _integer_field(2, 8443)
        + _bytes_field(3, b"K" * 32)
        + _bytes_field(4, b"campaign-fixture")
    )
    return b"PureLogs /plugin /userinfo /filesearch/req /finish " + base64.b64encode(config)


def _handler_spec():
    values = [item for item in discover_handlers() if item.id == HANDLER_ID]
    assert len(values) == 1
    return values[0]


def _detector_evaluation(data: bytes) -> dict:
    classification = one_shot.classify_sample.classify_bytes(
        data,
        Path("purelogs-static-fixture.bin"),
        REGISTRY,
    )
    assert classification["malware_type"] == "purelogs"
    return next(item for item in classification["detector_evaluations"] if item["malware_type"] == "purelogs")


def test_real_handler_preflight_accepts_static_operations() -> None:
    """実extractorの依存closureを静的処理だけとして受理する。"""

    preflight = preflight_handler_for_assessment(
        _handler_spec(),
        actual_format="data",
        input_size=len(_purelogs_fixture()),
    )

    assert preflight["eligible"] is True, preflight["blockers"]
    assert preflight["blockers"] == []
    assert preflight["sample_execution_allowed"] is False
    assert preflight["network_allowed"] is False
    assert preflight["filesystem_write_allowed"] is False
    assert preflight["dependency_audit"]["issues"] == []


def test_real_candidate_assessment_correlates_detector_and_config_on_same_layer() -> None:
    """同じ静的layerの独立detectorと復号設定だけをfamily確定へ使う。"""

    data = _purelogs_fixture()
    digest = hashlib.sha256(data).hexdigest()
    evaluation = _detector_evaluation(data)
    assessment = assess_candidate_handlers(
        ["purelogs"],
        [
            {
                "name": "purelogs-static-fixture.bin",
                "data": data,
                "sha256": digest,
                "parent_sha256": None,
                "depth": 0,
                "transform": "submission",
            }
        ],
        detector_evaluations={"purelogs": {digest: evaluation}},
        specs=[_handler_spec()],
        handler_timeout_seconds=30,
    )

    assert assessment["status"] == "confirmed"
    assert assessment["confirmed_families"] == ["purelogs"]
    attempt = assessment["families"][0]["attempts"][0]
    assert attempt["status"] == "corroborated"
    assert attempt["layer"]["sha256"] == digest
    assert attempt["detector_corroboration"]["layer_sha256"] == digest
    assert attempt["detector_corroboration"]["lineage_distance"] == 0
    result = attempt["result"]["result"]
    assert result["config"]["static_config_recovered"] is True
    assert result["config"]["configured_endpoints"] == ["logs.example.test:8443"]
    assert result["executed"] is False
    assert result["network_contacted"] is False


def test_family_unspecified_one_shot_projects_purelogs_config_and_c2(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """family未指定CLI相当の経路で実handler結果を標準成果物へ反映する。"""

    data = _purelogs_fixture()
    digest = hashlib.sha256(data).hexdigest()
    unit = one_shot.InputUnit(
        source_name="purelogs-static-fixture.bin",
        data=data,
        input_kind="raw",
        outer_sha256=digest,
        outer_size=len(data),
    )
    monkeypatch.setattr(
        one_shot,
        "_run_generic_triage",
        lambda _layers, _case_dir, **_kwargs: (
            {
                "analysis_coverage": {"status": "complete"},
                "executed_sample": False,
                "network_contacted": False,
            },
            "complete",
        ),
    )
    output = tmp_path / "out"

    one_shot.analyze_unit(
        unit,
        output=output,
        registry=REGISTRY,
        specs=[_handler_spec()],
        registered={"purelogs"},
        forced_family=None,
        minimum_confidence="medium",
        assessment_only=False,
        analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
    )

    case_dir = output / "cases" / digest
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    patterns = json.loads((case_dir / "communication-patterns.json").read_text(encoding="utf-8"))
    c2 = json.loads((case_dir / "c2-analysis.json").read_text(encoding="utf-8"))

    assert report["classification"]["selected_family"] == "purelogs"
    assert report["classification"]["automation_family"] == "purelogs"
    assert len(report["handler_executions"]) == 1
    execution = report["handler_executions"][0]
    assert execution["handler_id"] == HANDLER_ID
    assert execution["status"] == "succeeded"
    assert execution["selected_layer_sha256"] == digest
    assert report["candidate_handler_assessment"]["status"] == "no_candidates"
    assert patterns["family"] == "purelogs"
    assert patterns["config"]["static_config_recovered"] is True
    assert any(item["value"] == "logs.example.test:8443" for item in patterns["communication"]["candidate_patterns"])
    phases = {item["phase"]: item for item in c2["phase_evidence"]}
    assert phases["family_config_extraction"]["status"] == "completed"
    assert phases["c2_endpoint_extraction"]["status"] == "completed"
    assert patterns["safety"]["sample_executed"] is False
    assert patterns["safety"]["network_contacted"] is False
