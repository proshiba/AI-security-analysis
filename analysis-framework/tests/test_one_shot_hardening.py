"""一括静的解析パイプラインの失敗閉鎖と網羅性を回帰検証する。"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import zipfile

import pyzipper
import pytest


FRAMEWORK_ROOT = Path(__file__).resolve().parents[1]
COMMON_ROOT = FRAMEWORK_ROOT / "common"
REPOSITORY_ROOT = FRAMEWORK_ROOT.parent
for trusted in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT):
    value = str(trusted)
    if value not in sys.path:
        sys.path.insert(0, value)

import analyze_sample as one_shot  # noqa: E402
import profiled_family_detector  # noqa: E402
from analysis_contract import (  # noqa: E402
    handler_result_quality,
    runtime_dependency_versions,
    seal_report,
)
from extractors import profiled_family  # noqa: E402
from handler_catalog import HandlerSpec, discover_handlers, sanitize_public_value  # noqa: E402


REGISTRY = FRAMEWORK_ROOT / "registry" / "malware_types.json"


def _classification(family: str | None) -> dict:
    """合成レイヤー用の最小分類結果を返す。"""

    if family is None:
        return {
            "schema_version": 1,
            "malware_type": "unknown",
            "malware_type_confidence": "low",
            "campaign_type": "unknown",
            "attribution_basis": "no_unique_detector_match",
            "observations": {},
            "campaign_candidates": [],
        }
    return {
        "schema_version": 1,
        "malware_type": family,
        "malware_type_confidence": "high",
        "campaign_type": "unknown",
        "attribution_basis": "detector_unique",
        "observations": {},
        "campaign_candidates": [],
    }


def _handler_spec(family: str) -> HandlerSpec:
    """合成family用の自動handler仕様を返す。"""

    return HandlerSpec(
        id=f"{family}:fixture:extract",
        family=family,
        relative_path=f"extractors/{family}.py",
        callable_name="extract",
        invocation="bytes",
        source="fixture",
        automatic=True,
        campaign=None,
        supported_interface=True,
        reason="bounded_fixture",
        input_formats=("data",),
        input_contract_source="declared_contract",
        minimum_evidence_score=1,
    )


def test_assessment_only_case_is_complete_and_resumable(tmp_path: Path) -> None:
    """適用可否判定だけの正常caseも、明示的な完了状態として再開可能にする。"""

    sample = tmp_path / "assessment.bin"
    sample.write_bytes(b"bounded assessment-only fixture")
    output = tmp_path / "out"
    summary = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        assessment_only=True,
    )

    report = json.loads((output / summary["cases"][0]["report"]).read_text(encoding="utf-8"))
    assert report["case_state"] == {
        "status": "assessment_only_complete",
        "complete": True,
        "resumable": True,
        "blockers": [],
        "detector_error_families": [],
        "static_layer_issues": [],
        "incomplete_selected_layer_attempts": [],
    }


def test_each_selected_family_uses_only_its_own_layer(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """複数familyを含む外装でも、各handlerを対応レイヤーへ一度ずつ適用する。"""

    root_data = b"synthetic multi-family wrapper"
    child_a = b"family-a static payload"
    child_b = b"family-b static payload"
    root_hash = hashlib.sha256(root_data).hexdigest()
    layer_a = one_shot.StaticLayer(
        name="wrapper.bin::family_a",
        data=child_a,
        sha256=hashlib.sha256(child_a).hexdigest(),
        parent_sha256=root_hash,
        depth=1,
        transform="family_a",
    )
    layer_b = one_shot.StaticLayer(
        name="wrapper.bin::family_b",
        data=child_b,
        sha256=hashlib.sha256(child_b).hexdigest(),
        parent_sha256=root_hash,
        depth=1,
        transform="family_b",
    )
    root = one_shot.StaticLayer(
        name="wrapper.bin",
        data=root_data,
        sha256=root_hash,
        parent_sha256=None,
        depth=0,
        transform="submission",
    )
    layers = [root, layer_a, layer_b]
    layer_report = {
        "schema_version": 1,
        "counts": {
            "layers": 3,
            "recovered_layers": 2,
            "recovered_bytes": len(child_a) + len(child_b),
            "limit_events": 0,
        },
        "steps": [],
        "limit_events": [],
        "layers": [layer.public() for layer in layers],
        "executed_sample": False,
        "network_contacted": False,
        "recovered_content_exported": False,
    }

    monkeypatch.setattr(one_shot, "recover_static_layers", lambda _unit, **_kwargs: (layers, layer_report))

    def classify(data: bytes, *_args, **_kwargs) -> dict:
        if data == child_a:
            return _classification("family_a")
        if data == child_b:
            return _classification("family_b")
        return _classification(None)

    monkeypatch.setattr(one_shot.classify_sample, "classify_bytes", classify)
    monkeypatch.setattr(
        one_shot,
        "_preflight_applicable",
        lambda _specs, applicability: [
            {"handler_id": item["id"], "available": True, "error": None}
            for item in applicability
            if item["status"] in {"applicable", "applicable_forced"}
        ],
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

    calls: list[tuple[str, bytes]] = []

    def execute(spec: HandlerSpec, data: bytes, _source_name: str, **_kwargs) -> dict:
        calls.append((spec.family, data))
        return {
            "status": "completed",
            "preflight": {"eligible": True, "blockers": []},
            "handler_timeout_seconds": 30.0,
            "execution": {
                "handler": spec.public(),
                "result": {
                    "decoded_config_recovered": True,
                    "config": {
                        "family": spec.family,
                        "endpoint": f"{spec.family}.example.org:443",
                    },
                },
                "executed_sample": False,
                "network_contacted": False,
            },
        }

    monkeypatch.setattr(one_shot, "execute_handler_bounded_for_assessment", execute)
    unit = one_shot.InputUnit(
        source_name="wrapper.bin",
        data=root_data,
        input_kind="raw",
        outer_sha256=root_hash,
        outer_size=len(root_data),
    )
    result = one_shot.analyze_unit(
        unit,
        output=tmp_path / "out",
        registry=REGISTRY,
        specs=[_handler_spec("family_a"), _handler_spec("family_b")],
        registered={"family_a", "family_b"},
        forced_family=None,
        minimum_confidence="medium",
        assessment_only=False,
        analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
    )

    assert result["selected_families"] == ["family_a", "family_b"]
    assert calls == [("family_a", child_a), ("family_b", child_b)]
    report = json.loads((tmp_path / "out" / "cases" / root_hash / "report.json").read_text(encoding="utf-8"))
    assert {item["handler_id"]: item["selected_layer_sha256"] for item in report["handler_executions"]} == {
        "family_a:fixture:extract": layer_a.sha256,
        "family_b:fixture:extract": layer_b.sha256,
    }
    assert all(item["status"] == "succeeded" for item in report["handler_executions"])


def test_case_handler_attempt_budget_is_partial_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """layer数がcase budgetを超えても1回だけ実行し、成功へ昇格しない。"""

    root_data = b"bounded wrapper"
    children = [b"family-a payload one", b"family-a payload two"]
    root_hash = hashlib.sha256(root_data).hexdigest()
    root = one_shot.StaticLayer(
        name="wrapper.bin",
        data=root_data,
        sha256=root_hash,
        parent_sha256=None,
        depth=0,
        transform="submission",
    )
    child_layers = [
        one_shot.StaticLayer(
            name=f"wrapper.bin::child-{index}",
            data=data,
            sha256=hashlib.sha256(data).hexdigest(),
            parent_sha256=root_hash,
            depth=1,
            transform="fixture",
        )
        for index, data in enumerate(children)
    ]
    layers = [root, *child_layers]
    layer_report = {
        "schema_version": 1,
        "counts": {
            "layers": len(layers),
            "recovered_layers": len(child_layers),
            "recovered_bytes": sum(len(value) for value in children),
            "limit_events": 0,
        },
        "steps": [],
        "limit_events": [],
        "layers": [layer.public() for layer in layers],
        "executed_sample": False,
        "network_contacted": False,
        "recovered_content_exported": False,
    }
    monkeypatch.setattr(one_shot, "MAX_HANDLER_ATTEMPTS_PER_CASE", 1)
    monkeypatch.setattr(
        one_shot,
        "recover_static_layers",
        lambda _unit, **_kwargs: (layers, layer_report),
    )
    monkeypatch.setattr(
        one_shot.classify_sample,
        "classify_bytes",
        lambda data, *_args, **_kwargs: (
            _classification("family_a") if data in children else _classification(None)
        ),
    )
    monkeypatch.setattr(
        one_shot,
        "_preflight_applicable",
        lambda _specs, applicability: [
            {"handler_id": item["id"], "available": True, "error": None}
            for item in applicability
            if item["status"] == "applicable"
        ],
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
    calls: list[bytes] = []

    def execute(spec: HandlerSpec, data: bytes, _source_name: str, **_kwargs) -> dict:
        calls.append(data)
        return {
            "status": "completed",
            "preflight": {"eligible": True, "blockers": []},
            "execution": {
                "handler": spec.public(),
                "result": {
                    "decoded_config_recovered": True,
                    "config": {
                        "family": spec.family,
                        "endpoint": "family-a.example.org:443",
                    },
                },
                "executed_sample": False,
                "network_contacted": False,
            },
        }

    monkeypatch.setattr(one_shot, "execute_handler_bounded_for_assessment", execute)
    unit = one_shot.InputUnit(
        source_name="wrapper.bin",
        data=root_data,
        input_kind="raw",
        outer_sha256=root_hash,
        outer_size=len(root_data),
    )
    one_shot.analyze_unit(
        unit,
        output=tmp_path / "out",
        registry=REGISTRY,
        specs=[_handler_spec("family_a")],
        registered={"family_a"},
        forced_family=None,
        minimum_confidence="medium",
        assessment_only=False,
        analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
    )

    report = json.loads(
        (tmp_path / "out" / "cases" / root_hash / "report.json").read_text(encoding="utf-8")
    )
    execution = report["handler_executions"][0]
    assert len(calls) == 1
    assert execution["status"] == "ambiguous_evidence"
    assert execution["resource_budget_truncated"] is True
    assert execution["resource_budget_reason"] == "handler_attempt_limit"
    assert report["case_state"]["status"] == "partial"


def test_equivalent_pe_padding_parent_child_results_are_not_ambiguous() -> None:
    """padding除去前後の直系親子で同一configなら真の競合にしない。"""

    root_data = b"memory-region-with-padding"
    child_data = b"normalized-pe"
    root = one_shot.StaticLayer(
        name="memory.dmp",
        data=root_data,
        sha256=hashlib.sha256(root_data).hexdigest(),
        parent_sha256=None,
        depth=0,
        transform="submission",
    )
    child = one_shot.StaticLayer(
        name="memory.dmp::pe-overlay-padding-removed",
        data=child_data,
        sha256=hashlib.sha256(child_data).hexdigest(),
        parent_sha256=root.sha256,
        depth=1,
        transform="pe-overlay-padding-removed",
    )

    def execution(layer: one_shot.StaticLayer) -> dict:
        return {
            "handler": {"id": "family_a:fixture:extract"},
            "result": {
                "family": "family_a",
                "sample_sha256": layer.sha256,
                "config": {
                    "source_name": layer.name,
                    "endpoints": ["example.invalid:443"],
                },
            },
            "executed_sample": False,
            "network_contacted": False,
        }

    strongest = [
        ({"score": 100, "sufficient": True}, 0, root, execution(root)),
        ({"score": 100, "sufficient": True}, -1, child, execution(child)),
    ]
    assert one_shot._equivalent_pe_padding_handler_layers(strongest) == sorted(
        [root.sha256, child.sha256]
    )

    child_different = copy.deepcopy(execution(child))
    child_different["result"]["config"]["endpoints"] = ["other.invalid:443"]
    different_results = [
        strongest[0],
        ({"score": 100, "sufficient": True}, -1, child, child_different),
    ]
    assert one_shot._equivalent_pe_padding_handler_layers(different_results) == []

    other_transform = one_shot.StaticLayer(
        name="memory.dmp::other",
        data=child_data,
        sha256=child.sha256,
        parent_sha256=root.sha256,
        depth=1,
        transform="fixture",
    )
    wrong_transform = [
        strongest[0],
        ({"score": 100, "sufficient": True}, -1, other_transform, execution(other_transform)),
    ]
    assert one_shot._equivalent_pe_padding_handler_layers(wrong_transform) == []


@pytest.mark.parametrize(
    ("label", "layer_report"),
    [
        (
            "step_failed",
            {
                "counts": {"limit_events": 0},
                "steps": [{"status": "failed"}],
                "limit_events": [],
            },
        ),
        (
            "depth_limit",
            {
                "counts": {"limit_events": 0},
                "steps": [{"status": "skipped_depth_limit"}],
                "limit_events": [],
            },
        ),
        (
            "bounded_limit",
            {
                "counts": {"limit_events": 1},
                "steps": [{"status": "succeeded"}],
                "limit_events": [{"reason": "layer_count_limit"}],
            },
        ),
    ],
)
def test_static_layer_incompleteness_makes_case_partial(label: str, layer_report: dict) -> None:
    """復元失敗、深度打切り、量的上限到達を完全解析として扱わない。"""

    completion = one_shot._completion_state(
        assessment_only=False,
        generic_status="complete",
        layer_report=layer_report,
        layer_selections=[],
        selected_families=[],
        applicability=[],
        executions=[],
        logic_report={"status": "complete"},
    )
    assert completion["status"] == "partial", label
    assert completion["complete"] is False
    assert completion["resumable"] is False


def test_profile_validation_miss_is_not_a_static_layer_failure() -> None:
    """profile候補の非該当は復元失敗ではなく、正常なnegative判定として扱う。"""

    layer_report = {
        "counts": {"limit_events": 0},
        "steps": [
            {
                "status": "succeeded",
                "report": {
                    "profiled_transforms": {
                        "status": "no_profile_recovered_artifact",
                        "attempts": [{"status": "validation_failed"}],
                    }
                },
            }
        ],
        "limit_events": [],
    }
    completion = one_shot._completion_state(
        assessment_only=False,
        generic_status="complete",
        layer_report=layer_report,
        layer_selections=[],
        selected_families=[],
        applicability=[],
        executions=[],
        logic_report={"status": "complete"},
    )
    assert completion["status"] == "partial"
    assert completion["complete"] is False
    assert completion["resumable"] is False
    assert completion["blockers"] == ["representative_function_analysis_required"]
def test_successful_sevenzip_cab_fallback_is_complete() -> None:
    """LZX非対応の内蔵CAB parser失敗を、完全な代替抽出成功後に残さない。"""

    issues = one_shot._static_layer_issues(
        {
            "steps": [
                {
                    "status": "succeeded",
                    "report": {
                        "format": "cab",
                        "unpack_status": "artifacts_recovered",
                        "cab": {
                            "status": "parse_failed",
                            "error": "NotSupportedError: LZX compression not supported",
                        },
                        "sevenzip": {
                            "status": "extracted",
                            "extract_exit_code": 0,
                            "inventory": [{"name": "payload.bin", "status": "extracted"}],
                        },
                    },
                }
            ]
        }
    )
    assert issues == []


def test_successful_sevenzip_dotnet_bundle_fallback_is_complete() -> None:
    """.NET bundleの内蔵parser失敗は、7-Zipの完全展開で補完できる。"""

    issues = one_shot._static_layer_issues(
        {
            "steps": [
                {
                    "status": "succeeded",
                    "report": {
                        "format": "pe",
                        "unpack_status": "artifacts_recovered",
                        "dotnet_bundle": {"status": "parse_failed", "error": "unsupported bundle"},
                        "sevenzip": {
                            "status": "extracted",
                            "extract_exit_code": 0,
                            "inventory": [{"name": "payload.dll", "status": "extracted"}],
                        },
                    },
                }
            ]
        }
    )
    assert issues == []


def test_embedded_pe_dotnet_bundle_recovery_supersedes_outer_parse_failure() -> None:
    """外層の誤ったbundle parse失敗は、同一embedded PEの完全復元で補完する。"""

    child_sha256 = "a" * 64
    issues = one_shot._static_layer_issues(
        {
            "steps": [
                {
                    "status": "succeeded",
                    "input_layer": {"sha256": "b" * 64},
                    "report": {
                        "dotnet_bundle": {"status": "parse_failed", "error": "invalid offset"},
                        "recovered": [
                            {"kind": "embedded-pe", "sha256": child_sha256, "size": 100}
                        ],
                    },
                },
                {
                    "status": "succeeded",
                    "input_layer": {"sha256": child_sha256},
                    "report": {"dotnet_bundle": {"status": "recovered"}},
                },
            ]
        }
    )

    assert issues == []

def test_recover_static_layers_honors_explicit_layer_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLIから渡した静的復元層上限を共通パイプラインへ伝播する。"""

    observed: dict[str, int] = {}

    def fake_pipeline(unit: object, **kwargs: object) -> tuple[list[object], dict[str, object]]:
        observed["max_layers"] = kwargs["policy"].max_layers  # type: ignore[union-attr]
        return [], {}

    monkeypatch.setattr(one_shot, "recover_layer_pipeline", fake_pipeline)
    data = b"MZfixture"
    unit = one_shot.InputUnit(
        source_name="sample.exe",
        data=data,
        input_kind="raw",
        outer_sha256=hashlib.sha256(data).hexdigest(),
        outer_size=len(data),
    )

    one_shot.recover_static_layers(unit, max_static_layers=256)

    assert observed == {"max_layers": 256}

def test_layer_count_limit_detection_is_reason_specific() -> None:
    """段階再試行は層数上限だけで発火し、他の制限では発火しない。"""

    assert one_shot._layer_count_limit_reached(
        {"limit_events": [{"reason": "layer_count_limit"}]}
    )
    assert not one_shot._layer_count_limit_reached(
        {"limit_events": [{"reason": "recovered_total_limit"}]}
    )
    assert not one_shot._layer_count_limit_reached({"limit_events": "invalid"})


def test_parser_accepts_adaptive_static_layer_limits() -> None:
    """CLIで初回上限と再試行上限を別々に指定できる。"""

    args = one_shot.build_parser().parse_args(
        [
            "--input",
            "sample.zip",
            "--output",
            "out",
            "--max-static-layers",
            "64",
            "--retry-max-static-layers",
            "256",
        ]
    )
    assert args.max_static_layers == 64
    assert args.retry_max_static_layers == 256

def test_embedded_installer_recovery_supersedes_partial_sevenzip() -> None:
    """専用parserが全recordを復元した場合、補助7-Zip失敗をblockerにしない。"""

    issues = one_shot._static_layer_issues(
        {
            "steps": [
                {
                    "status": "succeeded",
                    "report": {
                        "format": "pe",
                        "unpack_status": "artifacts_recovered",
                        "embedded_installer_archive": {
                            "status": "artifacts_recovered",
                            "record_count": 2,
                        },
                        "sevenzip": {
                            "status": "partially_extracted",
                            "extract_exit_code": 2,
                            "inventory": [{"name": "package.dat", "status": "empty_file"}],
                        },
                    },
                }
            ]
        }
    )
    assert issues == []


@pytest.mark.parametrize(
    ("name", "data"),
    [("stage.cab", b"MSCFfixture"), ("stage.a3x", b"opaque")],
)
def test_generic_triage_delegates_recovered_container_layers(name: str, data: bytes, tmp_path: Path) -> None:
    """復元済みcontainer layerはstatic pipelineへ委譲し、二重の未実装判定を避ける。"""

    result = one_shot.analyze_family_sample.analyze(
        name,
        data,
        tmp_path,
        persist_normalized_text=False,
        recurse_archives=False,
    )
    assert result["format_specific_analysis"] == "delegated_to_static_layer_pipeline"
    assert result["analysis_coverage"]["status"] == "complete"


def _raw_unit(name: str, data: bytes) -> one_shot.InputUnit:
    digest = hashlib.sha256(data).hexdigest()
    return one_shot.InputUnit(
        source_name=name,
        data=data,
        input_kind="raw",
        outer_sha256=digest,
        outer_size=len(data),
    )


def test_one_shot_static_layers_recover_nested_aes_zip() -> None:
    """nested AES ZIPへ受入passwordを伝播し、script名を保持した層を復元する。"""

    stream = io.BytesIO()
    with pyzipper.AESZipFile(
        stream,
        "w",
        compression=pyzipper.ZIP_DEFLATED,
        encryption=pyzipper.WZ_AES,
    ) as archive:
        archive.setpassword(b"infected")
        archive.setencryption(pyzipper.WZ_AES, nbits=256)
        archive.writestr("stage/payload.ps1", b"Write-Output 'fixture'")

    layers, report = one_shot.recover_static_layers(
        _raw_unit("protected.zip", stream.getvalue()),
        archive_password="infected",
    )
    recovered = [item for item in layers if item.depth == 1]
    assert len(recovered) == 1
    assert recovered[0].transform == "zip-script-payload.ps1"
    assert recovered[0].public()["format"] == "script"
    assert report["counts"]["limit_events"] == 0


def test_one_shot_static_layers_propagate_remaining_quotas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """unpacker既定値より先にone-shotの残量quotaとpasswordを適用する。"""

    calls = []

    def fake_unpack(_data: bytes, _name: str, **kwargs):
        calls.append(kwargs)
        return {"format": "data", "unpack_status": "no_artifact_recovered"}, []

    monkeypatch.setattr(one_shot, "unpack_bytes", fake_unpack)
    one_shot.recover_static_layers(
        _raw_unit("sample.bin", b"fixture"),
        archive_password="infected",
    )
    assert len(calls) == 1
    assert calls[0]["archive_password"] == "infected"
    assert calls[0]["max_archive_members"] == one_shot.MAX_ARCHIVE_MEMBERS
    assert calls[0]["max_archive_member_size"] == one_shot.MAX_RECOVERED_LAYER_SIZE
    assert calls[0]["max_archive_total_size"] == one_shot.MAX_RECOVERED_TOTAL_SIZE
    assert calls[0]["max_archive_compression_ratio"] == one_shot.MAX_STATIC_COMPRESSION_RATIO


def test_external_container_without_extractor_is_always_partial() -> None:
    """一部carve済みcontainerとcontainerized PEも外部展開なしでは完了扱いしない。"""

    archive_issues = one_shot._static_layer_issues(
        {
            "steps": [
                {
                    "status": "succeeded",
                    "report": {
                        "format": "rar",
                        "unpack_status": "artifacts_recovered",
                        "recovered": [{"kind": "carved-pe"}],
                    },
                }
            ]
        }
    )
    pe_issues = one_shot._static_layer_issues(
        {
            "steps": [
                {
                    "status": "succeeded",
                    "report": {
                        "format": "pe",
                        "unpack_status": "artifacts_recovered",
                        "pe": {"containerized": True},
                    },
                }
            ]
        }
    )
    assert any("container_extractor_unavailable" in item for item in archive_issues)
    assert any("pe_container_extractor_unavailable" in item for item in pe_issues)


def test_static_layers_recover_payload_at_shared_depth_four() -> None:
    """generic側と同じ深度4までnested ZIP内payloadを層として到達可能にする。"""

    blob = b"Write-Output 'depth fixture'"
    member_name = "payload.ps1"
    for index in range(4):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w") as archive:
            archive.writestr(member_name, blob)
        blob = stream.getvalue()
        member_name = f"layer-{index}.zip"

    layers, _report = one_shot.recover_static_layers(_raw_unit("outer.zip", blob))
    assert one_shot.MAX_STATIC_DEPTH == 6
    assert any(item.depth == 4 and item.public()["format"] == "script" for item in layers)


def test_generic_triage_prefers_magic_over_script_suffix(tmp_path: Path) -> None:
    """拡張子がscriptでも、PE magicをscript本文より先に判定する。"""

    result = one_shot.analyze_family_sample.analyze(
        "masquerading.js",
        b"MZ" + b"\0" * 64,
        tmp_path,
        persist_normalized_text=False,
    )
    assert result["type"] == "pe"
    assert "pe_error" in result
    assert result["analysis_coverage"]["status"] == "partial"


def test_generic_triage_prefers_binary_magic_over_script_suffix(tmp_path: Path) -> None:
    """PNG magicを持つ偽装ps1をscriptとして本文保存・完全扱いしない。"""

    result = one_shot.analyze_family_sample.analyze(
        "masquerading.ps1",
        b"\x89PNG\r\n\x1a\n" + b"\0" * 64,
        tmp_path,
        persist_normalized_text=False,
    )
    assert result["type"] == "png"
    assert result["analysis_coverage"]["status"] == "partial"
    assert "script" not in result


def test_generic_ioc_domains_reject_out_of_range_ports() -> None:
    """domain候補の範囲外portをIOCへ残さない。"""

    iocs = one_shot.analyze_family_sample.extract_iocs([{"value": "good.example.org:443 bad.example.org:99999"}])
    assert "good.example.org:443" in iocs["domains"]
    assert "bad.example.org:99999" not in iocs["domains"]


def test_profile_detector_and_extractor_agree_on_tail_window() -> None:
    """大容量入力の末尾windowにある相関証拠を検出器と抽出器で同じように扱う。"""

    tail = b"AsyncRAT Client HwidGen Hosts https://8.8.8.8/gate"
    data = b"\0" * (8 * 1024 * 1024 + 128) + tail
    extracted = profiled_family.extract_family("asyncrat", data, "sample.bin")
    detected = profiled_family_detector.detect_family("asyncrat", data, Path("sample.bin"))

    assert extracted["config"]["profile_literal_correlation"] is True
    assert detected["matched"] is True
    assert detected["observations"]["profile_literal_correlation"] is True


def test_profile_handlers_accept_script_layers() -> None:
    """共有profile抽出器をPEだけでなく検出対象のscript層にも適用できるようにする。"""

    profiled = [item for item in discover_handlers() if item.source == "profiled_shared_extractor"]
    assert profiled
    assert all({"pe", "script"} <= set(item.input_formats) for item in profiled)


def test_bounded_payload_adapter_accepts_apple_disk_image() -> None:
    """macOS系handlerでDMG rootを形式不一致として除外しない。"""

    actual_format = one_shot.detect_format(b"ER\x02\x00fixture", "sample.dmg")
    assert actual_format == "apple-disk-image"
    specs = discover_handlers()
    for family in ("amosstealer", "macos_stealer_v2"):
        spec = next(
            item
            for item in specs
            if item.family == family and item.automatic and item.input_contract_source == "bounded_payload_adapter"
        )
        assert one_shot.format_compatible(
            spec.input_formats,
            actual_format,
        )


def test_html_magic_is_detected_as_script_without_suffix() -> None:
    """HTML本文は拡張子に依存せず静的script解析へ振り分ける。"""

    assert (
        one_shot.detect_format(
            b"<!doctype html><html><script>function run(){}</script></html>",
            "download.bin",
        )
        == "script"
    )


def test_profile_string_scan_reserves_capacity_for_utf16() -> None:
    """ASCII候補が上限以上あってもUTF-16LE設定文字列を飢餓させない。"""

    ascii_noise = b"\0".join(f"ASCII-{index:04d}".encode("ascii") for index in range(200))
    wide_marker = "AsyncRAT HWID Hosts".encode("utf-16le")
    values = profiled_family.bounded_strings(ascii_noise + b"\0\0" + wide_marker, limit=100)
    assert "AsyncRAT HWID Hosts" in values


def test_negative_findings_do_not_become_positive_evidence() -> None:
    """未検出・未解決だけのfindingをhandler成功証拠へ昇格しない。"""

    quality = handler_result_quality(
        {
            "family": "fixture",
            "findings": [
                {
                    "kind": "network.endpoint",
                    "role": "c2_candidate",
                    "confidence": "candidate",
                    "status": "not_found",
                    "value": "unknown",
                },
                {
                    "kind": "configuration",
                    "status": "not_recovered",
                    "value": "unresolved_variant",
                },
            ],
        }
    )
    assert quality["tier_name"] == "no_evidence"
    assert quality["sufficient"] is False
    assert quality["candidate_groups"] == []


@pytest.mark.parametrize(
    ("flag", "payload"),
    [
        (
            "decoded_config_recovered",
            {"config": {"endpoint": "decoded.example.org:443"}},
        ),
        (
            "static_config_recovered",
            {"config": {"endpoint": "static.example.org:443"}},
        ),
        ("matched", {"marker_hits": ["family-marker"]}),
        ("reviewed_hash", {"artifact_role": "reviewed_sample"}),
        (
            "profile_literal_correlation",
            {
                "marker_hits": ["family-marker"],
                "observed_config_keys": ["host"],
                "network_candidates": ["example.org:443"],
            },
        ),
    ],
)
def test_boolean_declarations_require_typed_evidence(flag: str, payload: dict) -> None:
    """成功宣言booleanは種類に対応した実値証拠と相関させる。"""

    isolated = handler_result_quality({flag: True})
    assert isolated["tier_name"] == "no_evidence"
    assert isolated["sufficient"] is False

    correlated = handler_result_quality({flag: True, **payload})
    assert correlated["sufficient"] is True


@pytest.mark.parametrize(
    "value",
    [
        {"matched": True, "feature_present": True},
        {"static_config_recovered": True, "validated": True},
        {"findings": [True]},
    ],
)
def test_boolean_only_nested_values_are_not_evidence(value: dict) -> None:
    """別keyやcollectionにtrueを置いても実値相関を迂回できない。"""

    quality = handler_result_quality(value)
    assert quality["tier_name"] == "no_evidence"
    assert quality["sufficient"] is False


@pytest.mark.parametrize(
    "confidence",
    ["unconfirmed", "not_confirmed", "inexact", "uncorroborated"],
)
def test_negated_confidence_labels_are_not_evidence(confidence: str) -> None:
    """否定語を含むconfidence自己申告をsubstring一致で証拠へ昇格しない。"""

    quality = handler_result_quality({"classification_confidence": confidence})
    assert quality["tier_name"] == "no_evidence"
    assert quality["sufficient"] is False


def test_public_sanitizer_rejects_invalid_url_port() -> None:
    """範囲外portを黙って除去した正常URLへ変換せず、URL全体を無効化する。"""

    value = sanitize_public_value(
        "https://example.org:70000/gate?token=secret",
    )
    assert value == "[REDACTED_INVALID_URL]"


@pytest.mark.parametrize(
    ("key", "secret"),
    [
        ("client_secret", "client-value"),
        ("access_token", 123456),
        ("private_key", "private-value"),
    ],
)
def test_public_sanitizer_redacts_compound_secret_keys(key: str, secret: object) -> None:
    """複合秘密keyを値の型にかかわらず公開しない。"""

    assert sanitize_public_value({key: secret})[key] == "[REDACTED]"


def test_public_sanitizer_parses_and_redacts_json_strings() -> None:
    """文字列化されたJSON内部の秘密keyも再帰的に無害化する。"""

    value = sanitize_public_value('{"password":"hunter2","token":"abc"}')
    assert value == {"password": "[REDACTED]", "token": "[REDACTED]"}


def test_public_sanitizer_redacts_bearer_credentials() -> None:
    """自由文中のAuthorization Bearer値を公開しない。"""

    value = sanitize_public_value("Authorization: Bearer super-secret")
    assert value == "Authorization: Bearer [REDACTED]"


@pytest.mark.parametrize(
    "raw",
    [
        "Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
        "github_pat_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890",
        "eyJabcdefghijk.abcdefghijkl.abcdefghijkl",
    ],
)
def test_public_sanitizer_redacts_opaque_credentials(raw: str) -> None:
    """header名がなくても既知token形式やJWTを公開しない。"""

    value = sanitize_public_value(raw)
    assert raw not in value
    assert "[REDACTED" in value


def test_public_sanitizer_redacts_sensitive_url_path_segments() -> None:
    """queryだけでなくURL pathへ埋め込まれたtokenも公開しない。"""

    value = sanitize_public_value("https://example.org/token/hunter2/gate")
    assert value == "https://example.org/token/[REDACTED]/gate"


@pytest.mark.parametrize(
    "url",
    [
        "https://example.org/auth/hunter2/gate",
        "https://example.org/password/hunter2/gate",
        "https://example.org/client_secret/hunter2/gate",
        "https://example.org/%74%6f%6b%65%6e/hunter2/gate",
    ],
)
def test_public_sanitizer_redacts_extended_url_secret_paths(url: str) -> None:
    """追加keyとpercent-encoded keyのpath秘密値も無害化する。"""

    value = sanitize_public_value(url)
    assert "hunter2" not in value
    assert "[REDACTED]" in value


def test_public_sanitizer_preserves_non_secret_campaign_path() -> None:
    """秘密keyでないcampaign pathまで過剰に除去しない。"""

    url = "https://example.org/gate/CAMPAIGN-ID"
    assert sanitize_public_value(url) == url


def test_public_sanitizer_renders_ipv6_with_brackets() -> None:
    """IPv6 URLのuserinfo、query、fragmentを除去し、host括弧を維持する。"""

    value = sanitize_public_value("https://user:pass@[2001:4860:4860::8888]:8443/path?token=secret#fragment")
    assert value == "https://[2001:4860:4860::8888]:8443/path"


def test_main_returns_twenty_when_any_case_is_partial(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """部分解析を含むbatchのCLI終了codeを成功の0にしない。"""

    monkeypatch.setattr(one_shot, "_interpreter_is_isolated", lambda: True)
    monkeypatch.setattr(one_shot, "_runtime_preflight_main", lambda: 0)
    monkeypatch.setattr(
        one_shot,
        "run_batch",
        lambda *_args, **_kwargs: {
            "counts": {
                "errors": 0,
                "triaged_unknown": 0,
                "partial": 1,
                "failed": 0,
            },
            "derived_counts": {"triaged_unknown": 0},
            "follow_on_analysis": {"status": "no_retained_payloads"},
        },
    )
    status = one_shot.main(
        [
            "--input",
            str(tmp_path / "sample.bin"),
            "--output",
            str(tmp_path / "out"),
        ]
    )
    assert status == 20


def test_main_returns_twenty_when_any_case_is_triaged_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """実行成功でも未分類caseを解析完了の終了code 0へ昇格しない。"""

    monkeypatch.setattr(one_shot, "_interpreter_is_isolated", lambda: True)
    monkeypatch.setattr(one_shot, "_runtime_preflight_main", lambda: 0)
    monkeypatch.setattr(
        one_shot,
        "run_batch",
        lambda *_args, **_kwargs: {
            "counts": {
                "errors": 0,
                "triaged_unknown": 1,
                "partial": 0,
                "failed": 0,
            },
            "derived_counts": {"triaged_unknown": 0},
            "follow_on_analysis": {"status": "no_retained_payloads"},
        },
    )

    status = one_shot.main(
        [
            "--input",
            str(tmp_path / "sample.bin"),
            "--output",
            str(tmp_path / "out"),
        ]
    )
    assert status == 20


def test_resume_rejects_case_state_without_status(tmp_path: Path) -> None:
    """resumable flagだけを持ちstatusが欠落したcaseは再利用せず再解析する。"""

    sample = tmp_path / "resume.bin"
    sample.write_bytes(b"resume state shape fixture")
    output = tmp_path / "out"
    first = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        assessment_only=True,
    )
    report_path = output / first["cases"][0]["report"]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    del report["case_state"]["status"]
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    resumed = one_shot.run_batch(
        [sample],
        output,
        registry=REGISTRY,
        assessment_only=True,
        resume=True,
    )
    assert resumed["counts"]["resumed"] == 0
    assert resumed["counts"]["analyzed"] == 1
    assert resumed["cases"][0]["case_state"] == "assessment_only_complete"


def test_unexpected_case_exception_is_isolated_from_later_samples(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """予期しない通常例外も検体単位へ隔離し、後続検体の解析を継続する。"""

    broken = tmp_path / "a-broken.bin"
    healthy = tmp_path / "b-healthy.bin"
    broken.write_bytes(b"unexpected failure fixture")
    healthy.write_bytes(b"healthy fixture")
    original = one_shot.analyze_unit

    def analyze(unit: one_shot.InputUnit, **kwargs) -> dict:
        if unit.source_name == broken.name:
            raise TypeError("合成した予期しないcase例外")
        return original(unit, **kwargs)

    monkeypatch.setattr(one_shot, "analyze_unit", analyze)
    summary = one_shot.run_batch(
        [broken, healthy],
        tmp_path / "out",
        registry=REGISTRY,
        assessment_only=True,
    )
    assert summary["counts"]["errors"] == 1
    assert summary["counts"]["analyzed"] == 1
    assert summary["errors"][0]["source_name"] == broken.name
    assert summary["cases"][0]["source_name"] == healthy.name


def test_assessment_only_with_selected_family_does_not_require_handler_execution() -> None:
    """assessment-onlyでは選択familyがあっても未実行handlerを失敗扱いしない。"""

    completion = one_shot._completion_state(
        assessment_only=True,
        generic_status="not_run_assessment_only",
        layer_report={"counts": {}, "steps": []},
        layer_selections=[{"classification": {"observations": {}}}],
        selected_families=["family_a"],
        applicability=[{"id": "family_a:handler", "family": "family_a", "status": "applicable"}],
        executions=[],
        logic_report={"status": "function_analysis_required"},
    )
    assert completion["status"] == "assessment_only_complete"
    assert completion["resumable"] is True


def test_each_selected_family_requires_its_own_successful_handler() -> None:
    """複数familyの一部だけが成功してもcase全体をcompleteにしない。"""

    completion = one_shot._completion_state(
        assessment_only=False,
        generic_status="complete",
        layer_report={"counts": {}, "steps": []},
        layer_selections=[{"classification": {"observations": {}}}],
        selected_families=["family_a", "family_b"],
        applicability=[{"id": "family_a:handler", "family": "family_a", "status": "applicable"}],
        executions=[{"handler_id": "family_a:handler", "status": "succeeded"}],
        logic_report={"status": "automated_script_structure"},
    )
    assert completion["status"] == "partial"
    assert "selected_family_has_no_automatic_handler:family_b" in completion["blockers"]


def test_incomplete_selected_anchor_blocks_other_anchor_success() -> None:
    """同一familyの選択layer失敗を別layerの成功で隠さない。"""

    completion = one_shot._completion_state(
        assessment_only=False,
        generic_status="complete",
        layer_report={"counts": {}, "steps": []},
        layer_selections=[{"classification": {"observations": {}}}],
        selected_families=["family_a"],
        applicability=[{"id": "family_a:handler", "family": "family_a", "status": "applicable"}],
        executions=[
            {
                "handler_id": "family_a:handler",
                "status": "succeeded",
                "attempts": [
                    {
                        "routing_role": "selected_family_layer",
                        "status": "failed",
                        "layer": {"sha256": "a" * 64},
                    },
                    {
                        "routing_role": "selected_family_layer",
                        "status": "succeeded",
                        "evidence_status": "sufficient",
                        "layer": {"sha256": "b" * 64},
                    },
                ],
            }
        ],
        logic_report={"status": "automated_script_structure"},
    )
    assert completion["status"] == "partial"
    assert "selected_family_layer_incomplete" in completion["blockers"]


def test_strongest_ancestor_fallback_is_not_skipped(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """innerの静的設定より強いouter祖先の復号済み設定まで探索する。"""

    root_data = b"ancestor decoded configuration"
    child_data = b"inner literal candidate"
    root_hash = hashlib.sha256(root_data).hexdigest()
    root = one_shot.StaticLayer(
        name="wrapper.bin",
        data=root_data,
        sha256=root_hash,
        parent_sha256=None,
        depth=0,
        transform="submission",
    )
    child = one_shot.StaticLayer(
        name="wrapper.bin::inner",
        data=child_data,
        sha256=hashlib.sha256(child_data).hexdigest(),
        parent_sha256=root_hash,
        depth=1,
        transform="inner",
    )
    layer_report = {
        "counts": {"limit_events": 0},
        "steps": [],
        "limit_events": [],
        "layers": [root.public(), child.public()],
    }
    monkeypatch.setattr(one_shot, "recover_static_layers", lambda _unit, **_kwargs: ([root, child], layer_report))
    monkeypatch.setattr(
        one_shot.classify_sample,
        "classify_bytes",
        lambda data, *_args, **_kwargs: _classification("family_a" if data == child_data else None),
    )
    monkeypatch.setattr(
        one_shot,
        "_preflight_applicable",
        lambda _specs, applicability: [
            {"handler_id": item["id"], "available": True, "error": None}
            for item in applicability
            if item["status"] == "applicable"
        ],
    )
    monkeypatch.setattr(
        one_shot,
        "_run_generic_triage",
        lambda _layers, _case_dir, **_kwargs: (
            {"analysis_coverage": {"status": "complete"}},
            "complete",
        ),
    )
    calls = []

    def execute(_spec: HandlerSpec, data: bytes, _source_name: str, **_kwargs) -> dict:
        calls.append(data)
        result = (
            {"static_config_recovered": True, "config": {"host": "inner.example.org"}}
            if data == child_data
            else {"decoded_config_recovered": True, "config": {"host": "outer.example.org"}}
        )
        return {
            "status": "completed",
            "preflight": {"eligible": True, "blockers": []},
            "handler_timeout_seconds": 30.0,
            "execution": {
                "result": result,
                "executed_sample": False,
                "network_contacted": False,
            },
        }

    monkeypatch.setattr(one_shot, "execute_handler_bounded_for_assessment", execute)
    unit = one_shot.InputUnit(
        source_name="wrapper.bin",
        data=root_data,
        input_kind="raw",
        outer_sha256=root_hash,
        outer_size=len(root_data),
    )
    one_shot.analyze_unit(
        unit,
        output=tmp_path / "out",
        registry=REGISTRY,
        specs=[_handler_spec("family_a")],
        registered={"family_a"},
        forced_family=None,
        minimum_confidence="medium",
        assessment_only=False,
        analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
    )
    report = json.loads((tmp_path / "out" / "cases" / root_hash / "report.json").read_text(encoding="utf-8"))
    execution = report["handler_executions"][0]
    assert calls == [child_data, root_data]
    assert execution["selected_layer_sha256"] == root_hash
    assert execution["selected_evidence"]["tier"] == 4


def test_one_shot_generic_triage_disables_duplicate_archive_recursion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """static layer復元後の汎用解析で同じarchiveを再帰展開しない。"""

    seen = []

    def analyze(*_args, **kwargs) -> dict:
        seen.append(kwargs.get("recurse_archives"))
        return {"type": "data", "analysis_coverage": {"status": "complete"}}

    monkeypatch.setattr(one_shot.analyze_family_sample, "analyze", analyze)
    data = b"bounded layer"
    layer = one_shot.StaticLayer(
        name="sample.bin",
        data=data,
        sha256=hashlib.sha256(data).hexdigest(),
        parent_sha256=None,
        depth=0,
        transform="submission",
    )
    _result, status = one_shot._run_generic_triage([layer], tmp_path)
    assert status == "complete"
    assert seen == [False]


def test_script_base64_candidate_has_encoded_size_limit(tmp_path: Path) -> None:
    """巨大な単一Base64 tokenをdecodeせずpartialとして記録する。"""

    payload = b"var value='" + b"A" * (1024 * 1024 + 4) + b"';"
    result = one_shot.analyze_family_sample.analyze("large.js", payload, tmp_path, persist_normalized_text=False)
    scan = result["script"]["base64_scan"]
    assert scan["oversized_candidates"] == 1
    assert scan["truncated"] is True
    assert result["analysis_coverage"]["status"] == "partial"


def test_script_base64_scan_keeps_more_than_legacy_hundred_candidates(tmp_path: Path) -> None:
    """入力上限内のBase64候補を旧100件表示上限で打ち切らない。"""

    payload = (("A" * 80) + "\n") * 101
    result = one_shot.analyze_family_sample.analyze(
        "many.js", payload.encode(), tmp_path, persist_normalized_text=False
    )
    scan = result["script"]["base64_scan"]
    assert scan["candidate_limit"] == 10_000
    assert len(result["script"]["base64_candidates"]) == 101
    assert scan["truncated"] is False


def test_script_base64_scan_bounds_retention_without_stopping_scan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全候補を走査し、公開inventoryだけを有界化した場合はpartialにしない。"""

    monkeypatch.setattr(
        one_shot.analyze_family_sample,
        "MAX_BASE64_CANDIDATES",
        2,
    )
    payload = (("A" * 80) + "\n") * 3
    result = one_shot.analyze_family_sample.analyze(
        "many.js", payload.encode(), tmp_path, persist_normalized_text=False
    )
    scan = result["script"]["base64_scan"]
    assert len(result["script"]["base64_candidates"]) == 2
    assert scan["total_candidates"] == 3
    assert scan["omitted_candidates"] == 1
    assert scan["retention_limited"] is True
    assert scan["truncated"] is False
    assert result["analysis_coverage"]["status"] == "complete"


def test_analysis_contract_components_include_shared_dependencies() -> None:
    """resume fingerprintへ共有I/O、detector support、profile、campaign定義を含める。"""

    components = {path.resolve() for path in one_shot._analysis_components(REGISTRY, discover_handlers())}
    assert (COMMON_ROOT / "malware_io.py").resolve() in components
    assert (COMMON_ROOT / "profiled_family_detector.py").resolve() in components
    assert (COMMON_ROOT / "detector_support.py").resolve() in components
    assert (REPOSITORY_ROOT / "extractors" / "profiles" / "windows_family_profiles.json").resolve() in components
    assert (REPOSITORY_ROOT / "unpackers" / "profiles" / "byte_transforms.json").resolve() in components
    assert (FRAMEWORK_ROOT / "registry" / "pe_structural_profiles.json").resolve() in components
    assert (FRAMEWORK_ROOT / "requirements.txt").resolve() in components
    assert any(path.name == "campaigns.json" for path in components)


def test_public_behavior_strings_drop_long_payload_like_values() -> None:
    """公開挙動根拠から長大なpayload様文字列をfail-closedで除外する。"""

    maximum = one_shot.analyze_family_sample.MAX_PUBLIC_BEHAVIOR_STRING_LENGTH
    short = "powershell -NoProfile"
    boundary = "password=" + "A" * (maximum - len("password="))
    oversized = "credential=" + "A" * maximum
    values = one_shot.analyze_family_sample._public_behavior_strings(
        [
            {"value": oversized},
            {"value": short},
            {"value": boundary},
            {"value": short},
            {"value": "unrelated value"},
            {"value": 42},
        ]
    )

    assert values == sorted([boundary, short])
    assert all(len(value) <= 255 for value in values)


def test_reanalysis_removes_stale_case_artifacts(tmp_path: Path) -> None:
    """再解析前に同じSHA caseの旧handler成果物だけを含むdirectoryを初期化する。"""

    digest = "a" * 64
    stale = tmp_path / "cases" / digest / "handlers" / "stale.json"
    stale.parent.mkdir(parents=True)
    stale.write_text('{"stale": true}', encoding="utf-8")
    case_dir = one_shot._prepare_case_directory(tmp_path, digest)
    assert case_dir.is_dir()
    assert not stale.exists()


def test_profiled_known_hash_cache_tracks_campaign_file_identity(tmp_path: Path) -> None:
    """同一processでcampaigns.jsonを更新しても古いknown hashを再利用しない。"""

    campaigns = tmp_path / "malware" / "family_a" / "campaigns.json"
    campaigns.parent.mkdir(parents=True)
    campaigns.write_text(json.dumps({"known_sample_sha256": ["a" * 64]}), encoding="utf-8")
    assert profiled_family_detector.known_hashes("family_a", tmp_path) == {"a" * 64}
    campaigns.write_text(
        json.dumps({"known_sample_sha256": ["b" * 64, "c" * 64]}),
        encoding="utf-8",
    )
    assert profiled_family_detector.known_hashes("family_a", tmp_path) == {
        "b" * 64,
        "c" * 64,
    }


@pytest.mark.parametrize(
    "known_hashes",
    [None, "a" * 64, ["short"], [123]],
)
def test_registry_schema_rejects_invalid_known_hashes_once(
    tmp_path: Path,
    known_hashes: object,
) -> None:
    """壊れたhash schemaを検体ごとに反復せずregistry読込境界で拒否する。"""

    registry = tmp_path / "registry.json"
    registry.write_text(
        json.dumps(
            {
                "malware_types": {
                    "valleyrat": {
                        "detector": "malware/valleyrat/detect.py",
                        "known_sample_sha256": known_hashes,
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(TypeError, match="known_sample_sha256"):
        one_shot.classify_sample._validated_registry(registry)


def _assessment_report(tmp_path: Path, name: str) -> tuple[Path, Path, dict]:
    """再開検証用の正常なassessment-only caseを作る。"""

    sample = tmp_path / name
    sample.write_bytes(f"resume hardening {name}".encode())
    output = tmp_path / f"out-{name}"
    first = one_shot.run_batch([sample], output, registry=REGISTRY, assessment_only=True)
    assert first["counts"]["analyzed"] == 1
    report_path = output / first["cases"][0]["report"]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    return sample, report_path, report


def test_resume_rejects_report_semantic_tamper(tmp_path: Path) -> None:
    """成果物が無傷でもreport分類の改変を検知して再解析する。"""

    sample, report_path, report = _assessment_report(tmp_path, "semantic.bin")
    report["classification"]["family"] = "forged-family"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    rerun = one_shot.run_batch(
        [sample],
        report_path.parents[2],
        registry=REGISTRY,
        assessment_only=True,
        resume=True,
    )
    assert rerun["counts"]["resumed"] == 0
    assert rerun["counts"]["analyzed"] == 1


def test_resume_rejects_resealed_mode_status_invariant_tamper(tmp_path: Path) -> None:
    """sealを再計算しても完了statusとblockerの矛盾を再利用しない。"""

    sample, report_path, report = _assessment_report(tmp_path, "state.bin")
    report["case_state"]["blockers"] = ["forged_blocker"]
    seal_report(report)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    rerun = one_shot.run_batch(
        [sample],
        report_path.parents[2],
        registry=REGISTRY,
        assessment_only=True,
        resume=True,
    )
    assert rerun["counts"]["resumed"] == 0
    assert rerun["counts"]["analyzed"] == 1


def test_resume_rejects_resealed_incomplete_artifact_manifest(tmp_path: Path) -> None:
    """必須成果物のmanifest entryを削除してsealし直しても再利用しない。"""

    sample, report_path, report = _assessment_report(tmp_path, "manifest.bin")
    del report["artifact_sha256"]["static-logic.json"]
    seal_report(report)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    rerun = one_shot.run_batch(
        [sample],
        report_path.parents[2],
        registry=REGISTRY,
        assessment_only=True,
        resume=True,
    )
    assert rerun["counts"]["resumed"] == 0
    assert rerun["counts"]["analyzed"] == 1


def test_resume_rejects_unsafe_knowledge_artifact_path(tmp_path: Path) -> None:
    """knowledge artifactのcase外pathをseal再計算後も再利用しない。"""

    sample, report_path, report = _assessment_report(tmp_path, "knowledge.bin")
    report["knowledge_artifacts"]["features"] = "../outside.json"
    seal_report(report)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    rerun = one_shot.run_batch(
        [sample],
        report_path.parents[2],
        registry=REGISTRY,
        assessment_only=True,
        resume=True,
    )
    assert rerun["counts"]["resumed"] == 0
    assert rerun["counts"]["analyzed"] == 1


def test_resume_cross_checks_rehashed_classification_artifact(tmp_path: Path) -> None:
    """artifactとmanifestを再hashされてもreport分類との不一致を再利用しない。"""

    sample, report_path, report = _assessment_report(tmp_path, "crosscheck.bin")
    classification_path = report_path.parent / "classification.json"
    classification = json.loads(classification_path.read_text(encoding="utf-8"))
    classification["selected_families"] = ["forged-family"]
    classification_path.write_text(json.dumps(classification), encoding="utf-8")
    report["artifact_sha256"]["classification.json"] = hashlib.sha256(classification_path.read_bytes()).hexdigest()
    seal_report(report)
    report_path.write_text(json.dumps(report), encoding="utf-8")
    rerun = one_shot.run_batch(
        [sample],
        report_path.parents[2],
        registry=REGISTRY,
        assessment_only=True,
        resume=True,
    )
    assert rerun["counts"]["resumed"] == 0
    assert rerun["counts"]["analyzed"] == 1


def test_resume_fails_closed_for_symlinked_manifest_artifact(tmp_path: Path) -> None:
    """manifest対象がsymbolic linkなら削除・再解析せずcase単位で拒否する。"""

    sample, report_path, _report = _assessment_report(tmp_path, "symlink.bin")
    case_dir = report_path.parent
    target = case_dir / "classification.json"
    original = target.read_bytes()
    external = tmp_path / "external-classification.json"
    external.write_bytes(original)
    target.unlink()
    try:
        os.symlink(external, target)
    except OSError as exc:
        pytest.skip(f"symbolic linkを作成できない環境です: {exc}")
    rerun = one_shot.run_batch(
        [sample],
        report_path.parents[2],
        registry=REGISTRY,
        assessment_only=True,
        resume=True,
    )
    assert rerun["counts"]["resumed"] == 0
    assert rerun["counts"]["analyzed"] == 0
    assert rerun["counts"]["errors"] == 1
    assert external.read_bytes() == original
    assert target.is_symlink()


def test_runtime_versions_are_stable_contract_material() -> None:
    """Python実装と主要依存版を再開契約へ含められる形で取得する。"""

    runtime = runtime_dependency_versions()
    assert runtime["python_implementation"]
    assert runtime["python_version"]
    assert set(runtime["dependencies"]) == {
        "cabarchive",
        "capstone",
        "cryptography",
        "dncil",
        "dnfile",
        "olefile",
        "pefile",
        "pydantic",
        "pyinstaller",
        "pyzipper",
        "PyYAML",
        "ruff",
        "yara-python",
    }


@pytest.mark.parametrize("max_files", [True, False, 1.5, "1", 0, -1])
def test_collect_inputs_rejects_non_integer_or_non_positive_limits(
    tmp_path: Path,
    max_files: object,
) -> None:
    """boolを含む曖昧なファイル数上限をプログラム呼び出しでも拒否する。"""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"A")
    with pytest.raises(ValueError, match="max_files"):
        one_shot.collect_inputs([sample], tmp_path / "output", max_files)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("archive_mode", "max_file_size"),
    [
        ("invalid", 10),
        ("auto", True),
        ("auto", 0),
        ("auto", -1),
        ("auto", 1.5),
        ("auto", "10"),
    ],
)
def test_read_input_unit_rejects_invalid_programmatic_contract(
    tmp_path: Path,
    archive_mode: object,
    max_file_size: object,
) -> None:
    """CLIを経由しない呼び出しでもmodeとサイズ上限を検証する。"""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"A")
    with pytest.raises(ValueError):
        one_shot.read_input_unit(
            sample,
            password="infected",
            archive_mode=archive_mode,  # type: ignore[arg-type]
            max_file_size=max_file_size,  # type: ignore[arg-type]
        )


def test_read_input_unit_uses_capped_stream_reader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """stat後に肥大化する入力も共通ストリーム上限で停止できる構成にする。"""
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"A")
    calls: list[tuple[Path, int]] = []

    def capped(path: Path, *, max_size: int) -> bytes:
        calls.append((path, max_size))
        return b"RAW"

    monkeypatch.setattr(one_shot, "read_file_capped", capped)
    unit = one_shot.read_input_unit(
        sample,
        password="infected",
        archive_mode="raw",
        max_file_size=4,
    )
    assert calls == [(sample, 4)]
    assert unit.data == b"RAW"
