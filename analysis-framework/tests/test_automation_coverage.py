"""script-only解析カバレッジ監査を検証する。"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import handler_catalog as handler_catalog_module  # noqa: E402
from automation_coverage import (  # noqa: E402
    _check_output,
    _rendered_outputs,
    render_markdown,
)
from automation_coverage import build_coverage as _production_build_coverage  # noqa: E402
from handler_catalog import HandlerSpec  # noqa: E402


def _spec(
    family: str,
    *,
    suffix: str = "extract",
    automatic: bool = True,
    supported: bool = True,
    formats: tuple[str, ...] = ("pe",),
) -> HandlerSpec:
    return HandlerSpec(
        id=f"{family}:{suffix}",
        family=family,
        relative_path=f"malware/{family}/{suffix}.py",
        callable_name="extract",
        invocation="bytes",
        source="test",
        automatic=automatic,
        campaign=None,
        supported_interface=supported,
        reason="fixture",
        input_formats=formats,
        input_contract_source="test",
        minimum_evidence_score=1,
    )


def _policies(*families: str) -> dict[str, dict[str, object]]:
    return {
        family: {
            "category": "rat",
            "config_required": True,
            "network_required": True,
            "terminal_payload_required": False,
        }
        for family in families
    }


def _preflight(*, blocked_formats: set[str] | None = None):
    blocked_formats = blocked_formats or set()

    def run(spec, *, actual_format, input_size, maximum_input_size):
        blocked = actual_format in blocked_formats or not spec.supported_interface
        digest = hashlib.sha256(spec.id.encode("utf-8")).hexdigest()
        return {
            "handler_id": spec.id,
            "eligible": not blocked,
            "blockers": ["fixture_blocked"] if blocked else [],
            "actual_format": actual_format,
            "input_size": input_size,
            "maximum_input_size": maximum_input_size,
            "source_sha256": digest,
            "dependency_audit": {
                "files": [
                    {
                        "path": spec.relative_path,
                        "sha256": digest,
                    }
                ]
            },
            "sample_execution_allowed": False,
            "network_allowed": False,
            "filesystem_write_allowed": False,
        }

    return run


def _runtime_import(*, blocked_handlers: set[str] | None = None):
    blocked_handlers = blocked_handlers or set()

    def run(spec, *, static_preflight, timeout_seconds):
        del static_preflight
        assert timeout_seconds == 10.0
        blocked = spec.id in blocked_handlers
        return {
            "handler_id": spec.id,
            "eligible": not blocked,
            "blockers": ["fixture_dependency_missing"] if blocked else [],
            "attempted": True,
            "handler_imported": not blocked,
            "invocation": None if blocked else spec.invocation,
            "isolated_process": True,
            "sanitized_environment": True,
            "sample_execution_allowed": False,
            "network_allowed": False,
            "filesystem_write_allowed": False,
        }

    return run


def build_coverage(**kwargs):
    """既存testは決定的な検体なしruntime import fixtureを既定利用する。"""

    kwargs.setdefault("runtime_import", _runtime_import())
    return _production_build_coverage(**kwargs)


def test_coverage_separates_safe_automation_states() -> None:
    report = build_coverage(
        registered_families={"full", "classifier", "manual"},
        specs=[
            _spec("full"),
            _spec("candidate"),
            _spec("manual", automatic=False),
        ],
        quality_policies=_policies("full", "candidate"),
        preflight=_preflight(),
    )
    states = {item["family"]: item["status"] for item in report["families"]}
    assert states == {
        "candidate": "candidate_verification_only",
        "classifier": "classification_only",
        "full": "fully_routable",
        "manual": "manual_handler_only",
    }
    assert report["counts"]["fully_routable"] == 1
    assert report["counts"]["declared_script_only_handler_available"] == 2
    assert report["counts"]["script_only_handler_available"] == 2
    assert report["counts"]["declared_automatic_handlers"] == 2
    assert report["counts"]["safe_automatic_handlers"] == 2
    assert report["counts"]["ast_preflight_eligible_handlers"] == 2
    assert report["counts"]["runtime_import_verified_handlers"] == 2
    assert report["counts"]["blocked_automatic_handlers"] == 0
    assert report["counts"]["quality_policy_declared"] == 2
    assert report["counts"]["quality_gated_script_only_handler_available"] == 2
    assert report["counts"]["automatic_family_selection_possible"] == 1
    assert report["counts"]["automated_analysis_completion_possible"] == 1
    assert report["counts"]["structurally_routable"] == 1
    assert report["counts"]["runtime_import_verified_structure"] == 1
    assert report["counts"]["automated_analysis_completion_verified"] == 0
    full = next(item for item in report["families"] if item["family"] == "full")
    assert full["structurally_routable"] is True
    assert full["runtime_import_verified_structure"] is True
    assert full["automated_analysis_completion_possible"] is True
    assert full["automated_analysis_completion_verified"] is False
    assert full["completion_verification"] == {
        "status": "not_verified",
        "blockers": [
            "representative_fixture_completion_not_verified",
            "required_output_contract_not_exercised",
        ],
        "required_evidence": [
            "representative_fixture",
            "required_output_contract",
            "orchestration_quality_gates",
        ],
    }
    assert report["metric_semantics"]["automated_analysis_completion_possible"].startswith(
        "後方互換用"
    )
    assert report["counts"]["executed_preflight_count"] == 2
    assert report["counts"]["planned_runtime_import_count"] == 2
    assert report["counts"]["executed_runtime_import_count"] == 2
    assert report["preflight_policy"] == {
        "ast_scope": "each_declared_format",
        "runtime_import_scope": "each_ast_eligible_handler",
        "declared_input_size_metadata": 1,
        "runtime_import_sample_input_size": 0,
        "runtime_import_timeout_seconds": 10.0,
        "maximum_input_size": 128 * 1024 * 1024,
        "maximum_preflight_count": 2_048,
        "handler_imported_during_ast_preflight": False,
        "handler_imported_during_runtime_preflight": True,
        "runtime_import_isolated_process": True,
        "runtime_import_sanitized_environment": True,
        "sample_execution_allowed": False,
        "network_allowed": False,
        "filesystem_write_allowed": False,
    }
    assert report["ai_used"] is False
    assert report["executed_sample"] is False
    assert report["network_contacted"] is False


def test_declared_automatic_is_not_safe_when_preflight_blocks() -> None:
    report = build_coverage(
        registered_families={"blocked"},
        specs=[_spec("blocked")],
        preflight=_preflight(blocked_formats={"pe"}),
    )
    item = report["families"][0]
    assert item["status"] == "automatic_handler_blocked"
    assert item["declared_script_only_handler_available"] is True
    assert item["script_only_handler_available"] is False
    assert item["automatic_handlers"] == []
    assert item["blocked_automatic_handlers"][0]["handler_id"] == "blocked:extract"
    assert item["blocked_automatic_handlers"][0]["blockers"] == ["fixture_blocked"]
    assert len(
        item["blocked_automatic_handlers"][0]["dependency_fingerprint_sha256"]
    ) == 64


def test_ast_safe_handler_is_blocked_when_runtime_dependency_is_missing() -> None:
    report = build_coverage(
        registered_families={"missing_dependency"},
        specs=[_spec("missing_dependency")],
        quality_policies=_policies("missing_dependency"),
        preflight=_preflight(),
        runtime_import=_runtime_import(
            blocked_handlers={"missing_dependency:extract"}
        ),
    )
    item = report["families"][0]
    handler = item["automatic_handler_preflights"][0]
    assert item["status"] == "automatic_handler_blocked"
    assert handler["ast_preflight_eligible"] is True
    assert handler["ast_eligible_formats"] == ["pe"]
    assert handler["eligible"] is False
    assert handler["eligible_formats"] == []
    assert "fixture_dependency_missing" in handler["blockers"]
    assert handler["runtime_import"]["eligible"] is False
    assert report["counts"]["ast_preflight_eligible_handlers"] == 1
    assert report["counts"]["runtime_import_verified_handlers"] == 0
    assert report["counts"]["runtime_import_verified_structure"] == 0


def test_runtime_import_safety_contract_is_fail_closed() -> None:
    def unsafe_runtime_import(spec, *, static_preflight, timeout_seconds):
        result = _runtime_import()(
            spec,
            static_preflight=static_preflight,
            timeout_seconds=timeout_seconds,
        )
        result["network_allowed"] = True
        return result

    report = build_coverage(
        registered_families={"unsafe_runtime"},
        specs=[_spec("unsafe_runtime")],
        quality_policies=_policies("unsafe_runtime"),
        preflight=_preflight(),
        runtime_import=unsafe_runtime_import,
    )
    blocked = report["families"][0]["blocked_automatic_handlers"][0]
    assert blocked["ast_preflight_eligible"] is True
    assert blocked["runtime_import"]["network_allowed"] is True
    assert blocked["blockers"] == [
        "runtime_import_safety_contract_invalid:network_allowed"
    ]


def test_runtime_import_is_not_attempted_when_ast_preflight_blocks() -> None:
    called = False

    def should_not_run(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("呼ばれないこと")

    report = build_coverage(
        registered_families={"ast_blocked"},
        specs=[_spec("ast_blocked")],
        preflight=_preflight(blocked_formats={"pe"}),
        runtime_import=should_not_run,
    )
    preflight = report["families"][0]["automatic_handler_preflights"][0]
    assert called is False
    assert preflight["runtime_import"]["attempted"] is False
    assert report["counts"]["planned_runtime_import_count"] == 1
    assert report["counts"]["executed_runtime_import_count"] == 0


def test_completion_possible_alias_is_explicitly_structural() -> None:
    report = build_coverage(
        registered_families={"structural"},
        specs=[_spec("structural")],
        quality_policies=_policies("structural"),
        preflight=_preflight(),
    )
    item = report["families"][0]
    assert item["automated_analysis_completion_possible"] is item[
        "runtime_import_verified_structure"
    ]
    assert report["counts"]["automated_analysis_completion_possible"] == report[
        "counts"
    ]["runtime_import_verified_structure"]
    semantics = report["metric_semantics"]
    assert "deprecated alias" in semantics["automated_analysis_completion_possible"]
    assert "構造指標" in semantics["automated_analysis_completion_possible"]
    assert "実検体の完了可能性" in semantics[
        "automated_analysis_completion_possible"
    ]
    assert item["automated_analysis_completion_verified"] is False


def test_public_runtime_import_preflight_never_needs_sample_data(monkeypatch) -> None:
    spec = _spec("runtime_contract")
    static = _preflight()(
        spec,
        actual_format="pe",
        input_size=1,
        maximum_input_size=128 * 1024 * 1024,
    )
    monkeypatch.setattr(
        handler_catalog_module,
        "_preflight_dependency_source_manifest",
        lambda _preflight: [],
    )
    monkeypatch.setattr(
        handler_catalog_module,
        "_preflight_dependency_data_manifest",
        lambda _preflight: [],
    )
    monkeypatch.setattr(
        handler_catalog_module,
        "_preflight_dependency_module_manifest",
        lambda _preflight: [],
    )
    received = {}

    def verified(spec, **kwargs):
        received["handler_id"] = spec.id
        received.update(kwargs)
        return "bytes"

    monkeypatch.setattr(
        handler_catalog_module,
        "_verify_handler_runtime_import_bounded",
        verified,
    )
    result = handler_catalog_module.preflight_handler_runtime_import(
        spec,
        static_preflight=static,
        timeout_seconds=2,
    )
    assert received == {
        "handler_id": spec.id,
        "timeout_seconds": 2.0,
        "dependency_source_manifest": [],
        "dependency_data_manifest": [],
        "dependency_module_manifest": [],
    }
    assert result["eligible"] is True
    assert result["handler_imported"] is True
    assert result["sample_execution_allowed"] is False
    assert result["network_allowed"] is False
    assert result["filesystem_write_allowed"] is False


def test_public_runtime_import_dependency_failure_is_not_available(
    monkeypatch,
) -> None:
    spec = _spec("missing_runtime_dependency")
    static = _preflight()(
        spec,
        actual_format="pe",
        input_size=1,
        maximum_input_size=128 * 1024 * 1024,
    )

    def missing(_preflight):
        raise OSError("credential=should-not-leak")

    monkeypatch.setattr(
        handler_catalog_module,
        "_preflight_dependency_source_manifest",
        missing,
    )
    result = handler_catalog_module.preflight_handler_runtime_import(
        spec,
        static_preflight=static,
    )
    assert result["eligible"] is False
    assert result["handler_imported"] is False
    assert result["attempted"] is False
    assert result["blockers"] == ["runtime_dependency_snapshot_unavailable"]
    assert "credential" not in repr(result)


def test_safe_handler_without_quality_policy_cannot_be_fully_routable() -> None:
    report = build_coverage(
        registered_families={"missing_policy"},
        specs=[_spec("missing_policy")],
        preflight=_preflight(),
    )
    item = report["families"][0]
    assert item["status"] == "quality_policy_missing"
    assert item["automatic_selection_possible"] is True
    assert item["automated_analysis_completion_possible"] is False
    assert item["structurally_routable"] is False
    assert item["automated_analysis_completion_verified"] is False
    assert item["completion_verification"]["blockers"] == ["quality_policy_missing"]
    assert item["quality_policy_declared"] is False
    assert report["counts"]["fully_routable"] == 0
    assert report["counts"]["quality_policy_missing"] == 1
    assert report["counts"]["automatic_family_selection_possible"] == 1
    assert report["counts"]["automated_analysis_completion_possible"] == 0


def test_missing_detector_and_policy_are_both_reported() -> None:
    report = build_coverage(
        registered_families=set(),
        specs=[_spec("missing_both")],
        preflight=_preflight(),
    )
    item = report["families"][0]
    assert item["status"] == "quality_policy_missing"
    assert item["blocker"] == "detector_and_quality_policy_missing"
    assert item["automatic_selection_possible"] is False


def test_programmatic_quality_policy_is_strictly_validated() -> None:
    with pytest.raises(ValueError, match="fieldが不正"):
        build_coverage(
            registered_families={"invalid_policy"},
            specs=[_spec("invalid_policy")],
            quality_policies={"invalid_policy": {}},
            preflight=_preflight(),
        )


def test_extended_quality_policy_category_is_accepted() -> None:
    policies = _policies("downloader_family")
    policies["downloader_family"]["category"] = "downloader"
    report = build_coverage(
        registered_families={"downloader_family"},
        specs=[_spec("downloader_family")],
        quality_policies=policies,
        preflight=_preflight(),
    )
    assert report["families"][0]["status"] == "fully_routable"
    assert report["families"][0]["quality_policy"]["category"] == "downloader"


def test_unknown_quality_policy_category_is_rejected() -> None:
    policies = _policies("unknown_category")
    policies["unknown_category"]["category"] = "unknown"
    with pytest.raises(ValueError, match="categoryが不正"):
        build_coverage(
            registered_families={"unknown_category"},
            specs=[_spec("unknown_category")],
            quality_policies=policies,
            preflight=_preflight(),
        )


def test_handler_is_safe_when_at_least_one_declared_format_is_eligible() -> None:
    report = build_coverage(
        registered_families={"mixed"},
        specs=[_spec("mixed", formats=("pe", "data"))],
        quality_policies=_policies("mixed"),
        preflight=_preflight(blocked_formats={"data"}),
    )
    item = report["families"][0]
    assert item["status"] == "fully_routable"
    assert item["accepted_formats"] == ["pe"]
    assert item["safe_automatic_handlers"] == ["mixed:extract"]
    preflight = item["automatic_handler_preflights"][0]
    assert preflight["eligible_formats"] == ["pe"]
    assert preflight["blocked_formats"] == [
        {"format": "data", "eligible": False, "blockers": ["fixture_blocked"]}
    ]


def test_unsupported_interface_is_declared_but_preflight_blocked() -> None:
    report = build_coverage(
        registered_families=set(),
        specs=[_spec("legacy", automatic=True, supported=False)],
        preflight=_preflight(),
    )
    item = report["families"][0]
    assert item["status"] == "automatic_handler_blocked"
    assert item["candidate_verification_possible"] is False
    assert item["declared_automatic_handlers"] == ["legacy:extract"]


def test_report_is_deterministic_for_spec_and_format_order() -> None:
    first = build_coverage(
        registered_families={"ordered"},
        specs=[
            _spec("ordered", suffix="z", formats=("pe", "data")),
            _spec("ordered", suffix="a", formats=("data", "pe")),
        ],
        quality_policies=_policies("ordered"),
        preflight=_preflight(blocked_formats={"data"}),
    )
    second = build_coverage(
        registered_families={"ordered"},
        specs=list(
            reversed(
                [
                    _spec("ordered", suffix="z", formats=("data", "pe")),
                    _spec("ordered", suffix="a", formats=("pe", "data")),
                ]
            )
        ),
        quality_policies=_policies("ordered"),
        preflight=_preflight(blocked_formats={"data"}),
    )
    assert first == second


def test_preflight_count_limit_fails_before_preflight_execution() -> None:
    called = False

    def should_not_run(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("呼ばれないこと")

    with pytest.raises(ValueError, match="preflight件数上限"):
        build_coverage(
            registered_families={"limited"},
            specs=[_spec("limited", formats=("pe", "data"))],
            preflight=should_not_run,
            maximum_preflights=1,
        )
    assert called is False


def test_preflight_safety_contract_is_fail_closed() -> None:
    def unsafe(spec, *, actual_format, input_size, maximum_input_size):
        result = _preflight()(
            spec,
            actual_format=actual_format,
            input_size=input_size,
            maximum_input_size=maximum_input_size,
        )
        result["network_allowed"] = True
        return result

    report = build_coverage(
        registered_families={"unsafe"},
        specs=[_spec("unsafe")],
        preflight=unsafe,
    )
    blocked = report["families"][0]["blocked_automatic_handlers"][0]
    assert blocked["blockers"] == [
        "preflight_safety_contract_invalid:network_allowed"
    ]


def test_ineligible_preflight_without_reason_gets_deterministic_blocker() -> None:
    def reasonless(spec, *, actual_format, input_size, maximum_input_size):
        result = _preflight()(
            spec,
            actual_format=actual_format,
            input_size=input_size,
            maximum_input_size=maximum_input_size,
        )
        result["eligible"] = False
        return result

    report = build_coverage(
        registered_families={"reasonless"},
        specs=[_spec("reasonless")],
        preflight=reasonless,
    )
    assert report["families"][0]["blocked_automatic_handlers"][0]["blockers"] == [
        "preflight_ineligible_without_blocker"
    ]


def test_preflight_identity_and_dependency_evidence_are_required() -> None:
    def forged(spec, *, actual_format, input_size, maximum_input_size):
        result = _preflight()(
            spec,
            actual_format=actual_format,
            input_size=input_size,
            maximum_input_size=maximum_input_size,
        )
        result["handler_id"] = "other:handler"
        result["actual_format"] = "data"
        result["source_sha256"] = "z" * 64
        result["dependency_audit"] = {"files": []}
        return result

    report = build_coverage(
        registered_families={"forged"},
        specs=[_spec("forged")],
        preflight=forged,
    )
    assert report["families"][0]["blocked_automatic_handlers"][0]["blockers"] == [
        "preflight_actual_format_mismatch",
        "preflight_dependency_audit_missing_or_invalid",
        "preflight_handler_id_mismatch",
        "preflight_source_digest_missing_or_invalid",
    ]


def test_duplicate_handler_ids_fail_before_preflight() -> None:
    duplicate = _spec("duplicate")
    with pytest.raises(ValueError, match="handler IDが重複"):
        build_coverage(
            registered_families={"duplicate"},
            specs=[duplicate, duplicate],
            preflight=_preflight(),
        )


def test_markdown_is_japanese_and_deterministic() -> None:
    report = build_coverage(
        registered_families={"full"},
        specs=[_spec("full")],
        quality_policies=_policies("full"),
        preflight=_preflight(),
    )
    rendered = render_markdown(report)
    assert rendered == render_markdown(report)
    assert "既知マルウェア自動解析カバレッジ" in rendered
    assert "生成AIは使用しません" in rendered
    assert "AST監査＋runtime import確認済み" in rendered
    assert "runtime import確認済みhandler＋品質policyが揃う構造" in rendered
    assert "代表fixtureで自動解析完了を実証済み: 0件" in rendered
    assert "後方互換用のdeprecated alias" in rendered
    assert "実検体を解析して測定した成功率ではなく" in rendered
    assert "AST監査と検体なしruntime import上で" in rendered
    assert "実検体での実行・完了を保証しません" in rendered
    assert "| full | fully_routable | あり | あり | 1 | 1 | なし |" in rendered


def test_rendered_outputs_can_detect_stale_artifacts(tmp_path: Path) -> None:
    """正本の完全一致と1文字でも古い成果物を区別する。"""

    report = build_coverage(
        registered_families={"full"},
        specs=[_spec("full")],
        quality_policies=_policies("full"),
        preflight=_preflight(),
    )
    rendered = _rendered_outputs(report)
    json_path = tmp_path / "coverage.json"
    markdown_path = tmp_path / "coverage.md"
    json_path.write_text(rendered["json"], encoding="utf-8", newline="\n")
    markdown_path.write_text(rendered["markdown"], encoding="utf-8", newline="\n")

    assert _check_output(json_path, rendered["json"])
    assert _check_output(markdown_path, rendered["markdown"])
    json_path.write_text(rendered["json"] + " ", encoding="utf-8", newline="\n")
    assert not _check_output(json_path, rendered["json"])
    assert not _check_output(tmp_path / "missing.json", rendered["json"])
