"""script-only解析カバレッジ監査を検証する。"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from automation_coverage import _check_output, _rendered_outputs, build_coverage, render_markdown
from handler_catalog import HandlerSpec


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
    assert report["counts"]["blocked_automatic_handlers"] == 0
    assert report["counts"]["quality_policy_declared"] == 2
    assert report["counts"]["quality_gated_script_only_handler_available"] == 2
    assert report["counts"]["automatic_family_selection_possible"] == 1
    assert report["counts"]["automated_analysis_completion_possible"] == 1
    assert report["counts"]["executed_preflight_count"] == 2
    assert report["preflight_policy"] == {
        "scope": "each_declared_format",
        "probe_input_size": 1,
        "maximum_input_size": 128 * 1024 * 1024,
        "maximum_preflight_count": 2_048,
        "handler_imported": False,
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
    assert "安全preflight済み" in rendered
    assert "自動完結経路を構成可能" in rendered
    assert "実検体での完了を保証しません" in rendered
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
