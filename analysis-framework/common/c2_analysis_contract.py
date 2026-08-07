#!/usr/bin/env python3
"""検体単位の終端payload・設定・C2解析契約をfail-closedで検証する。"""

from __future__ import annotations

import argparse
from collections.abc import Iterable
import json
from pathlib import Path
import re
from typing import Any


SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"[0-9a-f]{64}")
REQUIRED_PHASES = (
    "root_static_analysis",
    "embedded_layer_recovery",
    "external_payload_retrieval",
    "sandbox_artifact_review",
    "memory_artifact_review",
    "terminal_payload_analysis",
    "family_config_extraction",
    "c2_endpoint_extraction",
    "c2_protocol_analysis",
    "automation_and_tests",
)
PHASE_STATUSES = {"completed", "not_applicable", "blocked"}
C2_OUTCOMES = {"confirmed", "no_c2_capability_verified", "unresolved"}
DEFERRED_ALLOWED_FINDINGS = {
    "c2_phase_blocked",
    "terminal_payload_not_reached",
    "terminal_payload_unresolved",
    "terminal_payload_has_blockers",
    "c2_outcome_unresolved",
}


def _finding(findings: list[dict[str, str]], code: str, message: str) -> None:
    findings.append({"code": code, "message": message})


def _nonempty_strings(value: object) -> bool:
    return isinstance(value, list) and bool(value) and all(
        isinstance(item, str) and bool(item.strip()) for item in value
    )


def _repository_path(
    repository: Path | None,
    value: object,
) -> Path | None:
    if repository is None or not isinstance(value, str) or not value.strip():
        return None
    candidate = (repository / value).resolve()
    try:
        candidate.relative_to(repository.resolve())
    except ValueError:
        return None
    return candidate


def build_unresolved_contract(
    sha256: str,
    family: str,
    *,
    handlers: Iterable[str] = (),
) -> dict[str, Any]:
    """一括静的解析後に、深掘り未完了を明示する初期契約を生成する。"""

    digest = str(sha256).strip().lower()
    if not SHA256_RE.fullmatch(digest):
        raise ValueError("sha256は小文字64桁の16進数で指定してください")
    return {
        "schema_version": SCHEMA_VERSION,
        "sha256": digest,
        "family": str(family or "unclassified"),
        "analysis_attempted": True,
        "phase_evidence": [
            {
                "phase": phase,
                "status": "completed" if phase in {"root_static_analysis", "automation_and_tests"} else "blocked",
                "evidence": [
                    "一括静的解析と既存解析器の適用可否判定を実施した。"
                    if phase == "root_static_analysis"
                    else "一括解析・公開処理の再利用可能なscriptとtestを適用した。"
                    if phase == "automation_and_tests"
                    else "一括静的解析後の深掘りqueueへ登録した。"
                ],
            }
            for phase in REQUIRED_PHASES
        ],
        "terminal_payload": {
            "reached": False,
            "status": "unresolved",
            "family": None,
            "blockers": ["終端payload・設定・C2の深掘りが未完了"],
            "next_actions": ["公開sandbox成果物、memory、後段、設定decoderを追加解析する"],
        },
        "c2": {
            "outcome": "unresolved",
            "extraction_attempted": True,
            "endpoints": [],
            "evidence": ["汎用文字列候補を確認済みC2へ昇格していない。"],
            "protocol": {
                "status": "unresolved",
                "method": None,
                "confidence": "none",
                "tcp_open_only": False,
            },
            "live_check": {
                "status": "pending",
                "target_registered": False,
            },
        },
        "automation": {
            "status": "followup_required",
            "handlers": ["analysis-framework/common/publish_one_shot_collection.py"],
            "tests": ["analysis-framework/tests/test_publish_one_shot_collection.py"],
            "reusable_logic_recorded": True,
            "matched_handler_ids": sorted({str(item) for item in handlers if str(item).strip()}),
        },
        "deep_analysis": {
            "status": "deferred_for_deep_analysis",
            "priority": "normal",
            "queue": "terminal-payload-gap",
            "attempted_methods": ["一括静的解析", "既存解析器の適用可否判定", "C2候補文字列の精査"],
            "blockers": ["終端payload・設定・C2の深掘りが未完了"],
            "next_minimum_step": "公開sandbox成果物、memory、後段取得、またはfamily固有decoderのうち利用可能な証拠を1つ追加する。",
        },
        "safety": {
            "sample_executed_locally": False,
            "credentials_published": False,
            "raw_payload_published": False,
        },
    }


def validate_contract(
    document: dict[str, Any],
    expected_sha256: str,
    *,
    repository: Path | None = None,
) -> dict[str, Any]:
    """C2解析契約を検証し、未解決を完了扱いしない。"""

    findings: list[dict[str, str]] = []
    expected = str(expected_sha256).strip().lower()
    if not SHA256_RE.fullmatch(expected):
        raise ValueError("expected_sha256が不正です")
    if document.get("schema_version") != SCHEMA_VERSION:
        _finding(findings, "c2_contract_schema", "schema_versionが対応値ではありません。")
    if document.get("sha256") != expected:
        _finding(findings, "c2_contract_sha256", "sha256が対象検体と一致しません。")
    if document.get("analysis_attempted") is not True:
        _finding(findings, "c2_analysis_not_attempted", "C2解析を試行した証跡がありません。")

    phases = document.get("phase_evidence")
    phase_map: dict[str, dict[str, Any]] = {}
    if not isinstance(phases, list):
        _finding(findings, "c2_phase_evidence_missing", "phase_evidenceは配列である必要があります。")
        phases = []
    for item in phases:
        if not isinstance(item, dict) or not isinstance(item.get("phase"), str):
            _finding(findings, "c2_phase_invalid", "phase evidenceに不正な要素があります。")
            continue
        phase = item["phase"]
        if phase in phase_map:
            _finding(findings, "c2_phase_duplicate", f"phaseが重複しています: {phase}")
            continue
        phase_map[phase] = item
    for phase in REQUIRED_PHASES:
        item = phase_map.get(phase)
        if item is None:
            _finding(findings, "c2_phase_missing", f"必須phaseがありません: {phase}")
            continue
        status = item.get("status")
        if status not in PHASE_STATUSES:
            _finding(findings, "c2_phase_status", f"phase statusが不正です: {phase}")
        elif status == "blocked":
            _finding(findings, "c2_phase_blocked", f"phaseが未解決です: {phase}")
        if not _nonempty_strings(item.get("evidence")):
            _finding(findings, "c2_phase_evidence_empty", f"phaseの根拠がありません: {phase}")

    terminal = document.get("terminal_payload")
    if not isinstance(terminal, dict):
        _finding(findings, "terminal_payload_missing", "terminal_payloadがありません。")
        terminal = {}
    if terminal.get("reached") is not True:
        _finding(findings, "terminal_payload_not_reached", "終端payloadまで到達していません。")
    if terminal.get("status") not in {"recovered", "no_additional_payload_verified"}:
        _finding(findings, "terminal_payload_unresolved", "終端payloadの状態が未解決です。")
    blockers = terminal.get("blockers")
    if blockers not in (None, []) and not isinstance(blockers, list):
        _finding(findings, "terminal_payload_blockers_invalid", "blockersは配列である必要があります。")
    if isinstance(blockers, list) and blockers:
        _finding(findings, "terminal_payload_has_blockers", "終端解析blockerが残っています。")

    c2 = document.get("c2")
    if not isinstance(c2, dict):
        _finding(findings, "c2_result_missing", "c2結果がありません。")
        c2 = {}
    outcome = c2.get("outcome")
    if outcome not in C2_OUTCOMES:
        _finding(findings, "c2_outcome_invalid", "c2.outcomeが不正です。")
    elif outcome == "unresolved":
        _finding(findings, "c2_outcome_unresolved", "C2解析が未解決です。")
    if c2.get("extraction_attempted") is not True:
        _finding(findings, "c2_extraction_not_attempted", "設定・C2抽出を試行していません。")
    if not _nonempty_strings(c2.get("evidence")):
        _finding(findings, "c2_evidence_empty", "C2判定根拠がありません。")
    endpoints = c2.get("endpoints")
    if not isinstance(endpoints, list):
        _finding(findings, "c2_endpoints_invalid", "endpointsは配列である必要があります。")
        endpoints = []
    protocol = c2.get("protocol") if isinstance(c2.get("protocol"), dict) else {}
    live_check = c2.get("live_check") if isinstance(c2.get("live_check"), dict) else {}
    if outcome == "confirmed":
        if not endpoints:
            _finding(findings, "confirmed_c2_without_endpoint", "確認済みC2にendpointがありません。")
        for endpoint in endpoints:
            if not isinstance(endpoint, dict) or not all(
                isinstance(endpoint.get(key), str) and endpoint[key].strip()
                for key in ("value", "role", "source")
            ):
                _finding(findings, "confirmed_c2_endpoint_invalid", "C2 endpointの値・役割・根拠が不完全です。")
                break
        if protocol.get("status") != "confirmed":
            _finding(findings, "c2_protocol_unconfirmed", "malware protocolレベルの確認がありません。")
        if not isinstance(protocol.get("method"), str) or not protocol["method"].strip():
            _finding(findings, "c2_protocol_method_missing", "protocol確認方法がありません。")
        if protocol.get("confidence") not in {"medium", "high"}:
            _finding(findings, "c2_protocol_confidence_low", "protocol確認の確度が不足しています。")
        if protocol.get("tcp_open_only") is not False:
            _finding(findings, "c2_tcp_open_only", "TCP openだけでは確認済みC2にできません。")
        if live_check.get("target_registered") is not True:
            _finding(findings, "c2_live_target_not_registered", "全履歴C2監視へ登録されていません。")
        if live_check.get("status") != "observed":
            _finding(findings, "c2_live_check_not_observed", "dailyの限定ライブ観測が完了していません。")
    elif outcome == "no_c2_capability_verified":
        if endpoints:
            _finding(findings, "no_c2_outcome_has_endpoints", "C2機能なし判定とendpointが矛盾します。")
        if protocol.get("status") != "not_applicable":
            _finding(findings, "no_c2_protocol_not_applicable_missing", "C2非該当のprotocol評価がありません。")

    automation = document.get("automation")
    if not isinstance(automation, dict):
        _finding(findings, "c2_automation_missing", "automation記録がありません。")
        automation = {}
    for key in ("handlers", "tests"):
        values = automation.get(key)
        if not _nonempty_strings(values):
            _finding(findings, f"c2_automation_{key}_missing", f"automation.{key}がありません。")
            continue
        for value in values:
            resolved = _repository_path(repository, value)
            if repository is not None and (resolved is None or not resolved.is_file()):
                _finding(findings, f"c2_automation_{key}_path", f"repository内のfileを確認できません: {value}")
    if automation.get("reusable_logic_recorded") is not True:
        _finding(findings, "c2_automation_not_reusable", "解析ロジックが再利用可能なscriptへ反映されていません。")

    deep_analysis = document.get("deep_analysis")
    if outcome == "unresolved":
        if not isinstance(deep_analysis, dict):
            _finding(findings, "c2_deep_analysis_missing", "未解決検体の追加解析queue情報がありません。")
            deep_analysis = {}
        if deep_analysis.get("status") != "deferred_for_deep_analysis":
            _finding(findings, "c2_deep_analysis_status", "未解決検体の繰越状態が不正です。")
        if deep_analysis.get("priority") not in {"critical", "high", "normal", "low"}:
            _finding(findings, "c2_deep_analysis_priority", "追加解析の優先度がありません。")
        if not isinstance(deep_analysis.get("queue"), str) or not deep_analysis["queue"].strip():
            _finding(findings, "c2_deep_analysis_queue", "追加解析queueがありません。")
        if not _nonempty_strings(deep_analysis.get("attempted_methods")):
            _finding(findings, "c2_deep_analysis_attempts", "試行済み解析手法がありません。")
        if not _nonempty_strings(deep_analysis.get("blockers")):
            _finding(findings, "c2_deep_analysis_blockers", "未解決理由がありません。")
        next_step = deep_analysis.get("next_minimum_step")
        if not isinstance(next_step, str) or not next_step.strip():
            _finding(findings, "c2_deep_analysis_next_step", "次に必要な最小手順がありません。")

    safety = document.get("safety")
    if not isinstance(safety, dict):
        _finding(findings, "c2_safety_missing", "safety記録がありません。")
        safety = {}
    for key in ("sample_executed_locally", "credentials_published", "raw_payload_published"):
        if safety.get(key) is not False:
            _finding(findings, f"c2_unsafe_{key}", f"safety.{key}がfalseではありません。")
    complete = not findings
    blocking_for_daily = [
        item for item in findings if item["code"] not in DEFERRED_ALLOWED_FINDINGS
    ]
    daily_ready = complete or (
        outcome == "unresolved"
        and isinstance(deep_analysis, dict)
        and deep_analysis.get("status") == "deferred_for_deep_analysis"
        and not blocking_for_daily
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "sha256": expected,
        "complete": complete,
        "daily_ready": daily_ready,
        "deferred": daily_ready and not complete,
        "outcome": outcome if outcome in C2_OUTCOMES else "invalid",
        "finding_count": len(findings),
        "daily_blocking_finding_count": len(blocking_for_daily),
        "findings": findings,
    }


def validate_case(
    case_root: Path,
    expected_sha256: str,
    *,
    repository: Path | None = None,
) -> dict[str, Any]:
    """case directoryのc2-analysis.jsonを読んで検証する。"""

    path = case_root / "c2-analysis.json"
    if not path.is_file():
        return {
            "schema_version": SCHEMA_VERSION,
            "sha256": expected_sha256,
            "complete": False,
            "outcome": "missing",
            "finding_count": 1,
            "findings": [{"code": "c2_analysis_file_missing", "message": "c2-analysis.jsonがありません。"}],
        }
    try:
        document = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        return {
            "schema_version": SCHEMA_VERSION,
            "sha256": expected_sha256,
            "complete": False,
            "outcome": "invalid",
            "finding_count": 1,
            "findings": [
                {"code": "c2_analysis_json_invalid", "message": f"JSONを読めません: {type(error).__name__}"}
            ],
        }
    if not isinstance(document, dict):
        document = {}
    return validate_contract(document, expected_sha256, repository=repository)


def main(argv: list[str] | None = None) -> int:
    """CLI引数を処理する。"""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case-root", type=Path, required=True, help="検証対象case directory")
    parser.add_argument("--sha256", required=True, help="対象検体SHA-256")
    parser.add_argument("--repository", type=Path, help="handler/test pathを確認するrepository root")
    args = parser.parse_args(argv)
    result = validate_case(
        args.case_root.resolve(),
        args.sha256,
        repository=args.repository.resolve() if args.repository else None,
    )
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
