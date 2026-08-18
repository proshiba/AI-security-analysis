#!/usr/bin/env python3
"""one-shot成果から設定・C2解析phaseと通信パターンを自動合成する。"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from c2_analysis_contract import REQUIRED_PHASES, build_unresolved_contract
from handler_evidence import build_communication_pattern_document


def _phase(document: dict[str, Any], name: str) -> dict[str, Any]:
    for item in document["phase_evidence"]:
        if item["phase"] == name:
            return item
    raise ValueError(f"必須phaseがありません: {name}")


def _set_phase(
    document: dict[str, Any],
    name: str,
    status: str,
    evidence: str,
) -> None:
    if name not in REQUIRED_PHASES:
        raise ValueError(f"未登録phaseです: {name}")
    item = _phase(document, name)
    item["status"] = status
    item["evidence"] = [evidence]


def _recovered_layer_count(layer_report: Mapping[str, Any]) -> int:
    counts = layer_report.get("counts")
    value = counts.get("recovered_layers") if isinstance(counts, Mapping) else None
    return value if isinstance(value, int) and not isinstance(value, bool) and value >= 0 else 0


def _endpoint_value(record: Mapping[str, Any]) -> str | None:
    for key in ("url", "host", "domain", "ip", "address", "endpoint"):
        value = record.get(key)
        if not isinstance(value, str) or not value.strip():
            continue
        port = record.get("port")
        if key != "url" and isinstance(port, int) and not isinstance(port, bool):
            return f"{value}:{port}"
        return value
    return None


def build_case_automation_artifacts(
    *,
    sha256: str,
    family: str,
    layer_report: Mapping[str, Any],
    handler_results: Sequence[tuple[Mapping[str, Any], Mapping[str, Any]]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """通信パターン文書とfail-closedのC2解析契約を同じ証拠から生成する。"""

    patterns = build_communication_pattern_document(
        sha256=sha256,
        family=family,
        handler_results=handler_results,
    )
    contract = build_unresolved_contract(
        sha256,
        family,
        handlers=patterns["config"]["trusted_handler_ids"],
    )
    recovered_layers = _recovered_layer_count(layer_report)
    if recovered_layers:
        _set_phase(
            contract,
            "embedded_layer_recovery",
            "completed",
            f"上限付き静的復元で{recovered_layers}層を記録した。",
        )
    else:
        _set_phase(
            contract,
            "embedded_layer_recovery",
            "not_applicable",
            "構造検証を通過する追加埋め込み層は得られなかった。",
        )
    terminal_managed_client = patterns["config"].get("terminal_managed_client") is True
    protocols = patterns["communication"].get("protocol_evidence", [])
    protocol_confirmed = bool(protocols)
    _set_phase(
        contract,
        "external_payload_retrieval",
        "not_applicable" if terminal_managed_client else "blocked",
        (
            "root自体を終端managed clientと検証したため外部stage取得は不要です。"
            if terminal_managed_client
            else "外部stage取得は安全境界により実行せず、必要な場合は追加解析queueへ残した。"
        ),
    )
    for phase, evidence in (
        ("sandbox_artifact_review", "静的証拠で終端clientを確定したため追加sandbox成果物は必須ではありません。"),
        ("memory_artifact_review", "静的証拠で終端clientと設定を回収したためmemory成果物は必須ではありません。"),
    ):
        if terminal_managed_client:
            _set_phase(contract, phase, "not_applicable", evidence)
    if terminal_managed_client:
        _set_phase(
            contract,
            "terminal_payload_analysis",
            "completed",
            "root managed clientを終端payloadとして静的に確認しました。",
        )
        contract["terminal_payload"] = {
            "reached": True,
            "status": "no_additional_payload_verified",
            "family": family,
            "blockers": [],
            "next_actions": ["必要に応じて限定live観測を別履歴として実施します。"],
        }
    _set_phase(
        contract,
        "family_config_extraction",
        "completed" if patterns["config"]["static_config_recovered"] else "blocked",
        (
            "十分な静的handler証拠から設定回収を確認した。"
            if patterns["config"]["static_config_recovered"]
            else "十分な静的handler証拠から設定を回収できなかった。"
        ),
    )
    confirmed = patterns["communication"]["confirmed_static_endpoints"]
    candidates = patterns["communication"]["candidate_patterns"]
    _set_phase(
        contract,
        "c2_endpoint_extraction",
        "completed" if confirmed or candidates else "blocked",
        (
            f"静的設定endpoint {len(confirmed)}件と未確定pattern {len(candidates)}件を分離して記録した。"
            if confirmed or candidates
            else "信頼済みhandler成果物から通信endpointを回収できなかった。"
        ),
    )
    _set_phase(
        contract,
        "c2_protocol_analysis",
        "completed" if protocol_confirmed else "blocked",
        (
            "family固有の登録、frame、dispatcherを静的method証拠で確認しました。"
            if protocol_confirmed
            else "通信候補だけではprotocol確認へ昇格せず、family固有frameまたは通信関数の追加解析を要求する。"
        ),
    )
    contract["c2"]["endpoints"] = [
        {
            "value": value,
            "role": str(record.get("role") or "c2_candidate"),
            "source": str(record.get("source") or "static_handler"),
            "confidence": str(record.get("confidence") or "confirmed_static_configuration"),
        }
        for record in confirmed
        if (value := _endpoint_value(record)) is not None
    ]
    contract["c2"]["evidence"] = [
        "静的設定endpointと候補patternをcommunication-patterns.jsonへ分離して記録した。"
        if confirmed or candidates
        else "汎用文字列候補をC2へ昇格せず、静的handlerによる抽出不足を記録した。"
    ]
    hints = patterns["communication"]["protocol_hints"]
    selected_protocol = protocols[0] if protocol_confirmed else {}
    contract["c2"]["protocol"] = {
        "status": ("static_confirmed_live_unverified" if protocol_confirmed else "unresolved"),
        "method": selected_protocol.get("method") if protocol_confirmed else None,
        "confidence": selected_protocol.get("confidence", "none"),
        "tcp_open_only": False,
        "static_hints": hints,
        "live_verified": False,
    }
    contract["automation"].update(
        {
            "status": (
                "static_patterns_extracted" if confirmed or candidates or protocol_confirmed else "followup_required"
            ),
            "handlers": [
                "analysis-framework/common/handler_evidence.py",
                "analysis-framework/common/automated_case_analysis.py",
            ],
            "tests": ["analysis-framework/tests/test_automated_case_analysis.py"],
        }
    )
    contract["deep_analysis"]["attempted_methods"] = [
        "一括静的解析",
        "上限付き埋め込み層復元",
        "family分類とhandler適用可否判定",
        "静的config抽出",
        "通信pattern正規化",
        "family固有protocol methodの静的検証",
    ]
    if protocol_confirmed:
        contract["deep_analysis"]["blockers"] = ["静的protocolは確認済みですが限定live観測は未実施です。"]
        contract["deep_analysis"]["next_minimum_step"] = (
            "必要な場合だけ、安全gate下で限定live観測を別履歴として実施する。"
        )
    else:
        contract["deep_analysis"]["next_minimum_step"] = (
            "終端payloadの通信関数またはfamily固有frameを静的に復元し、protocol evidenceを追加する。"
            if confirmed or candidates
            else "追加の復元層、memory、公開sandbox成果物、またはfamily固有config decoderを1つ追加する。"
        )
    return patterns, contract
