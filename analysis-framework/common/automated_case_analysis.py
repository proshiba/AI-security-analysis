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
    _set_phase(
        contract,
        "external_payload_retrieval",
        "blocked",
        "外部stage取得は安全境界により実行せず、必要な場合は追加解析queueへ残した。",
    )
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
        "blocked",
        "通信候補だけではprotocol確認へ昇格せず、family固有frameまたは通信関数の追加解析を要求する。",
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
    contract["c2"]["protocol"] = {
        "status": "unresolved",
        "method": None,
        "confidence": "none",
        "tcp_open_only": False,
        "static_hints": hints,
    }
    contract["automation"].update(
        {
            "status": (
                "static_patterns_extracted"
                if confirmed or candidates
                else "followup_required"
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
    ]
    contract["deep_analysis"]["next_minimum_step"] = (
        "終端payloadの通信関数またはfamily固有frameを静的に復元し、protocol evidenceを追加する。"
        if confirmed or candidates
        else "追加の復元層、memory、公開sandbox成果物、またはfamily固有config decoderを1つ追加する。"
    )
    return patterns, contract
