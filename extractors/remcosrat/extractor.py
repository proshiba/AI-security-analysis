"""RemcosRATの厳格設定と保守的な静的候補を分離して抽出する。"""

from __future__ import annotations

from extractors.common import build_result, endpoint_candidates, extract_strings
from extractors.remcosrat.strict_config import RemcosConfigError
from extractors.remcosrat.strict_config import extract_config as extract_strict_config


def _public_strict_failure(error: RemcosConfigError) -> dict[str, object]:
    """preflight監査可能な属性参照だけで公開用失敗理由を組み立てる。"""

    return {
        "reason": error.reason,
        "stage": error.stage,
        "mapped_layout_retry_eligible": error.mapped_layout_retry_eligible,
    }


def marker_score(strings: list[str]) -> tuple[int, list[str]]:
    """包含関係にある文字列を重複加点せずfamily markerを数える。"""

    text = "\n".join(strings).lower()
    markers = []
    if "remcos agent" in text:
        markers.append("remcos agent")
    elif "remcos" in text:
        markers.append("remcos")
    markers.extend(marker for marker in ("rmc-", "control remote") if marker in text)
    return len(markers), markers


def extract(data: bytes, name: str = "sample") -> dict:
    """厳格SETTINGSを優先し、失敗時のliteralは候補のまま返す。"""

    try:
        strict = extract_strict_config(data)
    except RemcosConfigError as error:
        strict = None
        strict_failure = _public_strict_failure(error)
    if strict is not None:
        strict["config"]["source_name"] = name
        strict["strict_config_recovered"] = True
        strict["generic_candidate_fallback_used"] = False
        return strict

    strings = extract_strings(data)
    score, markers = marker_score(strings)
    endpoints = endpoint_candidates(strings)
    findings = [
        {
            "kind": "network.endpoint",
            "value": item,
            "role": "candidate_c2",
            "confidence": "unverified",
            "source": "static_string",
        }
        for item in endpoints
    ]
    result = build_result(
        "remcosrat",
        data,
        {
            "source_name": name,
            "status": "strict_configuration_not_recovered",
            "marker_score": score,
            "markers": markers,
            "endpoints": [],
            "candidate_endpoints": endpoints,
            "static_config_recovered": False,
            "decoded_config_recovered": False,
            "family_attribution_confirmed": False,
            "strict_failure": strict_failure,
        },
        findings,
        [
            "Remcos設定は暗号化またはresource内にある可能性がある。",
            "平文endpointは設定参照またはprocess帰属付き証拠がないため候補に限定する。",
        ],
    )
    result.update(
        {
            "classification_confidence": "unverified",
            "family_attribution_confirmed": False,
            "strict_config_recovered": False,
            "generic_candidate_fallback_used": True,
            "static_config_recovered": False,
            "decoded_config_recovered": False,
            "operational_c2_recovered": False,
            "c2": [],
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "raw_config_published": False,
                "credentials_published": False,
                "private_key_published": False,
            },
        }
    )
    return result
