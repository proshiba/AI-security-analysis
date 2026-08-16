"""Vidar extractorへdead-drop／最終C2の意味論を適用する互換adapter。"""

from __future__ import annotations

from .extractor import extract as _extract_base
from .semantic import classify_recovered_config


def extract(data: bytes, name: str = "sample") -> dict:
    """既存抽出結果を維持しつつ、設定URLの役割を保守的に補正する。"""

    result = _extract_base(data, name)
    config = result.get("config")
    if not isinstance(config, dict) or not config.get("static_config_recovered"):
        return result
    if isinstance(config.get("endpoint_semantics"), list) and isinstance(
        config.get("config_record_urls"), list
    ):
        return result
    semantics = classify_recovered_config(config)
    original_urls = [
        value for value in config.get("c2_urls", []) if isinstance(value, str)
    ]
    config["config_record_urls"] = original_urls
    config["c2_urls"] = list(semantics["final_c2_candidates"])
    config["dead_drop_urls"] = list(semantics["dead_drop_urls"])
    config["endpoint_semantics"] = semantics["endpoints"]
    config["final_c2_recovered"] = semantics["final_c2_recovered"]
    config["requires_dead_drop_resolution"] = semantics[
        "requires_dead_drop_resolution"
    ]
    features = config.get("features")
    if isinstance(features, dict) and any(
        item["role"] == "dead_drop.telegram" for item in semantics["endpoints"]
    ):
        features["telegram_dead_drop"] = True

    by_url = {item["url"]: item for item in semantics["endpoints"]}
    for finding in result.get("findings", []):
        if not isinstance(finding, dict):
            continue
        endpoint = by_url.get(finding.get("value"))
        if endpoint is None:
            continue
        finding["role"] = endpoint["role"]
        finding["confidence"] = endpoint["confidence"]
        finding["semantic_reason"] = endpoint["reason"]
    return result


__all__ = ["extract"]
