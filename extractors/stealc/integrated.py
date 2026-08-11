"""StealC v1 extractorへv2 memory復元を統合する公開adapter。"""

from __future__ import annotations

import urllib.parse

from extractors.stealc.extractor import extract as extract_v1
from extractors.stealc.structural import classify_module_role, protocol_guidance
from extractors.stealc.v2_memory import extract_v2_memory_profile


def _v2_profile(data: bytes) -> dict | None:
    profile = extract_v2_memory_profile(data)
    if profile is None:
        return None
    return {
        "generation": "StealC-v2",
        "method": "v2-memory-base64-standard-rc4",
        "base_url": profile.base_url,
        "gate_path": profile.gate_path,
        "c2_url": profile.c2_url,
        "build_id": profile.build_id,
        "traffic_key_hex": profile.traffic_key_hex,
        "traffic_key_sha256": profile.traffic_key_sha256,
        "string_key": profile.string_key,
        "decoded_string_count": profile.decoded_count,
        "config_offset": profile.config_offset,
        "active_probe": {
            "mode": "bounded_fake_registration",
            "supported": True,
            "network_tested": False,
            "max_requests": 2,
            "request_types": ["create", "loader"],
            "exact_path_required": True,
        },
    }


def _c2_host(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or ""


def extract(data: bytes, source_name: str = "sample.bin") -> dict:
    """v1を先に試し、失敗時だけv2 memory layoutを静的復元する。"""

    result = extract_v1(data, source_name)
    config = result["config"]
    if not config.get("static_config_recovered"):
        profile = _v2_profile(data)
        if profile is not None:
            config["profile"] = profile
            config["static_config_recovered"] = True
            result["findings"].extend(
                [
                    {
                        "kind": "url",
                        "value": profile["c2_url"],
                        "role": "stealc_c2_url",
                        "confidence": "confirmed_static_config",
                    },
                    {
                        "kind": "domain_or_ip",
                        "value": _c2_host(profile["c2_url"]),
                        "role": "stealc_c2_host",
                        "confidence": "confirmed_static_config",
                    },
                ]
            )
            result["limitations"] = [
                value
                for value in result["limitations"]
                if not value.startswith("No supported plaintext profile was recovered")
            ]
            result["limitations"].append(
                "StealC v2の設定は取得済みメモリから静的復元しました。能動通信は実施していません。"
            )

    structural_profile = classify_module_role(data)
    config["structural_profile"] = structural_profile
    config["protocol_analysis"] = protocol_guidance(structural_profile)
    if structural_profile["module_role"] == "chrome_app_bound_key_helper":
        result["limitations"].append(
            "最深の復元PEはChrome App-Bound Encryption helperであり、"
            "最終layerがStealC coreであることを意味しません。"
        )
    return result


__all__ = ["classify_module_role", "extract"]
