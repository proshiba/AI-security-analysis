"""既存ACRStealer extractorへv4 memory設定復元を統合するadapter。"""

from __future__ import annotations

from .extractor import extract as extract_base
from .extractor import recover_artifacts
from .v4_config import extract_v4_config


def extract(data: bytes, source_name: str = "sample.bin") -> dict:
    """取得済みmemoryにv4構造がある場合だけ高確度configを追加する。"""

    result = extract_base(data, source_name)
    recovered = extract_v4_config(data)
    if recovered is None:
        return result

    config = result["config"]
    config.update(
        {
            "artifact_role": "acrstealer_v4_reconstructed_memory",
            "static_config_recovered": True,
            "version": recovered.version,
            "final_c2_urls": list(recovered.final_c2_urls),
            "final_c2_hosts": list(recovered.final_c2_hosts),
            "final_c2_paths": list(recovered.final_c2_paths),
            "dead_drop_urls": list(recovered.dead_drop_urls),
            "dns_resolvers": list(recovered.dns_resolvers),
            "decoy_hosts": list(recovered.decoy_hosts),
            "guids": list(recovered.guids),
            "user_agent": recovered.user_agent,
            "string_key_hex": recovered.string_key_hex,
            "decoded_string_count": recovered.decoded_count,
            "memory_layout": recovered.layout,
            "protocol_fingerprint": list(recovered.protocol_fingerprint),
            "protocol_confidence": recovered.protocol_confidence,
            "active_registration_supported": recovered.active_registration_supported,
            "unresolved_fields": list(recovered.unresolved_fields),
            "generic_domain_findings": list(recovered.generic_domain_findings),
        }
    )
    result["findings"].extend(
        {
            "kind": "url",
            "value": value,
            "role": "acrstealer_dead_drop",
            "confidence": "confirmed_static_config",
        }
        for value in recovered.dead_drop_urls
    )
    result["findings"].extend(
        {
            "kind": "domain",
            "value": value,
            "role": "acrstealer_generic_domain_finding",
            "confidence": "decoded_string_only",
        }
        for value in recovered.generic_domain_findings
    )
    result["findings"].extend(
        {
            "kind": "domain",
            "value": value,
            "role": "acrstealer_final_c2_host",
            "confidence": "confirmed_static_config",
        }
        for value in recovered.final_c2_hosts
    )
    result["findings"].extend(
        {
            "kind": "domain",
            "value": value,
            "role": "dns_over_https_resolver",
            "confidence": "confirmed_static_config",
        }
        for value in recovered.dns_resolvers
    )
    result["limitations"] = [
        value
        for value in result["limitations"]
        if not value.startswith("対応済みファイルポンプまたはレビュー済みnative loader layout")
    ]
    result["limitations"].extend(
        [
            "ACRStealer v4の設定は取得済みメモリから静的復元しました。",
            "request body schemaと暗号が未復元のため、能動fake-registrationは無効です。",
            "wssというhost prefixだけをWebSocketの根拠にはしていません。",
        ]
    )
    return result


__all__ = ["extract", "recover_artifacts"]
