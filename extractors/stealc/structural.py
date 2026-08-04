"""StealC v2以降のcoreと補助moduleをオフラインで構造判定する。"""

from __future__ import annotations

import re

from extractors.common import extract_strings


CORE_JSON_MARKERS = (
    b"content-type: application/json",
    b"nlohmann",
    b"json.h",
)
CORE_TRANSPORT_MARKERS = (
    b"wininet.dll",
    b"httpsendrequestw",
    b"httpopenrequestw",
    b"internetconnectw",
)
CORE_COLLECTION_MARKERS = (
    b"login data",
    b"local state",
    b"web data",
    b"cookies",
    b"wallet",
    b"steam",
    b"telegram",
)
APP_BOUND_MARKERS = (
    b"app_bound_encrypted_key",
    b"cryptstringtobinarya",
    b"cryptunprotectdata",
    b"cocreateinstance",
)
STRUCTURAL_GATE_MARKERS = (
    *CORE_JSON_MARKERS,
    *CORE_TRANSPORT_MARKERS,
    *CORE_COLLECTION_MARKERS,
    b"app_bound_encrypted_key",
)


def classify_module_role(data: bytes) -> dict[str, object]:
    """collection／C2 coreとChrome App-Bound helperを保守的に区別する。"""
    lowered = "\n".join(extract_strings(data)).lower().encode(
        "utf-8", errors="ignore"
    )
    json_hits = [value.decode() for value in CORE_JSON_MARKERS if value in lowered]
    transport_hits = [
        value.decode() for value in CORE_TRANSPORT_MARKERS if value in lowered
    ]
    collection_hits = [
        value.decode() for value in CORE_COLLECTION_MARKERS if value in lowered
    ]
    app_bound_hits = [
        value.decode() for value in APP_BOUND_MARKERS if value in lowered
    ]
    builder_marker = re.search(rb"builder_v[0-9]+", lowered)

    if (
        len(json_hits) >= 2
        and len(transport_hits) >= 2
        and len(collection_hits) >= 2
    ):
        return {
            "module_role": "collection_and_c2_core",
            "confidence": "high",
            "generation_candidate": "StealC-v2-or-later",
            "version_confirmed": False,
            "evidence": {
                "json_markers": json_hits,
                "transport_markers": transport_hits,
                "collection_markers": collection_hits,
                "builder_marker": builder_marker.group().decode()
                if builder_marker
                else None,
            },
        }

    if b"app_bound_encrypted_key" in lowered and len(app_bound_hits) >= 2:
        return {
            "module_role": "chrome_app_bound_key_helper",
            "confidence": "high",
            "generation_candidate": "StealC-v2-or-later-related-helper",
            "version_confirmed": False,
            "evidence": {"app_bound_markers": app_bound_hits},
        }

    return {
        "module_role": "unknown",
        "confidence": "low",
        "generation_candidate": None,
        "version_confirmed": False,
        "evidence": {
            "json_markers": json_hits,
            "transport_markers": transport_hits,
            "collection_markers": collection_hits,
            "app_bound_markers": app_bound_hits,
        },
    }


def protocol_guidance(structural_profile: dict[str, object]) -> dict[str, object]:
    """構造判定から公開可能なC2解析状態と安全方針を作る。"""
    role = structural_profile.get("module_role")
    return {
        "confirmed_c2": [],
        "candidate_infrastructure_only": True,
        "profile_candidates": ["StealC-v2-JSON-RC4"]
        if role == "collection_and_c2_core"
        else [],
        "active_probe_policy": "guarded_active_reviewed_profile_only",
        "active_probe_reason": (
            "復号済みRC4鍵・build・完全一致endpoint・単一IP pinと二重の明示許可が"
            "揃う場合だけ、合成hwidのcreateとloader task取得を各1回行えます。"
        ),
    }
