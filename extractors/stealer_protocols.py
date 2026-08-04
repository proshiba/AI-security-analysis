"""スティーラー系抽出結果へ共通のC2証拠境界と安全方針を付加する。"""

from __future__ import annotations

import copy


PROTOCOL_GUIDANCE: dict[str, dict[str, object]] = {
    "formbook": {
        "profile_candidates": ["FormBook-4.1-or-XLoader-RC4-HTTP"],
        "version_confirmed": False,
        "active_probe_policy": "passive_only",
        "active_probe_reason": (
            "64 domainとmain URIのdecoy構造、および404偽装があるため、"
            "復号済み設定と鍵なしのHTTP応答をC2確認に使いません。"
        ),
        "minimum_confirmation": [
            "復元process imageの設定復号",
            "main URIとreal domainの識別",
            "process帰属付き通信または復号可能なPCAP",
        ],
    },
    "lummastealer": {
        "profile_candidates": [
            "Lumma-v5-or-earlier-act-ver-lid-j",
            "Lumma-v6-uid-cid",
        ],
        "version_confirmed": False,
        "active_probe_policy": "guarded_active_reviewed_profile_only",
        "active_probe_reason": (
            "v6は復号済み完全一致profile、単一IP pin、二重の明示許可がある場合だけ、"
            "合成hwidによる設定登録とtask取得を各1回行えます。"
            "v5以前もexact versionと復号設定がない対象へact=lifeを送りません。"
        ),
        "minimum_confirmation": [
            "version別フォームkey集合",
            "process帰属付きHTTP(S)要求",
            "hardcoded C2とfallback sourceの役割分離",
        ],
    },
    "remusstealer": {
        "profile_candidates": ["Remus-access-token-step-multipart-HTTP"],
        "version_confirmed": False,
        "active_probe_policy": "guarded_active_reviewed_profile_only",
        "active_probe_reason": (
            "復号済み完全一致profile、単一IP pin、二重の明示許可がある場合だけ、"
            "合成hwidで登録し、tokenを公開せずstep=1を1回取得できます。"
        ),
        "minimum_confirmation": [
            "復号済みC2 list",
            "tag/exp/hwidからaccess_token/stepへの要求列",
            "socket接続先とHTTP Hostの分離",
        ],
    },
}


def attach_protocol_guidance(result: dict, family: str) -> dict:
    """既存schemaを保ち、候補IOCと確定C2を混同しない状態を追加する。"""
    guidance = copy.deepcopy(PROTOCOL_GUIDANCE[family])
    config = result["config"]
    guidance.update(
        {
            "confirmed_c2": [],
            "candidate_infrastructure": [
                *config.get("urls", []),
                *config.get("endpoints", []),
            ],
            "terminal_protocol_recovered": False,
        }
    )
    config["protocol_analysis"] = guidance
    return result
