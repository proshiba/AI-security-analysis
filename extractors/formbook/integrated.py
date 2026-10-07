"""FormBook通常ルートから高度なFormBook／XLoader静的解析へ接続する。"""

from __future__ import annotations

from malware.formbook_loader.extract_config import (
    extract_config as _extract_loader_component,
)


HANDLER_CONTRACT = {
    "input_formats": ["script", "data", "pe", "macho", "ole", "zip"],
    "minimum_evidence_score": 20_000,
}


def extract(data: bytes, name: str = "sample") -> dict[str, object]:
    """高度解析結果を通常FormBookルートへ安全なcomponent証拠として返す。

    FormBookとXLoaderのローダー構造は共通し得るため、このadapterは高度解析器が
    得た後段、設定、通信候補を保持する一方、結果単独では終端FormBook帰属を
    支持しない。高度解析器が証拠なしと判定した場合は、その例外を変更せず上位の
    ``not_applicable``処理へ渡す。
    """

    recovered = _extract_loader_component(data)
    if not isinstance(recovered, dict):
        raise ValueError("FormBook高度解析結果がobjectではありません")
    if recovered.get("matched") is not True:
        raise ValueError("FormBook高度解析結果が構造一致を示していません")
    if recovered.get("family") != "formbook_loader":
        raise ValueError("FormBook高度解析結果のcomponent familyが不正です")
    if (
        recovered.get("executed_sample") is not False
        or recovered.get("network_contacted") is not False
    ):
        raise ValueError("FormBook高度解析結果の安全契約が不正です")
    supports_attribution = recovered.get("supports_family_attribution")
    terminal_confirmed = recovered.get("terminal_family_confirmed")
    if type(supports_attribution) is not bool or type(terminal_confirmed) is not bool:
        raise ValueError("FormBook高度解析結果の帰属契約が不正です")

    limitations = recovered.get("limitations")
    if not isinstance(limitations, list) or any(
        not isinstance(item, str) or not item for item in limitations
    ):
        raise ValueError("FormBook高度解析結果の制約一覧が不正です")

    return {
        **recovered,
        "family": "formbook",
        "source_name": name,
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "attribution_scope": "component_handler_route",
        "advanced_static_adapter": {
            "source_family": "formbook_loader",
            "source_supports_family_attribution": supports_attribution,
            "source_terminal_family_confirmed": terminal_confirmed,
            "family_promotion_allowed": False,
        },
        "limitations": [
            *limitations,
            "通常FormBook routeへのadapterは、共通ローダー構造だけで終端FormBook帰属を確定しない",
        ],
    }
