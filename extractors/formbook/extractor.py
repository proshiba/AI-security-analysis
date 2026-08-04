"""FormBook／XLoaderの配布段階と設定候補を保守的に抽出する。"""

from __future__ import annotations

from extractors.stealer_common import extract_stealer
from extractors.stealer_protocols import attach_protocol_guidance


def extract(data: bytes, name: str = "sample") -> dict:
    """配布URL、候補インフラ、確定C2を分離して返す。"""
    result = extract_stealer(
        "formbook",
        data,
        name,
        ("FormBook", "Formbook", "XLoader", "NtSetContextThread", "GetThreadContext"),
        {
            "browser_credential_theft": ("Login Data", "Web Data", "cookies.sqlite"),
            "mail_credential_theft": ("Outlook", "Thunderbird", "Foxmail"),
            "process_injection": (
                "NtSetContextThread",
                "WriteProcessMemory",
                "QueueUserAPC",
            ),
            "script_loader": ("WScript.Shell", "ADODB.Stream", "PowerShell"),
        },
        [
            "FormBookのpayload設定は暗号化されることが多く、復元したprocess imageが必要な場合があります。",
            "loader URLと証明書参照先は、確定C2へ昇格しません。",
        ],
    )
    return attach_protocol_guidance(result, "formbook")
