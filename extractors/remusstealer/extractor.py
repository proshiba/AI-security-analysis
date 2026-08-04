"""Remus Stealerの設定候補とtoken/task protocol状態を静的に抽出する。"""

from __future__ import annotations

from extractors.stealer_common import extract_stealer
from extractors.stealer_protocols import attach_protocol_guidance


def extract(data: bytes, name: str = "sample") -> dict:
    """Remusの収集機能とインフラ候補を保守的に返す。"""
    result = extract_stealer(
        "remusstealer",
        data,
        name,
        ("Remus", "RemusStealer", "Stealer", "wallet.dat", "Login Data"),
        {
            "browser_collection": ("Login Data", "Local State", "Cookies", "Web Data"),
            "wallet_collection": ("wallet.dat", "Electrum", "Exodus", "MetaMask"),
            "go_runtime": ("Go build ID", "runtime.main", "godebug"),
            "archive_delivery": ("7-zip", "7z", "Wrong password"),
        },
        [
            "暗号化された内側の7z配布物にはcampaign passwordが必要で、password guessingは行いません。",
            "Remus帰属とインフラは、復元payload levelの相関が必要です。",
        ],
    )
    return attach_protocol_guidance(result, "remusstealer")
