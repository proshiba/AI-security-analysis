"""Static Vidar configuration and infrastructure candidate extractor."""

from __future__ import annotations

from extractors.stealer_common import extract_stealer


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract literal Vidar config candidates from payloads and loaders."""
    return extract_stealer(
        "vidar",
        data,
        name,
        ("Vidar", "information.txt", "passwords.txt", "Autofill", "wallets"),
        {
            "browser_collection": ("Login Data", "Web Data", "History", "Cookies"),
            "wallet_collection": ("wallet.dat", "Electrum", "Exodus", "Atomic"),
            "telegram_dead_drop": ("t.me/", "telegram.me/", "api.telegram.org"),
            "dependency_download": ("sqlite3.dll", "freebl3.dll", "nss3.dll"),
        },
        [
            "Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.",
            "Packed or loader-stage samples require recursive recovery before a final config can be asserted.",
        ],
    )
