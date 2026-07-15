"""Static Atomic macOS Stealer (AMOS) configuration extractor."""

from __future__ import annotations

from extractors.stealer_common import extract_stealer


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract AMOS exfiltration URLs and macOS collection features."""
    return extract_stealer(
        "amosstealer",
        data,
        name,
        ("Atomic", "AMOS", "osascript", "keychain", "Login Data", "ledger"),
        {
            "keychain_collection": (
                "keychain",
                "security find-generic-password",
                "security dump-keychain",
            ),
            "browser_collection": ("Login Data", "Cookies", "History", "Web Data"),
            "wallet_collection": (
                "Ledger",
                "Electrum",
                "Exodus",
                "Atomic",
                "wallet.dat",
            ),
            "apple_script": ("osascript", "tell application", "System Events"),
            "user_prompt": ("display dialog", "password", "administrator privileges"),
        },
        [
            "The `/ledger/` URL pattern is treated as probable exfil/C2 infrastructure, not proof of server ownership.",
            "Script and macro submissions can be delivery stages rather than the final Mach-O payload.",
        ],
    )
