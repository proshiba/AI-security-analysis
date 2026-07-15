"""Static Remus Stealer configuration candidate extractor."""

from __future__ import annotations

from extractors.stealer_common import extract_stealer


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract Remus Stealer collection and infrastructure candidates."""
    return extract_stealer(
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
            "Encrypted inner 7z deliveries require the campaign password; password guessing is not performed.",
            "Remus attribution and infrastructure require recovered payload-level corroboration.",
        ],
    )
