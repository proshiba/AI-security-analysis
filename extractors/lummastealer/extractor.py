"""Static Lumma Stealer configuration candidate extractor."""

from __future__ import annotations

from extractors.stealer_common import extract_stealer


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract Lumma infrastructure and collection-feature candidates."""
    return extract_stealer(
        "lummastealer",
        data,
        name,
        ("Lumma", "LummaC2", "Lumma Stealer", "build_id", "hwid"),
        {
            "browser_collection": ("Login Data", "Local State", "Cookies", "Web Data"),
            "wallet_collection": ("wallet.dat", "MetaMask", "Electrum", "Exodus"),
            "loader_or_packer": ("Go build ID", "UPX!", "Nullsoft", "NSIS"),
            "c2_api": ("/api/", "/gate", "hwid", "build_id"),
        },
        [
            "Current Lumma deliveries often contain a loader or protected layer instead of plaintext final config.",
            "Literal infrastructure remains candidate until family config use is established.",
        ],
    )
