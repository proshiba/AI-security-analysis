"""Conservative Formbook/XLoader delivery and configuration extractor."""

from __future__ import annotations

from extractors.stealer_common import extract_stealer


def extract(data: bytes, name: str = "sample") -> dict:
    """Extract Formbook literals while separating delivery URLs from confirmed C2."""
    return extract_stealer(
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
            "Formbook payload configuration is commonly encrypted and may require a recovered process image.",
            "Loader URLs and certificate references are not promoted to confirmed C2.",
        ],
    )
