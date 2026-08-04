from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "malware"
    / "valleyrat"
    / "campaigns"
    / "signed_proxy_sideload"
    / "analyze.py"
)
SPEC = importlib.util.spec_from_file_location("valleyrat_minimal_proxy", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_six_export_pdfcore8_protected_proxy_is_recognized(monkeypatch) -> None:
    names = list(MODULE.PDFCORE_EXPORTS) + ["CorePluginInit", "CorePluginFin"]
    symbols = [
        SimpleNamespace(name=name.encode(), address=0xB170) for name in names
    ]
    imports = [
        SimpleNamespace(name=name.encode(), ordinal=0)
        for name in (
            "WriteProcessMemory",
            "CreateProcessW",
            "CreateThread",
            "DeviceIoControl",
        )
    ]
    pe = SimpleNamespace(
        DIRECTORY_ENTRY_IMPORT=[SimpleNamespace(dll=b"KERNEL32.dll", imports=imports)],
        DIRECTORY_ENTRY_EXPORT=SimpleNamespace(symbols=symbols),
        DIRECTORY_ENTRY_RESOURCE=SimpleNamespace(entries=[]),
        FILE_HEADER=SimpleNamespace(Machine=0x14C, TimeDateStamp=0),
        OPTIONAL_HEADER=SimpleNamespace(AddressOfEntryPoint=0x1000),
    )
    monkeypatch.setattr(MODULE.pefile, "PE", lambda **_kwargs: pe)
    monkeypatch.setattr(
        MODULE,
        "section_summaries",
        lambda _pe: [{"name": ".copilot", "entropy": 7.8, "raw_size": 1_500_000}],
    )

    result = MODULE._pe_summary("PDFCore8.dll", b"MZ synthetic")

    assert result["proxy_type"] == "pdfcore8_minimal_protected_proxy"
    assert result["export_count"] == 6
    assert result["export_target_peak_ratio"] == 1.0
