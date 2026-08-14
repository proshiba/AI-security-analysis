from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import SimpleNamespace

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "campaigns" / "signed_proxy_sideload" / "analyze.py"
)
SPEC = importlib.util.spec_from_file_location("valleyrat_minimal_proxy", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def test_six_export_pdfcore8_protected_proxy_is_recognized(monkeypatch) -> None:
    names = list(MODULE.PDFCORE_EXPORTS) + ["CorePluginInit", "CorePluginFin"]
    symbols = [SimpleNamespace(name=name.encode(), address=0xB170) for name in names]
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


def test_compact_nvml_dat_loader_is_recognized() -> None:
    result = MODULE.classify_proxy_profile(
        exports=set(MODULE.NVML_EXPORTS),
        all_imports={"QueueUserAPC", "VirtualAlloc", "VirtualProtect", "ReadFile"},
        resource_types=set(),
        sections=[],
        export_target_peak_ratio=1.0,
        text_markers={"nvml.dat", "snvml.dll", "runtimebroker.exe"},
    )

    assert result == "nvml_compact_dat_loader"


def test_large_pdfcore8_proxy_accepts_reviewed_rotated_resource_profile() -> None:
    result = MODULE.classify_proxy_profile(
        exports=set(MODULE.PDFCORE_EXPORTS) | {f"export_{index}" for index in range(1_000)},
        all_imports={"CreateProcessW", "CreateThread", "DeviceIoControl", "VirtualAlloc"},
        resource_types=set(MODULE.ROTATED_WINOS_RESOURCE_TYPES),
        sections=[{"name": ".i", "entropy": 7.4, "raw_size": 1_523_200}],
        export_target_peak_ratio=1.0,
        text_markers=set(),
    )

    assert result == "pdfcore8_winos_proxy"


def test_large_pdfcore8_proxy_rejects_incomplete_rotated_resource_profile() -> None:
    incomplete = set(MODULE.ROTATED_WINOS_RESOURCE_TYPES)
    incomplete.remove("COPILOT_OVERLAY_IMAGES_30")

    result = MODULE.classify_proxy_profile(
        exports=set(MODULE.PDFCORE_EXPORTS) | {f"export_{index}" for index in range(1_000)},
        all_imports={"CreateProcessW", "CreateThread", "DeviceIoControl", "VirtualAlloc"},
        resource_types=incomplete,
        sections=[{"name": ".i", "entropy": 7.4, "raw_size": 1_523_200}],
        export_target_peak_ratio=1.0,
        text_markers=set(),
    )

    assert result is None


def test_reviewed_rotated_pdfcore8_chain_keeps_terminal_attribution_unresolved() -> None:
    outer_sha256 = "a7f8757c780afc2fcb081f861b3be24b0be5badd3042f759e8af4fd47380dca2"
    image_sha256 = "8cd2977a4c8f1e0ebd1699bca23aaacb826fa3d11cc0d5aee477a3e99bb184ad"
    proxy_sha256 = "8136a9b1252e0d8c293c6c99444b371f3f7dc9fccbf351597a0aec029fe92a96"

    outer = MODULE.REVIEWED[outer_sha256]
    image = MODULE.REVIEWED[image_sha256]
    proxy = MODULE.REVIEWED[proxy_sha256]

    assert outer["components"] == {"Vat_N0.20260806080456.IMG": image_sha256}
    assert image["components"] == {
        "Vat_N0.20260806080456.EXE": "21cf7a17569852a7a4c93ea9faf1478b0a08b9695acf56f10d597e86cac8aed9",
        "pdfCORE8.dlL": proxy_sha256,
    }
    assert outer["final_rat_confirmed"] is False
    assert image["final_rat_confirmed"] is False
    assert proxy["final_rat_confirmed"] is False
    assert proxy["terminal_family_attribution"] == "pdfcore8_winos_lineage_correlated_terminal_unrecovered"
    assert proxy["resource_profile"] == "copilot_overlay_images_10_20_30"

    lineage = proxy["resource_lineage"]
    assert lineage["pairwise_xor_equal_bytes"] == lineage["pairwise_xor_total_bytes"] == 30320
    assert lineage["current_build_secret_recovered"] is False
    assert lineage["decoded_raw_resource_published"] is False
    assert lineage["recovered_watchdog_candidate"] == {
        "size": 1388,
        "sha256": "363e5db207bcc5702a61917991a1647e5a0cab822ae19440248bacc8c52791b8",
        "classification": "process_watchdog_restart_batch_template",
        "portable_executable": False,
        "network_literal_present": False,
    }

    protected = proxy["protected_terminal_scan"]
    assert protected["sha256"] == "e3d167a9439070218f5d897b70cdef8e44cb47198502afa15c036e2b41b38355"
    assert protected["static_decoder_candidates_checked"] == 61822
    assert protected["structurally_valid_terminal_pe_count"] == 0
    assert protected["terminal_payload_recovered"] is False
    assert protected["config_recovered"] is False
    assert protected["c2_endpoint_recovered"] is False
    assert protected["blocker"] == "protected_current_build_secret_and_indirect_transport_arguments_unrecovered"

    functions = {item["name"]: item for item in proxy["representative_functions"]}
    assert set(functions) == {
        "ConnectPdfCore8TcpController",
        "ConnectPdfCore8UdpController",
        "HandlePdfCore8WindowMessage",
        "SendPdfCore8FramedPayload",
    }
    assert functions["ConnectPdfCore8TcpController"]["opcode_hash_sha256"] == (
        "88bbf7952f9f1dc1773a534de1136d6979cb057e5c404264403da1662add8026"
    )
    assert functions["ConnectPdfCore8UdpController"]["opcode_hash_sha256"] == (
        "9adbe8361daef5d02f30ee8fdabb5ac598f9c6c8fcf30d57951b7ccf7392ff10"
    )
    assert functions["SendPdfCore8FramedPayload"]["opcode_hash_sha256"] == (
        "d68465355eb3b18ad226af7f33eb7c5852889e5872fcd742edd3148318906789"
    )
    assert all(
        item["program_selector"] == "/AdditionalAnalysis/20260813/ValleyRAT/a7f8757c/pdfCORE8.dlL"
        for item in functions.values()
    )


def test_reviewed_inner_component_functions_propagate_without_duplicates() -> None:
    image_sha256 = "8cd2977a4c8f1e0ebd1699bca23aaacb826fa3d11cc0d5aee477a3e99bb184ad"
    proxy_sha256 = "8136a9b1252e0d8c293c6c99444b371f3f7dc9fccbf351597a0aec029fe92a96"
    reviewed = MODULE.REVIEWED[image_sha256]
    components = [
        {"sha256": proxy_sha256},
        {"sha256": proxy_sha256},
        {"sha256": "0" * 64},
        {"sha256": None},
    ]

    component_records, functions = MODULE._reviewed_component_evidence(reviewed, components)

    assert set(component_records) == {proxy_sha256}
    assert component_records[proxy_sha256]["final_rat_confirmed"] is False
    assert component_records[proxy_sha256]["protected_terminal_scan"]["c2_endpoint_recovered"] is False
    assert [item["name"] for item in functions] == [
        "ConnectPdfCore8TcpController",
        "ConnectPdfCore8UdpController",
        "SendPdfCore8FramedPayload",
        "HandlePdfCore8WindowMessage",
    ]
    assert len(
        {
            (item["program_selector"], item["address"], item["name"])
            for item in functions
        }
    ) == len(functions)
