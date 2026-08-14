from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
CASE_SHA256 = "ad4a584f5e622c10703bca28c58ee8372899edb48cc1ccf28a2cff87d1afbf2d"
PROTECTED_PE_SHA256 = "136bdce277b8c810656eccc0b0e4b47f0fde81e1d5aba86a475a08d96b7a22a9"
CASE_DIR = REPOSITORY / "analysis-results/malware/valleyrat/versions/unknown/cases" / CASE_SHA256

ANALYSIS_CONTRACT_PATH = REPOSITORY / "analysis-framework/common/analysis_contract.py"
SPEC = importlib.util.spec_from_file_location("valleyrat_case_analysis_contract", ANALYSIS_CONTRACT_PATH)
assert SPEC is not None and SPEC.loader is not None
ANALYSIS_CONTRACT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ANALYSIS_CONTRACT)


def _json(name: str) -> dict[str, object]:
    return json.loads((CASE_DIR / name).read_text(encoding="utf-8"))


def test_protected_pe_layout_is_bound_to_exact_component() -> None:
    evidence = _json("protected-pe-evidence.json")
    component = evidence["recovered_component"]
    header = evidence["pe_header"]
    sections = header["sections"]

    assert component == {
        "sha256": PROTECTED_PE_SHA256,
        "size": 3_778_560,
        "kind": "pe32plus_dll",
    }
    assert header["entry_va"] == "0x1802f8bac"
    assert header["header_sha256"] == "7eab012aa8dcb93b0c2a9129f632c32c319ae250f0722a8ed38ed45114166362"
    assert header["section_count"] == 9
    assert header["zero_raw_section_count"] == 5
    assert header["file_backed_section_count"] == 4
    assert sum(section["raw_size"] for section in sections) + header["size_of_headers"] == component["size"]
    assert next(section for section in sections if section["name"] == ".HV/")["raw_size"] == 3_776_000


def test_entry_review_records_exact_calls_without_execution_claim() -> None:
    evidence = _json("protected-pe-evidence.json")
    entry = evidence["entry_review"]

    assert entry["window_sha256"] == "99cd6a98ec7888c16f1b507379993c5783c488c6a3484b9f55318dda320bbc28"
    assert [(edge["source"], edge["target"]) for edge in entry["direct_calls"]] == [
        ("0x1802f8bdf", "0x180604f55"),
        ("0x1802f8c09", "0x18060c862"),
        ("0x1802f8c35", "0x180605cbe"),
    ]
    assert entry["overlapping_target"]["interpretation"].endswith("not_execution_proof")
    assert evidence["raw_opcode_candidates"] == {
        "rdtsc_0f31_count": 75,
        "rdtscp_0f01f9_count": 0,
        "scope": ".HV/",
        "interpretation": "candidate_only_not_execution_proof",
    }
    assert evidence["safety"] == {
        "sample_executed": False,
        "cpu_emulation_used": False,
        "network_contacted": False,
        "raw_bytes_published": False,
        "raw_pseudocode_published": False,
    }


def test_export_surface_is_not_promoted_to_function_evidence() -> None:
    evidence = _json("protected-pe-evidence.json")
    static_logic = _json("static-logic.json")

    assert evidence["exports"] == {
        "label_count": 121,
        "ordinal_label_count": 60,
        "unique_address_count": 44,
        "file_backed_body_count": 0,
        "assessment": "unbacked_decoy_export_surface",
    }
    assert static_logic["coverage"]["function_count"] == 0
    assert static_logic["coverage"]["discovered_function_inventory_count"] == 1_303
    assert static_logic["coverage"]["function_bodies_reviewed"] is False
    assert static_logic["coverage"]["protected_regions_reviewed"] is True
    assert static_logic["functions"] == []


def test_case_remains_partial_without_config_or_c2() -> None:
    report = _json("report.json")
    classification = _json("classification.json")
    config = _json("config.json")
    c2 = _json("c2-analysis.json")

    assert report["case_state"] == {
        "blockers": [
            "config_and_c2_not_recovered",
            "native_virtualized_protector_not_recovered",
            "terminal_payload_not_recovered",
        ],
        "complete": False,
        "detector_error_families": [],
        "incomplete_selected_layer_attempts": [],
        "resumable": False,
        "static_layer_issues": [],
        "status": "partial",
    }
    assert classification["final_rat_confirmed"] is False
    assert config["endpoints"] == []
    assert c2["endpoints"] == []
    assert c2["network_contacted"] is False
    assert report["executed_sample"] is False
    assert report["network_contacted"] is False


def test_case_integrity_is_sealed() -> None:
    report = _json("report.json")
    assert (
        ANALYSIS_CONTRACT.case_integrity_errors(
            CASE_DIR,
            report,
            expected_digest=CASE_SHA256,
            require_resumable=False,
        )
        == []
    )
