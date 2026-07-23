"""全公開関数が生成済みpydocへ記載されていることを検証する。"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path


def test_all_public_functions_have_docstrings_and_pydoc() -> None:
    """全公開関数にdocstringと生成済みHTML項目を要求する。"""
    modules = [
        "asa.models",
        "asa.conditions",
        "asa.loader",
        "asa.catalog",
        "asa.compiler",
        "asa.cli",
        "asa.discovery",
        "asa.runner",
        "asa.runtime_cli",
        "malwarebazaar_batch",
        "malwarebazaar_unknown_batch",
        "profiled_family_detector",
        "detector_support",
        "scaffold_family_expansion",
        "generate_family_expansion_reports",
        "validate_family_expansion",
        "analyze_unknown_set",
        "update_unknown_analysis_history",
        "osint_hash_enricher",
        "deep_static_triage",
        "analyze_stealer_set",
        "c2_candidate_detector",
        "generate_stealer_reports",
        "generate_family_reports",
        "repository_history_collector",
        "supply_chain_audit",
        "generate_ioc_lists",
        "audit_analysis_coverage",
        "audit_japanese_docs",
        "localize_result_markdown",
        "render_malware_family_docs",
        "sanitize_public_results",
        "static_logic",
        "record_static_logic",
        "generate_code_similarity_index",
        "backfill_static_logic",
        "ghidra_function_batch",
        "validate_function_analysis",
        "result_publication",
        "result_layout",
        "normalize_result_layout",
        "unpackers.static_unpacker",
        "unpackers.static_control_flow",
        "unpackers.managed_il_triage",
        "unpackers.asar_unpacker",
        "unpackers.electron_nsis_unpacker",
        "unpackers.javascript_obfuscator",
        "unpackers.javascript_dropper_unpacker",
        "unpackers.nsis_unpacker",
        "unpackers.donut_unpacker",
        "unpackers.donut_wrapper_unpacker",
        "unpackers.container_recovery",
        "unpackers.purehvnc_unpacker",
        "unpackers.chrd_donut_unpacker",
        "unpackers.spyglace_unpacker",
        "unpackers.apt_c60_delivery",
        "unpackers.index_xor_pe_unpacker",
        "unpackers.path_safety",
        "extractors.purehvnc.extractor",
        "extractors.donutloader.extractor",
        "emulators.purehvnc.lab",
        "extractors.common",
        "extractors.config_extractor",
        "extractors.profiled_family",
        "extractors.stealer_common",
        "extractors.formbook.extractor",
        "extractors.vidar.extractor",
        "extractors.lummastealer.extractor",
        "extractors.remusstealer.extractor",
        "extractors.amosstealer.extractor",
        "extractors.amadey.extractor",
        "extractors.latrodectus.extractor",
        "emulators.stealers.lab",
        "emulators.common",
        "emulators.families.lab",
        "extractors.spyglace.extractor",
        "extractors.valleyrat.extractor",
        "emulators.spyglace.lab",
        "extractors.agenttesla.extractor",
        "extractors.remcosrat.extractor",
        "extractors.shadowpad.extractor",
        "extractors.shadowpad.legacy",
        "extractors.stealc.extractor",
        "extractors.venomrat.extractor",
        "extractors.npm_supply_chain.extractor",
        "extractors.atlascross.extractor",
        "extractors.unclassified.mx_go.extractor",
    ]
    repository = Path(__file__).parents[2]
    common = repository / "analysis-framework" / "common"
    if str(common) not in __import__("sys").path:
        __import__("sys").path.insert(0, str(common))
    root = repository / "docs" / "pydoc"
    for module_name in modules:
        module = importlib.import_module(module_name)
        public = [
            (name, value)
            for name, value in inspect.getmembers(module, inspect.isfunction)
            if value.__module__ == module_name and not name.startswith("_")
        ]
        html = (root / f"{module_name}.html").read_text(encoding="utf-8")
        for name, function in public:
            assert inspect.getdoc(function), f"missing docstring: {module_name}.{name}"
            assert f'name="-{name}"' in html, f"missing pydoc: {module_name}.{name}"
