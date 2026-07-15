"""Verify that every public function is documented by generated pydoc."""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path


def test_all_public_functions_have_docstrings_and_pydoc() -> None:
    """Require docstrings and generated HTML entries for every new public function."""
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
        "analyze_stealer_set",
        "c2_candidate_detector",
        "generate_stealer_reports",
        "repository_history_collector",
        "unpackers.static_unpacker",
        "unpackers.javascript_obfuscator",
        "unpackers.javascript_dropper_unpacker",
        "unpackers.nsis_unpacker",
        "unpackers.donut_unpacker",
        "unpackers.purehvnc_unpacker",
        "unpackers.chrd_donut_unpacker",
        "unpackers.spyglace_unpacker",
        "unpackers.apt_c60_delivery",
        "extractors.purehvnc.extractor",
        "extractors.donutloader.extractor",
        "emulators.purehvnc.lab",
        "extractors.common",
        "extractors.config_extractor",
        "extractors.stealer_common",
        "extractors.formbook.extractor",
        "extractors.vidar.extractor",
        "extractors.lummastealer.extractor",
        "extractors.remusstealer.extractor",
        "extractors.amosstealer.extractor",
        "emulators.stealers.lab",
        "extractors.spyglace.extractor",
        "extractors.valleyrat.extractor",
        "emulators.spyglace.lab",
        "extractors.agenttesla.extractor",
        "extractors.remcosrat.extractor",
        "extractors.venomrat.extractor",
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
