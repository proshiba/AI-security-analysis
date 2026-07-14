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
        "extractors.common",
        "extractors.config_extractor",
        "extractors.valleyrat.extractor",
        "extractors.agenttesla.extractor",
        "extractors.remcosrat.extractor",
        "extractors.venomrat.extractor",
        "extractors.unclassified.mx_go.extractor",
    ]
    root = Path(__file__).parents[2] / "docs" / "pydoc"
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
