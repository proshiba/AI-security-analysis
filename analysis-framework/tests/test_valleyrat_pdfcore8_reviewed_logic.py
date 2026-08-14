from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

FRAMEWORK = Path(__file__).resolve().parents[1]
ANALYZER_PATH = FRAMEWORK / "malware" / "valleyrat" / "campaigns" / "signed_proxy_sideload" / "analyze.py"
STATIC_LOGIC_PATH = FRAMEWORK / "common" / "static_logic.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_reviewed_rotated_pdfcore8_functions_satisfy_static_logic_gate() -> None:
    analyzer = _load("valleyrat_pdfcore8_reviewed_analyzer", ANALYZER_PATH)
    static_logic = _load("valleyrat_pdfcore8_reviewed_static_logic", STATIC_LOGIC_PATH)
    proxy_sha256 = "8136a9b1252e0d8c293c6c99444b371f3f7dc9fccbf351597a0aec029fe92a96"
    records = analyzer.REVIEWED[proxy_sha256]["representative_functions"]

    report = static_logic.build_static_logic_report(
        sha256="a7f8757c780afc2fcb081f861b3be24b0be5badd3042f759e8af4fd47380dca2",
        family="valleyrat",
        source_name="M_X20260806080501.zip",
        records=records,
        analysis_source="campaign_handler_representative_functions",
    )

    assert report["status"] == "reviewed_function_logic"
    assert report["coverage"]["function_count"] == 4
    assert report["coverage"]["function_bodies_reviewed"] is True
    assert static_logic.function_analysis_is_available(report) is True
    assert all(item["logic_steps_ja"] for item in report["functions"])
    assert all(item["raw_pseudocode_exported"] is False for item in report["functions"])
