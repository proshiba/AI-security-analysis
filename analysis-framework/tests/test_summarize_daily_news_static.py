from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "common"
    / "summarize_daily_news_static.py"
)
SPEC = importlib.util.spec_from_file_location("summarize_daily_news_static", MODULE_PATH)
assert SPEC and SPEC.loader
target = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = target
SPEC.loader.exec_module(target)


def test_capability_requires_observed_import() -> None:
    triage = {
        "pe": {
            "imports": {
                "KERNEL32.dll": [
                    "CreateProcessW",
                    "IsDebuggerPresent",
                    "FindFirstFileW",
                ],
                "GDI32.dll": ["BitBlt"],
            }
        }
    }

    capabilities = {
        item["id"]: item for item in target.infer_capabilities(triage)
    }

    assert capabilities["process_execution"]["evidence_imports"] == ["createprocessw"]
    assert capabilities["anti_analysis_surface"]["evidence_imports"] == [
        "isdebuggerpresent"
    ]
    assert capabilities["screen_capture"]["evidence_imports"] == ["bitblt"]
    assert "network_client" not in capabilities
    assert all(
        item["confidence"] == "import_surface_only"
        for item in capabilities.values()
    )


def test_imports_are_case_insensitive() -> None:
    triage = {
        "pe": {
            "imports": {
                "WS2_32.dll": ["WSAStartup"],
                "ADVAPI32.dll": ["RegSetValueExW"],
            }
        }
    }

    ids = {item["id"] for item in target.infer_capabilities(triage)}

    assert ids == {"network_client", "registry_change"}
