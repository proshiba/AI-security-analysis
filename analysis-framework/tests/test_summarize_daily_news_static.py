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


def test_sha1_provider_alias_labels_elf_case(tmp_path: Path) -> None:
    sha1 = "a" * 40
    sha256 = "b" * 64
    ioc_csv = tmp_path / "iocs.csv"
    ioc_csv.write_text(
        "ioc_type,ioc_value,malware,malware_type\n"
        f"file_hash_sha1,{sha1},Dysphoria,botnet\n",
        encoding="utf-8",
    )
    lookups = tmp_path / "lookups.json"
    lookups.write_text(
        __import__("json").dumps({
            "items": [{
                "digest": sha1,
                "hash_type": "sha1",
                "reported_malware": "Dysphoria",
                "found": True,
                "metadata": {"sha1_hash": sha1, "sha256_hash": sha256},
            }]
        }),
        encoding="utf-8",
    )
    case = tmp_path / "cases" / sha256
    case.mkdir(parents=True)
    (case / "generic-triage.json").write_text(
        __import__("json").dumps({
            "sha256": sha256,
            "type": "elf",
            "size": 1234,
            "entropy": 5.4,
            "magic": "7f454c46",
            "elf": {"machine": 40, "bits": 32, "byte_order": "little", "entry_point": "0x8000"},
            "analysis_coverage": {"status": "complete"},
        }),
        encoding="utf-8",
    )
    (case / "static-logic.json").write_text(
        __import__("json").dumps({
            "status": "function_analysis_required",
            "coverage": {"function_count": 0, "call_edge_count": 0, "function_bodies_reviewed": False},
            "limitations": [],
        }),
        encoding="utf-8",
    )

    reviews = tmp_path / "reviews.json"
    reviews.write_text(
        __import__("json").dumps({"samples": [{"sha256": sha256, "source": "ghidra_mcp", "functions": [{"address": "0x1000", "name": "main"}]}]}),
        encoding="utf-8",
    )
    summary = target.build_summary(
        tmp_path / "cases", ioc_csv, "2026-07-29", lookups, reviews
    )

    assert summary["counts"]["elf"] == 1
    assert summary["samples"][0]["reported_malware"] == "Dysphoria"
    assert summary["samples"][0]["source_hash"] == sha1
    assert summary["counts"]["function_analysis_complete"] == 1
    assert summary["counts"]["function_analysis_required"] == 0
    assert summary["samples"][0]["function_review_source"] == "ghidra_mcp"
    markdown = target.render_markdown(summary)
    assert "Dysphoria" in markdown
    assert "NukeSped" not in markdown
    assert "特徴関数レビュー" in markdown
    assert "`main`" in markdown
