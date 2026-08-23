from __future__ import annotations

import importlib.util
import os
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


class _SyntheticDirEntry:
    def __init__(self, name: str, root: Path) -> None:
        self.name = name
        self.path = str(root / name)

    def is_dir(self, *, follow_symlinks: bool) -> bool:
        assert follow_symlinks is False
        return False


class _SyntheticScandir:
    def __init__(self, entries: list[_SyntheticDirEntry]) -> None:
        self._entries = entries

    def __enter__(self):
        return iter(self._entries)

    def __exit__(self, *_args) -> None:
        return None


def test_legacy_case_enumeration_is_bounded_before_sort(
    tmp_path: Path,
    monkeypatch,
) -> None:
    case_root = tmp_path / "cases"
    case_root.mkdir()
    ioc_csv = tmp_path / "iocs.csv"
    ioc_csv.write_text("ioc_type,ioc_value\n", encoding="utf-8")
    monkeypatch.setattr(target, "MAX_SUMMARY_CASES", 2)
    entries = [_SyntheticDirEntry(str(index), case_root) for index in range(3)]
    monkeypatch.setattr(target.os, "scandir", lambda _path: _SyntheticScandir(entries))

    try:
        target.build_summary(case_root, ioc_csv, "2026-08-23")
    except ValueError as error:
        assert "件数" in str(error)
        assert str(tmp_path) not in str(error)
    else:
        raise AssertionError("case上限+1件目が拒否されませんでした")


def test_legacy_case_enumeration_accepts_exact_limit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    case_root = tmp_path / "cases"
    case_root.mkdir()
    ioc_csv = tmp_path / "iocs.csv"
    ioc_csv.write_text("ioc_type,ioc_value\n", encoding="utf-8")
    monkeypatch.setattr(target, "MAX_SUMMARY_CASES", 2)
    entries = [_SyntheticDirEntry(str(index), case_root) for index in range(2)]
    monkeypatch.setattr(target.os, "scandir", lambda _path: _SyntheticScandir(entries))

    assert target.build_summary(case_root, ioc_csv, "2026-08-23")["sample_count"] == 0


def test_legacy_case_root_reparse_or_identity_change_is_redacted(
    tmp_path: Path,
    monkeypatch,
) -> None:
    case_root = tmp_path / "cases"
    case_root.mkdir()
    ioc_csv = tmp_path / "iocs.csv"
    ioc_csv.write_text("ioc_type,ioc_value\n", encoding="utf-8")
    monkeypatch.setattr(target.analysis_contract, "_same_file_identity", lambda *_args: False)

    try:
        target.build_summary(case_root, ioc_csv, "2026-08-23")
    except ValueError as error:
        assert str(tmp_path) not in str(error)
    else:
        raise AssertionError("case root identity変更が拒否されませんでした")

    link = tmp_path / "case-link"
    try:
        os.symlink(case_root, link, target_is_directory=True)
    except OSError:
        return
    try:
        target.build_summary(link, ioc_csv, "2026-08-23")
    except ValueError as error:
        assert str(tmp_path) not in str(error)
    else:
        raise AssertionError("case root reparse pointが拒否されませんでした")


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
