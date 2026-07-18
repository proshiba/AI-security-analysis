"""Tests for publish-safe family expansion report generation helpers."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import generate_family_expansion_reports as reports  # noqa: E402


def test_public_source_and_findings_remove_private_paths() -> None:
    """Exclude local ZIP paths/reporters and preserve candidate confidence."""
    item = {
        "sha256": "a" * 64,
        "zip_path": "private.zip",
        "requested_signature": "AsyncRAT",
        "metadata": {"reporter": "private", "file_name": "x.exe", "tags": ["AsyncRAT"]},
    }
    source = reports.public_source(item)
    assert "zip_path" not in source and "reporter" not in source
    merged = reports.merge_findings(
        {"findings": [{"kind": "network.url", "value": "https://evil.example.org/a", "role": "c2_candidate", "confidence": "candidate"}]},
        {"iocs": {"urls": ["https://evil.example.org/a", "https://stage.example/b"], "ips": ["8.8.8.8:443"]}},
    )
    assert len(merged) == 2
    assert all(item["confidence"] in {"candidate", "probable"} for item in merged)


def test_case_markdown_iocs_yara_and_table() -> None:
    """Render case evidence, IOC-only output, and a bounded YARA profile."""
    profile = reports.load_profiles()["asyncrat"]
    case = {
        "display_name": "AsyncRAT",
        "family": "asyncrat",
        "source": {"sha256": "a" * 64, "first_seen": "2026", "file_name": "x.exe", "file_type": "exe", "file_size": 10},
        "static_analysis": {"root_unpack": {}, "layers": [], "profile_config": {"category": "rat", "transport": "tcp", "marker_hits": [], "observed_config_keys": [], "static_config_recovered": False}, "findings": []},
    }
    assert "オペレーター／キャンペーン: 未帰属" in reports.case_markdown(case)
    ioc = reports.ioc_markdown(
        ["a" * 64],
        [
            {
                "kind": "network.url",
                "value": "https://user:secret@evil.example/gate?token=hidden#fragment",
                "role": "stage_url_candidate",
                "confidence": "candidate",
                "source": "fixture",
            },
            {
                "kind": "network.url",
                "value": "https://api.ipify.org/",
                "role": "host_discovery_service",
                "confidence": "candidate",
                "source": "fixture",
            },
        ],
    )
    assert "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |" in ioc
    assert f"| sha256 | {'a' * 64} | submitted_sample | 確認済み | manifest |" in ioc
    assert "https://evil.example/gate" in ioc
    assert "secret" not in ioc and "token=" not in ioc and "api.ipify.org" not in ioc
    rule = reports.yara_rule("asyncrat", profile)
    assert "false_positive" in rule and "filesize < 100MB" in rule
    assert reports.markdown_table([["A", "B"], ["x|y", "z"]]).count("\\|") == 1


def test_build_case_and_parser() -> None:
    """Build a non-executing case and exercise command-line parsing."""
    item = {"sha256": "b" * 64, "requested_signature": "AsyncRAT", "metadata": {}}
    profile = {"family": "asyncrat", "display_name": "AsyncRAT"}
    case = reports.build_case(item, {"root_unpack": {}, "layers": [], "iocs": {}}, {"config": {}, "findings": []}, {"network_contacted": False}, profile)
    assert case["sample_executed"] is False and case["network_contacted"] is False
    args = reports.build_parser().parse_args(["--manifest", "m.json", "--cache", "cache"])
    assert args.cache == Path("cache")
    assert reports.normalize_finding({"value": ""}) is None


def test_generate_and_main(tmp_path: Path, monkeypatch) -> None:
    """Generate a complete one-case tree and cover the command dispatcher."""
    data = b"AsyncRAT Server HWID Hosts Ports https://evil.example.org/gate"
    digest = hashlib.sha256(data).hexdigest()
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"items": [{"requested_signature": "AsyncRAT", "sha256": digest, "zip_path": "fixture.zip", "metadata": {"file_type": "exe"}}]}), encoding="utf-8")
    cache = tmp_path / "cache"
    (cache / "cases" / digest).mkdir(parents=True)
    (cache / "cases" / digest / "case.json").write_text(json.dumps({"root_unpack": {}, "layers": [], "iocs": {}}), encoding="utf-8")
    output = tmp_path / "results"
    existing_digest = "f" * 64
    (output / "catalog").mkdir(parents=True)
    (output / "catalog" / "cases.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cases": {
                    existing_digest: {
                        "case_id": f"sha256:{existing_digest}",
                        "family": "existing",
                        "case_kind": "malware",
                        "version_key": "unknown",
                        "canonical_path": (
                            "results/malware/existing/versions/unknown/cases/"
                            + existing_digest
                        ),
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    existing_collection = output / "collections" / reports.RUN_ID / "manifest.json"
    existing_collection.parent.mkdir(parents=True)
    existing_collection.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "collection_id": reports.RUN_ID,
                "family_sources": [
                    {"family": "existing", "path": "sources/existing"}
                ],
                "cases": [{"case_id": f"sha256:{existing_digest}"}],
            }
        ),
        encoding="utf-8",
    )
    profile = {
        "display_name": "AsyncRAT", "category": "rat", "aliases": [],
        "markers": ["AsyncRAT", "HWID"], "minimum_markers": 2,
        "config_keys": ["Hosts", "Ports"], "transport": "tcp",
        "endpoint_role": "c2_candidate", "confirmation": "decode fixture",
    }
    monkeypatch.setattr(reports, "load_profiles", lambda: {"asyncrat": profile})
    monkeypatch.setattr(reports, "read_single_aes_zip_member", lambda path: SimpleNamespace(data=data, name="fixture.exe"))
    result = reports.generate(manifest, cache, output)
    case = (
        output / "malware" / "asyncrat" / "versions" / "unknown" / "cases" / digest
    )
    source = output / "collections" / reports.RUN_ID / "sources" / "asyncrat"
    assert result["cases"] == 1 and (case / "README.md").is_file()
    assert (case / "metadata.json").is_file()
    collection_manifest = json.loads(
        (output / "collections" / reports.RUN_ID / "manifest.json").read_text()
    )
    assert collection_manifest["cases"] == [
        {"case_id": f"sha256:{digest}"},
        {"case_id": f"sha256:{existing_digest}"},
    ]
    assert collection_manifest["family_sources"] == [
        {"family": "asyncrat", "path": "sources/asyncrat"},
        {"family": "existing", "path": "sources/existing"},
    ]
    collection_readme = (
        output / "collections" / reports.RUN_ID / "README.md"
    ).read_text(encoding="utf-8")
    assert "登録ケース数：2件" in collection_readme
    assert "ファミリー別集約資料：2件" in collection_readme
    assert "sources/asyncrat/README.md" in collection_readme
    assert "../../catalog/cases.json" in collection_readme
    catalog = json.loads((output / "catalog" / "cases.json").read_text())
    assert set(catalog["cases"]) == {digest, existing_digest}
    assert catalog["cases"][digest]["canonical_path"].endswith(
        f"malware/asyncrat/versions/unknown/cases/{digest}"
    )
    regenerated = reports.regenerate_run_ioc_lists(output)
    assert regenerated == {
        "families": 1,
        "cases": 1,
        "indicators": 2,
        "run_id": reports.RUN_ID,
    }
    assert "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |" in (
        source / "IOC-LIST.md"
    ).read_text(encoding="utf-8")
    assert "../../../../malware/asyncrat/versions/unknown/cases/" in (
        source / "README.md"
    ).read_text(encoding="utf-8")
    assert "AsyncRAT" in reports.family_markdown("asyncrat", {"family": "asyncrat", **profile}, [json.loads((case / "indicators.json").read_text())])
    target = tmp_path / "nested" / "text.txt"
    reports.write_text(target, "x\r\n")
    assert target.read_bytes() == b"x\n"
    monkeypatch.setattr(reports, "generate", lambda *args: {"cases": 0})
    assert reports.main(["--manifest", str(manifest), "--cache", str(cache), "--output-root", str(output)]) == 0
    monkeypatch.setattr(reports, "regenerate_run_ioc_lists", lambda *args: {"families": 0})
    assert reports.main(["--regenerate-run-iocs", "--output-root", str(output)]) == 0


def test_atomic_index_update_rolls_back_both_documents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """2つ目のreplace失敗時にcatalogだけを先行更新した状態を残さない。"""
    catalog = tmp_path / "catalog" / "cases.json"
    collection = tmp_path / "collections" / "run" / "manifest.json"
    for path, content in ((catalog, b"old-catalog\n"), (collection, b"old-collection\n")):
        path.parent.mkdir(parents=True)
        path.write_bytes(content)
    original_replace = Path.replace

    def fail_collection_replace(source: Path, target: Path) -> Path:
        if Path(target) == collection and source.name.endswith(".tmp"):
            raise OSError("forced collection replace failure")
        return original_replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_collection_replace)
    with pytest.raises(OSError, match="forced collection"):
        reports._write_json_documents_atomic(
            {
                catalog: {"schema_version": 1, "cases": {}},
                collection: {
                    "schema_version": 1,
                    "collection_id": "run",
                    "family_sources": [],
                    "cases": [],
                },
            }
        )

    assert catalog.read_bytes() == b"old-catalog\n"
    assert collection.read_bytes() == b"old-collection\n"
    assert not list(tmp_path.rglob("*.tmp"))
