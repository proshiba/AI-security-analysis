from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
COMMON = ROOT / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import publish_triage_case_evidence as publisher  # noqa: E402


SHA256 = "a" * 64
ARTIFACT_SHA256 = "b" * 64


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def repository(tmp_path: Path) -> tuple[Path, Path]:
    case = (
        tmp_path
        / "analysis-results"
        / "malware"
        / "unclassified"
        / "versions"
        / "unknown"
        / "cases"
        / SHA256
    )
    case.mkdir(parents=True)
    (case / "README.md").write_text("# 検体\n", encoding="utf-8")
    collection = tmp_path / "analysis-results" / "collections" / "test-collection"
    write_json(collection / "manifest.json", {"cases": [{"case_id": f"sha256:{SHA256}"}]})
    write_json(
        collection / "sources" / "unclassified" / "summary.json",
        {
            "cases": [
                {
                    "sha256": SHA256,
                    "case_path": case.relative_to(tmp_path).as_posix(),
                }
            ]
        },
    )
    return tmp_path, case


def test_safe_endpoint_strips_query_and_rejects_invalid_port() -> None:
    assert publisher._safe_endpoint("HTTPS://Example.test:443/a?q=secret#x") == (
        "https://example.test:443/a"
    )
    assert publisher._safe_endpoint("example.test:65536") is None
    assert publisher._safe_endpoint("netkata.io:443") == "netkata.io:443"


def test_publish_links_public_exact_hash_and_artifact_static_result(tmp_path: Path) -> None:
    repo, case = repository(tmp_path)
    triage = tmp_path / "private-triage.json"
    write_json(
        triage,
        {
            "results": [
                {
                    "sha256": SHA256,
                    "matches": [
                        {
                            "sample_id": "260802-abcdefghij",
                            "sha256": SHA256,
                            "visibility": "public_searchable_api",
                            "triage_url": "https://tria.ge/260802-abcdefghij",
                            "families": ["example"],
                            "config_endpoints": ["https://c2.example/a?token=hidden"],
                            "reports": [
                                {
                                    "processes": [
                                        {
                                            "image": "payload.exe",
                                            "command_sha256": ARTIFACT_SHA256,
                                            "command_pattern": "powershell_download",
                                            "processes_in_command": ["powershell.exe"],
                                        }
                                    ],
                                    "network_context": ["https://benign.example/x?q=1"],
                                    "dumped_files": [],
                                }
                            ],
                        }
                    ],
                    "errors": [],
                }
            ]
        },
    )
    artifacts = tmp_path / "private-artifacts.json"
    write_json(
        artifacts,
        {
            "downloads": [
                {
                    "parent_sha256": SHA256,
                    "sample_id": "260802-abcdefghij",
                    "kind": "memory_image",
                    "name": "memory.dmp",
                    "artifact_sha256": ARTIFACT_SHA256,
                    "size": 123,
                    "duplicate_of_parent": False,
                }
            ]
        },
    )
    analysis = tmp_path / "private-analysis.json"
    write_json(
        analysis,
        {
            "cases": [
                {
                    "sha256": ARTIFACT_SHA256,
                    "family": "unknown",
                    "selected_family": None,
                    "case_state": "partial",
                    "handler_succeeded": 0,
                    "analysis_stage_failed": False,
                }
            ]
        },
    )

    result = publisher.publish(
        repo,
        "test-collection",
        triage,
        artifacts,
        analysis,
        write=True,
    )

    assert result["cases_with_public_matches"] == 1
    evidence = json.loads((case / "triage-evidence.json").read_text(encoding="utf-8"))
    assert evidence["public_matches"][0]["config_endpoints"] == [
        "https://c2.example/a"
    ]
    recovered = evidence["recovered_artifacts"][0]
    assert recovered["static_analysis"]["case_state"] == "partial"
    assert "archive_path" not in recovered
    iocs = json.loads((case / "iocs.json").read_text(encoding="utf-8"))
    assert iocs["network"] == [
        {
            "value": "https://c2.example/a",
            "role": "c2_candidate_external_sandbox_config",
            "confidence": "medium_external_sandbox_exact_hash",
            "classification": "candidate_not_static_confirmed",
            "source": "hatching_triage_public_exact_sha256_config",
        }
    ]
    assert "公開sandbox・二段目解析" in (case / "README.md").read_text(encoding="utf-8")


def test_non_public_match_is_omitted(tmp_path: Path) -> None:
    repo, case = repository(tmp_path)
    triage = tmp_path / "private-triage.json"
    write_json(
        triage,
        {
            "results": [
                {
                    "sha256": SHA256,
                    "matches": [
                        {
                            "sample_id": "260802-abcdefghij",
                            "sha256": SHA256,
                            "visibility": "private",
                            "triage_url": "https://tria.ge/260802-abcdefghij",
                        }
                    ],
                }
            ]
        },
    )
    publisher.publish(repo, "test-collection", triage, None, None, write=True)
    evidence = json.loads((case / "triage-evidence.json").read_text(encoding="utf-8"))
    assert evidence["public_matches"] == []
    assert evidence["omitted_matches"] == 1
