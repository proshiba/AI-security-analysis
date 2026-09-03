"""ファミリー非依存の構造候補集約に対する回帰テスト。"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from pathlib import Path

COMMON_ROOT = Path(__file__).resolve().parents[1] / "common"
if str(COMMON_ROOT) not in sys.path:
    sys.path.insert(0, str(COMMON_ROOT))

import analyze_sample as analyzer  # noqa: E402
from structural_candidates import (  # noqa: E402
    build_structural_candidates,
    structural_candidate_summary,
)


def _step(
    digest: str,
    report: dict[str, object],
    *,
    depth: int = 0,
    accepted_children: int = 0,
    layer_format: str = "pe",
) -> dict[str, object]:
    """名前を含む合成入力から公開に必要な件数だけを集約させる。"""

    return {
        "input_layer": {
            "name": r"C:\private\secret-sample.exe",
            "sha256": digest,
            "size": 4096 + depth,
            "format": layer_format,
            "depth": depth,
            "parent_sha256": None,
            "transform": "submission",
        },
        "status": "succeeded",
        "report": {"sha256": digest, "executed": False, "network_contacted": False, **report},
        "accepted_children": [
            {
                "name": rf"C:\private\child-{index}.exe",
                "sha256": f"{index + 1:064x}",
                "size": 512,
                "format": "pe",
                "depth": depth + 1,
            }
            for index in range(accepted_children)
        ],
    }


def _candidate_by_kind(result: dict[str, object]) -> dict[str, dict[str, object]]:
    return {item["kind"]: item for item in result["candidates"]}


def test_collects_supported_structures_without_family_attribution() -> None:
    """PyInstaller、installer、packer、.NET resourceを別候補として保持する。"""

    pyinstaller = _step(
        "a" * 64,
        {
            "format": "pe",
            "pyinstaller": {
                "complete": False,
                "blockers": [r"secret=C:\private\payload.py"],
                "classification": {"packaging": "PyInstaller CArchive"},
                "archive": {
                    "format": "PyInstaller CArchive",
                    "reader": "bounded_memory_carchive",
                    "entry_count": 32,
                    "option_count": 2,
                    "toc_record_count": 34,
                    "total_compressed_size": 1000,
                    "total_uncompressed_size": 2000,
                    "inventory_commitment": {
                        "algorithm": "sha256",
                        "record_count": 34,
                        "sha256": "1" * 64,
                        "canonicalization": r"C:\private\must-not-leak",
                    },
                },
                "selection": {
                    "status": "selective_recovery",
                    "candidate_count": 20,
                    "retained_count": 8,
                    "omitted_entry_count": 24,
                    "non_candidate_count": 12,
                    "blockers": ["private diagnostic"],
                },
                "content_validation": {
                    "status": "partial_content_validation",
                    "full_content_validation": False,
                    "validated_entry_count": 8,
                    "total_entry_count": 32,
                    "discarded_after_validation_count": 0,
                    "content_commitment": None,
                },
            },
            "recovered": [{"name": "private.py"}],
        },
        accepted_children=1,
    )
    nsis = _step(
        "b" * 64,
        {
            "format": "pe",
            "pe": {
                "packer_markers": ["Nullsoft"],
                "containerized": True,
                "packing_suspected": False,
            },
            "sevenzip": {
                "status": "selectively_extracted",
                "archive_types": ["PE", "NSIS"],
                "total_members": 4,
                "retained_members": 2,
                "declared_total_size": 8000,
                "extracted_total_size": 6000,
                "inventory": [
                    {"name": "kept.exe", "status": "extracted"},
                    {"name": "secret.bin", "status": "size_blocked"},
                ],
            },
            "recovered": [{"name": "private"}, {"name": "private-2"}],
        },
        accepted_children=2,
    )
    inno = _step(
        "c" * 64,
        {
            "format": "pe",
            "pe": {"packer_markers": [], "containerized": False, "packing_suspected": False},
            "sevenzip": {
                "status": "extracted",
                "archive_types": ["PE", "Inno Setup"],
                "total_members": 2,
                "retained_members": 2,
                "inventory": [{"status": "extracted"}, {"status": "extracted"}],
            },
        },
        accepted_children=2,
    )
    upx = _step(
        "d" * 64,
        {
            "format": "pe",
            "pe": {
                "packer_markers": ["UPX!"],
                "sections": [{"name": "UPX0"}, {"name": "UPX1"}],
                "classification": "packed_or_protected",
                "packing_suspected": True,
            },
            "upx": {"status": "recovered", "path": r"C:\private\upx.exe"},
            "recovered": [{"kind": "upx", "address": "0x401000"}],
        },
        accepted_children=1,
    )
    packed = _step(
        "e" * 64,
        {
            "format": "pe",
            "pe": {
                "packer_markers": [],
                "classification": "suspected_packed",
                "packing_suspected": True,
                "high_entropy_sections": ["secret-a", "secret-b"],
                "code_entropy_sections": ["secret-a"],
            },
        },
    )
    dotnet = _step(
        "f" * 64,
        {
            "format": "pe",
            "pe": {"is_dotnet": True, "packer_markers": [], "packing_suspected": False},
            "dotnet_resources": {
                "status": "resources_recovered",
                "count": 2,
                "inventory": [
                    {"name": "private.resources", "status": "extracted", "format": "data"},
                    {"name": "payload", "status": "extracted", "format": "pe"},
                ],
            },
        },
        accepted_children=1,
    )
    source = {
        "steps": [pyinstaller, nsis, inno, upx, packed, dotnet],
        "limit_events": [{"parent_sha256": "e" * 64, "reason": "private reason"}],
    }

    result = build_structural_candidates(source)
    by_kind = _candidate_by_kind(result)

    assert result["candidate_count"] == 6
    assert set(by_kind) == {
        "dotnet_resource_container",
        "inno_setup_installer",
        "nsis_installer",
        "packed_or_protected_pe",
        "pyinstaller_carchive",
        "upx_packed",
    }
    assert result["status"] == "candidates_with_blockers"
    assert by_kind["pyinstaller_carchive"]["evidence"]["counts"]["entry_count"] == 32
    assert by_kind["pyinstaller_carchive"]["evidence"]["source_commitments"] == [
        {
            "role": "pyinstaller_inventory",
            "algorithm": "sha256",
            "record_count": 34,
            "sha256": "1" * 64,
        }
    ]
    assert by_kind["nsis_installer"]["extraction"]["status"] == "selective_recovery"
    assert by_kind["inno_setup_installer"]["extraction"]["status"] == "recovered"
    assert by_kind["upx_packed"]["extraction"]["status"] == "recovered"
    assert by_kind["packed_or_protected_pe"]["confidence"] == "medium"
    assert by_kind["packed_or_protected_pe"]["extraction"]["source_limit_event_count"] == 1
    assert by_kind["dotnet_resource_container"]["evidence"]["counts"]["resource_count"] == 2
    for candidate in result["candidates"]:
        assert candidate["maliciousness"] == "not_determined_from_packaging"
        assert candidate["family_attribution_allowed"] is False
        assert candidate["executed_sample"] is False
        assert candidate["network_contacted"] is False
        assert candidate["id"].startswith("sc-v1-")
        assert len(candidate["id"]) == len("sc-v1-") + 64
    rendered = json.dumps(result, ensure_ascii=False, sort_keys=True)
    assert "private" not in rendered.casefold()
    assert "0x401000" not in rendered
    assert "secret" not in rendered.casefold()


def test_output_and_stable_ids_are_deterministic_across_step_order() -> None:
    """step順序や非公開診断値を変えても候補順序・stable IDを維持する。"""

    first = _step(
        "2" * 64,
        {
            "pe": {
                "classification": "virtualized_or_packed",
                "packing_suspected": True,
                "packer_markers": ["Themida"],
            }
        },
    )
    second = _step(
        "1" * 64,
        {
            "pe": {
                "classification": "suspected_packed",
                "packing_suspected": True,
                "packer_markers": [],
            }
        },
        depth=1,
    )
    report_a = build_structural_candidates({"steps": [first, second], "limit_events": []})
    report_b = build_structural_candidates({"steps": [second, first], "limit_events": []})

    assert report_a == report_b
    assert [item["source_layer"]["sha256"] for item in report_a["candidates"]] == [
        "2" * 64,
        "1" * 64,
    ]


def test_fully_validated_nonpriority_pyinstaller_entries_are_not_blockers() -> None:
    """全内容検証済みの非候補破棄を高価値entry未保持と混同しない。"""

    step = _step(
        "3" * 64,
        {
            "pyinstaller": {
                "complete": True,
                "blockers": [],
                "classification": {"packaging": "PyInstaller CArchive"},
                "archive": {
                    "format": "PyInstaller CArchive",
                    "reader": "bounded_memory_carchive",
                    "entry_count": 158,
                    "toc_record_count": 158,
                },
                "selection": {
                    "candidate_count": 115,
                    "retained_count": 115,
                    "omitted_entry_count": 43,
                    "non_candidate_count": 43,
                    "blockers": [],
                },
                "content_validation": {
                    "full_content_validation": True,
                    "validated_entry_count": 158,
                    "total_entry_count": 158,
                    "discarded_after_validation_count": 43,
                },
            }
        },
        accepted_children=115,
    )

    result = build_structural_candidates({"steps": [step], "limit_events": []})
    candidate = result["candidates"][0]

    assert result["status"] == "candidates_recorded"
    assert candidate["extraction"]["status"] == "recovered"
    assert candidate["blockers"] == []
    assert candidate["evidence"]["counts"]["unretained_candidate_count"] == 0


def test_inno_overlay_marker_is_recorded_when_archive_parser_is_unsupported() -> None:
    """Inno markerを汎用SFXへ落とさず、未復元blocker付きで保持する。"""

    step = _step(
        "4" * 64,
        {
            "pe": {
                "packer_markers": ["Inno Setup"],
                "containerized": True,
                "packing_suspected": False,
            },
            "sevenzip": {"status": "not_archive_container", "archive_types": ["PE"]},
        },
    )

    result = build_structural_candidates({"steps": [step], "limit_events": []})
    candidate = result["candidates"][0]

    assert candidate["kind"] == "inno_setup_installer"
    assert candidate["status"] == "structure_suspected"
    assert candidate["extraction"]["status"] == "not_recovered"
    assert candidate["blockers"] == ["archive_extraction_incomplete"]


def test_assessment_only_is_explicitly_empty_and_summarized() -> None:
    """assessment-onlyでは構造解析を装わずnot_runと空一覧を返す。"""

    result = build_structural_candidates(
        {"steps": [_step("a" * 64, {"pe": {"packing_suspected": True}})]},
        assessment_only=True,
    )

    assert result["status"] == "not_run_assessment_only"
    assert result["candidate_count"] == 0
    assert result["candidates"] == []
    assert structural_candidate_summary(result) == {
        "artifact": "static-layers.json",
        "candidate_count": 0,
        "status": "not_run_assessment_only",
    }


def test_invalid_or_dynamic_source_is_not_reflected_to_public_output() -> None:
    """不正metadataや実行由来reportを候補へ採用せず、任意文字列も公開しない。"""

    invalid_format = _step(
        "7" * 64,
        {
            "pyinstaller": {
                "classification": {"packaging": "PyInstaller CArchive"},
                "archive": {"format": "PyInstaller CArchive", "entry_count": 1},
            }
        },
        layer_format=r"C:\private\format-secret",
    )
    dynamic = _step(
        "8" * 64,
        {
            "nested_dynamic_source": {"safety": {"sample_executed": True}},
            "pe": {
                "classification": "suspected_packed",
                "packing_suspected": True,
            },
        },
    )

    result = build_structural_candidates({"steps": [invalid_format, dynamic], "limit_events": []})

    assert result["candidate_count"] == 1
    assert result["invalid_step_count"] == 1
    assert result["status"] == "candidates_with_invalid_steps"
    assert result["candidates"][0]["source_layer"]["format"] == "unknown"
    assert "private" not in json.dumps(result, ensure_ascii=False).casefold()


def test_malformed_optional_fields_fail_closed_without_exception() -> None:
    """任意fieldの異常型を文字列化せず、安全な固定値へ縮退させる。"""

    nsis = _step(
        "6" * 64,
        {
            "pe": {
                "packer_markers": ["Nullsoft"],
                "sections": {"name": "UPX0"},
                "classification": {"secret": r"C:\private"},
                "packing_suspected": False,
            },
            "recovered": [{"kind": "unrelated-resource"}],
        },
        accepted_children=1,
    )

    result = build_structural_candidates({"steps": [nsis], "limit_events": "invalid"})
    candidate = result["candidates"][0]

    assert candidate["kind"] == "nsis_installer"
    assert candidate["extraction"]["status"] == "not_attempted"
    assert candidate["blockers"] == ["archive_extractor_not_run"]
    assert structural_candidate_summary({"status": r"C:\private\status-secret", "candidate_count": 1}) == {
        "artifact": "static-layers.json",
        "candidate_count": 1,
        "status": "source_report_unavailable",
    }


def test_candidate_status_is_outside_static_step_issue_scan() -> None:
    """候補のpartial語彙が既存のstep失敗判定へ誤混入しない。"""

    layer_report = {
        "steps": [
            _step(
                "9" * 64,
                {
                    "format": "data",
                    "unpack_status": "no_artifact_recovered",
                },
                layer_format="data",
            )
        ],
        "structural_candidates": {
            "status": "candidates_with_partial_recovery",
            "candidates": [{"status": "recovery_incomplete"}],
        },
    }

    assert analyzer._static_layer_issues(copy.deepcopy(layer_report)) == []


def test_analyze_sample_publishes_only_structural_summary_in_report(tmp_path: Path) -> None:
    """標準入口がstatic-layers本体とreportの最小summaryを同時生成する。"""

    sample = tmp_path / "assessment.bin"
    sample.write_bytes(b"bounded structural candidate integration fixture")
    output = tmp_path / "output"

    summary = analyzer.run_batch(
        [sample],
        output,
        registry=analyzer.DEFAULT_REGISTRY,
        assessment_only=True,
    )
    case_dir = output / "cases" / summary["cases"][0]["sha256"]
    layers_path = case_dir / "static-layers.json"
    layers = json.loads(layers_path.read_text(encoding="utf-8"))
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))

    assert layers["structural_candidates"]["status"] == "not_run_assessment_only"
    assert layers["structural_candidates"]["candidates"] == []
    assert report["structural_candidates"] == {
        "artifact": "static-layers.json",
        "candidate_count": 0,
        "status": "not_run_assessment_only",
    }
    assert report["artifact_sha256"]["static-layers.json"] == hashlib.sha256(layers_path.read_bytes()).hexdigest()
