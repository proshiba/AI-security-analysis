"""XLoader関数カタログの公開schema、lineage、atomic書出しを検証する。"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "analysis-framework" / "malware" / "formbook_loader" / "function_catalog.py"
SPEC = importlib.util.spec_from_file_location("xloader_function_catalog_security", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CATALOG = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CATALOG
SPEC.loader.exec_module(CATALOG)


def _fixture() -> tuple[bytes, dict[str, object]]:
    image = bytearray(b"\x90" * 0x100)
    body = b"\x55\x8b\xec\x33\xc0\xc3"
    image[0x20 : 0x20 + len(body)] = body
    image_bytes = bytes(image)
    report: dict[str, object] = {
        "schema_version": 1,
        "analysis_type": "xloader_static_recovery_reconcile",
        "output_sha256": hashlib.sha256(image_bytes).hexdigest(),
        "wrapper_count": 2,
        "recovered_count": 1,
        "unresolved_count": 1,
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
        },
        "functions": [
            {
                "wrapper_start": 0x80,
                "protected_target": 0x10,
                "function_start": 0x20,
                "function_end": 0x20 + len(body),
                "body_sha256": hashlib.sha256(body).hexdigest(),
                "method": "caller_dataflow",
            }
        ],
        "unresolved": [
            {
                "wrapper_start": 0x90,
                "protected_target": 0x70,
                "reason_code": "static_context_marker_mismatch",
                "runtime_context_required": True,
            }
        ],
    }
    return image_bytes, report


def _semantics() -> dict[int, dict[str, object]]:
    return {
        0x10: {
            "name": "SyntheticParser",
            "role": "構文解析",
            "summary_ja": "入力bufferを検査して処理状態を返す。",
            "prototype": "uint32_t SyntheticParser(void *context)",
            "inputs": [
                {
                    "name": "context",
                    "type": "void *",
                    "description_ja": "解析対象context。",
                }
            ],
            "outputs": [
                {
                    "kind": "return",
                    "type": "uint32_t",
                    "description_ja": "処理状態。",
                }
            ],
            "side_effects_ja": [],
            "confidence": "confirmed_static",
            "evidence_ja": ["synthetic fixture"],
            "similarity_notes_ja": ["body hashを版間比較する。"],
        }
    }


def _evidence(
    image: bytes,
    *,
    sample_sha256: str = "a" * 64,
    analysis_image_sha256: str | None = None,
    classification: str = "resolved_mix_marker_absent_all_images",
) -> object:
    return CATALOG.UnresolvedEvidenceSet(
        sample_sha256=sample_sha256,
        analysis_image_sha256=(analysis_image_sha256 or hashlib.sha256(image).hexdigest()),
        functions={
            0x70: {
                "wrapper_start": 0x90,
                "classification": classification,
                "runtime_capture_priority": "low",
                "execution_alone_may_help": False,
                "marker_hit_image_count": 0,
                "target_mutation_observed": False,
            }
        },
        safety={
            "sample_executed": False,
            "network_contacted": False,
        },
    )


def test_reviewed_semantics_rejects_nested_secret_key() -> None:
    image, report = _fixture()
    semantics = _semantics()
    semantics[0x10]["inputs"][0]["key_hex"] = "0011223344556677"

    with pytest.raises(CATALOG.FunctionCatalogError, match="秘密値用key"):
        CATALOG.build_catalog(image, report, semantics, sample_sha256="a" * 64)

@pytest.mark.parametrize(
    ("field", "value", "match"),
    [
        ("schema_version", 2, "schema_version"),
        ("analysis_type", "arbitrary_untrusted_report", "analysis_type"),
    ],
)
def test_recovery_report_rejects_wrong_schema_or_analysis_type(
    field: str,
    value: object,
    match: str,
) -> None:
    image, report = _fixture()
    report[field] = value

    with pytest.raises(CATALOG.FunctionCatalogError, match=match):
        CATALOG.build_catalog(image, report, {}, sample_sha256="a" * 64)


@pytest.mark.parametrize("field", ["schema_version", "analysis_type"])
def test_recovery_report_rejects_missing_schema_identity(field: str) -> None:
    image, report = _fixture()
    del report[field]

    with pytest.raises(CATALOG.FunctionCatalogError, match=field):
        CATALOG.build_catalog(image, report, {}, sample_sha256="a" * 64)



@pytest.mark.parametrize(
    "secret_text",
    ["key=0011223344556677", "password=not-a-hex-secret", '\"api_key\": \"encoded-value\"'],
)
def test_reviewed_semantics_rejects_secret_assignment_in_text(
    secret_text: str,
) -> None:
    image, report = _fixture()
    semantics = _semantics()
    semantics[0x10]["summary_ja"] = secret_text

    with pytest.raises(CATALOG.FunctionCatalogError, match="秘密値らしい"):
        CATALOG.build_catalog(image, report, semantics, sample_sha256="a" * 64)


@pytest.mark.parametrize(
    "field,value",
    [
        ("role", ["不正な型"]),
        ("summary_ja", "長" * 4097),
        ("evidence_ja", [[["深すぎる"]]]),
    ],
)
def test_reviewed_semantics_rejects_invalid_type_length_and_depth(field: str, value: object) -> None:
    image, report = _fixture()
    semantics = _semantics()
    semantics[0x10][field] = value

    with pytest.raises(CATALOG.FunctionCatalogError):
        CATALOG.build_catalog(image, report, semantics, sample_sha256="a" * 64)


def test_recovery_method_and_reason_code_are_enums() -> None:
    image, report = _fixture()
    report["functions"][0]["method"] = "caller_dataflow;key=00112233"
    with pytest.raises(CATALOG.FunctionCatalogError, match="許可enum"):
        CATALOG.build_catalog(image, report, {}, sample_sha256="a" * 64)

    _, report = _fixture()
    report["unresolved"][0]["reason_code"] = "自由記述"
    with pytest.raises(CATALOG.FunctionCatalogError, match="許可enum"):
        CATALOG.build_catalog(image, report, {}, sample_sha256="a" * 64)


def test_unresolved_classification_is_enum() -> None:
    image, report = _fixture()
    evidence = _evidence(image, classification="secret_marker_dump")

    with pytest.raises(CATALOG.FunctionCatalogError, match="許可enum"):
        CATALOG.build_catalog(
            image,
            report,
            {},
            evidence,
            sample_sha256="a" * 64,
        )


@pytest.mark.parametrize(
    "sample_sha256,analysis_image_sha256,match",
    [
        ("b" * 64, None, "sample SHA-256"),
        ("a" * 64, "0" * 64, "解析像SHA-256"),
    ],
)
def test_unresolved_evidence_lineage_mismatch_is_rejected(
    sample_sha256: str, analysis_image_sha256: str | None, match: str
) -> None:
    image, report = _fixture()
    evidence = _evidence(
        image,
        sample_sha256=sample_sha256,
        analysis_image_sha256=analysis_image_sha256,
    )

    with pytest.raises(CATALOG.FunctionCatalogError, match=match):
        CATALOG.build_catalog(
            image,
            report,
            {},
            evidence,
            sample_sha256="a" * 64,
        )


def test_recovery_report_sample_lineage_mismatch_is_rejected() -> None:
    image, report = _fixture()
    report["sample_sha256"] = "b" * 64

    with pytest.raises(CATALOG.FunctionCatalogError, match="指定sample"):
        CATALOG.build_catalog(image, report, {}, sample_sha256="a" * 64)


def test_safety_is_validated_and_preserved() -> None:
    image, report = _fixture()
    report["safety"] = {
        "sample_executed": True,
        "network_contacted": True,
    }

    catalog = CATALOG.build_catalog(image, report, {}, sample_sha256="a" * 64)

    assert catalog["safety"]["sample_executed"] is True
    assert catalog["safety"]["network_contacted"] is True
    assert catalog["safety"]["function_bytes_published"] is False


def test_missing_or_non_boolean_safety_is_rejected() -> None:
    image, report = _fixture()
    del report["safety"]
    with pytest.raises(CATALOG.FunctionCatalogError, match="safety"):
        CATALOG.build_catalog(image, report, {}, sample_sha256="a" * 64)

    _, report = _fixture()
    report["safety"]["sample_executed"] = 0
    with pytest.raises(CATALOG.FunctionCatalogError, match="boolean"):
        CATALOG.build_catalog(image, report, {}, sample_sha256="a" * 64)


def test_uppercase_sha256_is_rejected() -> None:
    image, report = _fixture()
    with pytest.raises(CATALOG.FunctionCatalogError, match="lowercase"):
        CATALOG.build_catalog(image, report, {}, sample_sha256="A" * 64)

    report["output_sha256"] = str(report["output_sha256"]).upper()
    with pytest.raises(CATALOG.FunctionCatalogError, match="lowercase"):
        CATALOG.build_catalog(image, report, {}, sample_sha256="a" * 64)


def test_unresolved_evidence_loader_preserves_lineage(tmp_path: Path) -> None:
    image, _ = _fixture()
    document = {
        "schema_version": 1,
        "analysis_type": "xloader_unresolved_static_evidence",
        "sample_sha256": "a" * 64,
        "analysis_image_sha256": hashlib.sha256(image).hexdigest(),
        "unresolved_count": 1,
        "classification_counts": {
            "resolved_mix_marker_absent_all_images": 1,
        },
        "functions": [
            {
                "wrapper_start": "0x90",
                "protected_target": "0x70",
                "classification": "resolved_mix_marker_absent_all_images",
                "runtime_capture_priority": "low",
                "execution_alone_may_help": False,
                "marker_hit_image_count": 0,
                "target_mutations": [],
                "mix_values_published": False,
                "marker_material_published": False,
            }
        ],
        "safety": {
            "sample_executed_locally": False,
            "network_contacted": False,
            "mix_values_published": False,
            "marker_material_published": False,
            "function_bytes_published": False,
        },
    }
    path = tmp_path / "evidence.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    evidence = CATALOG.load_unresolved_evidence(path)

    assert evidence.sample_sha256 == "a" * 64
    assert evidence.analysis_image_sha256 == hashlib.sha256(image).hexdigest()
    assert evidence.functions[0x70]["wrapper_start"] == 0x90


def test_cli_rejects_output_collisions(tmp_path: Path) -> None:
    input_path = tmp_path / "input.bin"
    input_path.write_bytes(b"input")
    output = tmp_path / "output.json"

    with pytest.raises(CATALOG.FunctionCatalogError, match="衝突"):
        CATALOG._validate_cli_paths([input_path], [output, output])
    with pytest.raises(CATALOG.FunctionCatalogError, match="衝突"):
        CATALOG._validate_cli_paths([input_path], [input_path, output])


def test_cli_rejects_symlink_alias_to_input(tmp_path: Path) -> None:
    input_path = tmp_path / "input.bin"
    input_path.write_bytes(b"input")
    alias = tmp_path / "alias.json"
    try:
        alias.symlink_to(input_path)
    except OSError as error:  # pragma: no cover - Windows権限依存
        pytest.skip(f"symbolic linkを作成できません: {error}")

    with pytest.raises(CATALOG.FunctionCatalogError, match="衝突"):
        CATALOG._validate_cli_paths([input_path], [alias, tmp_path / "report.md"])

    second_alias = tmp_path / "second-alias.md"
    second_alias.symlink_to(input_path)
    with pytest.raises(CATALOG.FunctionCatalogError, match="衝突"):
        CATALOG._validate_cli_paths([], [alias, second_alias])


def test_atomic_write_rolls_back_both_outputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    json_output = tmp_path / "catalog.json"
    markdown_output = tmp_path / "catalog.md"
    json_output.write_bytes(b"old-json")
    markdown_output.write_bytes(b"old-markdown")
    real_replace = os.replace
    replace_count = 0

    def fail_second_replace(source: object, destination: object) -> None:
        nonlocal replace_count
        if Path(destination) in {json_output, markdown_output}:
            replace_count += 1
            if replace_count == 2:
                raise OSError("synthetic replace failure")
        real_replace(source, destination)

    monkeypatch.setattr(CATALOG.os, "replace", fail_second_replace)

    with pytest.raises(CATALOG.FunctionCatalogError, match="atomic replace"):
        CATALOG._atomic_write_outputs(
            {
                json_output: "new-json",
                markdown_output: "new-markdown",
            }
        )

    assert json_output.read_bytes() == b"old-json"
    assert markdown_output.read_bytes() == b"old-markdown"
