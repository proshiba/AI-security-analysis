"""XLoader関数カタログ生成器のテスト。"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "analysis-framework" / "malware" / "formbook_loader" / "function_catalog.py"
SPEC = importlib.util.spec_from_file_location("xloader_function_catalog", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
CATALOG = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CATALOG
SPEC.loader.exec_module(CATALOG)


def test_catalog_covers_recovered_and_unresolved_functions() -> None:
    image = bytearray(b"\x90" * 0x100)
    body = b"\x55\x8b\xec\x8b\x45\x08\x8b\x4d\x0c\x33\xc0\xc2\x08\x00"
    image[0x20 : 0x20 + len(body)] = body
    image_bytes = bytes(image)
    report = {
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
    semantics = {
        0x10: {
            "name": "SyntheticParser",
            "role": "テスト用parser",
            "summary_ja": "2引数を受けて状態を返す。",
            "prototype": "uint32_t SyntheticParser(void *context, uint32_t size)",
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
            "similarity_notes_ja": ["synthetic body hashで比較する。"],
        }
    }
    unresolved_evidence = CATALOG.UnresolvedEvidenceSet(
        sample_sha256="b" * 64,
        analysis_image_sha256=hashlib.sha256(image_bytes).hexdigest(),
        functions={
            0x70: {
                "wrapper_start": 0x90,
                "classification": "resolved_mix_marker_absent_all_images",
                "runtime_capture_priority": "low",
                "execution_alone_may_help": False,
                "marker_hit_image_count": 0,
                "target_mutation_observed": False,
            }
        },
        safety={
            "sample_executed": True,
            "network_contacted": False,
        },
    )

    catalog = CATALOG.build_catalog(image_bytes, report, semantics, unresolved_evidence, sample_sha256="b" * 64)
    markdown = CATALOG.render_markdown(catalog)

    assert catalog["wrapper_count"] == 2
    assert catalog["recovered_count"] == 1
    assert catalog["unresolved_count"] == 1
    assert catalog["reviewed_semantics_count"] == 1
    assert catalog["functions"][0]["static_traits"]["argument_indices"] == [1, 2]
    assert catalog["functions"][1]["runtime_context_required"] is False
    assert catalog["functions"][1]["static_evidence_classification"] == "resolved_mix_marker_absent_all_images"
    assert catalog["functions"][1]["runtime_capture_priority"] == "low"
    assert catalog["functions"][1]["execution_alone_may_help"] is False
    assert "XLoader保護関数カタログ" in markdown
    assert "SyntheticParser" in markdown
    assert catalog["safety"]["key_material_published"] is False
    assert catalog["safety"]["sample_executed"] is True
    assert catalog["unresolved_evidence_lineage"]["sample_sha256"] == "b" * 64
    assert catalog["unresolved_evidence_lineage"]["analysis_image_sha256"] == hashlib.sha256(image_bytes).hexdigest()
