"""NanoCore追加設定の公開投影を検証する。"""

from __future__ import annotations

import json
import sys
from pathlib import Path


COMMON = Path(__file__).resolve().parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import publish_nanocore_c2_followup as publisher  # noqa: E402


def test_confirmed_endpoint_replaces_identical_external_candidate(tmp_path: Path) -> None:
    digest = "a" * 64
    path = tmp_path / "iocs.json"
    path.write_text(
        json.dumps({
            "schema_version": 1,
            "sha256": [digest],
            "sample_executed": False,
            "network_contacted": False,
            "network": [
                {
                    "value": "controller.example.org:443",
                    "role": "c2_candidate_external_sandbox_config",
                    "source": "hatching_triage_public_exact_sha256_config",
                },
                {
                    "value": "https://unrelated.example.org/",
                    "role": "c2_candidate_external_sandbox_config",
                    "source": "hatching_triage_public_exact_sha256_config",
                },
            ],
        }),
        encoding="utf-8",
    )
    endpoint = {
        "host": "controller.example.org",
        "port": 443,
        "role": "nanocore_configured_controller",
        "confidence": "confirmed_static_configuration",
        "source": "handler:nanocore:fixture",
        "evidence": {"kind": "nanocore_des_cbc_typed_config"},
    }
    updated = publisher._updated_iocs(path, digest, [endpoint])
    assert updated["network"] == [
        {
            "value": "https://unrelated.example.org/",
            "role": "c2_candidate_external_sandbox_config",
            "source": "hatching_triage_public_exact_sha256_config",
        },
        endpoint,
    ]


def test_followup_note_is_idempotent(tmp_path: Path) -> None:
    path = tmp_path / "README.md"
    path.write_text("# 検体\n\n## 概要\n\n本文。\n", encoding="utf-8")
    first = publisher._readme_with_note(path)
    path.write_text(first, encoding="utf-8")
    assert publisher._readme_with_note(path) == first
    assert first.count("<!-- nanocore-c2-followup:start -->") == 1
