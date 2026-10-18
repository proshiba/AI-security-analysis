"""Remcos mapped PEのdetector・handler・one-shot接続を回帰検証する。"""

from __future__ import annotations

import hashlib
import json
import struct
import sys
from pathlib import Path

from extractors.remcosrat.strict_config import DELIMITERS, rc4_crypt

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
COMMON_ROOT = REPOSITORY_ROOT / "analysis-framework" / "common"
CLASSIFIERS_ROOT = REPOSITORY_ROOT / "analysis-framework" / "classifiers"
for import_root in (REPOSITORY_ROOT, COMMON_ROOT, CLASSIFIERS_ROOT):
    if str(import_root) not in sys.path:
        sys.path.insert(0, str(import_root))

import analyze_sample as one_shot
from handler_catalog import discover_handlers, preflight_handler_for_assessment

REGISTRY = REPOSITORY_ROOT / "analysis-framework" / "registry" / "malware_types.json"
HANDLER_ID = "remcosrat:analysis.framework.malware.remcosrat.extract.config.py:extract_config"
HOST = "mapped-remcos.example.test"
PORT = 2404


def _settings_blob() -> bytes:
    """秘密値を含まない合成Remcos SETTINGS resourceを作る。"""

    fields = [b"0"] * 57
    fields[0] = f"{HOST}:{PORT}:1".encode("ascii")
    fields[1] = b"mapped-pipeline-fixture"
    fields[2] = b"30"
    fields[0x0E] = b"Rmc-PIPELINE-FIXTURE"
    fields[0x29] = b"5"
    clear = DELIMITERS[0].join(fields)
    key = b"fixture-key"
    return bytes([len(key)]) + key + rc4_crypt(clear, key)


def _resource_section(blob: bytes) -> bytes:
    """RCDATA/SETTINGS/1033を持つ最小resource sectionを返す。"""

    section = bytearray(0x600)
    struct.pack_into("<IIHHHH", section, 0x00, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", section, 0x10, 10, 0x80000020)
    struct.pack_into("<IIHHHH", section, 0x20, 0, 0, 0, 0, 1, 0)
    struct.pack_into("<II", section, 0x30, 0x80000060, 0x80000040)
    struct.pack_into("<IIHHHH", section, 0x40, 0, 0, 0, 0, 0, 1)
    struct.pack_into("<II", section, 0x50, 1033, 0x80)
    name = "SETTINGS".encode("utf-16le")
    struct.pack_into("<H", section, 0x60, len("SETTINGS"))
    section[0x62 : 0x62 + len(name)] = name
    struct.pack_into("<IIII", section, 0x80, 0x1100, len(blob), 0, 0)
    section[0x100 : 0x100 + len(blob)] = blob
    return bytes(section)


def _mapped_remcos_fixture() -> bytes:
    """entrypointを持たず、sectionだけをRVA配置したmapped PEを作る。"""

    data = bytearray(0x2000)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<II", data, optional + 96 + 2 * 8, 0x1000, 0x600)
    section_header = optional + 0xE0
    data[section_header : section_header + 8] = b".rsrc\0\0\0"
    struct.pack_into("<IIII", data, section_header + 8, 0x600, 0x1000, 0x600, 0x200)
    struct.pack_into("<I", data, section_header + 36, 0x40000040)
    data[0x1000:0x1600] = _resource_section(_settings_blob())
    return bytes(data)


def _handler_spec():
    values = [item for item in discover_handlers() if item.id == HANDLER_ID]
    assert len(values) == 1
    return values[0]


def test_mapped_detector_to_handler_one_shot_recovers_config_and_c2(
    tmp_path: Path,
    monkeypatch,
) -> None:
    """mapped再構成をdetectorと正規handlerの双方で同じlayerへ適用する。"""

    data = _mapped_remcos_fixture()
    digest = hashlib.sha256(data).hexdigest()
    classification = one_shot.classify_sample.classify_bytes(
        data,
        Path("remcos-mapped-static-fixture.bin"),
        REGISTRY,
    )
    evaluation = next(item for item in classification["detector_evaluations"] if item["malware_type"] == "remcosrat")
    assert classification["malware_type"] == "remcosrat"
    assert evaluation["detector_matched"] is True
    assert evaluation["supports_family_attribution"] is True
    assert evaluation["detection"]["observations"]["input_layout"] == ("mapped_pe_memory_image")
    assert evaluation["detection"]["observations"]["mapped_pe_reconstructed"] is True

    spec = _handler_spec()
    preflight = preflight_handler_for_assessment(
        spec,
        actual_format="pe",
        input_size=len(data),
    )
    assert preflight["eligible"] is True, preflight["blockers"]
    assert preflight["blockers"] == []
    assert preflight["sample_execution_allowed"] is False
    assert preflight["network_allowed"] is False
    assert preflight["filesystem_write_allowed"] is False

    monkeypatch.setattr(
        one_shot,
        "_run_generic_triage",
        lambda _layers, _case_dir, **_kwargs: (
            {
                "analysis_coverage": {"status": "complete"},
                "executed_sample": False,
                "network_contacted": False,
            },
            "complete",
        ),
    )
    unit = one_shot.InputUnit(
        source_name="remcos-mapped-static-fixture.bin",
        data=data,
        input_kind="raw",
        outer_sha256=digest,
        outer_size=len(data),
    )
    output = tmp_path / "out"

    one_shot.analyze_unit(
        unit,
        output=output,
        registry=REGISTRY,
        specs=discover_handlers(),
        registered={"remcosrat"},
        forced_family=None,
        minimum_confidence="medium",
        assessment_only=False,
        analysis_contract={"schema_version": 1, "sha256": "fixture-contract"},
    )

    case_dir = output / "cases" / digest
    report = json.loads((case_dir / "report.json").read_text(encoding="utf-8"))
    patterns = json.loads((case_dir / "communication-patterns.json").read_text(encoding="utf-8"))
    c2 = json.loads((case_dir / "c2-analysis.json").read_text(encoding="utf-8"))

    assert report["classification"]["selected_family"] == "remcosrat"
    assert report["classification"]["automation_family"] == "remcosrat"
    assert len(report["handler_executions"]) == 1
    execution = report["handler_executions"][0]
    assert execution["handler_id"] == HANDLER_ID
    assert execution["status"] == "succeeded"
    assert execution["selected_layer_sha256"] == digest
    assert patterns["family"] == "remcosrat"
    assert patterns["config"]["static_config_recovered"] is True
    confirmed = patterns["communication"]["confirmed_static_c2_endpoints"]
    assert len(confirmed) == 1
    assert confirmed[0]["endpoint"] == f"{HOST}:{PORT}"
    assert confirmed[0]["host"] == HOST
    assert confirmed[0]["port"] == PORT
    assert confirmed[0]["role"] == "interactive_c2"
    assert confirmed[0]["confidence"] == "confirmed_static_configuration"
    assert confirmed[0]["evidence"] == {
        "kind": "rc4_decrypted_rcdata_settings",
        "resource_type": "RT_RCDATA",
        "resource_name": "SETTINGS",
        "config_field_index": 0,
        "all_expected_fields_validated": True,
        "validated_field_indices": [0, 1, 2, 14, 41],
        "complete_c2_record_set_validated": True,
        "family_specific_schema_validated": True,
        "family_specific_mutex_prefix_validated": True,
        "family_schema_validation_profile": "elastic_published_56_field_subset_v1",
    }
    assert confirmed[0]["contacted"] is False
    assert confirmed[0]["liveness_confirmed"] is False
    assert patterns["communication"]["candidate_patterns"] == []
    phases = {item["phase"]: item for item in c2["phase_evidence"]}
    assert phases["family_config_extraction"]["status"] == "completed"
    assert phases["c2_endpoint_extraction"]["status"] == "completed"
    assert "確認済みC2 endpoint 1件" in phases["c2_endpoint_extraction"]["evidence"][0]
    assert "未確定pattern 0件" in phases["c2_endpoint_extraction"]["evidence"][0]
    assert patterns["safety"]["sample_executed"] is False
    assert patterns["safety"]["network_contacted"] is False
