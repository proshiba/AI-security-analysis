"""Remus process dump 静的一括解析の結合テスト。"""

from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

FRAMEWORK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FRAMEWORK))

from common import analyze_remus_process_dump as analyze
from common import remus_memory_config as remus

PARENT_SHA256 = "8" * 64
IMAGE_SIZE = 0x3000
TEXT_RVA = 0x1000
DATA_RVA = 0x2000
KEY_RVA = 0x2000
CIPHER_RVA = 0x2030
TAG_RVA = 0x2160
TOKEN_RVA = 0x21D0
STATE_RVA = 0x2200
RUNTIME_ENDPOINT_RVA = 0x2280
SELECTOR_RVA = 0x23F0
CODE_RVA = 0x1100
KEY = bytes(range(1, 33))
NONCE = bytes.fromhex("1020304050607080")
TAG = "844bd1dce6c8ac2a8b8a026e61811dac"
ENDPOINTS = (
    "http://none",
    "http://onesdto.shop:2535",
    "http://slyfogx.shop:5776",
)

FLOW_SHA256 = "a" * 64


def _write_evidence_manifest(tmp_path: Path, *, dump_sha256: str, recovered_pe_sha256: str) -> dict:
    endpoint = {
        "slot_index": 1,
        "uri": "http://onesdto.shop:2535",
        "scheme": "http",
        "host": "onesdto.shop",
        "port": 2535,
    }
    values = {
        "parent_sha256": PARENT_SHA256,
        "dump_sha256": dump_sha256,
        "recovered_pe_sha256": recovered_pe_sha256,
        "tag": TAG,
        "exp": 1_785_860_014,
        "http_host": "microsoft.com",
        "pinned_ip": "154.12.237.176",
        "endpoint": endpoint,
    }
    flow_relative = "evidence/remus-flow.json"
    flow_artifact = {
        "schema_version": 1,
        "artifact_type": analyze.remus_profile_evidence.FLOW_ARTIFACT_TYPE,
        "sample": {"sha256": PARENT_SHA256},
        "run": {"id": "analyzer-test-run"},
        "artifacts": {
            "process_dump": {"sha256": dump_sha256},
            "recovered_pe": {"sha256": recovered_pe_sha256},
        },
        "flow": {
            "tag": TAG,
            "exp": 1_785_860_014,
            "http_host": "microsoft.com",
            "pinned_ip": "154.12.237.176",
            "endpoint": endpoint,
        },
    }
    flow_raw = (json.dumps(flow_artifact, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    flow_path = tmp_path / Path(*flow_relative.split("/"))
    flow_path.parent.mkdir(parents=True, exist_ok=True)
    flow_path.write_bytes(flow_raw)
    flow_sha256 = hashlib.sha256(flow_raw).hexdigest()
    flow_fields = {"tag", "exp", "http_host", "pinned_ip", "endpoint"}
    manifest = {
        "schema_version": 1,
        "manifest_type": analyze.remus_profile_evidence.MANIFEST_TYPE,
        "family": "remusstealer",
        "review": {
            "status": "reviewed",
            "same_sample_verified": True,
            "same_flow_verified": True,
            "flow_evidence_sha256": flow_sha256,
        },
        "fields": {
            name: {
                "value": value,
                "sample_sha256": PARENT_SHA256,
                "flow_evidence_sha256": flow_sha256 if name in flow_fields else None,
            }
            for name, value in values.items()
        },
    }
    raw = (json.dumps(manifest, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    relative = Path("evidence") / "remus.json"
    path = tmp_path / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)
    manifest_sha256 = hashlib.sha256(raw).hexdigest()
    review_id = "analyzer-test-review"
    registry = {
        "schema_version": 1,
        "registry_type": analyze.remus_profile_evidence.REVIEW_REGISTRY_TYPE,
        "reviews": [
            {
                "review_id": review_id,
                "status": "approved",
                "manifest_source": relative.as_posix(),
                "manifest_sha256": manifest_sha256,
                "flow_artifact_source": flow_relative,
                "flow_artifact_sha256": flow_sha256,
                "flow_artifact_pointers": analyze.remus_profile_evidence.FLOW_ARTIFACT_POINTERS,
                "sample_sha256": PARENT_SHA256,
                "run_id": "analyzer-test-run",
                "dump_sha256": dump_sha256,
                "recovered_pe_sha256": recovered_pe_sha256,
            }
        ],
    }
    registry_path = tmp_path / Path(*analyze.remus_profile_evidence.REVIEW_REGISTRY_SOURCE.split("/"))
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps(registry, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return analyze.remus_profile_evidence.build_evidence_binding(
        relative.as_posix(),
        manifest_sha256,
        review_id,
    )


def _chacha(value: bytes, counter: int) -> bytes:
    transform = Cipher(
        algorithms.ChaCha20(KEY, counter.to_bytes(8, "little") + NONCE),
        mode=None,
    ).encryptor()
    return transform.update(value) + transform.finalize()


def _mapped_remus_pe(*, tag: str = TAG, include_state: bool = True) -> bytes:
    """回収処理と config 抽出処理の両方を通る mapped PE を作る。"""

    output = bytearray(IMAGE_SIZE)
    output[:2] = b"MZ"
    struct.pack_into("<I", output, 0x3C, 0x80)
    output[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", output, 0x84, 0x8664, 2, 0, 0, 0, 0xF0, 0x22)
    optional = 0x98
    struct.pack_into("<H", output, optional, 0x20B)
    struct.pack_into("<I", output, optional + 16, CODE_RVA)
    struct.pack_into("<I", output, optional + 20, TEXT_RVA)
    struct.pack_into("<Q", output, optional + 24, 0x140000000)
    struct.pack_into("<II", output, optional + 32, 0x1000, 0x200)
    struct.pack_into("<I", output, optional + 56, IMAGE_SIZE)
    struct.pack_into("<I", output, optional + 60, 0x400)
    struct.pack_into("<H", output, optional + 68, 3)
    struct.pack_into("<I", output, optional + 108, 16)

    section = optional + 0xF0
    output[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", output, section + 8, 0x400, TEXT_RVA, 0x400, 0x400)
    struct.pack_into("<I", output, section + 36, 0x60000020)
    section += 40
    output[section : section + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", output, section + 8, 0x1000, DATA_RVA, 0x1000, 0x800)
    struct.pack_into("<I", output, section + 36, 0xC0000040)

    output[KEY_RVA : KEY_RVA + 32] = KEY
    output[KEY_RVA + 32 : KEY_RVA + 40] = NONCE
    output[KEY_RVA + 40 : KEY_RVA + 48] = bytes(8)
    for index, uri in enumerate((*ENDPOINTS, "not-a-url")):
        plain = (uri.encode("ascii") + b"\0").ljust(remus.SLOT_SIZE, b"\0")
        start = CIPHER_RVA + index * remus.SLOT_SIZE
        output[start : start + remus.SLOT_SIZE] = _chacha(plain, index)

    output[TAG_RVA : TAG_RVA + len(tag)] = tag.encode("ascii")
    token = b"11111111-2222-4333-8444-555555555555"
    output[TOKEN_RVA : TOKEN_RVA + len(token)] = token
    if include_state:
        output[STATE_RVA : STATE_RVA + 16] = remus.CHACHA_CONSTANT
        output[STATE_RVA + 16 : STATE_RVA + 48] = KEY
        struct.pack_into("<Q", output, STATE_RVA + 48, 2)
        output[STATE_RVA + 56 : STATE_RVA + 64] = NONCE
    runtime = ENDPOINTS[1].encode("utf-16le") + b"\0\0"
    output[RUNTIME_ENDPOINT_RVA : RUNTIME_ENDPOINT_RVA + len(runtime)] = runtime
    output[SELECTOR_RVA] = 1 ^ 0x16

    code = bytearray()
    code += b"\x0f\xb6\x05" + struct.pack("<i", SELECTOR_RVA - (CODE_RVA + 7))
    code += b"\x83\xf0\x16\xc1\xe0\x06"
    code += b"\x48\x8d\x15" + struct.pack("<i", CIPHER_RVA - (CODE_RVA + 20))
    code += b"\x48\x01\xc2"
    code += b"\x48\x8d\x0d" + struct.pack("<i", STATE_RVA - (CODE_RVA + 30))
    output[CODE_RVA : CODE_RVA + len(code)] = code
    return bytes(output)


def test_end_to_end_recovers_pe_config_and_blocked_active_profile(tmp_path: Path) -> None:
    dump = tmp_path / "process.dmp"
    dump_bytes = b"prefix" + _mapped_remus_pe()
    dump.write_bytes(dump_bytes)
    output = tmp_path / "private-output"

    report = analyze.analyze_remus_process_dump_file(
        dump,
        output,
        parent_sha256=PARENT_SHA256,
    )

    assert report["status"] == "partial"
    assert report["input"]["parent_sha256"] == PARENT_SHA256
    assert report["input"]["dump_sha256"] == hashlib.sha256(dump_bytes).hexdigest()
    recovery = report["stages"]["pe_recovery"]
    assert recovery["mapped_mode"] == "expanded_memory_sections"
    assert recovery["summary"]["recovered_outputs"] == 1
    recovered_hash = recovery["recovered_outputs"][0]["recovered_pe_sha256"]
    assert len(recovered_hash) == 64
    config = report["stages"]["config_extraction"]["candidates"][0]["config"]
    assert [item["uri"] for item in config["config"]["endpoints"]] == list(ENDPOINTS[1:])
    assert config["config"]["tag"]["value"] == TAG
    assert "value" not in config["config"]["runtime"]["access_token"]

    profile = report["stages"]["c2_profile_generation"]["sanitized_profile"]
    assert profile["status"] == "blocked"
    reason_codes = {item["code"] for item in profile["active_profile_generation"]["blocked_reasons"]}
    assert {"tag_unreviewed", "exp_missing", "reviewed_http_host_missing", "evidence_manifest_missing"} <= reason_codes
    assert profile["safety"]["other_sample_defaults_used"] is False
    assert all(value is False for value in recovery["safety"].values())
    assert all(value is False for value in report["stages"]["config_extraction"]["safety"].values())
    assert all(value is False for value in report["stages"]["c2_profile_generation"]["safety"].values())

    stored = json.loads((output / analyze.REPORT_NAME).read_text(encoding="utf-8"))
    assert stored == report
    recovered_path = output / recovery["recovered_outputs"][0]["output_name"]
    assert hashlib.sha256(recovered_path.read_bytes()).hexdigest() == recovered_hash
    assert os.stat(recovered_path).st_nlink == 1


def test_zero_config_candidates_returns_reasoned_error() -> None:
    outputs, report = analyze.analyze_remus_process_dump_bytes(
        _mapped_remus_pe(include_state=False),
        parent_sha256=PARENT_SHA256,
    )

    assert len(outputs) == 1
    assert report["status"] == "error"
    assert report["error"]["code"] == "remus_config_not_found"
    assert report["error"]["successful_config_candidates"] == 0
    assert report["stages"]["c2_profile_generation"]["status"] == "not_run"
    assert report["stages"]["config_extraction"]["candidates"][0]["error_ja"]


def test_multiple_config_candidates_returns_reasoned_error() -> None:
    first = _mapped_remus_pe(tag="1" * 32)
    second = _mapped_remus_pe(tag="2" * 32)
    outputs, report = analyze.analyze_remus_process_dump_bytes(
        first + b"padding" + second,
        parent_sha256=PARENT_SHA256,
    )

    assert len(outputs) == 2
    assert report["status"] == "error"
    assert report["error"]["code"] == "remus_config_ambiguous"
    assert report["error"]["successful_config_candidates"] == 2
    assert report["stages"]["c2_profile_generation"]["status"] == "not_run"


def test_complete_same_sample_evidence_can_generate_active_profile(tmp_path: Path) -> None:
    data = _mapped_remus_pe()
    initial_outputs, _ = analyze.analyze_remus_process_dump_bytes(
        data,
        parent_sha256=PARENT_SHA256,
    )
    binding = _write_evidence_manifest(
        tmp_path,
        dump_sha256=hashlib.sha256(data).hexdigest(),
        recovered_pe_sha256=str(initial_outputs[0].metadata["output_sha256"]),
    )
    outputs, report = analyze.analyze_remus_process_dump_bytes(
        data,
        parent_sha256=PARENT_SHA256,
        reviewed_tag=TAG,
        exp=1_785_860_014,
        reviewed_http_host="microsoft.com",
        pinned_ip="154.12.237.176",
        evidence_binding=binding,
        repository_root=tmp_path,
    )

    assert len(outputs) == 1
    assert report["status"] == "complete"
    profile = report["stages"]["c2_profile_generation"]["sanitized_profile"]
    assert profile["status"] == "ready"
    active = profile["active_profile_generation"]["profile"]
    assert active["sample_sha256s"] == [PARENT_SHA256]
    assert active["pinned_ips"] == ["154.12.237.176"]
    assert active["recovered_pe_sha256"] == outputs[0].metadata["output_sha256"]


def test_cli_distinguishes_partial_and_complete_exit_codes(tmp_path: Path, capsys) -> None:
    dump = tmp_path / "process.dmp"
    dump_bytes = _mapped_remus_pe()
    dump.write_bytes(dump_bytes)
    initial_outputs, _ = analyze.analyze_remus_process_dump_bytes(dump_bytes, parent_sha256=PARENT_SHA256)
    binding = _write_evidence_manifest(
        tmp_path,
        dump_sha256=hashlib.sha256(dump_bytes).hexdigest(),
        recovered_pe_sha256=str(initial_outputs[0].metadata["output_sha256"]),
    )
    partial_code = analyze.main(
        [
            "--input",
            str(dump),
            "--output-dir",
            str(tmp_path / "partial"),
            "--parent-sha256",
            PARENT_SHA256,
        ]
    )
    assert partial_code == 3
    assert json.loads(capsys.readouterr().out)["status"] == "partial"

    complete_code = analyze.main(
        [
            "--input",
            str(dump),
            "--output-dir",
            str(tmp_path / "complete"),
            "--parent-sha256",
            PARENT_SHA256,
            "--reviewed-tag",
            TAG,
            "--exp",
            "1785860014",
            "--reviewed-http-host",
            "microsoft.com",
            "--pinned-ip",
            "154.12.237.176",
            "--source-reference",
            (
                "analysis-results/malware/remusstealer/versions/unknown/cases/"
                + PARENT_SHA256
                + "/remus-c2-profile.json:active_profile_generation.profile"
            ),
            "--evidence-manifest-source",
            binding["source"],
            "--evidence-manifest-sha256",
            binding["sha256"],
            "--evidence-review-id",
            binding["review_id"],
            "--repository-root",
            str(tmp_path),
        ]
    )
    assert complete_code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "complete"


def test_existing_output_is_rejected_without_overwrite(tmp_path: Path) -> None:
    dump = tmp_path / "process.dmp"
    dump.write_bytes(_mapped_remus_pe())
    output = tmp_path / "already-exists"
    output.mkdir()
    marker = output / "preserve.txt"
    marker.write_text("preserve", encoding="utf-8")

    with pytest.raises(analyze.RemusProcessDumpAnalysisError, match="既存"):
        analyze.analyze_remus_process_dump_file(
            dump,
            output,
            parent_sha256=PARENT_SHA256,
        )

    assert marker.read_text(encoding="utf-8") == "preserve"
    assert sorted(path.name for path in output.iterdir()) == ["preserve.txt"]


def test_hardlinked_input_is_rejected(tmp_path: Path) -> None:
    dump = tmp_path / "process.dmp"
    alias = tmp_path / "process-alias.dmp"
    dump.write_bytes(_mapped_remus_pe())
    try:
        os.link(dump, alias)
    except OSError as exc:
        pytest.skip(f"この filesystem では hardlink を作成できません: {exc}")

    with pytest.raises(pe_error(), match="ハードリンク"):
        analyze.analyze_remus_process_dump_file(
            dump,
            tmp_path / "output",
            parent_sha256=PARENT_SHA256,
        )


def pe_error() -> type[ValueError]:
    """依存moduleの具体的な例外型をtest collection後に返す。"""

    return analyze.pe_recovery.ProcessDumpPEError


def test_parent_hash_is_required_and_output_must_not_be_inside_input_path(tmp_path: Path) -> None:
    with pytest.raises(analyze.RemusProcessDumpAnalysisError, match="必須"):
        analyze.analyze_remus_process_dump_bytes(
            _mapped_remus_pe(),
            parent_sha256="bad",
        )

    dump = tmp_path / "process.dmp"
    dump.write_bytes(_mapped_remus_pe())
    with pytest.raises(analyze.RemusProcessDumpAnalysisError, match="内包"):
        analyze._prepare_new_output_directory(dump, dump / "child-output")
