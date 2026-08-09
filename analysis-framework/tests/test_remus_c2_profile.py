from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_protocol_probe_profiles as profile_registry
import remus_c2_profile as remus_profile
import remus_profile_evidence as evidence
from remus_c2_profile import (
    RemusC2ProfileError,
    build_remus_c2_profile,
    build_remus_c2_profile_from_payload,
    main,
)
from remus_profile_evidence import build_evidence_binding

PARENT_SHA256 = "8" * 64
RECOVERED_SHA256 = "f" * 64
TAG = "844bd1dce6c8ac2a8b8a026e61811dac"
DUMP_SHA256 = "d" * 64
FLOW_SHA256 = "a" * 64
PINNED_IP = "154.12.237.176"
SOURCE_REFERENCE = (
    "analysis-results/malware/remusstealer/versions/unknown/cases/"
    + PARENT_SHA256
    + "/remus-c2-profile.json:active_profile_generation.profile"
)


def endpoints() -> list[dict]:
    return [
        {
            "slot_index": 1,
            "uri": "http://onesdto.shop:2535",
            "scheme": "http",
            "host": "onesdto.shop",
            "port": 2535,
            "pinned_ips": [PINNED_IP],
        },
        {
            "slot_index": 2,
            "uri": "http://slyfogx.shop:5776",
            "scheme": "http",
            "host": "slyfogx.shop",
            "port": 5776,
        },
    ]


def build(**overrides):
    values = {
        "endpoints": endpoints(),
        "selected_index": 1,
        "tag_candidate": TAG,
        "exp": 1_785_860_014,
        "reviewed_http_host": "microsoft.com",
        "parent_sha256": PARENT_SHA256,
        "dump_sha256": DUMP_SHA256,
        "recovered_pe_sha256": RECOVERED_SHA256,
        "source_reference": SOURCE_REFERENCE,
    }
    values.update(overrides)
    return build_remus_c2_profile(**values)


def write_evidence_manifest(tmp_path: Path) -> dict:
    endpoint = {
        "slot_index": 1,
        "uri": "http://onesdto.shop:2535",
        "scheme": "http",
        "host": "onesdto.shop",
        "port": 2535,
    }
    values = {
        "parent_sha256": PARENT_SHA256,
        "dump_sha256": DUMP_SHA256,
        "recovered_pe_sha256": RECOVERED_SHA256,
        "tag": TAG,
        "exp": 1_785_860_014,
        "http_host": "microsoft.com",
        "pinned_ip": PINNED_IP,
        "endpoint": endpoint,
    }
    flow_relative = "evidence/remus-flow.json"
    flow = {
        "schema_version": 1,
        "artifact_type": evidence.FLOW_ARTIFACT_TYPE,
        "sample": {"sha256": PARENT_SHA256},
        "run": {"id": "profile-test-run"},
        "artifacts": {
            "process_dump": {"sha256": DUMP_SHA256},
            "recovered_pe": {"sha256": RECOVERED_SHA256},
        },
        "flow": {
            "tag": TAG,
            "exp": 1_785_860_014,
            "http_host": "microsoft.com",
            "pinned_ip": PINNED_IP,
            "endpoint": endpoint,
        },
    }
    flow_raw = (json.dumps(flow, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    flow_path = tmp_path / Path(*flow_relative.split("/"))
    flow_path.parent.mkdir(parents=True, exist_ok=True)
    flow_path.write_bytes(flow_raw)
    flow_sha256 = hashlib.sha256(flow_raw).hexdigest()
    flow_fields = {"tag", "exp", "http_host", "pinned_ip", "endpoint"}
    manifest = {
        "schema_version": 1,
        "manifest_type": evidence.MANIFEST_TYPE,
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
    review_id = "profile-test-review"
    registry = {
        "schema_version": 1,
        "registry_type": evidence.REVIEW_REGISTRY_TYPE,
        "reviews": [
            {
                "review_id": review_id,
                "status": "approved",
                "manifest_source": relative.as_posix(),
                "manifest_sha256": manifest_sha256,
                "flow_artifact_source": flow_relative,
                "flow_artifact_sha256": flow_sha256,
                "flow_artifact_pointers": evidence.FLOW_ARTIFACT_POINTERS,
                "sample_sha256": PARENT_SHA256,
                "run_id": "profile-test-run",
                "dump_sha256": DUMP_SHA256,
                "recovered_pe_sha256": RECOVERED_SHA256,
            }
        ],
    }
    registry_path = tmp_path / Path(*evidence.REVIEW_REGISTRY_SOURCE.split("/"))
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        json.dumps(registry, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return build_evidence_binding(relative.as_posix(), manifest_sha256, review_id)


def build_ready(tmp_path: Path, *, tag_status: str = "reviewed"):
    return build(
        tag_candidate={"status": tag_status, "value": TAG},
        evidence_binding=write_evidence_manifest(tmp_path),
        repository_root=tmp_path,
    )


def test_exp_missing_blocks_only_active_profile() -> None:
    report = build(exp=None)
    assert report["status"] == "blocked"
    generation = report["active_profile_generation"]
    assert generation["profile"] is None
    assert [reason["code"] for reason in generation["blocked_reasons"]] == [
        "exp_missing",
        "evidence_manifest_missing",
    ]
    passive = report["passive_profile"]
    assert passive["endpoints"][0]["role"] == "selected"
    assert [phase["phase"] for phase in passive["protocol_sequence"]] == [
        "registration",
        "registration_response",
        "task_poll",
        "task_response",
    ]
    assert passive["protocol_sequence"][0]["form_fields"] == ["tag", "exp", "hwid"]
    assert passive["protocol_sequence"][2]["required_values"] == {"step": "1"}
    assert passive["response_envelope"]["key_length_bytes"] == 32
    assert passive["response_envelope"]["nonce_length_bytes"] == 8


def test_source_reference_is_passive_and_evidence_manifest_remains_required() -> None:
    report = build(source_reference=None)
    assert report["passive_profile"]["protocol"] == "remusstealer"
    assert report["active_profile_generation"]["profile"] is None
    assert [reason["code"] for reason in report["active_profile_generation"]["blocked_reasons"]] == [
        "evidence_manifest_missing"
    ]


def test_complete_profile_is_applied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    report = build_ready(tmp_path)
    assert report["status"] == "ready"
    profile = report["active_profile_generation"]["profile"]
    assert profile["handler"] == "remus_registration_task"
    assert profile["host"] == "onesdto.shop"
    assert profile["port"] == 2535
    assert profile["pinned_ips"] == [PINNED_IP]
    assert profile["tag"] == TAG
    assert profile["exp"] == 1_785_860_014
    assert profile["http_host"] == "microsoft.com"
    assert profile["sample_sha256s"] == [PARENT_SHA256]
    assert profile["recovered_pe_sha256"] == RECOVERED_SHA256
    assert profile["source"] == "evidence/remus.json:/fields/endpoint/value"
    registry = tmp_path / "profiles.json"
    registry.write_text(
        json.dumps({"schema_version": 1, "profiles": [profile]}),
        encoding="utf-8",
    )
    monkeypatch.setattr(profile_registry, "DEFAULT_PROFILE_PATH", registry)
    targets, added = profile_registry.apply_profiles([], repository_root=tmp_path)
    assert added == 1
    assert targets[0]["protocol_profile_id"] == profile["profile_id"]
    assert targets[0]["host"] == "onesdto.shop"
    assert targets[0]["sources"] == [profile["source"]]
    assert targets[0]["protocol_profile_evidence_source"] == "evidence/remus.json"
    assert targets[0]["protocol_profile_evidence_sha256"] == profile["evidence_sha256"]


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"endpoints": [{"slot_index": 1, "uri": "ftp://bad.example:21"}]}, "rootのhttp"),
        ({"endpoints": [{"slot_index": 1, "uri": "http://user@bad.example:80"}]}, "rootのhttp"),
        ({"tag_candidate": "not-a-tag"}, "32桁hex"),
        ({"exp": "1785860014"}, "integer"),
        ({"exp": 42}, "範囲外"),
        ({"reviewed_http_host": "microsoft.com\r\nX-Test: yes"}, "印字可能ASCII"),
        ({"parent_sha256": "abc"}, "64桁hex"),
        ({"selected_index": True}, "0..255"),
        ({"source_reference": "C:/private/evidence.json:profile"}, "repo相対"),
        ({"source_reference": "/absolute/evidence.json:profile"}, "repo相対"),
        ({"source_reference": "analysis-results/../secret.json:profile"}, "backslash、.."),
        ({"source_reference": "analysis-results\\case.json:profile"}, "backslash、.."),
        ({"source_reference": "analysis-results/case.json:bad\u0001value"}, "backslash、.."),
    ],
)
def test_malformed_inputs_are_rejected(overrides: dict, message: str) -> None:
    with pytest.raises(RemusC2ProfileError, match=message):
        build(**overrides)


@pytest.mark.parametrize("status", ["recovered", "confirmed"])
def test_reviewed_tag_status_can_enable_active_profile(status: str, tmp_path: Path) -> None:
    report = build_ready(tmp_path, tag_status=status)
    assert report["status"] == "ready"
    assert report["evidence"]["tag_status"] == status
    assert report["active_profile_generation"]["profile"]["tag"] == TAG


def test_runtime_uuid_and_chacha_values_are_never_reflected() -> None:
    runtime_uuid = "fd44eb3c-b2d9-4cfc-9599-eb8a6ed4a911"
    chacha_key = "9ec1f0e917bdd04bae1c6c3db4d7d541929e1e1419cf3d4fd68ba2e966bedd24"
    nonce = "33a8c4d48b001d4c"
    payload = {
        "endpoints": [
            {
                **endpoints()[0],
                "runtime_uuid": runtime_uuid,
                "chacha_key": chacha_key,
                "nonce": nonce,
            }
        ],
        "selected_index": 1,
        "tag_candidate": {
            "status": "candidate",
            "value": TAG,
            "runtime_uuid": runtime_uuid,
            "key": chacha_key,
            "nonce": nonce,
        },
        "exp": 1_785_860_014,
        "reviewed_http_host": "microsoft.com",
        "parent_sha256": PARENT_SHA256,
        "dump_sha256": DUMP_SHA256,
        "recovered_pe_sha256": RECOVERED_SHA256,
        "runtime_uuid": runtime_uuid,
        "source_reference": SOURCE_REFERENCE,
        "chacha_key": chacha_key,
        "chacha_nonce": nonce,
    }
    report = build_remus_c2_profile_from_payload(payload)
    rendered = json.dumps(report)
    assert runtime_uuid not in rendered
    assert chacha_key not in rendered
    assert nonce not in rendered
    assert report["status"] == "blocked"
    assert report["passive_profile"]["tag_candidate"] == TAG
    assert report["passive_profile"]["tag_candidate_status"] == "candidate"
    assert report["active_profile_generation"]["profile"] is None
    assert [item["code"] for item in report["active_profile_generation"]["blocked_reasons"]] == [
        "tag_unreviewed",
        "evidence_manifest_missing",
    ]


def test_cli_writes_json_exclusively(tmp_path: Path, capsys) -> None:
    source = tmp_path / "input.json"
    destination = tmp_path / "output.json"
    source.write_text(
        json.dumps(
            {
                "endpoints": endpoints(),
                "selected_index": 1,
                "tag_candidate": TAG,
                "exp": None,
                "reviewed_http_host": "microsoft.com",
                "parent_sha256": PARENT_SHA256,
                "dump_sha256": DUMP_SHA256,
                "recovered_pe_sha256": RECOVERED_SHA256,
                "source_reference": SOURCE_REFERENCE,
            }
        ),
        encoding="utf-8",
    )
    assert main(["--input", str(source), "--output", str(destination)]) == 0
    assert json.loads(destination.read_text(encoding="utf-8"))["status"] == "blocked"
    capsys.readouterr()
    assert main(["--input", str(source), "--output", str(destination)]) == 2
    captured = capsys.readouterr()
    assert "上書きしません" in captured.err


@pytest.mark.parametrize(
    "raw",
    [
        b'{"value": 1, "value": 2}',
        b'{"value": NaN}',
        b'{"value": Infinity}',
    ],
)
def test_profile_input_reader_rejects_noncanonical_json(
    tmp_path: Path,
    raw: bytes,
) -> None:
    source = tmp_path / "input.json"
    source.write_bytes(raw)
    with pytest.raises(RemusC2ProfileError):
        remus_profile._read_payload(source, 1024)


def test_profile_input_reader_rejects_empty_oversize_and_boolean_limit(
    tmp_path: Path,
) -> None:
    source = tmp_path / "input.json"
    source.write_bytes(b"")
    with pytest.raises(RemusC2ProfileError):
        remus_profile._read_payload(source, 1024)

    source.write_bytes(b'{"value": 1}')
    with pytest.raises(RemusC2ProfileError):
        remus_profile._read_payload(source, 4)
    with pytest.raises(RemusC2ProfileError):
        remus_profile._read_payload(source, True)


def test_profile_input_reader_rejects_hardlink_and_reparse(
    tmp_path: Path,
) -> None:
    source = tmp_path / "input.json"
    source.write_text('{"value": 1}', encoding="utf-8")
    hardlink = tmp_path / "hardlink.json"
    try:
        os.link(source, hardlink)
    except OSError as exc:
        pytest.skip(f"hardlink unavailable: {exc}")
    with pytest.raises(RemusC2ProfileError):
        remus_profile._read_payload(source, 1024)

    source.unlink()
    hardlink.unlink()
    target = tmp_path / "target.json"
    target.write_text('{"value": 1}', encoding="utf-8")
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symbolic link unavailable: {exc}")
    with pytest.raises((RemusC2ProfileError, ValueError)):
        remus_profile._read_payload(link, 1024)


def test_profile_input_reader_detects_toctou_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "input.json"
    source.write_text('{"value": 1}', encoding="utf-8")
    source_key = str(source.resolve()).casefold()
    original = remus_profile.reject_existing_reparse_components
    calls = 0

    def mutate_after_read(candidate: Path) -> None:
        nonlocal calls
        original(candidate)
        if str(Path(candidate).resolve()).casefold() == source_key:
            calls += 1
            if calls == 2:
                with source.open("ab") as stream:
                    stream.write(b" ")

    monkeypatch.setattr(
        remus_profile,
        "reject_existing_reparse_components",
        mutate_after_read,
    )
    with pytest.raises(RemusC2ProfileError):
        remus_profile._read_payload(source, 1024)
