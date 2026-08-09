"""Remus active profileのfield-level証拠結合と再検証の回帰test。"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from copy import deepcopy
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import analysis_contract
import c2_protocol_probe_profiles as registry
import monitor_recent_c2 as monitor
import remus_profile_evidence as evidence
import stealer_registration_probe as registration_probe
from remus_c2_profile import build_remus_c2_profile

PARENT = "1" * 64
DUMP = "2" * 64
RECOVERED = "3" * 64
FLOW = "4" * 64
TAG = "a" * 32
PIN = "154.12.237.176"
EXP = 1_785_860_014
ENDPOINT = {
    "slot_index": 1,
    "uri": "http://c2.example:80",
    "scheme": "http",
    "host": "c2.example",
    "port": 80,
}

TRUST_PINS: dict[str, dict[str, str]] = {}


def manifest_payload() -> dict:
    values = {
        "parent_sha256": PARENT,
        "dump_sha256": DUMP,
        "recovered_pe_sha256": RECOVERED,
        "tag": TAG,
        "exp": EXP,
        "http_host": "microsoft.com",
        "pinned_ip": PIN,
        "endpoint": deepcopy(ENDPOINT),
    }
    return {
        "schema_version": 1,
        "manifest_type": evidence.MANIFEST_TYPE,
        "family": "remusstealer",
        "review": {
            "status": "reviewed",
            "same_sample_verified": True,
            "same_flow_verified": True,
            "flow_evidence_sha256": FLOW,
        },
        "fields": {
            name: {
                "value": value,
                "sample_sha256": PARENT,
                "flow_evidence_sha256": (FLOW if name in evidence.FLOW_FIELD_NAMES else None),
            }
            for name, value in values.items()
        },
    }


def write_manifest(
    root: Path,
    payload: dict | None = None,
    *,
    relative: str = "evidence/remus.json",
    raw: bytes | None = None,
) -> tuple[Path, dict]:
    flow_relative = "evidence/remus-flow.json"
    flow_payload = {
        "schema_version": 1,
        "artifact_type": evidence.FLOW_ARTIFACT_TYPE,
        "sample": {"sha256": PARENT},
        "run": {"id": "test-run-1"},
        "artifacts": {
            "process_dump": {"sha256": DUMP},
            "recovered_pe": {"sha256": RECOVERED},
        },
        "flow": {
            "tag": TAG,
            "exp": EXP,
            "http_host": "microsoft.com",
            "pinned_ip": PIN,
            "endpoint": deepcopy(ENDPOINT),
        },
    }
    flow_body = (json.dumps(flow_payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    flow_path = root / Path(*flow_relative.split("/"))
    flow_path.parent.mkdir(parents=True, exist_ok=True)
    flow_path.write_bytes(flow_body)
    flow_sha256 = hashlib.sha256(flow_body).hexdigest()

    path = root / Path(*relative.split("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    body = raw
    if body is None:
        selected = deepcopy(payload or manifest_payload())
        if selected["review"]["flow_evidence_sha256"] == FLOW:
            selected["review"]["flow_evidence_sha256"] = flow_sha256
        for record in selected["fields"].values():
            if record["flow_evidence_sha256"] == FLOW:
                record["flow_evidence_sha256"] = flow_sha256
        body = (json.dumps(selected, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    path.write_bytes(body)
    manifest_sha256 = hashlib.sha256(body).hexdigest()
    review_id = "test-review"
    binding = evidence.build_evidence_binding(relative, manifest_sha256, review_id)

    registry_payload = {
        "schema_version": 1,
        "registry_type": evidence.REVIEW_REGISTRY_TYPE,
        "reviews": [
            {
                "review_id": review_id,
                "status": "approved",
                "manifest_source": relative,
                "manifest_sha256": manifest_sha256,
                "flow_artifact_source": flow_relative,
                "flow_artifact_sha256": flow_sha256,
                "flow_artifact_pointers": evidence.FLOW_ARTIFACT_POINTERS,
                "sample_sha256": PARENT,
                "run_id": "test-run-1",
                "dump_sha256": DUMP,
                "recovered_pe_sha256": RECOVERED,
            }
        ],
    }
    registry_body = (json.dumps(registry_payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
    registry_path = root / Path(*evidence.REVIEW_REGISTRY_SOURCE.split("/"))
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_bytes(registry_body)
    TRUST_PINS[manifest_sha256] = {
        "review_id": review_id,
        "review_registry_source": evidence.REVIEW_REGISTRY_SOURCE,
        "review_registry_sha256": hashlib.sha256(registry_body).hexdigest(),
        "flow_artifact_source": flow_relative,
        "flow_artifact_sha256": flow_sha256,
        "run_id": "test-run-1",
    }
    return path, binding


def active_profile(binding: dict) -> dict:
    return {
        "profile_id": "remus-evidence-test",
        "family": "remusstealer",
        "sample_sha256s": [PARENT],
        "host": ENDPOINT["host"],
        "port": ENDPOINT["port"],
        "selected_slot_index": ENDPOINT["slot_index"],
        "protocol": "remusstealer",
        "method": "remus_registration_task",
        "handler": "remus_registration_task",
        "http_path": "/",
        "http_host": "microsoft.com",
        "pinned_ips": [PIN],
        "tag": TAG,
        "exp": EXP,
        "request_budget": 2,
        "timeout_seconds": 3.0,
        "maximum_request_bytes": 4096,
        "maximum_response_bytes": 8192,
        "role": "test",
        "source": f"{binding['source']}:{evidence.EVIDENCE_POINTERS['endpoint']}",
        "dump_sha256": DUMP,
        "recovered_pe_sha256": RECOVERED,
        "evidence_binding": deepcopy(binding),
        "evidence_source": binding["source"],
        "evidence_sha256": binding["sha256"],
        **TRUST_PINS.get(
            binding["sha256"],
            {
                "review_id": binding["review_id"],
                "review_registry_source": evidence.REVIEW_REGISTRY_SOURCE,
                "review_registry_sha256": "0" * 64,
                "flow_artifact_source": "evidence/missing-flow.json",
                "flow_artifact_sha256": "0" * 64,
                "run_id": "unregistered",
            },
        ),
    }


def test_valid_manifest_is_bound_and_registry_application_revalidates(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, binding = write_manifest(tmp_path)
    profile = active_profile(binding)
    result = evidence.validate_remus_profile_evidence(
        profile, repository_root=tmp_path, expected_sha256=binding["sha256"]
    )
    assert result["parent_sha256"] == PARENT
    assert result["dump_sha256"] == DUMP
    assert result["recovered_pe_sha256"] == RECOVERED
    assert result["endpoint"] == "c2.example:80"

    profile_path = tmp_path / "profiles.json"
    profile_path.write_text(json.dumps({"schema_version": 1, "profiles": [profile]}), encoding="utf-8")
    monkeypatch.setattr(registry, "DEFAULT_PROFILE_PATH", profile_path)
    targets, added = registry.apply_profiles([], repository_root=tmp_path)
    assert added == 1
    assert targets[0]["protocol_profile_evidence_sha256"] == binding["sha256"]
    assert targets[0]["protocol_profile_evidence_source"] == binding["source"]


def test_nonexistent_empty_and_oversize_manifest_are_rejected(tmp_path: Path) -> None:
    missing_binding = evidence.build_evidence_binding("evidence/missing.json", "0" * 64)
    with pytest.raises(evidence.RemusEvidenceError):
        evidence.validate_remus_profile_evidence(active_profile(missing_binding), repository_root=tmp_path)

    _, empty_binding = write_manifest(tmp_path, raw=b"", relative="evidence/empty.json")
    with pytest.raises(evidence.RemusEvidenceError, match="空file"):
        evidence.validate_remus_profile_evidence(active_profile(empty_binding), repository_root=tmp_path)

    _, large_binding = write_manifest(
        tmp_path,
        raw=b"{" + b" " * evidence.MAXIMUM_EVIDENCE_BYTES + b"}",
        relative="evidence/large.json",
    )
    with pytest.raises(evidence.RemusEvidenceError, match="65536 byte"):
        evidence.validate_remus_profile_evidence(active_profile(large_binding), repository_root=tmp_path)


@pytest.mark.parametrize("source", ["../outside.json", "/absolute.json", "C:/abs.json"])
def test_absolute_and_traversal_sources_are_rejected(source: str) -> None:
    with pytest.raises(evidence.RemusEvidenceError):
        evidence.build_evidence_binding(source, "0" * 64)


def test_self_reference_and_circular_manifest_are_rejected(tmp_path: Path) -> None:
    path, binding = write_manifest(tmp_path)
    with pytest.raises(evidence.RemusEvidenceError, match="自身"):
        evidence.validate_remus_profile_evidence(
            active_profile(binding),
            repository_root=tmp_path,
            forbidden_paths=(path,),
        )

    circular = manifest_payload()
    circular["evidence_binding"] = {
        "source": "evidence/circular.json",
        "pointer": "/evidence_binding",
    }
    _, circular_binding = write_manifest(tmp_path, circular, relative="evidence/circular.json")
    with pytest.raises(evidence.RemusEvidenceError, match="canonical schema"):
        evidence.validate_remus_profile_evidence(active_profile(circular_binding), repository_root=tmp_path)


def test_pointer_mismatch_is_rejected_before_manifest_use(tmp_path: Path) -> None:
    _, binding = write_manifest(tmp_path)
    changed = deepcopy(binding)
    changed["pointers"]["tag"] = "/fields/exp/value"
    profile = active_profile(changed)
    with pytest.raises(evidence.RemusEvidenceError, match="pointer集合"):
        evidence.validate_remus_profile_evidence(profile, repository_root=tmp_path)


@pytest.mark.parametrize(
    ("field", "replacement"),
    [
        ("parent_sha256", "9" * 64),
        ("recovered_pe_sha256", "8" * 64),
        ("tag", "b" * 32),
        ("endpoint", {**ENDPOINT, "port": 81, "uri": "http://c2.example:81"}),
    ],
)
def test_field_value_swaps_are_rejected(tmp_path: Path, field: str, replacement: object) -> None:
    payload = manifest_payload()
    payload["fields"][field]["value"] = replacement
    _, binding = write_manifest(tmp_path, payload)
    with pytest.raises(evidence.RemusEvidenceError, match="profile値"):
        evidence.validate_remus_profile_evidence(active_profile(binding), repository_root=tmp_path)


def test_config_profile_tag_mismatch_is_blocked(tmp_path: Path) -> None:
    payload = manifest_payload()
    payload["fields"]["tag"]["value"] = "b" * 32
    _, binding = write_manifest(tmp_path, payload)
    report = build_remus_c2_profile(
        endpoints=[{**ENDPOINT, "pinned_ips": [PIN]}],
        selected_index=1,
        tag_candidate={"status": "reviewed", "value": TAG},
        exp=EXP,
        reviewed_http_host="microsoft.com",
        parent_sha256=PARENT,
        dump_sha256=DUMP,
        recovered_pe_sha256=RECOVERED,
        source_reference=None,
        evidence_binding=binding,
        repository_root=tmp_path,
    )
    assert report["status"] == "blocked"
    assert report["active_profile_generation"]["profile"] is None
    assert {item["code"] for item in report["active_profile_generation"]["blocked_reasons"]} == {
        "evidence_manifest_validation_failed"
    }


def test_cross_sample_tag_exp_and_unrelated_endpoint_pin_are_rejected(
    tmp_path: Path,
) -> None:
    cross_sample = manifest_payload()
    cross_sample["fields"]["exp"]["sample_sha256"] = "5" * 64
    _, binding = write_manifest(tmp_path, cross_sample)
    with pytest.raises(evidence.RemusEvidenceError, match="別sample"):
        evidence.validate_remus_profile_evidence(active_profile(binding), repository_root=tmp_path)

    unrelated_pin = manifest_payload()
    unrelated_pin["fields"]["pinned_ip"]["flow_evidence_sha256"] = "6" * 64
    _, binding = write_manifest(tmp_path, unrelated_pin)
    with pytest.raises(evidence.RemusEvidenceError, match="別flow"):
        evidence.validate_remus_profile_evidence(active_profile(binding), repository_root=tmp_path)


def test_hardlink_and_reparse_manifest_are_rejected(tmp_path: Path) -> None:
    path, binding = write_manifest(tmp_path)
    alias = tmp_path / "evidence" / "alias.json"
    try:
        os.link(path, alias)
    except OSError as exc:
        pytest.skip(f"hardlinkを作成できません: {exc}")
    with pytest.raises(evidence.RemusEvidenceError, match="単一link"):
        evidence.validate_remus_profile_evidence(active_profile(binding), repository_root=tmp_path)


def test_reparse_manifest_is_rejected_when_supported(tmp_path: Path) -> None:
    target, _ = write_manifest(tmp_path, relative="evidence/target.json")
    link = tmp_path / "evidence" / "linked.json"
    try:
        link.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symbolic linkを作成できません: {exc}")
    raw = target.read_bytes()
    binding = evidence.build_evidence_binding("evidence/linked.json", hashlib.sha256(raw).hexdigest())
    with pytest.raises(evidence.RemusEvidenceError):
        evidence.validate_remus_profile_evidence(active_profile(binding), repository_root=tmp_path)


def test_growth_and_path_swap_are_detected_post_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    path, binding = write_manifest(tmp_path)
    original = evidence.reject_existing_reparse_components
    target_key = evidence._path_key(path)
    calls = 0

    def grow_after_read(candidate: Path) -> None:
        nonlocal calls
        original(candidate)
        if evidence._path_key(candidate) == target_key:
            calls += 1
            if calls == 2:
                with path.open("ab") as stream:
                    stream.write(b" ")

    monkeypatch.setattr(evidence, "reject_existing_reparse_components", grow_after_read)
    with pytest.raises(evidence.RemusEvidenceError, match="置換"):
        evidence.validate_remus_profile_evidence(active_profile(binding), repository_root=tmp_path)

    monkeypatch.setattr(evidence, "reject_existing_reparse_components", original)
    path, binding = write_manifest(tmp_path)
    replacement = tmp_path / "evidence" / "replacement.json"
    replacement.write_bytes(path.read_bytes())
    calls = 0

    def swap_after_read(candidate: Path) -> None:
        nonlocal calls
        original(candidate)
        if evidence._path_key(candidate) == target_key:
            calls += 1
            if calls == 2:
                os.replace(replacement, path)

    monkeypatch.setattr(evidence, "reject_existing_reparse_components", swap_after_read)
    with pytest.raises(evidence.RemusEvidenceError, match="置換"):
        evidence.validate_remus_profile_evidence(active_profile(binding), repository_root=tmp_path)


def test_manifest_mutation_is_blocked_at_plan_and_immediately_before_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, binding = write_manifest(tmp_path)
    profile = active_profile(binding)
    profile_path = tmp_path / "profiles.json"
    profile_path.write_text(json.dumps({"schema_version": 1, "profiles": [profile]}), encoding="utf-8")
    monkeypatch.setattr(registry, "DEFAULT_PROFILE_PATH", profile_path)
    profile_pin = registry.profile_registry_metadata()
    remus_pin = registry.remus_review_registry_metadata(repository_root=tmp_path)
    targets, _ = registry.apply_profiles(
        [],
        repository_root=tmp_path,
        expected_profile_registry_sha256=profile_pin["sha256"],
        expected_remus_review_registry_sha256=remus_pin["sha256"],
    )
    plan = {
        "schema_version": 1,
        "protocol_profile_registry": profile_pin,
        "remus_review_registry": remus_pin,
        "analysis_window": {"start": "2026-08-09", "end": "2026-08-09"},
        "targets": targets,
    }
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(monitor.PlanError, match="Remus profile証拠"):
        monitor.validate_plan(plan, repository_root=tmp_path)

    calls: list[object] = []

    def no_send(*args: object, **kwargs: object) -> None:
        calls.append((args, kwargs))
        raise AssertionError("evidence不一致時はapplication dataを送信しない")

    with pytest.raises(registration_probe.StealerProbeError):
        registration_probe.probe_reviewed_stealer_registration(
            profile,
            allow_network=True,
            allow_registration_tasking=True,
            post=no_send,
            repository_root=tmp_path,
            expected_evidence_sha256=binding["sha256"],
            expected_evidence_source=binding["source"],
            expected_profile_registry_source=profile_pin["source"],
            expected_profile_registry_sha256=profile_pin["sha256"],
            expected_registry_source=profile["review_registry_source"],
            expected_registry_sha256=profile["review_registry_sha256"],
            expected_flow_artifact_source=profile["flow_artifact_source"],
            expected_flow_artifact_sha256=profile["flow_artifact_sha256"],
            expected_review_id=profile["review_id"],
        )
    assert calls == []


def test_fake_values_and_missing_manifest_never_make_builder_ready(tmp_path: Path) -> None:
    fake_binding = evidence.build_evidence_binding("evidence/missing.json", "0" * 64)
    report = build_remus_c2_profile(
        endpoints=[{**ENDPOINT, "pinned_ips": [PIN]}],
        selected_index=1,
        tag_candidate={"status": "reviewed", "value": TAG},
        exp=EXP,
        reviewed_http_host="microsoft.com",
        parent_sha256=PARENT,
        dump_sha256=DUMP,
        recovered_pe_sha256=RECOVERED,
        source_reference=None,
        evidence_binding=fake_binding,
        repository_root=tmp_path,
    )
    assert report["status"] == "blocked"
    assert report["active_profile_generation"]["profile"] is None
    assert [item["code"] for item in report["active_profile_generation"]["blocked_reasons"]] == [
        "evidence_review_registry_validation_failed"
    ]


def test_case_config_and_profile_tag_status_are_consistent() -> None:
    repository = Path(__file__).resolve().parents[2]
    case = (
        repository
        / "analysis-results/malware/remusstealer/versions/unknown/cases"
        / "843eec789f90f15c13e6905f36f54c32a0dbf767d9715aef1387d232aa11ab93"
    )
    config = json.loads((case / "remus-memory-config.json").read_text(encoding="utf-8"))
    profile = json.loads((case / "remus-c2-profile.json").read_text(encoding="utf-8"))
    assert config["config"]["tag"]["status"] == "candidate"
    assert profile["evidence"]["tag_status"] == "candidate"
    assert profile["passive_profile"]["tag_candidate_status"] == "candidate"
    assert "tag_unreviewed" in {item["code"] for item in profile["active_profile_generation"]["blocked_reasons"]}
    expected_blockers = [
        "tag_unreviewed",
        "exp_missing",
        "reviewed_http_host_missing",
        "evidence_manifest_missing",
        "selected_endpoint_pinned_ip_missing",
    ]
    report = json.loads((case / "report.json").read_text(encoding="utf-8"))
    assert [item["code"] for item in profile["active_profile_generation"]["blocked_reasons"]] == expected_blockers
    assert report["manual_deep_analysis"]["active_c2_profile_blockers"] == expected_blockers
    assert len(report["case_state"]["blockers"]) == 5
    assert (
        analysis_contract.verify_artifact_hashes(
            case,
            report["artifact_sha256"],
        )
        == []
    )
    assert analysis_contract.verify_report_semantics(report) == []


def test_fabricated_self_manifest_is_rejected_without_registry_allowlist(
    tmp_path: Path,
) -> None:
    _, binding = write_manifest(tmp_path)
    registry_path = tmp_path / Path(*evidence.REVIEW_REGISTRY_SOURCE.split("/"))
    registry_path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "registry_type": evidence.REVIEW_REGISTRY_TYPE,
                "reviews": [],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(evidence.RemusEvidenceError, match="not allowlisted"):
        evidence.validate_remus_profile_evidence(
            active_profile(binding),
            repository_root=tmp_path,
        )


def test_flow_artifact_swap_is_rejected(
    tmp_path: Path,
) -> None:
    _, binding = write_manifest(tmp_path)
    profile = active_profile(binding)
    flow_path = tmp_path / Path(*profile["flow_artifact_source"].split("/"))
    flow_path.write_bytes(flow_path.read_bytes() + b" ")

    with pytest.raises(evidence.RemusEvidenceError, match="SHA-256"):
        evidence.validate_remus_profile_evidence(
            profile,
            repository_root=tmp_path,
        )


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"schema_version":1,"registry_type":"remus_active_profile_review_registry","reviews":[]}',
        b'{"schema_version":NaN,"registry_type":"remus_active_profile_review_registry","reviews":[]}',
        b'{"schema_version":Infinity,"registry_type":"remus_active_profile_review_registry","reviews":[]}',
    ],
)
def test_review_registry_reader_rejects_noncanonical_json(
    tmp_path: Path,
    raw: bytes,
) -> None:
    registry_path = tmp_path / Path(*evidence.REVIEW_REGISTRY_SOURCE.split("/"))
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_bytes(raw)

    with pytest.raises(evidence.RemusEvidenceError):
        evidence.load_remus_review_registry(repository_root=tmp_path)


def test_review_registry_reader_rejects_oversize(
    tmp_path: Path,
) -> None:
    registry_path = tmp_path / Path(*evidence.REVIEW_REGISTRY_SOURCE.split("/"))
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_bytes(b"{" + b" " * evidence.MAXIMUM_REVIEW_REGISTRY_BYTES + b"}")

    with pytest.raises(evidence.RemusEvidenceError):
        evidence.load_remus_review_registry(repository_root=tmp_path)


def test_review_registry_reader_rejects_hardlink_and_reparse(
    tmp_path: Path,
) -> None:
    registry_path = tmp_path / Path(*evidence.REVIEW_REGISTRY_SOURCE.split("/"))
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        '{"schema_version":1,"registry_type":"remus_active_profile_review_registry","reviews":[]}',
        encoding="utf-8",
    )
    hardlink = registry_path.with_name("review-registry-hardlink.json")
    try:
        os.link(registry_path, hardlink)
    except OSError as exc:
        pytest.skip(f"hardlink unavailable: {exc}")
    with pytest.raises(evidence.RemusEvidenceError):
        evidence.load_remus_review_registry(repository_root=tmp_path)

    registry_path.unlink()
    hardlink.unlink()
    target = registry_path.with_name("review-registry-target.json")
    target.write_text(
        '{"schema_version":1,"registry_type":"remus_active_profile_review_registry","reviews":[]}',
        encoding="utf-8",
    )
    try:
        registry_path.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symbolic link unavailable: {exc}")
    with pytest.raises(evidence.RemusEvidenceError):
        evidence.load_remus_review_registry(repository_root=tmp_path)


def test_review_registry_reader_detects_toctou_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry_path = tmp_path / Path(*evidence.REVIEW_REGISTRY_SOURCE.split("/"))
    registry_path.parent.mkdir(parents=True, exist_ok=True)
    registry_path.write_text(
        '{"schema_version":1,"registry_type":"remus_active_profile_review_registry","reviews":[]}',
        encoding="utf-8",
    )
    target_key = evidence._path_key(registry_path)
    original = evidence.reject_existing_reparse_components
    calls = 0

    def mutate_after_read(candidate: Path) -> None:
        nonlocal calls
        original(candidate)
        if evidence._path_key(candidate) == target_key:
            calls += 1
            if calls == 2:
                with registry_path.open("ab") as stream:
                    stream.write(b" ")

    monkeypatch.setattr(
        evidence,
        "reject_existing_reparse_components",
        mutate_after_read,
    )
    with pytest.raises(evidence.RemusEvidenceError):
        evidence.load_remus_review_registry(repository_root=tmp_path)


def test_review_registry_digest_is_crlf_lf_invariant(
    tmp_path: Path,
) -> None:
    raw = b'{\n  "schema_version": 1,\n  "registry_type": "remus_active_profile_review_registry",\n  "reviews": []\n}\n'
    digests = []
    for name, body in (
        ("lf", raw),
        ("crlf", raw.replace(b"\n", b"\r\n")),
    ):
        root = tmp_path / name
        path = root / Path(*evidence.REVIEW_REGISTRY_SOURCE.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        digests.append(evidence.load_remus_review_registry(repository_root=root)["sha256"])

    assert digests[0] == digests[1]
    assert digests[0] == evidence.canonical_lf_json_sha256(raw)


def test_manifest_flow_and_registry_pins_are_crlf_lf_invariant(
    tmp_path: Path,
) -> None:
    lf_root = tmp_path / "lf"
    _, binding = write_manifest(lf_root)
    profile = active_profile(binding)
    crlf_root = tmp_path / "crlf"
    relative_sources = (
        binding["source"],
        profile["flow_artifact_source"],
        evidence.REVIEW_REGISTRY_SOURCE,
    )
    for relative in relative_sources:
        source = lf_root / Path(*relative.split("/"))
        destination = crlf_root / Path(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(source.read_bytes().replace(b"\n", b"\r\n"))

    result = evidence.validate_remus_profile_evidence(
        profile,
        repository_root=crlf_root,
        expected_sha256=binding["sha256"],
        expected_registry_sha256=profile["review_registry_sha256"],
        expected_flow_artifact_sha256=profile["flow_artifact_sha256"],
    )

    assert result["sha256"] == binding["sha256"]
    assert result["review_registry_sha256"] == profile["review_registry_sha256"]
    assert result["flow_artifact_sha256"] == profile["flow_artifact_sha256"]
