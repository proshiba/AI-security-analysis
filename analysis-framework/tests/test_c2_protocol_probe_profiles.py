from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

import c2_protocol_probe_profiles as profile_module
import remus_profile_evidence as evidence
from build_all_c2_monitoring_targets import build_inventory
from c2_protocol_probe_profiles import (
    ProtocolProfileError,
    apply_profiles,
    load_profiles,
    profile_registry_metadata,
    remus_review_registry_metadata,
    resolve_profile,
)


def test_registry_contains_reviewed_protocols() -> None:
    profiles = load_profiles()
    assert len(profiles) == 16
    assert {profile["method"] for profile in profiles.values()} == {
        "winos_heartbeat",
        "vvas_checkin",
        "n520_server_first",
        "ftp_authenticated",
        "asyncrat_tls_messagepack",
        "venomrat_tls_messagepack",
        "stealc_v2_registration_task",
        "lumma_v6_registration_task",
        "remus_registration_task",
        "darkcomet_server_first_idtype",
        "redline_checkconnect_soap11",
    }


def test_profile_requires_exact_host_and_port() -> None:
    with pytest.raises(ProtocolProfileError):
        resolve_profile(
            "valleyrat-winos-heartbeat-20260727",
            "other.example",
            6685,
        )
    with pytest.raises(ProtocolProfileError):
        resolve_profile(
            "valleyrat-winos-heartbeat-20260727",
            "haochisadnka.cc",
            6698,
        )


def test_builder_adds_only_profiles_with_existing_repository_evidence(
    tmp_path: Path,
) -> None:
    results_root = tmp_path / "analysis-results"
    profile = load_profiles()["valleyrat-vvas-8bf54-6666"]
    evidence = tmp_path / profile["source"].split(":", 1)[0]
    evidence.parent.mkdir(parents=True)
    evidence.write_text("{}", encoding="utf-8")

    plan, inventory = build_inventory(results_root, generated_date="2026-08-02")
    assert [(item["host"], item["port"], item["method"]) for item in plan["targets"]] == [
        ("202.95.8.27", 6666, "vvas_checkin"),
        ("202.95.8.27", 8888, "vvas_checkin"),
    ]
    assert inventory["reviewed_protocol_target_count"] == 2
    assert inventory["reviewed_profile_only_target_count"] == 2


def test_asyncrat_and_venomrat_profiles_keep_distinct_packet_fields() -> None:
    profiles = load_profiles()
    asyncrat = profiles["asyncrat-058-20f21565-191-96-78-221-7788"]
    venomrat = profiles["venomrat-603-6a24ba25-localto-6377"]
    assert asyncrat["packet_key"] == "Packet"
    assert asyncrat["expected_response_packets"] == ["pong"]
    assert venomrat["packet_key"] == "Pac_ket"
    assert venomrat["expected_response_packets"] == ["Po_ng"]
    assert len(asyncrat["expected_certificate_sha256"]) == 64
    assert len(venomrat["expected_certificate_sha256"]) == 64
    agenttesla = profiles["agenttesla-ftp-auth-3f091457-vilimorin"]
    assert agenttesla["maximum_response_bytes"] == 1024


def test_cross_sample_endpoint_is_kept_separate_from_reviewed_profile(
    tmp_path: Path,
) -> None:
    repository = tmp_path
    profile = load_profiles()["valleyrat-vvas-8bf54-6666"]
    source = repository / profile["source"].split(":", 1)[0]
    source.parent.mkdir(parents=True)
    source.write_text("{}", encoding="utf-8")
    unrelated_sample = "f" * 64
    ordinary = {
        "target_id": "ordinary-cross-sample",
        "family": "fixture",
        "host": profile["host"],
        "port": profile["port"],
        "protocol": "tcp",
        "method": "tcp_connect",
        "transport": "direct",
        "sample_sha256s": [unrelated_sample],
        "associated_case_count": 1,
        "analyzed_dates": [],
        "sources": ["fixture:iocs.json"],
        "roles": ["c2"],
        "selection_basis": "test",
    }

    targets, added = apply_profiles([ordinary], repository_root=repository)
    same_endpoint = [
        target for target in targets if (target["host"], target["port"]) == (profile["host"], profile["port"])
    ]

    assert added == 2
    assert len(same_endpoint) == 2
    unchanged = next(target for target in same_endpoint if target["target_id"] == ordinary["target_id"])
    reviewed = next(target for target in same_endpoint if target.get("protocol_profile_id"))
    assert unchanged["sample_sha256s"] == [unrelated_sample]
    assert "protocol_profile_id" not in unchanged
    assert reviewed["sample_sha256s"] == profile["sample_sha256s"]
    assert set(unchanged["sample_sha256s"]).isdisjoint(reviewed["sample_sha256s"])


def test_all_repository_profiles_apply_except_rejected_remus() -> None:
    repository = Path(__file__).resolve().parents[2]
    profile_pin = profile_registry_metadata()
    review_pin = remus_review_registry_metadata(repository_root=repository)
    rejections: list[dict[str, str]] = []

    targets, added = apply_profiles(
        [],
        repository_root=repository,
        rejections=rejections,
        expected_profile_registry_sha256=profile_pin["sha256"],
        expected_remus_review_registry_sha256=review_pin["sha256"],
    )

    remus_profile_id = "remus-ba0044e8-onesdto-2535"
    applied = {target["protocol_profile_id"] for target in targets}
    assert added == len(targets) == 15
    assert applied == set(load_profiles()) - {remus_profile_id}
    assert all(target["method"] != "remus_registration_task" for target in targets)
    assert [
        {
            "profile_id": item["profile_id"],
            "reason_code": item["reason_code"],
        }
        for item in rejections
    ] == [
        {
            "profile_id": remus_profile_id,
            "reason_code": "remus_review_evidence_unavailable",
        }
    ]


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":1,"schema_version":1,"profiles":[]}',
        b'{"schema_version":NaN,"profiles":[]}',
        b'{"schema_version":Infinity,"profiles":[]}',
    ],
)
def test_profile_registry_reader_rejects_noncanonical_json(
    tmp_path: Path,
    raw: bytes,
) -> None:
    source = tmp_path / "profiles.json"
    source.write_bytes(raw)
    with pytest.raises(ProtocolProfileError):
        profile_module.load_profiles(source)


def test_profile_registry_reader_rejects_oversize(
    tmp_path: Path,
) -> None:
    source = tmp_path / "profiles.json"
    source.write_bytes(b"{" + b" " * profile_module.MAXIMUM_PROFILE_REGISTRY_BYTES + b"}")
    with pytest.raises(ProtocolProfileError):
        profile_module.load_profiles(source)


def test_profile_registry_reader_rejects_hardlink_and_reparse(
    tmp_path: Path,
) -> None:
    source = tmp_path / "profiles.json"
    source.write_text('{"schema_version":1,"profiles":[]}', encoding="utf-8")
    hardlink = tmp_path / "profiles-hardlink.json"
    try:
        os.link(source, hardlink)
    except OSError as exc:
        pytest.skip(f"hardlink unavailable: {exc}")
    with pytest.raises(ProtocolProfileError):
        profile_module.load_profiles(source)

    source.unlink()
    hardlink.unlink()
    target = tmp_path / "profiles-target.json"
    target.write_text('{"schema_version":1,"profiles":[]}', encoding="utf-8")
    try:
        source.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symbolic link unavailable: {exc}")
    with pytest.raises(ProtocolProfileError):
        profile_module.load_profiles(source)


def test_profile_registry_reader_detects_toctou_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = tmp_path / "profiles.json"
    source.write_text('{"schema_version":1,"profiles":[]}', encoding="utf-8")
    target_key = evidence._path_key(source)
    original = evidence.reject_existing_reparse_components
    calls = 0

    def mutate_after_read(candidate: Path) -> None:
        nonlocal calls
        original(candidate)
        if evidence._path_key(candidate) == target_key:
            calls += 1
            if calls == 2:
                with source.open("ab") as stream:
                    stream.write(b" ")

    monkeypatch.setattr(
        evidence,
        "reject_existing_reparse_components",
        mutate_after_read,
    )
    with pytest.raises(ProtocolProfileError):
        profile_module.load_profiles(source)


def test_profile_registry_digest_is_crlf_lf_invariant(
    tmp_path: Path,
) -> None:
    lf = tmp_path / "profiles-lf.json"
    crlf = tmp_path / "profiles-crlf.json"
    raw = b'{\n  "schema_version": 1,\n  "profiles": []\n}\n'
    lf.write_bytes(raw)
    crlf.write_bytes(raw.replace(b"\n", b"\r\n"))

    _, lf_digest = profile_module._read_profile_registry(lf)
    _, crlf_digest = profile_module._read_profile_registry(crlf)

    assert lf_digest == crlf_digest
    assert lf_digest == evidence.canonical_lf_json_sha256(raw)
