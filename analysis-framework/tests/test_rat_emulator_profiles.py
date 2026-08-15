"""防御用RAT emulator profileの完全一致検証。"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
ROOT = Path(__file__).parents[2]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from rat_emulator_profiles import (
    DEFAULT_REGISTRY_PATH,
    RatEmulatorProfileError,
    load_registry,
    registry_metadata,
    resolve_profile,
)


def _registry_document() -> dict:
    return json.loads(DEFAULT_REGISTRY_PATH.read_text(encoding="utf-8"))


def _write_registry(path: Path, document: dict) -> None:
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def test_registry_digest_is_identical_for_lf_and_crlf(tmp_path: Path) -> None:
    expected_sha256 = (
        "e0bee32089355702a37b6a4f4c014e35df1d409873d0afc97ef71376a482a43d"
    )
    canonical_lf = (
        DEFAULT_REGISTRY_PATH.read_bytes()
        .replace(b"\r\n", b"\n")
        .replace(b"\r", b"\n")
    )
    lf_path = tmp_path / "registry-lf.json"
    crlf_path = tmp_path / "registry-crlf.json"
    lf_path.write_bytes(canonical_lf)
    crlf_path.write_bytes(canonical_lf.replace(b"\n", b"\r\n"))

    for path in (lf_path, crlf_path):
        assert load_registry(path, root=ROOT).sha256 == expected_sha256
        assert registry_metadata(path)["sha256"] == expected_sha256


def _copy_evidence_tree(root: Path, *, crlf: bool) -> dict[str, str]:
    expected: dict[str, str] = {}
    for profile in _registry_document()["profiles"]:
        source = Path(profile["evidence_source"])
        canonical_lf = (ROOT / source).read_bytes().replace(b"\r\n", b"\n")
        assert b"\r" not in canonical_lf
        target = root / source
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(
            canonical_lf.replace(b"\n", b"\r\n") if crlf else canonical_lf
        )
        expected[profile["profile_id"]] = profile["evidence_sha256"]
    return expected


def test_all_evidence_pins_are_identical_for_lf_and_crlf(tmp_path: Path) -> None:
    expected = {
        "valleyrat-n520-host-d11e793-9999": (
            "2c91c9d80e685244b9b984cc511b24d48f9c4afc5ba76c1b8df31108f72531bc"
        ),
        "asyncrat-058-20f21565-191-96-78-221-7788": (
            "479f96e2d8c9179e1e982ee094a1f83b102d1803cfe83f00fb1b711b93810340"
        ),
        "venomrat-603-6a24ba25-localto-6377": (
            "f1841e6e00e029065494ceedf32d11291261f10b17081f9d951b241c1e0015d8"
        ),
        "valleyrat-winos-heartbeat-20260803-ljdnxz": (
            "a5aa744072c48e98f1765d4184e42f4a08b8363c322fde2fcf5dc6c6e8e45424"
        ),
        "purerat-441-d025a296-direct-tls10-empty-gclass4": (
            "73422aedd0227225850dc2df3edea996b3bd1c30ec334c0c079f93c8277822a8"
        ),
    }
    for line_ending in ("lf", "crlf"):
        root = tmp_path / line_ending
        assert _copy_evidence_tree(root, crlf=line_ending == "crlf") == expected
        registry = load_registry(root=root)
        assert {
            profile_id: profile["evidence_sha256"]
            for profile_id, profile in registry.profiles.items()
        } == expected


def test_evidence_content_mutation_is_rejected_after_lf_normalization(
    tmp_path: Path,
) -> None:
    _copy_evidence_tree(tmp_path, crlf=True)
    source = Path(_registry_document()["profiles"][0]["evidence_source"])
    target = tmp_path / source
    target.write_bytes(target.read_bytes() + b" ")

    with pytest.raises(RatEmulatorProfileError, match="evidence SHA-256"):
        load_registry(root=tmp_path)


def test_default_registry_is_bound_to_all_reviewed_host_evidence() -> None:
    registry = load_registry()
    assert list(registry.profiles) == [
        "valleyrat-n520-host-d11e793-9999",
        "asyncrat-058-20f21565-191-96-78-221-7788",
        "venomrat-603-6a24ba25-localto-6377",
        "valleyrat-winos-heartbeat-20260803-ljdnxz",
        "purerat-441-d025a296-direct-tls10-empty-gclass4",
    ]
    profile = registry.profiles["valleyrat-n520-host-d11e793-9999"]
    assert profile["adapter_id"] == "valleyrat_n520_v1"
    assert profile["registration_mode"] == "empty_command_1"
    assert profile["station_id_sent"] is False
    assert profile["unknown_task_action"] == "no_response"
    assert profile["file_transfer_action"] == "reject_and_close"
    assert profile["fake_result_scope"] == "loopback_or_offline_only"
    assert profile["allow_live_fake_results"] is False
    assert profile["live_scope"] == "leased_external"
    assert profile["limits"]["maximum_connections"] == 1
    assert profile["limits"]["maximum_outbound_frames"] == 1
    assert profile["protocol_profile_object_sha256"] == (
        "31f8615bdc76624d3db6138bd14b443390fd5b55f2f90a1871431d2c8e03752b"
    )

    expected = {
        "asyncrat-058-20f21565-191-96-78-221-7788": {
            "object": "b405159f6bbc446541f75517eb561555531b9b30572c5826ff60ff9bb06992a3",
            "evidence": "479f96e2d8c9179e1e982ee094a1f83b102d1803cfe83f00fb1b711b93810340",
            "host": "191.96.78.221",
            "pin": "191.96.78.221",
        },
        "venomrat-603-6a24ba25-localto-6377": {
            "object": "d73c9bd57ed96071fbc398cc1252e1f5e34faab7fbd4cb3dd97071d6faed2d54",
            "evidence": "f1841e6e00e029065494ceedf32d11291261f10b17081f9d951b241c1e0015d8",
            "host": "s2gj9tonn.localto.net",
            "pin": "45.140.42.50",
        },
    }
    for profile_id, values in expected.items():
        tls_profile = registry.profiles[profile_id]
        assert tls_profile["adapter_id"] == "tls_messagepack_rat_host"
        assert tls_profile["protocol_profile_id"] == profile_id
        assert tls_profile["protocol_profile_object_sha256"] == values["object"]
        assert tls_profile["evidence_sha256"] == values["evidence"]
        assert tls_profile["host"] == values["host"]
        assert tls_profile["pinned_ips"] == [values["pin"]]
        assert tls_profile["certificate_mismatch_is_negative_evidence"] is False
        assert tls_profile["live_scope"] == "leased_external"
        assert tls_profile["limits"]["duration_seconds"] == 30.0
        assert tls_profile["limits"]["maximum_inbound_frames"] == 1
        assert tls_profile["limits"]["maximum_outbound_frames"] == 2
        assert tls_profile["limits"]["maximum_commands"] == 1
        assert tls_profile["limits"]["maximum_frame_bytes"] == 65536


def test_winos_profile_is_control_only_and_offline_only() -> None:
    profile = load_registry().profiles[
        "valleyrat-winos-heartbeat-20260803-ljdnxz"
    ]
    assert profile["adapter_id"] == "valleyrat_winos_v1"
    assert profile["host"] == "ljdnxz.cc"
    assert profile["port"] == 8868
    assert profile["pinned_ips"] == ["121.127.253.206"]
    assert profile["transport"] == "raw_tcp"
    assert profile["tls_version"] is None
    assert profile["registration_mode"] == "fixed_c9_heartbeat"
    assert profile["live_scope"] == "offline_or_loopback_only"
    assert profile["limits"] == {
        "duration_seconds": 3.0,
        "maximum_connections": 1,
        "maximum_outbound_frames": 1,
        "maximum_outbound_bytes": 15,
        "maximum_inbound_frames": 1,
        "maximum_inbound_read_calls": 16,
        "maximum_inbound_bytes": 64,
        "maximum_frame_bytes": 64,
        "maximum_commands": 1,
        "minimum_send_interval_seconds": 0.0,
    }
    assert ":8856" not in json.dumps(profile, ensure_ascii=False)


@pytest.mark.parametrize(
    ("mutation", "value"),
    [
        ("missing", None),
        ("unknown", "unreviewed_scope"),
        ("wrong_for_adapter", "offline_or_loopback_only"),
    ],
)
def test_live_scope_missing_unknown_or_wrong_adapter_fails_closed(
    tmp_path: Path,
    mutation: str,
    value: object,
) -> None:
    document = _registry_document()
    if mutation == "missing":
        document["profiles"][0].pop("live_scope")
    else:
        document["profiles"][0]["live_scope"] = value
    path = tmp_path / f"bad-scope-{mutation}.json"
    _write_registry(path, document)
    with pytest.raises(RatEmulatorProfileError):
        load_registry(path, root=ROOT)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("host", "8.8.8.8"),
        ("pinned_ips", ["8.8.8.8"]),
        ("protocol_profile_object_sha256", "0" * 64),
        ("evidence_sha256", "0" * 64),
        ("allow_live_fake_results", True),
    ],
)
def test_profile_mutation_fails_closed(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    document = _registry_document()
    document["profiles"][0][field] = value
    path = tmp_path / "registry.json"
    _write_registry(path, document)
    with pytest.raises(RatEmulatorProfileError):
        load_registry(path, root=ROOT)


def test_limit_expansion_and_wrong_registry_pin_fail_closed(tmp_path: Path) -> None:
    document = _registry_document()
    document["profiles"][0]["limits"]["maximum_outbound_frames"] = 2
    path = tmp_path / "expanded.json"
    _write_registry(path, document)
    with pytest.raises(RatEmulatorProfileError, match="1 frame"):
        load_registry(path, root=ROOT)
    with pytest.raises(RatEmulatorProfileError, match="SHA-256"):
        load_registry(DEFAULT_REGISTRY_PATH, expected_sha256="0" * 64)


def test_unknown_profile_and_duplicate_json_key_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(RatEmulatorProfileError, match="未レビュー"):
        resolve_profile("missing-profile")
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":1,"schema_version":1,"protocol_profile_registry":{},'
        '"profiles":[]}',
        encoding="utf-8",
    )
    with pytest.raises(RatEmulatorProfileError):
        load_registry(duplicate, root=ROOT)


def test_callers_receive_a_copy_not_registry_mutable_state() -> None:
    first = resolve_profile("valleyrat-n520-host-d11e793-9999")
    second = resolve_profile("valleyrat-n520-host-d11e793-9999")
    first["limits"]["maximum_commands"] = 999
    assert second["limits"]["maximum_commands"] == 16
    assert first != copy.deepcopy(second)
