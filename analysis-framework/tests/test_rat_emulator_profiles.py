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

from rat_emulator_profiles import (  # noqa: E402
    DEFAULT_REGISTRY_PATH,
    RatEmulatorProfileError,
    load_registry,
    resolve_profile,
)


def _registry_document() -> dict:
    return json.loads(DEFAULT_REGISTRY_PATH.read_text(encoding="utf-8"))


def _write_registry(path: Path, document: dict) -> None:
    path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def test_default_registry_is_bound_to_all_reviewed_host_evidence() -> None:
    registry = load_registry()
    assert list(registry.profiles) == [
        "valleyrat-n520-host-d11e793-9999",
        "asyncrat-058-20f21565-191-96-78-221-7788",
        "venomrat-603-6a24ba25-localto-6377",
    ]
    profile = registry.profiles["valleyrat-n520-host-d11e793-9999"]
    assert profile["adapter_id"] == "valleyrat_n520_v1"
    assert profile["registration_mode"] == "empty_command_1"
    assert profile["station_id_sent"] is False
    assert profile["unknown_task_action"] == "no_response"
    assert profile["file_transfer_action"] == "reject_and_close"
    assert profile["fake_result_scope"] == "loopback_or_offline_only"
    assert profile["allow_live_fake_results"] is False
    assert profile["limits"]["maximum_connections"] == 1
    assert profile["limits"]["maximum_outbound_frames"] == 1
    assert profile["protocol_profile_object_sha256"] == (
        "31f8615bdc76624d3db6138bd14b443390fd5b55f2f90a1871431d2c8e03752b"
    )

    expected = {
        "asyncrat-058-20f21565-191-96-78-221-7788": {
            "object": "b405159f6bbc446541f75517eb561555531b9b30572c5826ff60ff9bb06992a3",
            "evidence": "4c4f598aa861c1da660f513d419184b7b195994d322ed236684c7042ede31f81",
            "host": "191.96.78.221",
            "pin": "191.96.78.221",
        },
        "venomrat-603-6a24ba25-localto-6377": {
            "object": "d73c9bd57ed96071fbc398cc1252e1f5e34faab7fbd4cb3dd97071d6faed2d54",
            "evidence": "2db755d8ed49d1488d558da77171be8a7ff95a175f1322e65b359a368a8219b9",
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
        assert tls_profile["limits"]["duration_seconds"] == 30.0
        assert tls_profile["limits"]["maximum_inbound_frames"] == 1
        assert tls_profile["limits"]["maximum_outbound_frames"] == 2
        assert tls_profile["limits"]["maximum_commands"] == 1
        assert tls_profile["limits"]["maximum_frame_bytes"] == 65536


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
