from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest

COMMON = Path(__file__).parents[1] / "common"
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from c2_protocol_probe_profiles import ProtocolProfileError, load_profiles


def test_darkcomet_profiles_are_exact_receive_only_endpoints() -> None:
    profiles = load_profiles()
    selected = [
        profile
        for profile in profiles.values()
        if profile["handler"] == "darkcomet_server_first_idtype"
    ]
    assert {(profile["host"], profile["port"]) for profile in selected} == {
        ("f168.name", 1604),
        ("f168.com.co", 1604),
        ("f168hi.com", 1604),
    }
    for profile in selected:
        assert base64.b64decode(profile["network_rc4_key_base64"], validate=True) == b"#KCMDDC5#-"
        assert profile["password_concatenated"] is False
        assert profile["config_resource_key_reused"] is False
        assert profile["primary_wire_encoding"] == "ascii_hex"
        assert profile["wire_encodings"] == ["raw", "ascii_hex"]
        assert profile["maximum_response_bytes"] == 12
        assert not any(field in profile for field in ("send_hex", "payload", "checkin"))


def test_darkcomet_profile_fails_closed_when_key_is_not_static_verified(
    tmp_path: Path,
) -> None:
    source = COMMON / "c2_protocol_probe_profiles.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    profile = next(
        item
        for item in payload["profiles"]
        if item["handler"] == "darkcomet_server_first_idtype"
    )
    profile["key_derivation_status"] = "inferred"
    destination = tmp_path / "profiles.json"
    destination.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ProtocolProfileError, match="受信専用境界"):
        load_profiles(destination)


def test_darkcomet_profile_fails_closed_when_resource_key_is_substituted(
    tmp_path: Path,
) -> None:
    source = COMMON / "c2_protocol_probe_profiles.json"
    payload = json.loads(source.read_text(encoding="utf-8"))
    profile = next(
        item
        for item in payload["profiles"]
        if item["handler"] == "darkcomet_server_first_idtype"
    )
    profile["password_concatenated"] = True
    profile["config_resource_key_reused"] = True
    profile["network_rc4_key_base64"] = base64.b64encode(b"#KCMDDC5#-890").decode("ascii")
    destination = tmp_path / "profiles.json"
    destination.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(ProtocolProfileError, match="受信専用境界"):
        load_profiles(destination)
