"""x64直結型ValleyRAT終端の公開証拠再検証を確認する。"""

from __future__ import annotations

import copy
import importlib.util
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1] / "malware" / "valleyrat" / "detect.py"
)
SPEC = importlib.util.spec_from_file_location(
    "valleyrat_direct_native_terminal_detect", MODULE_PATH
)
assert SPEC and SPEC.loader
DETECT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DETECT)


def _probe() -> dict:
    proof = {
        group: True for group in DETECT._DIRECT_NATIVE_REQUIRED_TERMINAL_PROOF
    }
    return {
        "matched": True,
        "family": "valleyrat",
        "variant": "direct_native_x64_winos_terminal",
        "supports_family_attribution": True,
        "terminal_family_confirmed": True,
        "static_config_recovered": True,
        "candidate_config_recovered": False,
        "attribution_scope": "terminal_payload",
        "endpoints": ["198.51.100.10:443", "example.test:8443"],
        "slots": [{"slot": 1}, {"slot": 2}],
        "config": {
            "endpoint_count": 2,
            "configured_slot_count": 3,
            "raw_config_included": False,
            "raw_network_values_included": False,
        },
        "evidence": {
            "status": "validated_terminal_family_config",
            "profile": "direct_native_x64_winos",
            "analysis_complete": True,
            "terminal_family_lineage_proven": True,
            "configured_slot_count": 3,
            "external_endpoint_count": 2,
            "excluded_loopback_slot_count": 1,
            "proof": proof,
            "protocol": {
                "transport": "tcp",
                "length_prefix_size": 4,
                "session_header_size": 10,
                "frame_header_size": 14,
                "marker": "uint16_0x01ca",
                "initial_registration_command": 6,
                "registration_structure_size": 0x1250,
                "dispatcher_max_command": 0xCA,
                "periodic_keepalive_command": 0xC9,
                "raw_frame_included": False,
            },
            "raw_addresses_included": False,
            "raw_config_included": False,
            "raw_payload_included": False,
            "sample_executed": False,
            "network_contacted": False,
        },
        "sample_executed": False,
        "network_contacted": False,
    }


def test_strict_direct_native_terminal_accepts_complete_public_proof():
    assert DETECT._strict_direct_native_terminal_probe(_probe()) is True


@pytest.mark.parametrize(
    "group", sorted(DETECT._DIRECT_NATIVE_REQUIRED_TERMINAL_PROOF)
)
def test_strict_direct_native_terminal_rejects_each_missing_proof(group: str):
    probe = copy.deepcopy(_probe())
    probe["evidence"]["proof"][group] = False

    assert DETECT._strict_direct_native_terminal_probe(probe) is False


def test_public_observation_redacts_endpoints_and_slots():
    observation = DETECT._direct_native_probe_observation(_probe())

    assert "endpoints" not in observation
    assert "slots" not in observation
    assert observation["raw_endpoints_included"] is False
    assert observation["raw_slots_included"] is False
