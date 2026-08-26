"""Winos session bindingとprivate verified event境界を検証する。"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest


FRAMEWORK = Path(__file__).resolve().parents[1]
VALLEY = FRAMEWORK / "malware" / "valleyrat"
sys.path.insert(0, str(VALLEY))
WINOS = importlib.import_module("winos_session_state")


def test_all_bindings_pin_exact_variant_provenance_and_directions() -> None:
    for variant in WINOS.WinosVariant:
        binding = WINOS.binding_for_variant(variant)
        definition = WINOS.PROFILE_DEFINITIONS[variant]
        assert binding.sample_sha256 == definition.sample_sha256
        assert binding.root_sample_sha256 == WINOS.PROFILE_ROOT_SAMPLES[variant]
        assert binding.program_selector == WINOS.PROFILE_PROGRAM_SELECTORS[variant]
        assert binding.header_mode is definition.header_mode
        assert binding.cipher_mode is definition.cipher_mode
        assert binding.dispatcher == definition.dispatcher
        assert binding.allowed_directions == WINOS.PROFILE_ALLOWED_DIRECTIONS[variant]


def test_binding_rejects_direction_or_cipher_override() -> None:
    exact = WINOS.binding_for_variant(WINOS.WinosVariant.CA01_X64_FIXED)
    values = dict(exact.__dict__)
    values["allowed_directions"] = (WINOS.Direction.SERVER_TO_CLIENT,)
    with pytest.raises(ValueError, match="allowed_directions"):
        WINOS.SessionBinding(**values)
    values = dict(exact.__dict__)
    values["cipher_mode"] = WINOS.CipherMode.ROLLING_HEADER_PLUS_0X36
    with pytest.raises(ValueError, match="組合せ"):
        WINOS.SessionBinding(**values)


def test_ca00_ca01_command_0b_difference_is_explicit() -> None:
    direction = WINOS.Direction.SERVER_TO_CLIENT
    assert WINOS.command_role(WINOS.WinosVariant.CA00_X86, direction, 0x0B) == "restart_security_tray_targets"
    assert (
        WINOS.command_role(WINOS.WinosVariant.CA01_X64_FIXED, direction, 0x0B)
        == "clear_application_security_system_event_logs"
    )
    assert WINOS.command_role(WINOS.WinosVariant.CA00_X86, direction, 0xFE) == "unknown"


def test_bootstrap_client_heartbeat_and_raw_profile_are_separate() -> None:
    assert (
        WINOS.command_role(
            WINOS.WinosVariant.NVML_BOOTSTRAP,
            WINOS.Direction.CLIENT_TO_SERVER,
            0xC9,
        )
        == "bootstrap_client_heartbeat"
    )
    raw = WINOS.binding_for_variant(WINOS.WinosVariant.DOWNLOADER_RAW_STAGE)
    assert raw.header_mode is WINOS.HeaderMode.RAW_14_BYTE_STAGE_PREFIX
    assert WINOS.PROFILE_COMMAND_CLASSIFIER_IDS[raw.variant] is None
    assert WINOS.PROFILE_DEFINITIONS[raw.variant].permits_raw_stage_handshake is True
    assert WINOS.PROFILE_DEFINITIONS[WINOS.WinosVariant.NVML_BOOTSTRAP].permits_raw_stage_handshake is False


def test_public_scalar_frame_and_raw_fabrication_are_rejected() -> None:
    binding = WINOS.binding_for_variant(WINOS.WinosVariant.CA00_X86)
    with pytest.raises(PermissionError):
        WINOS.SessionEvent(
            WINOS.EventKind.FRAME,
            binding=binding,
            direction=WINOS.Direction.SERVER_TO_CLIENT,
            command=0x02,
            observed_size=15,
            observed_sha256="0" * 64,
            payload_size=1,
            contract_profile_id="winos-ca00-x86-4df8bda2",
            contract_payload_sha256="0" * 64,
            contract_known_command=True,
            contract_valid=True,
            contract_length_valid=True,
            contract_structure_valid=True,
            body_shape_validated=True,
        )
    raw = WINOS.binding_for_variant(WINOS.WinosVariant.DOWNLOADER_RAW_STAGE)
    with pytest.raises(PermissionError):
        WINOS.SessionEvent(
            WINOS.EventKind.RAW_INITIAL_REQUEST,
            binding=raw,
            direction=WINOS.Direction.CLIENT_TO_SERVER,
            observed_size=3,
            observed_sha256=WINOS.NVML_RAW_INITIAL_REQUEST_SHA256,
        )
    assert not hasattr(WINOS.SessionEvent, "frame")
    assert not hasattr(WINOS.SessionEvent, "raw_initial_request")
    assert not hasattr(WINOS.SessionEvent, "raw_stage_body")


def test_open_stop_and_invalid_transitions() -> None:
    binding = WINOS.binding_for_variant(WINOS.WinosVariant.CA00_X86)
    opened = WINOS.transition_session(WINOS.SessionSnapshot(), WINOS.SessionEvent.open(binding)).snapshot
    assert opened.state is WINOS.SessionState.ACTIVE
    assert opened.phase is WINOS.ProtocolPhase.CONNECTED
    with pytest.raises(WINOS.InvalidTransitionError):
        WINOS.transition_session(opened, WINOS.SessionEvent.open(binding))
    stopped = WINOS.transition_session(opened, WINOS.SessionEvent.stop()).snapshot
    assert stopped.state is WINOS.SessionState.CLOSED
    assert stopped.stop_reason == "stopped_by_caller"
    with pytest.raises(WINOS.InvalidTransitionError):
        WINOS.transition_session(stopped, WINOS.SessionEvent.stop())


def test_wire_code_caps_are_variant_scoped_not_global_claims() -> None:
    caps = WINOS.PROFILE_MALWARE_CODE_MAXIMUM_FRAME_BYTES
    assert caps[WINOS.WinosVariant.CA00_X86] is None
    assert caps[WINOS.WinosVariant.CA01_X64_FIXED] is None
    assert caps[WINOS.WinosVariant.NVML_BOOTSTRAP] == 0x02000000
    assert caps[WINOS.WinosVariant.NVML_MAIN] == 0x02000000
    assert caps[WINOS.WinosVariant.REMOTE_DESKTOP] == 0x02000000
    assert WINOS.OFFLINE_DEFENSIVE_MAXIMUM_FRAME_BYTES == 0x02000000


def test_session_limits_are_bounded_and_distinguish_frame_from_aggregate() -> None:
    limits = WINOS.SessionLimits(
        maximum_frames=2,
        maximum_frame_bytes=1024,
        maximum_payload_bytes=1010,
        maximum_total_frame_bytes=2048,
    )
    assert limits.maximum_total_frame_bytes > limits.maximum_frame_bytes
    with pytest.raises(ValueError):
        WINOS.SessionLimits(maximum_frames=0)
    with pytest.raises(ValueError):
        WINOS.SessionLimits(maximum_frame_bytes=WINOS.OFFLINE_DEFENSIVE_MAXIMUM_FRAME_BYTES + 1)


def test_private_raw_stage_factory_rejects_forged_declared_prefix() -> None:
    binding = WINOS.binding_for_variant(WINOS.WinosVariant.DOWNLOADER_RAW_STAGE)
    with pytest.raises(ValueError, match="declared"):
        WINOS.SessionEvent._verified_raw_stage_body(binding, bytes(WINOS.NVML_RAW_STAGE_TOTAL_BYTES))
