"""Winos offline orchestratorのfail-closed統合境界を検証する。"""

from __future__ import annotations

import ast
import hashlib
import importlib
import struct
import sys
from pathlib import Path

import pytest


FRAMEWORK = Path(__file__).resolve().parents[1]
VALLEY = FRAMEWORK / "malware" / "valleyrat"
sys.path.insert(0, str(VALLEY))
STATE = importlib.import_module("winos_session_state")
REGISTRY = importlib.import_module("winos_variant_registry")
ORCH = importlib.import_module("winos_offline_orchestrator")


def _xor(payload: bytes, header: bytes, mode: str) -> bytes:
    if mode == "fixed_xor_cc":
        return bytes(value ^ 0xCC for value in payload)
    return bytes(
        value ^ ((header[0 if index == 0 else (index - 1) % 10] + 0x36) & 0xFF) for index, value in enumerate(payload)
    )


def _frame(payload: bytes, profile_id: str) -> bytes:
    profile = REGISTRY.resolve_variant_profile(profile_id)
    prefix = b"\x38" + b"\x00" * 7
    header = prefix + bytes.fromhex(profile.header_suffix_hex)
    encrypted = _xor(payload, header, profile.cipher_mode)
    return struct.pack("<I", 14 + len(payload)) + header + encrypted


def test_rolling_ca00_complete_command_uses_registry_owned_evidence() -> None:
    profile_id = "winos-ca00-x86-4df8bda2"
    snapshot = ORCH.open_command_session(profile_id)
    result = ORCH.classify_and_observe_frame(
        snapshot,
        _frame(b"\x02", profile_id),
        profile_id=profile_id,
        direction=STATE.Direction.SERVER_TO_CLIENT,
    )
    assert result.state_transition_admitted is True
    assert result.classification.shape_assurance == REGISTRY.SHAPE_COMPLETE
    assert result.snapshot.phase is STATE.ProtocolPhase.CONTROL
    assert result.snapshot.state is STATE.SessionState.ACTIVE
    assert result.parsed.command == 0x02
    assert result.parsed.decoded_payload_sha256 == hashlib.sha256(b"\x02").hexdigest()
    assert result.wire_bytes is None
    assert result.operation_executed is False


def test_fixed_ca01_is_selected_by_profile_not_ca01_suffix() -> None:
    profile_id = "winos-ca01-x64-fixed-807361fe"
    result = ORCH.classify_and_observe_frame(
        ORCH.open_command_session(profile_id),
        _frame(b"\x02", profile_id),
        profile_id=profile_id,
        direction=STATE.Direction.SERVER_TO_CLIENT,
    )
    assert result.parsed.header_suffix_hex == "ca01"
    assert result.parsed.cipher_mode == "fixed_xor_cc"
    assert result.classification.command == 0x02
    assert result.state_transition_admitted is True


def test_opaque_and_unknown_are_refused_without_phase_progress() -> None:
    profile_id = "winos-ca00-x86-4df8bda2"
    snapshot = ORCH.open_command_session(profile_id)
    opaque = ORCH.classify_and_observe_frame(
        snapshot,
        _frame(b"\x05" + b"\x00" * 0x2D7, profile_id),
        profile_id=profile_id,
        direction=STATE.Direction.SERVER_TO_CLIENT,
    )
    assert opaque.classification.opaque_or_delegated is True
    assert opaque.state_transition_admitted is False
    assert opaque.snapshot is snapshot
    assert opaque.decision is None
    unknown = ORCH.classify_and_observe_frame(
        snapshot,
        _frame(b"\xfe", profile_id),
        profile_id=profile_id,
        direction=STATE.Direction.SERVER_TO_CLIENT,
    )
    assert unknown.classification.known_command is False
    assert unknown.state_transition_admitted is False
    assert unknown.snapshot is snapshot
    assert unknown.decision is None


def test_remote_compressed_body_is_prefix_only_and_not_admitted() -> None:
    profile_id = "winos-nvml-remote-desktop-9ad36bf2"
    snapshot = ORCH.open_command_session(profile_id)
    result = ORCH.classify_and_observe_frame(
        snapshot,
        _frame(b"\x00" + struct.pack("<I", 1) + b"X", profile_id),
        profile_id=profile_id,
        direction=STATE.Direction.CLIENT_TO_SERVER,
    )
    assert result.classification.payload_processing_validated is False
    assert result.state_transition_admitted is False
    assert result.snapshot is snapshot


def test_direction_header_and_public_scalar_forgery_fail_closed() -> None:
    profile_id = "winos-ca00-x86-4df8bda2"
    snapshot = ORCH.open_command_session(profile_id)
    with pytest.raises(REGISTRY.DirectionMismatchError):
        ORCH.classify_and_observe_frame(
            snapshot,
            _frame(b"\x02", profile_id),
            profile_id=profile_id,
            direction=STATE.Direction.CLIENT_TO_SERVER,
        )
    bad = bytearray(_frame(b"\x02", profile_id))
    bad[-2:] = b"\xca\x01"
    with pytest.raises(ORCH.FrameBoundaryError):
        ORCH.classify_and_observe_frame(
            snapshot,
            bytes(bad),
            profile_id=profile_id,
            direction=STATE.Direction.SERVER_TO_CLIENT,
        )
    binding = snapshot.binding
    assert binding is not None
    with pytest.raises(PermissionError):
        STATE.SessionEvent(
            STATE.EventKind.FRAME,
            binding=binding,
            direction=STATE.Direction.SERVER_TO_CLIENT,
            command=0x02,
            observed_size=15,
            observed_sha256="0" * 64,
            payload_size=1,
            contract_profile_id=profile_id,
            contract_payload_sha256="0" * 64,
            contract_known_command=True,
            contract_valid=True,
            contract_length_valid=True,
            contract_structure_valid=True,
            body_shape_validated=True,
        )
    assert not hasattr(STATE.SessionEvent, "frame")


def test_raw_downloader_exact_request_and_stage_metadata_only() -> None:
    snapshot = ORCH.open_raw_downloader_session()
    request = ORCH.observe_raw_initial_request(snapshot, b"\x36\x34\x00")
    assert request.snapshot.phase is STATE.ProtocolPhase.RAW_INITIAL_REQUEST_SENT
    header = b"\x38" + b"\x00" * 9
    decoded = b"MZ" + b"\x00" * (STATE.NVML_RAW_STAGE_BODY_BYTES - 2)
    encrypted = _xor(decoded, header, "rolling_header_plus_0x36")
    raw = struct.pack("<I", STATE.NVML_RAW_STAGE_TOTAL_BYTES) + header + encrypted
    stage = ORCH.observe_raw_stage_frame(request.snapshot, raw)
    assert stage.classification is None
    assert stage.raw_stage.decoded_body_length == STATE.NVML_RAW_STAGE_BODY_BYTES
    assert stage.raw_stage.decoded_body_sha256 == hashlib.sha256(decoded).hexdigest()
    assert stage.raw_stage.decoded_begins_with_mz is True
    assert stage.raw_stage.handoff_executed is False
    assert stage.snapshot.stop_reason == "stage_handoff_refused"
    assert stage.operation_executed is False
    assert "MZ" not in repr(stage)


def test_raw_stage_bad_declared_length_and_bad_request_are_rejected() -> None:
    snapshot = ORCH.open_raw_downloader_session()
    with pytest.raises(ORCH.FrameBoundaryError):
        ORCH.observe_raw_initial_request(snapshot, b"\x36\x34\x01")
    request = ORCH.observe_raw_initial_request(snapshot, b"\x36\x34\x00")
    raw = bytearray(STATE.NVML_RAW_STAGE_TOTAL_BYTES)
    struct.pack_into("<I", raw, 0, STATE.NVML_RAW_STAGE_TOTAL_BYTES - 1)
    with pytest.raises(ORCH.FrameBoundaryError):
        ORCH.observe_raw_stage_frame(request.snapshot, bytes(raw))


def test_module_has_no_live_or_operation_imports() -> None:
    source = (VALLEY / "winos_offline_orchestrator.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names
    }
    assert "socket" not in imports
    assert "winos_protocol" not in imports
    assert "subprocess" not in imports
    assert "os" not in imports
    assert "pathlib" not in imports
