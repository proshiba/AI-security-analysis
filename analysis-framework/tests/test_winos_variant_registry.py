"""Exact Winos variant registryのprovenanceと安全な分類境界を検証する。"""

from __future__ import annotations

import ast
import hashlib
import importlib.util
import sys
from dataclasses import asdict
from pathlib import Path

import pytest


FRAMEWORK = Path(__file__).resolve().parents[1]
VALLEY = FRAMEWORK / "malware" / "valleyrat"
sys.path.insert(0, str(VALLEY))
MODULE_PATH = VALLEY / "winos_variant_registry.py"
SPEC = importlib.util.spec_from_file_location("winos_variant_registry_test_target", MODULE_PATH)
assert SPEC and SPEC.loader
REGISTRY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = REGISTRY
SPEC.loader.exec_module(REGISTRY)


PROFILE_IDS = {
    "winos-ca00-x86-4df8bda2",
    "winos-ca01-x64-fixed-807361fe",
    "winos-nvml-bootstrap-39b20658",
    "winos-nvml-main-024ab2a6",
    "winos-nvml-remote-desktop-9ad36bf2",
}


def _classify(profile_id: str, payload: bytes, **overrides):
    profile = REGISTRY.resolve_variant_profile(profile_id)
    arguments = {
        "sample_sha256": profile.sample_sha256,
        "program_selector": profile.program_selector,
        "dispatcher": profile.dispatcher,
        "header_suffix_hex": profile.header_suffix_hex,
        "cipher_mode": profile.cipher_mode,
        "direction": profile.allowed_directions[0],
        "root_lineage_sample_sha256": profile.root_lineage_sample_sha256,
        "payload_kind": REGISTRY.DECODED_COMMAND_PAYLOAD_KIND,
    }
    arguments.update(overrides)
    return REGISTRY.classify_decoded_for_variant(
        profile_id,
        payload,
        **arguments,
    )


def test_registry_pins_five_exact_variants_and_explicit_ghidra_provenance() -> None:
    assert set(REGISTRY.VARIANT_PROFILES) == PROFILE_IDS
    assert {profile.profile_id for profile in REGISTRY.variant_profiles()} == PROFILE_IDS
    for profile in REGISTRY.variant_profiles():
        assert profile.program_selector.endswith(f"/{profile.sample_sha256}.bin")
        assert profile.dispatcher.startswith("FUN_")
        assert profile.header_suffix_hex in {"ca00", "ca01"}
        assert profile.classifier_name.endswith("payload")
        assert profile.raw_stage_is_decoded_command is False
        assert profile.root_lineage_sample_sha256 is not None

    ca00 = REGISTRY.resolve_variant_profile("winos-ca00-x86-4df8bda2")
    assert ca00.sample_sha256.startswith("4df8bda2")
    assert ca00.root_lineage_sample_sha256.startswith("da33a95b")
    assert ca00.header_suffix_hex == "ca00"
    assert ca00.cipher_mode == "rolling_header_plus_0x36"


def test_ca01_suffix_does_not_select_cipher_mode() -> None:
    fixed = REGISTRY.resolve_variant_profile("winos-ca01-x64-fixed-807361fe")
    rolling = REGISTRY.resolve_variant_profile("winos-nvml-main-024ab2a6")
    assert fixed.header_suffix_hex == rolling.header_suffix_hex == "ca01"
    assert fixed.cipher_mode == "fixed_xor_cc"
    assert rolling.cipher_mode == "rolling_header_plus_0x36"

    assert _classify(fixed.profile_id, b"\x02").cipher_mode == "fixed_xor_cc"
    assert _classify(rolling.profile_id, b"\x02").cipher_mode == "rolling_header_plus_0x36"
    with pytest.raises(REGISTRY.CipherModeMismatchError):
        _classify(fixed.profile_id, b"\x02", cipher_mode=rolling.cipher_mode)


@pytest.mark.parametrize(
    ("profile_id", "payload", "role"),
    [
        ("winos-ca00-x86-4df8bda2", b"\x02", "disconnect"),
        ("winos-ca01-x64-fixed-807361fe", b"\x02", "disconnect"),
        (
            "winos-nvml-bootstrap-39b20658",
            b"\xc9",
            "heartbeat_ignored_by_bootstrap_dispatcher",
        ),
        ("winos-nvml-main-024ab2a6", b"\x02", "disconnect"),
        (
            "winos-nvml-remote-desktop-9ad36bf2",
            b"\xc9",
            "heartbeat",
        ),
    ],
)
def test_exact_profiles_dispatch_to_metadata_only_contracts(
    profile_id: str,
    payload: bytes,
    role: str,
) -> None:
    result = _classify(profile_id, payload)
    assert result.role == role
    assert result.payload_sha256 == hashlib.sha256(payload).hexdigest()
    assert result.expected_safe_outcome == "refused_no_wire"
    assert result.raw_stage_body_classified is False
    assert result.contract_metadata_included is True
    assert result.validation_scope == "sanitized_variant_contract_projection"
    assert isinstance(result.sanitized_contract_metadata, tuple)
    assert result.content_disclosure_allowed is False
    assert result.should_respond is False
    assert result.send_allowed is False
    assert result.operation_executed is False
    assert result.raw_payload_retained is False
    assert result.wire_bytes is None


def test_remote_profile_is_bidirectional_but_other_dispatchers_are_not() -> None:
    remote_id = "winos-nvml-remote-desktop-9ad36bf2"
    outbound = _classify(
        remote_id,
        b"\xc9",
        direction=REGISTRY.CLIENT_TO_SERVER,
    )
    assert outbound.direction == REGISTRY.CLIENT_TO_SERVER
    assert outbound.known_command is True

    with pytest.raises(REGISTRY.DirectionMismatchError):
        _classify(
            "winos-nvml-main-024ab2a6",
            b"\x02",
            direction=REGISTRY.CLIENT_TO_SERVER,
        )


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("sample_sha256", "0" * 64, "VariantProvenanceMismatchError"),
        ("program_selector", "/wrong/program", "VariantProvenanceMismatchError"),
        ("dispatcher", "FUN_deadbeef", "VariantProvenanceMismatchError"),
        ("header_suffix_hex", "ca00", "HeaderSuffixMismatchError"),
        ("cipher_mode", "fixed_xor_cc", "CipherModeMismatchError"),
        ("root_lineage_sample_sha256", "0" * 64, "VariantProvenanceMismatchError"),
    ],
)
def test_every_explicit_variant_binding_mismatch_fails_closed(
    field: str,
    value: str,
    error: str,
) -> None:
    error_type = getattr(REGISTRY, error)
    with pytest.raises(error_type):
        _classify("winos-nvml-main-024ab2a6", b"\x02", **{field: value})


def test_unknown_profile_and_raw_stage_are_explicitly_rejected() -> None:
    with pytest.raises(REGISTRY.UnknownVariantProfileError):
        REGISTRY.resolve_variant_profile("winos-auto-detect")
    with pytest.raises(REGISTRY.RawStagePayloadNotClassifiableError):
        _classify(
            "winos-nvml-bootstrap-39b20658",
            b"not-a-command",
            payload_kind="raw_stage_body",
        )
    with pytest.raises(REGISTRY.RawStagePayloadNotClassifiableError):
        _classify(
            "winos-nvml-bootstrap-39b20658",
            bytes.fromhex("363400"),
            payload_kind="raw_initial_stage_request",
        )


@pytest.mark.parametrize("profile_id", sorted(PROFILE_IDS))
def test_reserved_raw_request_is_rejected_even_with_decoded_label(profile_id: str) -> None:
    with pytest.raises(REGISTRY.RawStagePayloadNotClassifiableError):
        _classify(
            profile_id,
            bytes.fromhex("363400"),
            payload_kind=REGISTRY.DECODED_COMMAND_PAYLOAD_KIND,
        )


def test_required_payload_kind_and_lineage_cannot_be_omitted_or_none() -> None:
    profile = REGISTRY.resolve_variant_profile("winos-nvml-main-024ab2a6")
    common = {
        "sample_sha256": profile.sample_sha256,
        "program_selector": profile.program_selector,
        "dispatcher": profile.dispatcher,
        "header_suffix_hex": profile.header_suffix_hex,
        "cipher_mode": profile.cipher_mode,
        "direction": profile.allowed_directions[0],
    }
    with pytest.raises(TypeError, match="payload_kind"):
        REGISTRY.classify_decoded_for_variant(
            profile.profile_id,
            b"\x02",
            root_lineage_sample_sha256=profile.root_lineage_sample_sha256,
            **common,
        )
    with pytest.raises(TypeError, match="root_lineage_sample_sha256"):
        REGISTRY.classify_decoded_for_variant(
            profile.profile_id,
            b"\x02",
            payload_kind=REGISTRY.DECODED_COMMAND_PAYLOAD_KIND,
            **common,
        )
    with pytest.raises(REGISTRY.VariantProvenanceMismatchError):
        _classify(profile.profile_id, b"\x02", root_lineage_sample_sha256=None)


def test_assurance_blocks_opaque_delegated_and_unprocessed_payloads() -> None:
    opaque = _classify("winos-ca00-x86-4df8bda2", b"\x05")
    assert opaque.shape_assurance == REGISTRY.SHAPE_OPAQUE_OR_DELEGATED
    assert opaque.opaque_or_delegated is True
    assert opaque.admissible_for_state_transition is False

    delegated = _classify("winos-nvml-main-024ab2a6", b"\x66")
    assert delegated.shape_assurance == REGISTRY.SHAPE_OPAQUE_OR_DELEGATED
    assert delegated.admissible_for_state_transition is False
    assert any(name == "delegated_handler_called" for name, _ in delegated.sanitized_contract_metadata)

    compressed = _classify(
        "winos-nvml-remote-desktop-9ad36bf2",
        b"\x00\x10\x00\x00\x00x",
        direction=REGISTRY.CLIENT_TO_SERVER,
    )
    assert compressed.payload_processing_required is True
    assert compressed.payload_processing_validated is False
    assert compressed.admissible_for_state_transition is False


def test_sensitive_remote_body_is_not_exposed_by_registry_result() -> None:
    secret = b"private-clipboard-body"
    result = _classify(
        "winos-nvml-remote-desktop-9ad36bf2",
        b"\x02" + secret,
        direction=REGISTRY.CLIENT_TO_SERVER,
    )
    serialized = repr(asdict(result))
    assert result.sensitive_content is True
    assert result.body_sha256 == hashlib.sha256(secret).hexdigest()
    assert secret.hex() not in serialized
    assert secret.decode() not in serialized
    assert not hasattr(result, "payload")
    assert not hasattr(result, "payload_hex")
    assert not hasattr(result, "utf16_summary")
    assert not hasattr(result, "module_transfer_summary")
    assert not hasattr(result, "metadata")
    assert result.opaque_or_delegated is True
    assert result.admissible_for_state_transition is False
    assert secret not in repr(result.sanitized_contract_metadata).encode()


def test_remote_only_shape_options_are_not_silently_applied_to_other_variants() -> None:
    remote = _classify(
        "winos-nvml-remote-desktop-9ad36bf2",
        b"\x0c" + bytes(80),
        input_record_size=40,
    )
    assert remote.contract_valid is True
    with pytest.raises(ValueError, match="remote desktop"):
        _classify(
            "winos-ca00-x86-4df8bda2",
            b"\x02",
            input_record_size=40,
        )


def test_registry_source_has_no_network_process_file_or_reply_implementation() -> None:
    tree = ast.parse(MODULE_PATH.read_text(encoding="utf-8"))
    imported_roots = {
        alias.name.split(".", 1)[0] for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names
    }
    imported_roots.update(
        node.module.split(".", 1)[0] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module
    )
    assert imported_roots.isdisjoint(
        {
            "ctypes",
            "http",
            "os",
            "pathlib",
            "requests",
            "shutil",
            "socket",
            "ssl",
            "subprocess",
            "urllib",
            "winreg",
        }
    )
    forbidden_calls = {
        "open",
        "send",
        "sendall",
        "write",
        "write_bytes",
        "write_text",
    }
    assert not {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }.intersection(forbidden_calls)


def test_contract_false_never_admits_even_when_length_and_structure_are_true() -> None:
    fake = type(
        "FakeContract",
        (),
        {
            "role": "disconnect",
            "metadata": (),
            "delegated_handler_called": False,
            "delegated_family": None,
            "structure_valid": True,
            "structure_status": "no_additional_confirmed_structure",
            "decoded_payload_length": 1,
            "known_command": True,
            "length_valid": True,
            "contract_valid": False,
        },
    )()
    projection = REGISTRY._assurance_projection(fake)
    assert projection[-1] is False
