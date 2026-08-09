from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODULE_DIR = ROOT / "analysis-framework" / "malware" / "formbook_loader"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_load("native_xloader", MODULE_DIR / "native_xloader.py")
_load("xloader_c2", MODULE_DIR / "xloader_c2.py")
_load("xloader_active_probe", MODULE_DIR / "xloader_active_probe.py")
MATERIAL = _load(
    "xloader_probe_material",
    MODULE_DIR / "xloader_probe_material.py",
)


def test_reconstruct_stack_constants_applies_register_xor() -> None:
    code = bytes.fromhex(
        "c745e004030201"  # mov dword ptr [ebp-0x20], 0x01020304
        "b8d4d72722"  # mov eax, 0x2227d7d4
        "3145e0"  # xor dword ptr [ebp-0x20], eax
    )
    stack = MATERIAL.reconstruct_stack_constants(code, 0x1000)
    recovered = bytes(stack[-0x20 + index] for index in range(4))
    expected = (0x01020304 ^ 0x2227D7D4).to_bytes(4, "little")
    assert recovered == expected


def test_reconstruct_stack_constants_rejects_stale_register_after_add() -> None:
    code = bytes.fromhex(
        "c745e004030201"  # mov dword ptr [ebp-0x20], 0x01020304
        "b8d4d72722"  # mov eax, 0x2227d7d4
        "83c001"  # add eax, 1 (unsupported value propagation)
        "3145e0"  # xor dword ptr [ebp-0x20], eax
    )
    stack = MATERIAL.reconstruct_stack_constants(code, 0x1000)
    assert all(-0x20 + index not in stack for index in range(4))


def test_reconstruct_stack_constants_clears_register_at_call_boundary() -> None:
    code = bytes.fromhex(
        "c745e004030201"  # mov dword ptr [ebp-0x20], 0x01020304
        "b8d4d72722"  # mov eax, 0x2227d7d4
        "e800000000"  # call next instruction
        "3145e0"  # xor dword ptr [ebp-0x20], eax
    )
    stack = MATERIAL.reconstruct_stack_constants(code, 0x1000)
    assert all(-0x20 + index not in stack for index in range(4))


def test_reconstruct_stack_constants_invalidates_unknown_stack_byte_write() -> None:
    code = bytes.fromhex(
        "c745e041414141"  # mov dword ptr [ebp-0x20], 0x41414141
        "8845e0"  # mov byte ptr [ebp-0x20], al (AL is unknown)
    )
    stack = MATERIAL.reconstruct_stack_constants(code, 0x1000)
    assert -0x20 not in stack
    assert bytes(stack[-0x1F + index] for index in range(3)) == b"AAA"


def test_reconstruct_stack_constants_clears_on_indexed_stack_write() -> None:
    code = bytes.fromhex(
        "c745e041414141"  # mov dword ptr [ebp-0x20], 0x41414141
        "894c05e0"  # mov dword ptr [ebp+eax-0x20], ecx
    )
    stack = MATERIAL.reconstruct_stack_constants(code, 0x1000)
    assert stack == {}


def test_reconstruct_stack_constants_clears_on_unresolved_memory_write() -> None:
    code = bytes.fromhex(
        "c745e041414141"  # mov dword ptr [ebp-0x20], 0x41414141
        "8908"  # mov dword ptr [eax], ecx
    )
    stack = MATERIAL.reconstruct_stack_constants(code, 0x1000)
    assert stack == {}


def test_reconstruct_stack_constants_clears_stack_at_call_boundary() -> None:
    code = bytes.fromhex(
        "c745e041414141"  # mov dword ptr [ebp-0x20], 0x41414141
        "e800000000"  # unknown callee may modify caller locals by reference
        "90"
    )
    stack = MATERIAL.reconstruct_stack_constants(code, 0x1000)
    assert stack == {}


def test_reconstruct_stack_constants_invalidates_register_written_by_xor() -> None:
    code = bytes.fromhex(
        "c745e004030201"  # mov dword ptr [ebp-0x20], 0x01020304
        "b8d4d72722"  # mov eax, 0x2227d7d4
        "31c0"  # xor eax, eax (unsupported value propagation)
        "3145e0"  # xor dword ptr [ebp-0x20], eax
    )
    stack = MATERIAL.reconstruct_stack_constants(code, 0x1000)
    assert all(-0x20 + index not in stack for index in range(4))


def test_reconstruct_stack_constants_stops_at_unconditional_jump() -> None:
    code = bytes.fromhex(
        "c745e041414141"  # mov dword ptr [ebp-0x20], 0x41414141
        "eb07"  # jump over the unreachable write
        "c745e042424242"  # unreachable mov [ebp-0x20], 0x42424242
        "90"
    )
    stack = MATERIAL.reconstruct_stack_constants(code, 0x1000)
    assert bytes(stack[-0x20 + index] for index in range(4)) == b"AAAA"


def test_reconstruct_stack_constants_clears_state_at_conditional_jump() -> None:
    code = bytes.fromhex(
        "c745e041414141"  # mov dword ptr [ebp-0x20], 0x41414141
        "7407"  # conditional path split cannot be merged linearly
        "c745e042424242"
        "90"
    )
    stack = MATERIAL.reconstruct_stack_constants(code, 0x1000)
    assert stack == {}


def test_immediate_sequence_rejects_unreachable_fallthrough() -> None:
    code = bytes.fromhex(
        "eb07"  # jump to the trailing nop
        "c745e041414141"  # unreachable direct immediate sequence
        "90"
    )
    with pytest.raises(MATERIAL.ProbeMaterialError, match="unique branch-local"):
        MATERIAL._unique_direct_immediate_sequence(
            code,
            0x1000,
            stack_start=-0x20,
            count=1,
            name="unreachable",
        )


def test_xor_mask_sequence_rejects_unreachable_fallthrough() -> None:
    code = bytes.fromhex(
        "eb08"  # jump to the trailing nop
        "b8d4d72722"  # unreachable mov eax, 0x2227d7d4
        "3145e0"  # unreachable xor [ebp-0x20], eax
        "90"
    )
    with pytest.raises(MATERIAL.ProbeMaterialError, match="unique branch-local"):
        MATERIAL._unique_direct_xor_mask_sequence(
            code,
            0x1000,
            stack_start=-0x20,
            count=1,
            name="unreachable XOR",
        )


def test_build_artifacts_substitutes_bootstrap_and_public_is_hash_only() -> None:
    image = b"MZ" + bytes(range(128))
    records = [
        {
            "classification": "primary_candidate_seed",
            "candidate_index": index,
            "plaintext_hex": f"c{index:02d}.example.com".encode().hex(),
        }
        for index in range(1, 65)
    ]
    records.append(
        {
            "classification": "isolated_bootstrap_seed",
            "plaintext_hex": b"bootstrap.example.com".hex(),
        }
    )
    static_material = {
        "input_sha256": hashlib.sha256(image).hexdigest(),
        "records": records,
    }
    layout = {
        "selectors": tuple(range(1, 17)),
        "paths": tuple(f"/a{index:03d}/" for index in range(1, 17)),
        "path_base_key_sha256": "1" * 64,
        "path_dword_table_sha256": "2" * 64,
        "first_pkt2_key": bytes(range(20)),
        "bootstrap_slot": 12,
        "function_bounds": {
            "dispatcher": [0x1000, 0x1100],
            "initializer": [0x2000, 0x2100],
            "resources": [0x3000, 0x3100],
        },
    }
    private, public = MATERIAL.build_artifacts(
        image,
        static_material,
        sample_sha256="a" * 64,
        layout=layout,
        selected_slot=12,
    )
    assert private["host"] == "bootstrap.example.com"
    assert private["selector"] == 13
    assert private["http_path"] == "/a013/"
    assert private["selector_path_table"][12]["effective_host"] == (
        "bootstrap.example.com"
    )
    assert private["candidate_classification"] == "real_c2_decoy_unresolved"
    assert private["synthetic_template_id"] == MATERIAL.SYNTHETIC_TEMPLATE_ID
    assert private["pkt2_inner_plaintext_sha256"] is None
    assert private["request_wire_format"] == (
        "xloader-http11-get-crlf-v1"
    )
    assert private["request_sha256"] is None
    assert public["profile_activation_status"] == "blocked"
    assert public["required_synthetic_template_id"] == (
        MATERIAL.SYNTHETIC_TEMPLATE_ID
    )
    assert public["synthetic_pkt2_plaintext_reviewed"] is False
    assert public["request_wire_format"] == "xloader-http11-get-crlf-v1"
    assert public["request_sha256_reviewed"] is False
    assert public["independent_live_capture_fixture_available"] is False
    assert "canonical_request_sha256_not_reviewed" in public[
        "readiness_blockers"
    ]
    assert "independent_live_get_capture_fixture_unavailable" in public[
        "readiness_blockers"
    ]
    assert public["network_contacted"] is False
    assert public["sample_executed"] is False
    serialized = json.dumps(public, sort_keys=True)
    assert "bootstrap.example.com" not in serialized
    assert "c13.example.com" not in serialized
    assert "first_pkt2_rc4_key_base64" not in serialized
