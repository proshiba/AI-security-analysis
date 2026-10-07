"""XLoader JIT保護関数profileのfail-closed自動導出を検証する。"""

from __future__ import annotations

import importlib.util
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FORMBOOK = ROOT / "analysis-framework" / "malware" / "formbook_loader"
sys.path.insert(0, str(FORMBOOK))


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


NATIVE = _load("xloader_auto_profile_native", FORMBOOK / "native_xloader.py")
PROTECTED = _load(
    "xloader_auto_profile_protected", FORMBOOK / "protected_functions.py"
)


def _call(source: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target - (source + 5))


def _write_relative_call(buffer: bytearray, base: int, target: int) -> None:
    source = base + len(buffer)
    buffer += _call(source, target)


def _synthetic_auto_profile_image() -> tuple[bytes, tuple[bytes, ...], int]:
    base_key = (
        0x10203040,
        0x50607080,
        0x90A0B0C0,
        0xD0E0F000,
        0x12345678,
    )
    xor_constant = 0x33333333
    helper_offset = 0x100
    copy_offset = 0x1E0
    core_offset = 0x240
    decrypt_target = 0x340
    restore_target = 0x380
    wrapper_offsets = (0x500, 0x600, 0x700, 0x800)
    caller_offsets = (0x900, 0x980, 0xA00, 0xA80)
    marker_offsets = (0x1200, 0x1280, 0x1300, 0x1380)
    image = bytearray(b"\x90" * 0x1800)

    helper = bytearray(b"\x55\x8b\xec\x83\xec\x24\x8b\x4d\x08")
    helper += b"\xb8" + struct.pack("<I", xor_constant)
    for index, value in enumerate(base_key):
        displacement = -0x24 + index * 4
        helper += b"\xc7\x45" + struct.pack("b", displacement)
        helper += struct.pack("<I", value ^ xor_constant)
        helper += b"\x31\x45" + struct.pack("b", displacement)
    helper += b"\x6a\x14\x8d\x45\xdc\x50\x51"
    _write_relative_call(helper, helper_offset, copy_offset)
    helper += b"\x83\xc4\x0c\xc9\xc3"
    image[helper_offset : helper_offset + len(helper)] = helper
    image[copy_offset] = 0xC3

    core = bytearray(b"\x55\x8b\xec\x53\x56\x57")
    core += b"\x8b\x7d\x0c"
    core += b"\x8b\x87\x80\x00\x00\x00"
    core += b"\x31\x87\x18\x00\x00\x00"
    core += b"\x8b\x5f\x18\x8d\x77\x44\x56"
    core += b"\xc7\x87\x7c\x00\x00\x00" + struct.pack(
        "<I", xor_constant
    )
    core += b"\xc7\x47\x14\x06\x00\x00\x00"
    core += b"\x81\xf3" + struct.pack("<I", xor_constant)
    _write_relative_call(core, core_offset, helper_offset)
    core += b"\x83\xc4\x04"
    core += b"\x31\x1e\x31\x5e\x04\x31\x5e\x08\x31\x5e\x0c\x31\x5e\x10"
    core += b"\x8d\x47\x6c\x8d\x4f\x34\x5f\x5e\x5b\xc9\xc3"
    image[core_offset : core_offset + len(core)] = core

    thunk = bytearray(b"\x55\x8b\xec\x8b\x45\x0c\x8b\x4d\x08")
    thunk += b"\x6a\x00\x50\x51"
    _write_relative_call(thunk, decrypt_target, core_offset)
    thunk += b"\x83\xc4\x0c\x5d\xc3"
    image[decrypt_target : decrypt_target + len(thunk)] = thunk
    image[restore_target : restore_target + 4] = b"\x55\x8b\xec\xc3"

    recovered_bodies: list[bytes] = []
    for index, (wrapper_offset, caller_offset, marker_offset) in enumerate(
        zip(wrapper_offsets, caller_offsets, marker_offsets, strict=True)
    ):
        seed = 0x11111111 + index
        mix = 0x22222222 + index
        start_marker = f"S{index:02d}!?!".encode("ascii")
        end_marker = f"E{index:02d}!?!".encode("ascii")
        body = b"\x55\x8b\xec\x33\xc0\x5d\xc3" + bytes([0x90 + index])
        recovered_bodies.append(body)
        descriptor = NATIVE.ProtectedFunctionDescriptor(
            name=f"synthetic_{index}",
            seed=seed,
            mix=mix,
            encrypted_start_marker=b"",
            encrypted_end_marker=b"",
        )
        key = NATIVE.derive_protected_function_key(
            descriptor, base_key, xor_constant
        )
        encrypted_start = NATIVE.encrypt_rc4_sub(start_marker, key)
        encrypted_end = NATIVE.encrypt_rc4_sub(end_marker, key)
        encrypted_body = NATIVE.encrypt_rc4_sub(body, key)
        image[
            marker_offset : marker_offset
            + len(start_marker)
            + len(encrypted_body)
            + len(end_marker)
        ] = start_marker + encrypted_body + end_marker

        wrapper = bytearray(b"\x55\x8b\xec\x81\xec\x90\x00\x00\x00")
        wrapper += b"\x8b\x45\x08\x8b\x48\x04"
        wrapper += b"\x8d\x95\x70\xff\xff\xff\x52\x6a\x00"
        wrapper += b"\xc7\x45\x88" + struct.pack("<I", seed)
        wrapper += b"\x89\x4d\xf0"
        wrapper += b"\xc7\x45\xdc" + encrypted_start[:4]
        wrapper += b"\x66\xc7\x45\xe0" + encrypted_start[4:]
        wrapper += b"\xc7\x45\xa4" + encrypted_end[:4]
        wrapper += b"\x66\xc7\x45\xa8" + encrypted_end[4:]
        _write_relative_call(wrapper, wrapper_offset, decrypt_target)
        wrapper += b"\x83\xc4\x08\x85\xc0\x74\x10"
        _write_relative_call(
            wrapper, wrapper_offset, marker_offset + len(start_marker)
        )
        wrapper += b"\x8d\x85\x70\xff\xff\xff\x50"
        _write_relative_call(wrapper, wrapper_offset, restore_target)
        wrapper += b"\x83\xc4\x04\xc9\xc3"
        image[wrapper_offset : wrapper_offset + len(wrapper)] = wrapper

        caller = bytearray(b"\x55\x8b\xec\x83\xec\x40")
        caller += b"\xc7\x45\xc0\xef\xbe\xad\xde"
        caller += b"\xc7\x45\xc4" + struct.pack("<I", mix)
        caller += b"\x8d\x45\xc0\x50"
        _write_relative_call(caller, caller_offset, wrapper_offset)
        caller += b"\x83\xc4\x04\xc9\xc3"
        image[caller_offset : caller_offset + len(caller)] = caller

    return bytes(image), tuple(recovered_bodies), helper_offset


def test_auto_profile_discovery_and_iterative_recovery() -> None:
    image, bodies, _ = _synthetic_auto_profile_image()

    discovery = PROTECTED.discover_protected_function_profile(image)

    assert discovery.status == "resolved"
    assert discovery.profile is not None
    assert discovery.validated_wrapper_count == 4
    assert discovery.profile.seed_displacement == -0x78
    assert discovery.profile.start_marker_displacement == -0x24
    assert discovery.profile.end_marker_displacement == -0x5C
    assert discovery.profile.mix_destination_displacement == -0x10

    patched, report = PROTECTED.recover_protected_functions_auto(
        image,
        allow_constant_fallback=False,
        allow_target_marker_fallback=False,
    )

    assert all(body in patched for body in bodies)
    assert report["wrapper_count"] == 4
    assert report["recovered_count"] == 4
    assert report["unresolved_count"] == 0
    assert report["profile_source"] == "statically_derived"
    public = report["profile_discovery"]
    assert public["profile_material_published"] is False
    assert public["base_key_published"] is False
    assert public["xor_constant_published"] is False
    serialized = json.dumps(public, sort_keys=True)
    assert "base_key_dwords" not in serialized
    assert str(0x33333333) not in serialized


def test_auto_profile_fails_closed_without_unique_base_key_copy() -> None:
    image, _, helper_offset = _synthetic_auto_profile_image()
    mutable = bytearray(image)
    push_length = mutable.find(b"\x6a\x14", helper_offset, helper_offset + 0x100)
    assert push_length >= 0
    mutable[push_length + 1] = 0x13

    discovery = PROTECTED.discover_protected_function_profile(bytes(mutable))

    assert discovery.status == "not_found"
    assert discovery.profile is None
    assert "key_schedule_not_found" in discovery.reason_codes


def test_auto_recovery_keeps_missing_marker_as_explicit_blocker() -> None:
    image, _, _ = _synthetic_auto_profile_image()
    mutable = bytearray(image)
    marker_offset = mutable.find(b"S00!?!")
    assert marker_offset >= 0
    mutable[marker_offset : marker_offset + 6] = b"BROKEN"

    _, report = PROTECTED.recover_protected_functions_auto(
        bytes(mutable),
        allow_constant_fallback=False,
        allow_target_marker_fallback=False,
    )

    assert report["unresolved_count"] == 1
    unresolved = report["unresolved"][0]
    assert unresolved["blocked"] is True
    assert unresolved["blocker_code"] == "validated_marker_pair_not_observed"
    assert unresolved["validated_marker_pair_observed"] is False


def test_builder_inventory_classifies_64_plus_1_plus_8_without_values() -> None:
    encoded = b"QUJDREVGRw=="
    main_offsets = [0x1000 + index * 0x60 for index in range(64)]
    bootstrap_offset = 0x4000
    auxiliary_offsets = [
        0x4900,
        0x4960,
        0x49C0,
        0x4A20,
        0x6000,
        0x6060,
        0x60C0,
        0x6120,
    ]
    builders = [
        NATIVE.DecodedBuilder(
            function_offset=offset,
            bl_value=0,
            decoded=encoded,
        )
        for offset in [*main_offsets, bootstrap_offset, *auxiliary_offsets]
    ]

    inventory = NATIVE.inventory_encoded_network_candidates(builders)

    assert inventory["primary_layout_cluster_candidate_count"] == 64
    assert inventory["bootstrap_layout_resolved"] is True
    assert inventory["bootstrap_layout_candidate_count"] == 1
    assert inventory["auxiliary_layout_candidate_count"] == 8
    assert inventory["unclassified_non_primary_candidate_count"] == 0
    assert inventory["values_retained"] is False
