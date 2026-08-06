"""XLoader JIT保護関数の自動静的復元を検証する。"""

from __future__ import annotations

import importlib.util
import struct
import sys
from pathlib import Path

import pytest

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


NATIVE = _load("xloader_protected_native", FORMBOOK / "native_xloader.py")
PROTECTED = _load(
    "xloader_protected_functions", FORMBOOK / "protected_functions.py"
)


def _call(source: int, target: int) -> bytes:
    return b"\xe8" + struct.pack("<i", target - (source + 5))


def _synthetic_image(*, duplicate_start: bool = False):
    base = (0x10203040, 0x50607080, 0x90A0B0C0, 0xD0E0F000, 0x12345678)
    xor_constant = 0x33333333
    seed = 0x11111111
    mix = 0x22222222
    start_marker = b"START!"
    end_marker = b"!END!!"
    body = b"\x55\x8b\xec\x83\xec\x08\x33\xc0\xc3"
    descriptor = NATIVE.ProtectedFunctionDescriptor(
        name="synthetic",
        seed=seed,
        mix=mix,
        encrypted_start_marker=b"",
        encrypted_end_marker=b"",
    )
    key = NATIVE.derive_protected_function_key(descriptor, base, xor_constant)
    encrypted_start = NATIVE.encrypt_rc4_sub(start_marker, key)
    encrypted_end = NATIVE.encrypt_rc4_sub(end_marker, key)
    encrypted_body = NATIVE.encrypt_rc4_sub(body, key)

    decrypt_target = 0x100
    wrapper_start = 0x200
    caller_start = 0x300
    marker_offset = 0x500
    image = bytearray(b"\x90" * 0x800)
    wrapper = bytearray(b"\x55\x8b\xec")
    wrapper += b"\xc7\x45\xc0" + struct.pack("<I", seed)
    wrapper += b"\xc7\x45\xec" + encrypted_start[:4]
    wrapper += b"\x66\xc7\x45\xf0" + encrypted_start[4:]
    wrapper += b"\xc7\x45\xdc" + encrypted_end[:4]
    wrapper += b"\x66\xc7\x45\xe0" + encrypted_end[4:]
    wrapper += b"\x8b\x45\x08"  # mov eax,[ebp+8]
    wrapper += b"\x8b\x48\x04"  # mov ecx,[eax+4]
    wrapper += b"\x89\x8d\x78\xff\xff\xff"  # mov [ebp-0x88],ecx
    decrypt_call = wrapper_start + len(wrapper)
    wrapper += _call(decrypt_call, decrypt_target)
    protected_call = wrapper_start + len(wrapper)
    wrapper += _call(protected_call, marker_offset + len(start_marker))
    wrapper += b"\xc3"
    image[wrapper_start : wrapper_start + len(wrapper)] = wrapper

    caller = bytearray(b"\x55\x8b\xec")
    caller += b"\xc7\x45\xc0" + struct.pack("<I", 0xAABBCCDD)
    caller += b"\xc7\x45\xc4" + struct.pack("<I", mix)
    caller += b"\x8d\x45\xc0\x50"
    caller_call = caller_start + len(caller)
    caller += _call(caller_call, wrapper_start)
    caller += b"\xc3"
    image[caller_start : caller_start + len(caller)] = caller

    protected = start_marker + encrypted_body + end_marker
    image[marker_offset : marker_offset + len(protected)] = protected
    if duplicate_start:
        image[0x600 : 0x600 + len(start_marker)] = start_marker

    profile = PROTECTED.ProtectedFunctionProfile(
        base_key_dwords=base,
        xor_constant=xor_constant,
        decrypt_call_targets=frozenset({decrypt_target}),
        restore_targets=frozenset(),
        minimum_x86_score=1,
    )
    return bytes(image), profile, body, wrapper_start, mix


def test_caller_dataflow_recovers_protected_function() -> None:
    image, profile, body, wrapper_start, _ = _synthetic_image()

    patched, report = PROTECTED.recover_protected_functions(
        image, profile, allow_constant_fallback=False
    )

    assert body in patched
    assert report["wrapper_count"] == 1
    assert report["recovered_count"] == 1
    assert report["unresolved_count"] == 0
    assert report["dataflow_recovered_count"] == 1
    assert report["functions"][0]["wrapper_start"] == wrapper_start
    assert "mix" not in report["functions"][0]


def test_duplicate_start_marker_fails_closed() -> None:
    image, profile, _, _, mix = _synthetic_image(duplicate_start=True)
    wrapper = PROTECTED.find_wrappers(image, profile)[0]

    with pytest.raises(PROTECTED.ProtectedFunctionError, match="一意"):
        PROTECTED.recover_wrapper(image, wrapper, mix, profile)


def test_profile_requires_key_and_decrypt_targets() -> None:
    with pytest.raises(PROTECTED.ProtectedFunctionError, match="必要"):
        PROTECTED.profile_from_mapping(
            {"base_key_dwords": [], "decrypt_call_targets": []}
        )
