from __future__ import annotations

import pytest

from unpackers import remcos_obfuscated_shellcode as profile


def _rel32(source: int, target: int) -> bytes:
    return (target - source - 5).to_bytes(4, "little", signed=True)


def _place(output: bytearray, offset: int, value: bytes) -> None:
    output[offset : offset + len(value)] = value


def _fixture() -> bytes:
    output = bytearray(b"\x90" * 0x400)
    _place(output, 0, b"\x5e\x56\xe9" + _rel32(2, 0x20))

    bootstrap = bytearray(b"\xe8" + _rel32(0x20, 0x300))
    bootstrap += b"\x85\xd8"  # test eax,ebx
    bootstrap += b"\xc6\x00\xf7"  # mov byte ptr [eax],0xf7
    bootstrap += b"\x80\x00\x9e"  # add byte ptr [eax],0x9e
    bootstrap += b"\x80\x30\x88"  # xor byte ptr [eax],0x88
    bootstrap += b"\x80\x30\x1d"  # xor byte ptr [eax],0x1d -> 0
    jump_offset = 0x20 + len(bootstrap)
    bootstrap += b"\xe9" + _rel32(jump_offset, 0x50)
    _place(output, 0x20, bytes(bootstrap))

    branch_end = 0x50 + 1 + 2 + 2
    _place(
        output,
        0x50,
        b"\x40\x39\xc6\x75" + (0x25 - branch_end).to_bytes(1, "little", signed=True),
    )
    _place(
        output,
        0x55,
        b"\xb8\x78\x56\x34\x12\xeb\x07"
        + b"\x90" * 7
        + b"\x86\xe4"
        + b"\x3d\x78\x56\x34\x12\x74\x14",
    )

    stack = bytearray(
        b"\x5b"  # pop ebx
        b"\x89\xe5"  # mov ebp,esp
        b"\x81\xec\x00\x03\x00\x00"  # sub esp,0x300
        b"\x55"  # push ebp
        b"\x89\xe5"  # mov ebp,esp
        b"\xb9\x18\x00\x00\x00"  # mov ecx,0x18
    )
    zero_offset = 0x80 + len(stack)
    stack += b"\xc7\x44\x0d\x00\x00\x00\x00\x00"
    stack += b"\x83\xc1\x04"
    stack += b"\x89\x8d\x00\x02\x00\x00"
    stack += b"\xb9\x78\x01\x00\x00"
    stack += b"\x39\x8d\x00\x02\x00\x00"
    stack += b"\x8b\x8d\x00\x02\x00\x00"
    branch_offset = 0x80 + len(stack)
    stack += b"\x0f\x85" + (zero_offset - branch_offset - 6).to_bytes(
        4, "little", signed=True
    )
    _place(output, 0x80, bytes(stack))

    helper = bytearray(
        b"\x8b\x5c\x24\x04"  # mov ebx,[esp+4]
        b"\x43"  # inc ebx
        b"\x87\xc9"  # xchg ecx,ecx
        b"\x4b"  # dec ebx
        b"\x31\xd2"  # xor edx,edx
        b"\x89\xd8"  # mov eax,ebx
        b"\xb9\x20\x00\x00\x00"  # mov ecx,0x20
        b"\xc1\xc1\x07"  # rol ecx,7 -> 0x1000
        b"\xf7\xf1"  # div ecx
        b"\x83\xfa\x00"  # cmp edx,0
    )
    helper_branch = 0x300 + len(helper)
    helper += b"\x75" + (0x305 - helper_branch - 2).to_bytes(1, "little", signed=True)
    helper += b"\x89\xd8\xc2\x04\x00"
    _place(output, 0x300, bytes(helper))
    return bytes(output)


def test_confirms_bounded_page_erasing_bootstrap() -> None:
    report = profile.analyze_remcos_obfuscated_shellcode(_fixture())

    assert report["status"] == "bootstrap_profile_confirmed"
    assert report["candidate_set_complete"] is True
    assert report["architecture"] == "x86-32"
    assert report["self_erasure"]["caller_page_alignment_bytes"] == 0x1000
    assert report["stack_initialization"] == {
        "allocation_bytes": 0x300,
        "zero_start_offset": 0x18,
        "zero_end_exclusive": 0x178,
        "zero_stride_bytes": 4,
        "zero_iteration_count": 88,
    }
    assert report["safety"]["shellcode_executed"] is False
    assert report["safety"]["emulation_used"] is False
    assert report["evidence_boundary"]["terminal_payload_recovered"] is False


def test_rejects_nonzero_self_erasure_writer() -> None:
    data = bytearray(_fixture())
    data[0x32] ^= 1

    report = profile.analyze_remcos_obfuscated_shellcode(bytes(data))

    assert report["status"] == "zero_writer_nonzero_result"
    assert report["candidate_set_complete"] is False


def test_rejects_stack_allocation_mismatch() -> None:
    data = bytearray(_fixture())
    data[0x85] = 1

    report = profile.analyze_remcos_obfuscated_shellcode(bytes(data))

    assert report["status"] == "stack_allocation_rejected"


def test_dependency_unavailable_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(profile, "capstone", None)

    report = profile.analyze_remcos_obfuscated_shellcode(_fixture())

    assert report["status"] == "dependency_unavailable"
    assert report["candidate_set_complete"] is False
