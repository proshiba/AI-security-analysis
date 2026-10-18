from __future__ import annotations

import pytest

from unpackers import remcos_polymorphic_xor_loader as recovery

KEY = 0x6D57597D


def _jump_next(output: bytearray) -> None:
    output.extend(b"\xeb\x01\x90")


def _fixture(payload_size: int, *, direct_jumps: int = 40) -> bytes:
    expected_loop_size = ((payload_size + 3) & ~3) + 0x400
    output = bytearray()
    for instruction in (
        b"\x8b\x44\x24\x04",  # mov eax,[esp+4]
        b"\x8b\x7c\x24\x04",  # mov edi,[esp+4]
        b"\x89\x5c\x24\x0c",  # mov [esp+c],ebx
        b"\xff\xd2",  # call edx
        b"\xba" + expected_loop_size.to_bytes(4, "little"),
        b"\x33\xc0",  # xor eax,eax
        b"\x8b\x7c\x24\x0c",  # mov edi,[esp+c]
    ):
        output.extend(instruction)
        _jump_next(output)

    while output.count(b"\xeb\x01\x90") < direct_jumps - 5:
        output.extend(b"\x09\xc9")  # or ecx,ecx
        _jump_next(output)

    xor_offset = len(output)
    output.extend(b"\x81\x34\x07" + KEY.to_bytes(4, "little"))
    _jump_next(output)
    output.extend(b"\x83\xc0\x04")  # add eax,4
    _jump_next(output)
    output.extend(b"\x3b\xc2")  # cmp eax,edx
    _jump_next(output)
    branch_offset = len(output)
    branch_end = branch_offset + 6
    output.extend(
        b"\x0f\x85" + (xor_offset - branch_end).to_bytes(4, "little", signed=True)
    )
    output.extend(b"\xff\xd7")  # call edi
    _jump_next(output)
    # targetは追加後のloader末尾と一致する。
    output.extend(b"\xe9\x00\x00\x00\x00")
    return bytes(output)


def _encoded(clear: bytes) -> bytes:
    key = KEY.to_bytes(4, "little")
    return bytes(value ^ key[index & 3] for index, value in enumerate(clear))


def test_recovers_only_profile_bound_x86_shellcode() -> None:
    clear = b"reviewed-x86-shellcode" * 8
    report, artifacts = recovery.recover_remcos_polymorphic_xor_loader(
        _fixture(len(clear)), _encoded(clear)
    )

    assert report["status"] == "shellcode_recovered"
    assert report["candidate_set_complete"] is True
    assert report["architecture"] == "x86-32"
    assert report["input_padding_bytes"] == 0x400
    assert report["safety"]["sample_executed"] is False
    assert report["safety"]["emulation_used"] is False
    assert report["safety"]["raw_key_included"] is False
    assert KEY.to_bytes(4, "little").hex() not in repr(report)
    assert artifacts == [("remcos-polymorphic-xor-shellcode.bin", clear)]


def test_rejects_loader_payload_length_mismatch() -> None:
    clear = b"A" * 65
    report, artifacts = recovery.recover_remcos_polymorphic_xor_loader(
        _fixture(len(clear)), _encoded(clear + b"BBBB")
    )

    assert report["status"] == "xor_dataflow_not_unique"
    assert artifacts == []


def test_rejects_insufficient_polymorphic_cfg() -> None:
    clear = b"A" * 64
    report, artifacts = recovery.recover_remcos_polymorphic_xor_loader(
        _fixture(len(clear), direct_jumps=8), _encoded(clear)
    )

    assert report["status"] == "polymorphic_cfg_profile_rejected"
    assert artifacts == []


def test_reports_missing_capstone_without_fallback_emulation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear = b"A" * 64
    monkeypatch.setattr(recovery, "capstone", None)
    monkeypatch.setattr(recovery, "x86_const", None)

    report, artifacts = recovery.recover_remcos_polymorphic_xor_loader(
        _fixture(len(clear)), _encoded(clear)
    )

    assert report["status"] == "dependency_unavailable"
    assert artifacts == []
