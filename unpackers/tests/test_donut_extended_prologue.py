"""Donut loader prologueの有界なvariant認識を検証する。"""

from __future__ import annotations

import struct

from unpackers.donut_unpacker import find_donut_shellcodes, is_donut_shellcode


def _synthetic_shellcode(gap: int, prologue: bytes) -> bytes:
    instance = b"A" * 0x300
    return b"\xe8" + struct.pack("<I", len(instance)) + instance + bytes(gap) + prologue


def test_extended_loader_prologue_with_bounded_prefix() -> None:
    prologue = b"\x59\x5a\x51\x52\x81\xec\xd4\x02\x00\x00"
    shellcode = _synthetic_shellcode(0x20, prologue)
    assert is_donut_shellcode(shellcode)
    candidates = find_donut_shellcodes(shellcode, strides=(1,))
    assert len(candidates) == 1
    assert candidates[0].data == shellcode


def test_extended_loader_prologue_rejects_out_of_bound_prefix() -> None:
    prologue = b"\x59\x5a\x51\x52\x81\xec\xd4\x02\x00\x00"
    shellcode = _synthetic_shellcode(0x21, prologue)
    assert not is_donut_shellcode(shellcode)
    assert find_donut_shellcodes(shellcode, strides=(1,)) == []


def test_unknown_loader_prologue_is_not_promoted() -> None:
    shellcode = _synthetic_shellcode(0, b"\x90" * 12)
    assert not is_donut_shellcode(shellcode)
