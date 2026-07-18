from __future__ import annotations

import pytest

from unpackers.nsis_unpacker import (
    DEFAULT_WORD_XOR_KEY,
    apply_dword_xor,
    decode_nsis_hex_xor_words,
    extract_system_call_fragments,
    find_static_dword_xor_loop,
    recover_nsis_scripted_layers,
)


def _encode_words(decoded: bytes, key: int = DEFAULT_WORD_XOR_KEY) -> bytes:
    assert len(decoded) % 4 == 0
    return b"".join(
        f"{int.from_bytes(decoded[index : index + 4], 'big') ^ key:08X}".encode()
        for index in range(0, len(decoded), 4)
    )


def _xor_loop_stub(key: int = 0x11223344, length: int = 16) -> bytes:
    return (
        b"\x48\xc7\xc0\x00\x00\x00\x00"  # mov rax, 0
        + b"\xbb"
        + key.to_bytes(4, "little")  # mov ebx, key
        + b"\x48\xc7\xc2"
        + length.to_bytes(4, "little")  # mov rdx, length
        + b"\x41\x31\x1c\x01"  # xor dword ptr [r9 + rax], ebx
        + b"\x48\x83\xc0\x04"  # add rax, 4
        + b"\x48\x39\xd0"  # cmp rax, rdx
        + b"\x75\xf3"  # jne loop
    )


def test_decode_nsis_hex_xor_words_and_calls() -> None:
    decoded = b"KERNEL32::ReadFile(ir5, i r1, i 16,*i 0, i 0)Q"
    decoded += b"_" * (-len(decoded) % 4)
    report, output = decode_nsis_hex_xor_words(
        b"0" * 12 + _encode_words(decoded), read_chars=len(decoded) * 2
    )
    assert output == decoded
    assert report["status"] == "decoded"
    assert report["group_count"] == 2
    assert report["system_calls"] == ["KERNEL32::ReadFile(ir5, i r1, i 16,*i 0, i 0)"]


def test_extract_system_call_fragments_strips_group_marker() -> None:
    calls = extract_system_call_fragments(
        b"\xffQKERNEL32::SetFilePointer(ir5, i 64, i 0,i 0)Q"
    )
    assert calls == ["KERNEL32::SetFilePointer(ir5, i 64, i 0,i 0)"]


def test_find_static_dword_xor_loop() -> None:
    pytest.importorskip("capstone")
    report = find_static_dword_xor_loop(_xor_loop_stub())
    assert report["status"] == "identified"
    assert report["key"] == 0x11223344
    assert report["length"] == 16
    assert report["step"] == 4


def test_apply_dword_xor_round_trip() -> None:
    original = bytes(range(16))
    encoded = apply_dword_xor(original, 0x11223344, len(original))
    assert apply_dword_xor(encoded, 0x11223344, len(original)) == original
    with pytest.raises(ValueError):
        apply_dword_xor(b"", 1, 3)


def test_recover_nsis_scripted_layers() -> None:
    pytest.importorskip("capstone")
    stub = _xor_loop_stub()
    key = 0x11223344
    decoded_payload = b"static-layer-123"
    assert len(decoded_payload) == 16
    encoded_payload = apply_dword_xor(decoded_payload, key, len(decoded_payload))
    command_stream = (
        f"KERNEL32::SetFilePointer(ir5, i 16, i 0,i 0)Q"
        f"KERNEL32::ReadFile(ir5, i r1, i {len(stub)},*i 0,i 0)Q"
        f"KERNEL32::SetFilePointer(ir5, i 64, i 0,i 0)Q"
    ).encode()
    command_stream += b"_" * (-len(command_stream) % 4)
    encoded_commands = _encode_words(command_stream)
    script = f"""
StrCpy $R9 {DEFAULT_WORD_XOR_KEY}
StrCpy $4 $INSTDIR\\Flagskibene
StrCpy $_51_ $INSTDIR\\Pengeoverfrsel\\Drbler
FileSeek $_52_ 12
FileRead $_52_ $_53_ {len(encoded_commands)}
""".encode()
    payload = bytearray(64 + len(encoded_payload))
    payload[16 : 16 + len(stub)] = stub
    payload[64:] = encoded_payload
    files = {
        "[NSIS].nsi": script,
        "Pengeoverfrsel/Drbler": b"0" * 12 + encoded_commands,
        "Flagskibene": bytes(payload),
    }
    report, artifacts = recover_nsis_scripted_layers(files)
    assert report["stage_recovery"]["status"] == "intermediate_recovered"
    assert artifacts[-1] == ("nsis-static-dword-xor-stage", decoded_payload)


def test_recover_nsis_layers_without_decompiled_script() -> None:
    """Use a corroborated encoded call stream when 7-Zip omits [NSIS].nsi."""
    pytest.importorskip("capstone")
    stub = _xor_loop_stub()
    key = 0x11223344
    decoded_payload = b"static-layer-123"
    encoded_payload = apply_dword_xor(decoded_payload, key, len(decoded_payload))
    command_stream = (
        b"KERNEL32::VirtualAlloc(i0,i 16,i 0x3000,i 0x40)Q"
        b"KERNEL32::SetFilePointer(ir5,i 16,i 0,i 0)Q"
        b"KERNEL32::ReadFile(ir5,i r1,i "
        + str(len(stub)).encode()
        + b",*i 0,i 0)Q"
        b"KERNEL32::SetFilePointer(ir5,i 64,i 0,i 0)Q"
    )
    command_stream += b"Q" * ((4 - len(command_stream) % 4) % 4)
    encoded_commands = _encode_words(command_stream)
    payload = bytearray(64 + len(encoded_payload))
    payload[16 : 16 + len(stub)] = stub
    payload[64:] = encoded_payload
    files = {
        "Pengeoverfrsel/Drbler": b"0" * 12 + encoded_commands,
        "Flagskibene": bytes(payload),
        "LargerUnrelated": b"Z" * 4096,
    }
    report, artifacts = recover_nsis_scripted_layers(files)
    assert report["recovery_basis"] == "corroborated_encoded_command_stream"
    assert report["stage_recovery"]["status"] == "intermediate_recovered"
    assert report["stage_recovery"]["payload_data"] == "Flagskibene"
    assert artifacts[-1] == ("nsis-static-dword-xor-stage", decoded_payload)


def test_scriptless_nsis_recovery_rejects_ambiguous_payloads() -> None:
    """Fail closed when two payload files pass bounds and XOR-loop validation."""
    pytest.importorskip("capstone")
    stub = _xor_loop_stub()
    command_stream = (
        b"KERNEL32::VirtualAlloc(i0,i 16,i 0x3000,i 0x40)Q"
        b"KERNEL32::SetFilePointer(ir5,i 16,i 0,i 0)Q"
        b"KERNEL32::ReadFile(ir5,i r1,i "
        + str(len(stub)).encode()
        + b",*i 0,i 0)Q"
        b"KERNEL32::SetFilePointer(ir5,i 64,i 0,i 0)Q"
    )
    command_stream += b"Q" * ((4 - len(command_stream) % 4) % 4)
    encoded_commands = _encode_words(command_stream)
    payload = bytearray(80)
    payload[16 : 16 + len(stub)] = stub
    files = {
        "Pengeoverfrsel/Drbler": b"0" * 12 + encoded_commands,
        "ValidOne": bytes(payload),
        "ValidTwo": bytes(payload),
    }
    report, artifacts = recover_nsis_scripted_layers(files)
    assert report["stage_recovery"] == {
        "status": "ambiguous_scriptless_payload_candidates",
        "candidate_count": 2,
        "candidate_names": ["ValidOne", "ValidTwo"],
    }
    assert [name for name, _ in artifacts] == ["nsis-xor-command-stream"]


def test_scriptless_nsis_recovery_rejects_ambiguous_streams() -> None:
    """Fail closed when more than one file matches the command-stream shape."""
    command_stream = (
        b"KERNEL32::VirtualAlloc(i0,i 16,i 0x3000,i 0x40)Q"
        b"KERNEL32::SetFilePointer(ir5,i 16,i 0,i 0)Q"
        b"KERNEL32::ReadFile(ir5,i r1,i 16,*i 0,i 0)Q"
    )
    command_stream += b"Q" * ((4 - len(command_stream) % 4) % 4)
    encoded = b"0" * 12 + _encode_words(command_stream)
    report, artifacts = recover_nsis_scripted_layers({"one": encoded, "two": encoded})
    assert report["status"] == "ambiguous_scriptless_command_stream"
    assert report["candidate_count"] == 2
    assert artifacts == []
