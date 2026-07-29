"""LuaJIT PolyRot自動復元器の構造ベース判定を検証する。"""

from __future__ import annotations

import base64
import struct

from unpackers import luajit_polyrot_auto


def _polyrot(payload: bytes, rotation: int) -> bytes:
    return bytes([128 + rotation]) + bytes(
        33 + ((value - 33 + rotation) % 94) if 33 <= value <= 126 else value
        for value in payload
    )


def _source_table() -> list[str]:
    alphabet = list("!#$%&()*,-.:;<=>?@[\\]^_`{|}~")
    return [
        "".join(alphabet[(row + column) % len(alphabet)] for column in range(10))
        for row in range(25)
    ]


def _lua(payload: bytes) -> bytes:
    rows = _source_table()
    selected = rows[16]
    target = "ABCDEFabcd"
    encoded = base64.b64encode(_polyrot(payload, 7)).decode()[::-1]
    encoded = encoded.translate(str.maketrans(target, selected))
    table = ";".join(
        "{" + ",".join(f'"\\{ord(value):03d}"' for value in row) + "}"
        for row in rows
    )
    target_table = ",".join(f'"\\{ord(value):03d}"' for value in target)
    return (
        f'local PAYLOAD="|G{encoded}"\n'
        f"local TABLE={{{table}}}\n"
        f"local TARGET={{{target_table}}}\n"
        'if E:sub(1,1)~="\\124" then return end\n'
        "function PolyRot(E) return E end\n"
        "NtAllocateVirtualMemory()\n"
    ).encode()


def test_recovers_unseen_table_and_variable_without_hash_profile() -> None:
    payload = b"\xe8" + struct.pack("<I", 1024) + b"A" * 1024 + b"YU\x48\x89\xe5"
    report, artifacts = luajit_polyrot_auto.recover_bytes(_lua(payload))
    assert report["status"] == "donut_shellcode_recovered"
    assert artifacts == [("luajit-polyrot-donut-shellcode", payload)]
    assert report["payloads"][0]["table_row"] == 16


def test_rejects_lua_without_polyrot_structure() -> None:
    report, artifacts = luajit_polyrot_auto.recover_bytes(b"local x='ordinary'")
    assert report["status"] == "pattern_not_found"
    assert artifacts == []
