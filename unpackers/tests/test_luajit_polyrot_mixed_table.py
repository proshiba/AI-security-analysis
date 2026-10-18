"""混在表記Lua置換表の静的PolyRot復元を検証する。"""

from __future__ import annotations

import base64
import struct

from unpackers import luajit_polyrot_mixed_table, static_unpacker


def _polyrot(payload: bytes, rotation: int) -> bytes:
    return bytes([128 + rotation]) + bytes(
        33 + ((value - 33 + rotation) % 94) if 33 <= value <= 126 else value
        for value in payload
    )


def _source_table() -> list[str]:
    alphabet = list("!#$%&()*,-.:;<>?@[\\]^_`{|}~")
    return [
        "".join(alphabet[(row + column) % len(alphabet)] for column in range(10))
        for row in range(25)
    ]


def _cell(value: str, index: int) -> str:
    if index % 3 == 0 and value not in {'"', "\\"}:
        return f'"{value}"'
    return f'"\\{ord(value):03d}"'


def _lua(payload: bytes, *, row_index: int, rotation: int, prefix: str) -> bytes:
    rows = _source_table()
    selected = rows[row_index]
    target = "ABCDEFabcd"
    encoded = base64.b64encode(_polyrot(payload, rotation)).decode()[::-1]
    encoded = encoded.translate(str.maketrans(target, selected))
    encoded_literal = encoded.replace("\\", "\\092").replace('"', "\\034")
    selector = (
        chr(ord("0") + row_index) if row_index < 10 else chr(ord("A") + row_index - 10)
    )
    table = ";".join(
        "{" + ",".join(_cell(value, index) for index, value in enumerate(row)) + "}"
        for row in rows
    )
    target_table = ";".join(_cell(value, index) for index, value in enumerate(target))
    return (
        f'local {prefix}_payload="|{selector}{encoded_literal}"\n'
        f"local {prefix}_rows={{{table}}}\n"
        f"local {prefix}_target={{{target_table}}}\n"
        f'local {prefix}_base64="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"\n'
        'if value:sub(1,1)~="\\124" then return end\n'
        "return (table.concat(output)):reverse()\n"
    ).encode()


def _donut_fixture() -> bytes:
    instance = bytes(range(256)) * 4
    return (
        b"\xe8" + struct.pack("<I", len(instance)) + instance + b"\x59\x31\xc0\x48\x0f"
    )


def test_recovers_two_mixed_table_variants_without_hash_profile() -> None:
    payload = _donut_fixture()
    for row_index, rotation, prefix in ((7, 19, "first"), (16, 37, "renamed")):
        report, artifacts = luajit_polyrot_mixed_table.recover_bytes(
            _lua(payload, row_index=row_index, rotation=rotation, prefix=prefix)
        )
        assert report["status"] == "donut_shellcode_recovered", (
            report.get("status"),
            report.get("payload_literal_count"),
            report.get("source_table_count"),
            report.get("attempt_count"),
            report.get("rejected_count"),
        )
        assert artifacts == [("luajit-polyrot-mixed-table-donut-shellcode", payload)]
        assert report["payloads"][0]["table_row"] == row_index
        assert "source_alphabet" not in report["payloads"][0]
        assert report["executed"] is False
        assert report["network_contacted"] is False


def test_rejects_table_whose_selected_row_does_not_match_payload() -> None:
    source = _lua(_donut_fixture(), row_index=16, rotation=37, prefix="mismatch")
    source = source.replace(b"local mismatch_rows={{", b'local mismatch_rows={{"!",', 1)
    report, artifacts = luajit_polyrot_mixed_table.recover_bytes(source)
    assert report["status"] == "strict_validation_failed", report
    assert artifacts == []


def test_rejects_missing_semantic_anchor() -> None:
    source = _lua(_donut_fixture(), row_index=7, rotation=19, prefix="anchor")
    source = source.replace(b":reverse()", b":forward()")
    report, artifacts = luajit_polyrot_mixed_table.recover_bytes(source)
    assert report["status"] == "semantic_anchor_missing"
    assert artifacts == []


def test_blocks_oversized_input(monkeypatch) -> None:
    monkeypatch.setattr(luajit_polyrot_mixed_table, "MAX_SCRIPT_SIZE", 32)
    report, artifacts = luajit_polyrot_mixed_table.recover_bytes(b"A" * 33)
    assert report["status"] == "size_blocked"
    assert artifacts == []


def test_static_unpacker_routes_mixed_table_lua_to_recursive_donut_layer() -> None:
    """共通pipelineが復元器を呼び、検証済みDonutだけを子層へ渡す。"""

    payload = _donut_fixture()
    report, artifacts = static_unpacker.unpack_bytes(
        _lua(payload, row_index=16, rotation=37, prefix="pipeline"),
        "loader.lua",
    )

    assert report["format"] == "script"
    assert report["luajit_polyrot_mixed_table"]["status"] == (
        "donut_shellcode_recovered"
    )
    assert (
        "luajit-polyrot-mixed-table-donut-shellcode",
        payload,
    ) in artifacts


def test_rejects_truncated_source_table_candidate_set(monkeypatch) -> None:
    source = _lua(_donut_fixture(), row_index=7, rotation=19, prefix="tables")
    lines = source.splitlines()
    duplicate = lines[1].replace(b"tables_rows", b"duplicate_rows", 1)
    source = b"\n".join([lines[0], lines[1], duplicate, *lines[2:]]) + b"\n"
    monkeypatch.setattr(luajit_polyrot_mixed_table, "MAX_TABLE_CANDIDATES", 1)

    report, artifacts = luajit_polyrot_mixed_table.recover_bytes(source)

    assert report["status"] == "candidate_limit_exceeded"
    assert report["candidate_set_complete"] is False
    assert report["candidate_set_truncated"] is True
    assert artifacts == []


def test_recovers_reviewed_variant_with_more_than_4096_local_assignments() -> None:
    filler = b"\n".join(f'local filler_{index}="x"'.encode() for index in range(4200))
    source = (
        filler
        + b"\n"
        + _lua(_donut_fixture(), row_index=7, rotation=19, prefix="many_locals")
    )

    report, artifacts = luajit_polyrot_mixed_table.recover_bytes(source)

    assert report["status"] == "donut_shellcode_recovered"
    assert len(artifacts) == 1


def test_attempt_limit_discards_earlier_success(monkeypatch) -> None:
    source = _lua(_donut_fixture(), row_index=7, rotation=19, prefix="attempt")
    lines = source.splitlines()
    duplicate = lines[1].replace(b"attempt_rows", b"duplicate_rows", 1)
    source = b"\n".join([lines[0], lines[1], duplicate, *lines[2:]]) + b"\n"
    monkeypatch.setattr(luajit_polyrot_mixed_table, "MAX_TRANSFORM_ATTEMPTS", 1)

    report, artifacts = luajit_polyrot_mixed_table.recover_bytes(source)

    assert report["status"] == "attempt_limit_exceeded"
    assert report["candidate_set_complete"] is False
    assert artifacts == []


def test_transform_work_limit_fails_closed(monkeypatch) -> None:
    source = _lua(_donut_fixture(), row_index=7, rotation=19, prefix="work")
    monkeypatch.setattr(luajit_polyrot_mixed_table, "MAX_TOTAL_TRANSFORM_BYTES", 1)

    report, artifacts = luajit_polyrot_mixed_table.recover_bytes(source)

    assert report["status"] == "transform_work_limit_exceeded"
    assert report["candidate_set_complete"] is False
    assert artifacts == []


def test_unterminated_quote_obeys_cumulative_scan_budget(monkeypatch) -> None:
    """大量の未終端quoteで入力全体を候補数回再走査しない。"""

    monkeypatch.setattr(luajit_polyrot_mixed_table, "MAX_TOTAL_QUOTED_SCAN_CHARS", 64)
    source = b'local first="' + b"A" * 256 + b'\nlocal second="unterminated'

    report, artifacts = luajit_polyrot_mixed_table.recover_bytes(source)

    assert report["status"] == "candidate_limit_exceeded"
    assert report["candidate_set_complete"] is False
    assert report["candidate_set_truncated"] is True
    assert artifacts == []
