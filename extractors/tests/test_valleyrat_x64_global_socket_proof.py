"""ValleyRAT x64 parsed-global／object／socket第二証明経路を検証する。"""

from __future__ import annotations

from itertools import pairwise
from types import SimpleNamespace

import pytest
from capstone import CS_ARCH_X86, CS_MODE_64, Cs
from capstone.x86 import X86_OP_MEM, X86_OP_REG

from extractors.valleyrat import extractor


def _x64_instructions(
    code: bytes,
    address: int,
) -> tuple[dict[int, object], dict[int, tuple[int, ...]]]:
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    disassembler.detail = True
    instructions = {item.address: item for item in disassembler.disasm(code, address)}
    ordered = sorted(instructions)
    successors = {
        current: ((following,) if instructions[current].mnemonic != "ret" else ())
        for current, following in pairwise(ordered)
    }
    if ordered:
        successors.setdefault(ordered[-1], ())
    return instructions, successors


def test_x64_static_callback_argument_is_recovered_fail_closed() -> None:
    """R8のRIP-relative callbackだけを復元し、直前clobberを拒否する。"""

    address = 0x140001000
    target = 0x140002000
    displacement = target - (address + 7)
    prefix = b"\x4c\x8d\x05" + displacement.to_bytes(4, "little", signed=True)
    call = b"\xff\x15\x00\x00\x00\x00"
    instructions, cfg = _x64_instructions(prefix + b"\x90" + call, address)
    callsite = max(instructions)

    assert extractor._vvas_x64_static_argument(
        instructions,
        cfg,
        callsite,
        "r8",
    ) == target

    clobbered, clobbered_cfg = _x64_instructions(
        prefix + b"\x45\x31\xc0" + call,
        address,
    )
    assert (
        extractor._vvas_x64_static_argument(
            clobbered,
            clobbered_cfg,
            max(clobbered),
            "r8",
        )
        is None
    )


def test_x64_vtable_materialization_requires_object_store() -> None:
    """LEAしたtableが同じregisterからobjectへ保存される場合だけ採用する。"""

    address = 0x140001000
    table = 0x140003000
    displacement = table - (address + 7)
    prefix = b"\x48\x8d\x05" + displacement.to_bytes(4, "little", signed=True)
    sections = [
        extractor._VvasPeSection(
            name=".rdata",
            virtual_start=table,
            virtual_end=table + 0x100,
            mapped_end=table + 0x100,
            raw_start=0,
            raw_end=0x100,
            executable=False,
            resource=False,
        )
    ]
    instructions, cfg = _x64_instructions(prefix + b"\x48\x89\x01\xc3", address)
    assert extractor._vvas_x64_vtable_references(
        instructions,
        cfg,
        sections,
    ) == {table: {address + 7}}

    global_store, global_cfg = _x64_instructions(
        prefix + b"\x48\x89\x05\x00\x00\x00\x00\xc3",
        address,
    )
    assert (
        extractor._vvas_x64_vtable_references(
            global_store,
            global_cfg,
            sections,
        )
        == {}
    )


def _summary(start: int, **values: object) -> SimpleNamespace:
    defaults: dict[str, object] = {
        "start": start,
        "direct_calls": set(),
        "callback_targets": set(),
        "callback_call_sites": {},
        "direct_call_sites": {},
        "instructions": {},
        "api_calls": set(),
        "vtable_target_sites": {},
    }
    defaults.update(values)
    return SimpleNamespace(**defaults)


def _proof_fixture(
    monkeypatch: pytest.MonkeyPatch,
    *,
    parser_present: bool = True,
    component_reachable: bool = True,
    descriptor: int = 3,
    send_field: int = 0x58,
    overwrite_global: bool = False,
) -> dict[str, object]:
    globals_ = frozenset({0x5000, 0x5010, 0x5020})
    operand_type = X86_OP_MEM if overwrite_global else X86_OP_REG
    callback_instructions = {
        index: SimpleNamespace(
            operands=[SimpleNamespace(type=operand_type, address=address)]
        )
        for index, address in enumerate(sorted(globals_))
    }
    summaries = {
        100: _summary(100),
        110: _summary(
            110,
            direct_calls={100},
            callback_targets={200},
            direct_call_sites={100: (10,)},
            callback_call_sites={200: (20,)},
        ),
        200: _summary(200, direct_calls={300}, instructions=callback_instructions),
        300: _summary(
            300,
            api_calls={("wsastartup", 3)},
            vtable_target_sites={400: (30,), 410: (30,), 420: (30,)},
        ),
        400: _summary(400),
        410: _summary(410),
        420: _summary(420),
    }
    monkeypatch.setattr(
        extractor,
        "_vvas_x64_parser_global_destinations",
        lambda *_args: ({100: (100, globals_)} if parser_present else {}),
    )
    monkeypatch.setattr(extractor, "_vvas_cfg_reaches", lambda *_args: True)
    monkeypatch.setattr(
        extractor,
        "_vvas_operand_address",
        lambda _instruction, operand, _pointer_size: getattr(
            operand,
            "address",
            None,
        ),
    )
    monkeypatch.setattr(
        extractor,
        "_vvas_x64_interface_virtual_calls",
        lambda _summary: 4,
    )

    def reachable(
        _summaries: dict[int, object],
        roots: tuple[int, ...],
    ) -> set[int]:
        if not component_reachable:
            return set()
        if roots == (200,):
            return set(summaries)
        return {400, 410, 420}

    monkeypatch.setattr(extractor, "_vvas_reachable_functions", reachable)
    monkeypatch.setattr(
        extractor,
        "_vvas_x64_socket_object_field",
        lambda summary, selected: (
            0x58 if summary.start == 400 and selected == 3 else None
        ),
    )
    monkeypatch.setattr(
        extractor,
        "_vvas_x64_io_object_field",
        lambda summary, selected, api: (
            send_field
            if summary.start == 410 and selected == 3 and api == "send"
            else (
                0x58
                if summary.start == 420 and selected == 3 and api == "recv"
                else None
            )
        ),
    )
    return extractor._vvas_parsed_global_object_socket_proof(
        [],
        summaries,
        {100: ({90}, {80})},
        [(0x6000, 0x6100)],
        set(summaries),
        descriptor,
    )


def test_parsed_global_object_socket_proof_accepts_complete_lineage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """parser、同一interface、同一descriptor/socket fieldが揃えば成立する。"""

    proof = _proof_fixture(monkeypatch)

    assert proof["matched"] is True
    assert proof["parsed_global_count"] == 3
    assert proof["object_socket_lineage_count"] == 1
    assert proof["network_groups"]["receive"] is True
    assert proof["raw_addresses_included"] is False


@pytest.mark.parametrize(
    "values",
    [
        {"parser_present": False},
        {"component_reachable": False},
        {"descriptor": 4},
        {"send_field": 0x60},
        {"overwrite_global": True},
    ],
)
def test_parsed_global_object_socket_proof_rejects_split_or_unproven_lineage(
    monkeypatch: pytest.MonkeyPatch,
    values: dict[str, object],
) -> None:
    """候補/importだけ、非到達、descriptor/object/socket分断を拒否する。"""

    proof = _proof_fixture(monkeypatch, **values)

    assert proof["matched"] is False


def test_parsed_global_object_socket_proof_requires_unique_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """mapped設定が複数なら完全なnetwork fixtureでも昇格しない。"""

    monkeypatch.setattr(
        extractor,
        "_vvas_x64_parser_global_destinations",
        lambda *_args: {100: (100, frozenset({1, 2, 3}))},
    )
    assert extractor._vvas_parsed_global_object_socket_proof(
        [],
        {},
        {},
        [(0x1000, 0x1100), (0x2000, 0x2100)],
        set(),
        3,
    )["matched"] is False
