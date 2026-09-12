"""managed resource外層とnative parser wrapperの静的lineageを検証する。"""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from capstone import CS_ARCH_X86, CS_MODE_32, Cs

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
FRAMEWORK_ROOT = REPOSITORY_ROOT / "analysis-framework"
COMMON_ROOT = FRAMEWORK_ROOT / "common"
for root in (REPOSITORY_ROOT, FRAMEWORK_ROOT, COMMON_ROOT):
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

from extractors.valleyrat import extractor  # noqa: E402

from malware.valleyrat import managed_vvas_lineage as lineage  # noqa: E402

CALLS = {
    1: "System.Reflection.Assembly.GetExecutingAssembly",
    2: "System.Resources.ResourceManager..ctor",
    3: "System.Environment.GetFolderPath",
    4: "System.String.Concat",
    5: "System.Resources.ResourceManager.GetObject",
    6: "System.IO.File.WriteAllBytes",
    7: "System.Diagnostics.Process.Start",
}
STRINGS = {
    101: "bundle",
    102: "resource-one",
    103: "resource-two",
    104: "\\first.bin",
    105: "\\second.bin",
    106: "\\different.bin",
}


def _instruction(name: str, operand: object = None) -> SimpleNamespace:
    return SimpleNamespace(
        opcode=SimpleNamespace(name=name),
        operand=SimpleNamespace(value=operand),
    )


def _path(suffix_token: int) -> list[SimpleNamespace]:
    return [
        _instruction("ldc.i4.s", 26),
        _instruction("call", 3),
        _instruction("ldstr", suffix_token),
        _instruction("call", 4),
    ]


def _drop_start_chain(key_token: int, suffix_token: int) -> list[SimpleNamespace]:
    return [
        *_path(suffix_token),
        _instruction("ldloc.0"),
        _instruction("ldstr", key_token),
        _instruction("callvirt", 5),
        _instruction("castclass", 200),
        _instruction("call", 6),
        *_path(suffix_token),
        _instruction("call", 7),
        _instruction("pop"),
    ]


def _managed_method(second_start_suffix: int = 105) -> list[SimpleNamespace]:
    second = _drop_start_chain(103, 105)
    if second_start_suffix != 105:
        second[-4] = _instruction("ldstr", second_start_suffix)
    return [
        _instruction("ldstr", 101),
        _instruction("call", 1),
        _instruction("newobj", 2),
        _instruction("stloc.0"),
        *_drop_start_chain(102, 104),
        *second,
        _instruction("ret"),
    ]


def _resources() -> list[dict[str, object]]:
    return [
        {
            "original_name": "resource-one",
            "container_name": "bundle.resources",
            "resource_type": "System.ByteArray",
            "value_encoding": "binary",
            "data": b"MZ" + bytes(128),
        },
        {
            "original_name": "resource-two",
            "container_name": "bundle.resources",
            "resource_type": "System.ByteArray",
            "value_encoding": "binary",
            "data": bytes(range(64)),
        },
    ]


def _install_managed_fixture(
    monkeypatch: pytest.MonkeyPatch,
    instructions: list[SimpleNamespace],
) -> None:
    monkeypatch.setattr(lineage, "has_clr_metadata", lambda _data: True)
    monkeypatch.setattr(lineage, "resource_blobs", lambda _data: (_resources(), []))
    monkeypatch.setattr(
        lineage.dnfile,
        "dnPE",
        lambda **_kwargs: SimpleNamespace(net=object()),
    )
    monkeypatch.setattr(lineage, "_method_bodies", lambda *_args: [instructions])
    monkeypatch.setattr(lineage, "_token_name", lambda _image, token: CALLS.get(token, ""))
    monkeypatch.setattr(lineage, "_user_string", lambda _image, token: STRINGS[token])


def test_managed_resource_write_and_start_lineage_is_complete_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """全resourceの書込先と起動先が同一の場合だけ完全lineageになる。"""

    _install_managed_fixture(monkeypatch, _managed_method())

    result = lineage.validate_managed_resource_lineage(b"MZ managed fixture")

    assert result is not None
    assert result.observation["resource_key_binding_complete"] is True
    assert result.observation["write_all_bytes_lineage_count"] == 2
    assert result.observation["same_path_process_start_lineage_count"] == 2
    serialized = repr(result.observation)
    assert "resource-one" not in serialized
    assert "first.bin" not in serialized


def test_managed_resource_lineage_rejects_write_start_path_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """書込とは異なるパスのProcess.Startを同一payload起動とみなさない。"""

    _install_managed_fixture(monkeypatch, _managed_method(second_start_suffix=106))

    assert lineage.validate_managed_resource_lineage(b"MZ managed fixture") is None


def _summary(
    start: int,
    *,
    calls: set[int] | None = None,
    counts: dict[int, int] | None = None,
    config_references: int = 0,
    reverse: bool = False,
) -> SimpleNamespace:
    return SimpleNamespace(
        start=start,
        direct_calls=calls or set(),
        direct_call_counts=counts or {},
        callback_targets=set(),
        config_reference_count=config_references,
        utf16_reverse_loop=reverse,
    )


def test_native_parser_wrapper_keeps_signals_in_one_component() -> None:
    """wrapper直下に分割されたconfig参照・反転・field parseを結合する。"""

    summaries = {
        100: _summary(100, calls={200}),
        200: _summary(
            200,
            calls={300, 400},
            counts={300: 1, 400: 3},
            config_references=1,
        ),
        300: _summary(300, reverse=True),
        400: _summary(400),
    }

    assert extractor._vvas_parser_paths(summaries) == {100: ({300}, {400})}


def test_native_parser_wrapper_rejects_missing_repeated_field_parser() -> None:
    """設定参照と反転だけではparser lineageへ昇格しない。"""

    summaries = {
        100: _summary(100, calls={200}),
        200: _summary(
            200,
            calls={300, 400},
            counts={300: 1, 400: 2},
            config_references=1,
        ),
        300: _summary(300, reverse=True),
        400: _summary(400),
    }

    assert extractor._vvas_parser_paths(summaries) == {}


def _x86_summary_instructions(code: bytes, address: int) -> tuple[dict[int, object], dict[int, tuple[int, ...]]]:
    disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
    disassembler.detail = True
    instructions = {item.address: item for item in disassembler.disasm(code, address)}
    ordered = sorted(instructions)
    successors = {
        current: ((following,) if instructions[current].mnemonic != "ret" else ())
        for current, following in zip(ordered, ordered[1:])
    }
    if ordered:
        successors.setdefault(ordered[-1], ())
    return instructions, successors


def test_static_thread_wrapper_tracks_callback_through_trampoline() -> None:
    """非stack movを挟む6引数callと保存fieldの間接呼出しを追跡する。"""

    wrapper_address = 0x401000
    trampoline_address = 0x402000
    invoke_address = 0x403000
    wrapper_prefix = (
        b"\x55\x8b\xec"  # push ebp; mov ebp, esp
        b"\x8b\x7d\x10"  # mov edi, [ebp+0x10]
        b"\x89\x7e\x54"  # mov [esi+0x54], edi
    )
    wrapper_code = (
        wrapper_prefix
        + b"\x68\x00\x00\x00\x00" * 3
        + b"\x68"
        + trampoline_address.to_bytes(4, "little")
        + b"\x68\x00\x00\x00\x00" * 2
        + b"\x89\x5c\x24\x34"  # mov [esp+0x34], ebx
        + b"\xff\x15\x00\x50\x40\x00"  # call [CreateThread IAT]
        + b"\xc3"
    )
    wrapper_instructions, wrapper_cfg = _x86_summary_instructions(
        wrapper_code,
        wrapper_address,
    )
    create_call = next(
        address
        for address, instruction in wrapper_instructions.items()
        if instruction.mnemonic == "call"
    )
    trampoline_instructions, trampoline_cfg = _x86_summary_instructions(
        b"\xe8" + (invoke_address - (trampoline_address + 5)).to_bytes(4, "little", signed=True) + b"\xc3",
        trampoline_address,
    )
    invoke_instructions, invoke_cfg = _x86_summary_instructions(
        b"\xff\x50\x54\xc3",  # call [eax+0x54]; ret
        invoke_address,
    )

    def summary(
        start: int,
        instructions: dict[int, object],
        cfg: dict[int, tuple[int, ...]],
        *,
        calls: set[int] | None = None,
        callbacks: set[int] | None = None,
        api_sites: tuple[tuple[int, str, int], ...] = (),
    ) -> SimpleNamespace:
        return SimpleNamespace(
            start=start,
            instructions=instructions,
            cfg_successors=cfg,
            direct_calls=calls or set(),
            callback_targets=callbacks or set(),
            api_call_sites=api_sites,
        )

    summaries = {
        wrapper_address: summary(
            wrapper_address,
            wrapper_instructions,
            wrapper_cfg,
            callbacks={trampoline_address},
            api_sites=((create_call, "createthread", 0),),
        ),
        trampoline_address: summary(
            trampoline_address,
            trampoline_instructions,
            trampoline_cfg,
            calls={invoke_address},
        ),
        invoke_address: summary(
            invoke_address,
            invoke_instructions,
            invoke_cfg,
        ),
    }

    assert (
        extractor._vvas_thread_wrapper_callback_parameter(
            summaries,
            wrapper_address,
        )
        == 2
    )
