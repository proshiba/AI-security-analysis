#!/usr/bin/env python3
"""Equation Editor OLEのx86 downloader stageを静的に復元する。

対象は、OOXML内のEquation Editor OLE object、OLE compound file、または
``\x01OLe10nATive`` streamそのものである。検体を実行せず、Capstoneで有界CFGを
構築し、``EBP``／``EBX``／``EAX``の定数だけを伝播してLCG dword XOR decoderを
検証する。hash、URL、file名を検出条件には使わず、decoder、復号stage、API集合、
URL、保存先が一意に整合した場合だけartifactを返す。
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import posixpath
import re
import zipfile
from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit
from xml.etree import ElementTree

try:
    import capstone
    from capstone import x86_const
except ImportError:  # pragma: no cover - 呼出側へstatusを返す
    capstone = None
    x86_const = None

try:
    import olefile
    from olefile.olefile import OleFileError as _OleFileError
except ImportError:  # pragma: no cover - 呼出側へstatusを返す
    olefile = None
    _OleFileError = OSError


SCHEMA_VERSION = 1
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
ZIP_MAGICS = (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")
EQUATION_EDITOR_CLSID = "0002CE02-0000-0000-C000-000000000046"
OLE_NATIVE_STREAM = "\x01ole10native"
NATIVE_ENTRY_OFFSET = 0x50
MAX_INPUT_SIZE = 128 * 1024 * 1024
MAX_XLSX_MEMBERS = 4096
MAX_XLSX_EXPANDED_SIZE = 256 * 1024 * 1024
MAX_EMBEDDING_SIZE = 16 * 1024 * 1024
MAX_NATIVE_SIZE = 4 * 1024 * 1024
MAX_OLE_STREAMS = 256
MAX_CFG_INSTRUCTIONS = 8192
MAX_DATAFLOW_STATES = 32768
MIN_DECODED_STAGE_SIZE = 128

_REQUIRED_ASCII_APIS = frozenset(
    {
        "LoadLibraryW",
        "GetProcAddress",
        "ExpandEnvironmentStringsW",
        "URLDownloadToFileW",
        "ShellExecuteExW",
        "ExitProcess",
    }
)
_REL_NS = "http://schemas.openxmlformats.org/package/2006/relationships"
_SHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_DOC_REL_NS = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
)


class EquationOleError(ValueError):
    """Equation OLE構造を一意かつ安全に復元できない場合の例外。"""


class _NotEquationObject(EquationOleError):
    """有効なOLEだが対象CLSID／streamを持たないことを表す。"""


@dataclass(frozen=True)
class _DecoderCandidate:
    """定数伝播で検証したLCG dword XOR decoder。"""

    entry_offset: int
    decoder_entry: int
    bootstrap_entry: int
    return_address: int
    xor_address: int
    multiplier_address: int
    stage_offset: int
    stage_end: int
    first_key: int
    multiplier: int
    increment: int
    step: int


@dataclass(frozen=True)
class _FlowState:
    """decoderの3 registerだけを保持する有限な抽象状態。"""

    address: int
    ebp: int | None
    ebx: int | None
    eax: int | None
    zeroed_eax: bool
    multiplier: int | None
    multiplier_address: int | None
    increment: int | None


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_zip_member_name(name: str) -> bool:
    path = PurePosixPath(name.replace("\\", "/"))
    return bool(name) and not path.is_absolute() and ".." not in path.parts


def _direct_target(instruction: Any) -> int | None:
    try:
        operands = tuple(instruction.operands)
        if operands and operands[0].type == x86_const.X86_OP_IMM:
            return int(operands[0].imm)
    except (AttributeError, IndexError, TypeError, ValueError, capstone.CsError):
        return None
    return None


def _single_instruction(engine: Any, data: bytes, address: int) -> Any | None:
    if not 0 <= address < len(data):
        return None
    try:
        return next(engine.disasm(data[address : address + 15], address, count=1), None)
    except (TypeError, ValueError, capstone.CsError):
        return None


def _successors(instruction: Any, size: int) -> tuple[int, ...]:
    next_address = int(instruction.address) + int(instruction.size)
    mnemonic = str(instruction.mnemonic).lower()
    if mnemonic.startswith(("ret", "iret")) or mnemonic in {"int", "int3", "hlt"}:
        return ()
    target = _direct_target(instruction)
    if mnemonic == "jmp":
        return () if target is None else (target,)
    if mnemonic.startswith(("j", "loop")):
        return (next_address,) if target is None else (target, next_address)
    if mnemonic == "call":
        return (next_address,) if target is None else (target, next_address)
    return (next_address,) if next_address < size else ()


def _build_cfg(data: bytes, start: int) -> tuple[dict[int, Any], dict[int, tuple[int, ...]]]:
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    queue: deque[int] = deque([start])
    instructions: dict[int, Any] = {}
    edges: dict[int, tuple[int, ...]] = {}
    while queue:
        address = queue.popleft()
        if address in instructions or not 0 <= address < len(data):
            continue
        if len(instructions) >= MAX_CFG_INSTRUCTIONS:
            raise EquationOleError("decoder CFGが命令数上限を超えています")
        instruction = _single_instruction(engine, data, address)
        if instruction is None:
            continue
        instructions[address] = instruction
        successors = tuple(
            value for value in _successors(instruction, len(data)) if 0 <= value < len(data)
        )
        edges[address] = successors
        queue.extend(successors)
    return instructions, edges


def _register_id(operand: Any) -> int | None:
    try:
        if operand.type == x86_const.X86_OP_REG:
            return int(operand.reg)
    except (AttributeError, TypeError, ValueError):
        return None
    return None


def _immediate(operand: Any) -> int | None:
    try:
        if operand.type == x86_const.X86_OP_IMM:
            return int(operand.imm) & 0xFFFFFFFF
    except (AttributeError, TypeError, ValueError):
        return None
    return None


def _is_dword_ebp_memory(operand: Any) -> bool:
    try:
        return (
            operand.type == x86_const.X86_OP_MEM
            and operand.size == 4
            and operand.mem.base == x86_const.X86_REG_EBP
            and operand.mem.index == x86_const.X86_REG_INVALID
            and int(operand.mem.disp) == 0
        )
    except (AttributeError, TypeError, ValueError):
        return False


def _apply_instruction(state: _FlowState, instruction: Any) -> _FlowState:
    ebp, ebx, eax = state.ebp, state.ebx, state.eax
    zeroed_eax = state.zeroed_eax
    multiplier = state.multiplier
    multiplier_address = state.multiplier_address
    increment = state.increment
    try:
        operands: Sequence[Any] = tuple(instruction.operands)
    except (AttributeError, capstone.CsError):
        operands = ()
    mnemonic = str(instruction.mnemonic).lower()
    handled: set[int] = set()

    if len(operands) >= 2:
        destination = _register_id(operands[0])
        immediate = _immediate(operands[-1])
        if destination in {
            x86_const.X86_REG_EAX,
            x86_const.X86_REG_EBP,
            x86_const.X86_REG_EBX,
        }:
            if mnemonic in {"add", "sub"} and immediate is not None:
                sign = 1 if mnemonic == "add" else -1
                if destination == x86_const.X86_REG_EAX:
                    eax = None if eax is None else (eax + sign * immediate) & 0xFFFFFFFF
                    handled.add(destination)
                    if multiplier is not None and mnemonic == "add":
                        increment = immediate
                elif destination == x86_const.X86_REG_EBP:
                    ebp = None if ebp is None else (ebp + sign * immediate) & 0xFFFFFFFF
                    handled.add(destination)
                elif destination == x86_const.X86_REG_EBX:
                    ebx = None if ebx is None else (ebx + sign * immediate) & 0xFFFFFFFF
                    handled.add(destination)
            elif mnemonic == "xor" and len(operands) == 2:
                source = _register_id(operands[1])
                if source == destination:
                    if destination == x86_const.X86_REG_EAX:
                        eax = 0
                        zeroed_eax = True
                    elif destination == x86_const.X86_REG_EBP:
                        ebp = 0
                    else:
                        ebx = 0
                    handled.add(destination)

    if mnemonic == "imul" and len(operands) == 3:
        destination = _register_id(operands[0])
        source = _register_id(operands[1])
        immediate = _immediate(operands[2])
        if destination == source == x86_const.X86_REG_EAX and immediate is not None:
            # ``x * 0``は入力値が未知でも必ず0へ収束する。ここを未知のまま
            # 保つと、sampleの明示的なzeroing idiomを復号keyへ伝播できない。
            eax = 0 if immediate == 0 else (
                None if eax is None else (eax * immediate) & 0xFFFFFFFF
            )
            handled.add(x86_const.X86_REG_EAX)
            if immediate == 0:
                zeroed_eax = True
            elif zeroed_eax and multiplier is None:
                multiplier = immediate
                multiplier_address = int(instruction.address)

    if mnemonic == "lea" and len(operands) == 2:
        try:
            if (
                _register_id(operands[0]) == x86_const.X86_REG_EBX
                and operands[1].type == x86_const.X86_OP_MEM
                and operands[1].mem.base == x86_const.X86_REG_EBP
                and operands[1].mem.index == x86_const.X86_REG_INVALID
            ):
                ebx = (
                    None
                    if ebp is None
                    else (ebp + int(operands[1].mem.disp)) & 0xFFFFFFFF
                )
                handled.add(x86_const.X86_REG_EBX)
        except (AttributeError, TypeError, ValueError):
            pass

    try:
        _reads, writes = instruction.regs_access()
    except (AttributeError, capstone.CsError):
        writes = ()
    for register in writes:
        if register in handled:
            continue
        if register == x86_const.X86_REG_EAX:
            eax = None
            zeroed_eax = False
        elif register == x86_const.X86_REG_EBP:
            ebp = None
        elif register == x86_const.X86_REG_EBX:
            ebx = None

    return _FlowState(
        address=state.address,
        ebp=ebp,
        ebx=ebx,
        eax=eax,
        zeroed_eax=zeroed_eax,
        multiplier=multiplier,
        multiplier_address=multiplier_address,
        increment=increment,
    )


def _chase_entry_call(data: bytes, engine: Any) -> tuple[int, Any]:
    address = NATIVE_ENTRY_OFFSET
    visited: set[int] = set()
    for _ in range(12):
        if address in visited:
            break
        visited.add(address)
        instruction = _single_instruction(engine, data, address)
        if instruction is None:
            break
        mnemonic = str(instruction.mnemonic).lower()
        target = _direct_target(instruction)
        if mnemonic == "call" and target is not None:
            return address, instruction
        if mnemonic == "jmp" and target is not None:
            address = target
            continue
        if mnemonic == "nop":
            address += int(instruction.size)
            continue
        break
    raise EquationOleError("0x50からdecoderのdirect callへ一意に到達できません")


def _find_decoder(data: bytes) -> _DecoderCandidate:
    if capstone is None or x86_const is None:
        raise EquationOleError("Capstoneが利用できません")
    if not MIN_DECODED_STAGE_SIZE <= len(data) <= MAX_NATIVE_SIZE:
        raise EquationOleError("native streamのsizeが許容範囲外です")

    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    call_address, call_instruction = _chase_entry_call(data, engine)
    bootstrap = _direct_target(call_instruction)
    if bootstrap is None:
        raise EquationOleError("decoder bootstrap targetを取得できません")
    bootstrap_instruction = _single_instruction(engine, data, bootstrap)
    if bootstrap_instruction is None:
        raise EquationOleError("decoder bootstrapを逆アセンブルできません")
    try:
        bootstrap_operands = tuple(bootstrap_instruction.operands)
    except (AttributeError, capstone.CsError):
        bootstrap_operands = ()
    if not (
        str(bootstrap_instruction.mnemonic).lower() == "pop"
        and len(bootstrap_operands) == 1
        and _register_id(bootstrap_operands[0]) == x86_const.X86_REG_EBP
    ):
        raise EquationOleError("decoder bootstrapがcall/pop EBP形式ではありません")

    instructions, edges = _build_cfg(data, bootstrap)
    return_address = call_address + int(call_instruction.size)
    start_address = bootstrap + int(bootstrap_instruction.size)
    work: deque[_FlowState] = deque(
        [
            _FlowState(
                address=start_address,
                ebp=return_address,
                ebx=None,
                eax=None,
                zeroed_eax=False,
                multiplier=None,
                multiplier_address=None,
                increment=None,
            )
        ]
    )
    seen: set[_FlowState] = set()
    candidates: set[_DecoderCandidate] = set()
    while work:
        state = work.popleft()
        if state in seen:
            continue
        if len(seen) >= MAX_DATAFLOW_STATES:
            raise EquationOleError("decoder定数伝播が状態数上限を超えています")
        seen.add(state)
        instruction = instructions.get(state.address)
        if instruction is None:
            continue
        try:
            operands = tuple(instruction.operands)
        except (AttributeError, capstone.CsError):
            operands = ()
        if (
            str(instruction.mnemonic).lower() == "xor"
            and len(operands) == 2
            and _is_dword_ebp_memory(operands[0])
            and _register_id(operands[1]) == x86_const.X86_REG_EAX
        ):
            if None not in {
                state.ebp,
                state.ebx,
                state.eax,
                state.multiplier,
                state.multiplier_address,
                state.increment,
            }:
                candidates.add(
                    _DecoderCandidate(
                        entry_offset=NATIVE_ENTRY_OFFSET,
                        decoder_entry=call_address,
                        bootstrap_entry=bootstrap,
                        return_address=return_address,
                        xor_address=int(instruction.address),
                        multiplier_address=int(state.multiplier_address),
                        stage_offset=int(state.ebp),
                        stage_end=int(state.ebx),
                        first_key=int(state.eax),
                        multiplier=int(state.multiplier),
                        increment=int(state.increment),
                        step=4,
                    )
                )
            continue

        updated = _apply_instruction(state, instruction)
        for successor in edges.get(state.address, ()):
            work.append(
                _FlowState(
                    address=successor,
                    ebp=updated.ebp,
                    ebx=updated.ebx,
                    eax=updated.eax,
                    zeroed_eax=updated.zeroed_eax,
                    multiplier=updated.multiplier,
                    multiplier_address=updated.multiplier_address,
                    increment=updated.increment,
                )
            )

    if len(candidates) != 1:
        raise EquationOleError(
            f"LCG XOR decoder候補が一意ではありません: {len(candidates)}"
        )
    candidate = next(iter(candidates))
    if not (
        NATIVE_ENTRY_OFFSET < candidate.stage_offset < candidate.stage_end <= len(data)
        and candidate.stage_end - candidate.stage_offset >= MIN_DECODED_STAGE_SIZE
    ):
        raise EquationOleError("decoderのstage境界が不正です")
    if candidate.first_key != candidate.increment:
        raise EquationOleError("初回XOR keyとLCG加算値が一致しません")
    if not (candidate.multiplier & 1 and candidate.increment & 1):
        raise EquationOleError("LCGの乗数または加算値が観測形式の奇数条件を満たしません")

    has_step = False
    has_cmp = False
    has_back_edge = False
    for instruction in instructions.values():
        try:
            operands = tuple(instruction.operands)
        except (AttributeError, capstone.CsError):
            operands = ()
        mnemonic = str(instruction.mnemonic).lower()
        if len(operands) == 2:
            if (
                mnemonic == "add"
                and _register_id(operands[0]) == x86_const.X86_REG_EBP
                and _immediate(operands[1]) == candidate.step
            ):
                has_step = True
            if (
                mnemonic == "cmp"
                and _register_id(operands[0]) == x86_const.X86_REG_EBP
                and _register_id(operands[1]) == x86_const.X86_REG_EBX
            ):
                has_cmp = True
        if (
            mnemonic in {"jb", "jc", "jnae"}
            and _direct_target(instruction) == candidate.multiplier_address
        ):
            has_back_edge = True
    if not (has_step and has_cmp and has_back_edge):
        raise EquationOleError("XOR loopのstep、上限比較、LCG back-edgeが揃っていません")
    return candidate


def _decode_stage(data: bytes, candidate: _DecoderCandidate) -> bytes:
    encrypted = data[candidate.stage_offset : candidate.stage_end]
    key = candidate.first_key
    output = bytearray()
    for offset in range(0, len(encrypted), candidate.step):
        chunk = encrypted[offset : offset + candidate.step]
        padded = chunk + bytes(candidate.step - len(chunk))
        value = int.from_bytes(padded, "little") ^ key
        output.extend(value.to_bytes(candidate.step, "little")[: len(chunk)])
        key = (
            key * candidate.multiplier + candidate.increment
        ) & 0xFFFFFFFF
    return bytes(output)


def _ascii_strings(data: bytes) -> tuple[str, ...]:
    values = {
        match.group(0).decode("ascii")
        for match in re.finditer(rb"[\x20-\x7e]{4,}\x00", data)
    }
    return tuple(sorted(value.rstrip("\x00") for value in values))


def _utf16le_strings(data: bytes) -> tuple[str, ...]:
    values: set[str] = set()
    for parity in (0, 1):
        offset = parity
        while offset + 1 < len(data):
            start = offset
            chars: list[str] = []
            while offset + 1 < len(data):
                low, high = data[offset], data[offset + 1]
                if high != 0 or not 0x20 <= low <= 0x7E:
                    break
                chars.append(chr(low))
                offset += 2
            if len(chars) >= 4 and offset + 1 < len(data) and data[offset : offset + 2] == b"\0\0":
                values.add("".join(chars))
                offset += 2
            elif offset == start:
                offset += 2
    return tuple(sorted(values))


def _validate_stage(stage: bytes) -> dict[str, object]:
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    first = _single_instruction(engine, stage, 0)
    if first is None or str(first.mnemonic).lower() != "sub":
        raise EquationOleError("復号stageがstack確保命令から始まりません")
    try:
        operands = tuple(first.operands)
    except (AttributeError, capstone.CsError):
        operands = ()
    stack_size = _immediate(operands[1]) if len(operands) == 2 else None
    if not (
        len(operands) == 2
        and _register_id(operands[0]) == x86_const.X86_REG_ESP
        and stack_size is not None
        and 0 < stack_size <= 0x10000
    ):
        raise EquationOleError("復号stageのstack確保境界が不正です")

    ascii_values = _ascii_strings(stage)
    ascii_set = set(ascii_values)
    missing_apis = sorted(_REQUIRED_ASCII_APIS - ascii_set)
    if missing_apis:
        raise EquationOleError(
            "復号stageの必須API集合が不足しています: " + ",".join(missing_apis)
        )
    wide_values = _utf16le_strings(stage)
    folded = {value.casefold() for value in wide_values}
    if not {"kernel32", "urlmon", "shell32"}.issubset(folded):
        raise EquationOleError("復号stageのmodule集合が不足しています")

    urls = [
        value
        for value in wide_values
        if value.lower().startswith(("http://", "https://"))
    ]
    if len(urls) != 1:
        raise EquationOleError(f"stage URL候補が一意ではありません: {len(urls)}")
    parsed = urlsplit(urls[0])
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or len(urls[0]) > 2048
    ):
        raise EquationOleError("stage URLの構造が不正です")

    destinations = [
        value
        for value in wide_values
        if re.fullmatch(r"%[A-Za-z0-9_]+%\\[^\x00]{1,240}\.exe", value, re.IGNORECASE)
    ]
    if len(destinations) != 1:
        raise EquationOleError(
            f"保存先path候補が一意ではありません: {len(destinations)}"
        )
    return {
        "stack_allocation": int(stack_size),
        "ascii_apis": sorted(_REQUIRED_ASCII_APIS),
        "modules": sorted(
            value for value in wide_values if value.casefold() in {"kernel32", "urlmon", "shell32"}
        ),
        "stage_url": urls[0],
        "stage_url_role": "payload_distribution",
        "destination_path": destinations[0],
        "download_api": "URLDownloadToFileW",
        "execution_api": "ShellExecuteExW",
        "execution_command": (
            f"ShellExecuteExW(lpFile={destinations[0]}, nShow=SW_SHOWNORMAL)"
        ),
        "download_payload_transform": "identity",
        "download_payload_recovered": False,
    }


def recover_equation_native_stream(
    data: bytes,
    *,
    source_kind: str = "native_stream",
    embedding_member: str | None = None,
    clsid: str | None = None,
    worksheet_context: dict[str, object] | None = None,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """native streamから検証済みLCG XOR stageを復元する。

    構造が曖昧、不完全、または必須API／URL／保存先が一意でない場合は、
    ``artifacts``を空にして停止する。検体命令の実行やCPU emulationは行わない。
    """

    if type(data) is not bytes:
        raise TypeError("dataはbytesで指定してください")
    base = {
        "schema_version": SCHEMA_VERSION,
        "source_kind": source_kind,
        "embedding_member": embedding_member,
        "clsid": clsid,
        "native_stream_name": "\\x01OLe10nATive",
        "native_stream_size": len(data),
        "native_stream_sha256": _sha256(data),
        "worksheet": worksheet_context,
        "sample_executed": False,
        "cpu_emulated": False,
        "network_contacted": False,
    }
    try:
        candidate = _find_decoder(data)
        stage = _decode_stage(data, candidate)
        stage_metadata = _validate_stage(stage)
    except EquationOleError as exc:
        return {**base, "status": "structure_rejected", "reason": str(exc)}, []

    report = {
        **base,
        "status": "equation_ole_stage_recovered",
        "decoder": {
            "method": "bounded_x86_cfg_constant_propagation",
            "entry_offset": candidate.entry_offset,
            "decoder_entry": candidate.decoder_entry,
            "bootstrap_entry": candidate.bootstrap_entry,
            "return_address": candidate.return_address,
            "xor_address": candidate.xor_address,
            "stage_offset": candidate.stage_offset,
            "stage_end": candidate.stage_end,
            "word_size": 4,
            "byte_order": "little",
            "first_key": f"0x{candidate.first_key:08x}",
            "multiplier": f"0x{candidate.multiplier:08x}",
            "increment": f"0x{candidate.increment:08x}",
            "key_update": "key = (key * multiplier + increment) mod 2^32",
        },
        "decoded_stage": {
            "size": len(stage),
            "sha256": _sha256(stage),
            **stage_metadata,
        },
    }
    return report, [("equation-ole-decoded-stage", stage)]


def _extract_native_stream(ole_data: bytes) -> tuple[bytes, str]:
    if olefile is None:
        raise EquationOleError("olefileが利用できません")
    if not ole_data.startswith(OLE_MAGIC) or len(ole_data) > MAX_EMBEDDING_SIZE:
        raise _NotEquationObject("Equation OLE compound fileではありません")
    try:
        with olefile.OleFileIO(io.BytesIO(ole_data)) as container:
            clsid = str(container.root.clsid).upper()
            if clsid != EQUATION_EDITOR_CLSID:
                raise _NotEquationObject("Equation Editor CLSIDではありません")
            paths = container.listdir(streams=True, storages=False)
            if not paths or len(paths) > MAX_OLE_STREAMS:
                raise EquationOleError("OLE stream数が許容範囲外です")
            matches = [
                path
                for path in paths
                if len(path) == 1 and str(path[0]).casefold() == OLE_NATIVE_STREAM
            ]
            if len(matches) != 1:
                raise EquationOleError(
                    f"OLe10nATive stream候補が一意ではありません: {len(matches)}"
                )
            size = int(container.get_size(matches[0]))
            if not MIN_DECODED_STAGE_SIZE <= size <= MAX_NATIVE_SIZE:
                raise EquationOleError("OLe10nATive streamのsizeが許容範囲外です")
            native = container.openstream(matches[0]).read(MAX_NATIVE_SIZE + 1)
    except _NotEquationObject:
        raise
    except (OSError, ValueError, _OleFileError) as exc:
        raise EquationOleError(
            f"OLE compound fileを検証できません: {type(exc).__name__}"
        ) from exc
    if len(native) != size:
        raise EquationOleError("OLe10nATive streamの宣言sizeと読取sizeが不一致です")
    return native, clsid


def _xml_root(archive: zipfile.ZipFile, name: str) -> ElementTree.Element | None:
    try:
        info = archive.getinfo(name)
        if info.file_size > 2 * 1024 * 1024:
            return None
        return ElementTree.fromstring(archive.read(info))
    except (KeyError, ElementTree.ParseError, OSError, RuntimeError, ValueError):
        return None


def _worksheet_context(
    archive: zipfile.ZipFile, embedding_member: str
) -> dict[str, object] | None:
    workbook = _xml_root(archive, "xl/workbook.xml")
    workbook_rels = _xml_root(archive, "xl/_rels/workbook.xml.rels")
    if workbook is None or workbook_rels is None:
        return None
    workbook_targets = {
        item.attrib.get("Id", ""): posixpath.normpath(
            posixpath.join("xl", item.attrib.get("Target", ""))
        )
        for item in workbook_rels.findall(f"{{{_REL_NS}}}Relationship")
        if item.attrib.get("Id") and item.attrib.get("Target")
    }
    contexts: list[dict[str, object]] = []
    for sheet in workbook.findall(f".//{{{_SHEET_NS}}}sheet"):
        rel_id = sheet.attrib.get(f"{{{_DOC_REL_NS}}}id", "")
        sheet_path = workbook_targets.get(rel_id)
        if not sheet_path or not _safe_zip_member_name(sheet_path):
            continue
        worksheet = _xml_root(archive, sheet_path)
        rels_path = posixpath.join(
            posixpath.dirname(sheet_path),
            "_rels",
            posixpath.basename(sheet_path) + ".rels",
        )
        sheet_rels = _xml_root(archive, rels_path)
        if worksheet is None or sheet_rels is None:
            continue
        targets = {
            item.attrib.get("Id", ""): posixpath.normpath(
                posixpath.join(posixpath.dirname(sheet_path), item.attrib.get("Target", ""))
            )
            for item in sheet_rels.findall(f"{{{_REL_NS}}}Relationship")
            if item.attrib.get("Id") and item.attrib.get("Target")
        }
        for ole_object in worksheet.findall(f".//{{{_SHEET_NS}}}oleObject"):
            object_rel = ole_object.attrib.get(f"{{{_DOC_REL_NS}}}id", "")
            if targets.get(object_rel) != embedding_member:
                continue
            contexts.append(
                {
                    "name": sheet.attrib.get("name"),
                    "state": sheet.attrib.get("state", "visible"),
                    "auto_load": ole_object.attrib.get("autoLoad") in {"1", "true", "True"},
                    "prog_id": ole_object.attrib.get("progId"),
                }
            )
    return contexts[0] if len(contexts) == 1 else None


def _extract_xlsx_equation_object(
    data: bytes,
) -> tuple[bytes, str, str, dict[str, object] | None]:
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > MAX_XLSX_MEMBERS:
                raise EquationOleError("OOXML member数が許容範囲外です")
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                raise EquationOleError("OOXMLに重複member名があります")
            if any(not _safe_zip_member_name(name) for name in names):
                raise EquationOleError("OOXMLに安全でないmember pathがあります")
            if sum(int(item.file_size) for item in infos) > MAX_XLSX_EXPANDED_SIZE:
                raise EquationOleError("OOXML展開size合計が上限を超えています")
            candidates = [
                item
                for item in infos
                if item.filename.startswith("xl/embeddings/")
                and item.filename.lower().endswith(".bin")
                and 0 < item.file_size <= MAX_EMBEDDING_SIZE
                and not (item.flag_bits & 1)
            ]
            matches: list[tuple[bytes, str, str]] = []
            for item in candidates:
                try:
                    ole_data = archive.read(item)
                    native, clsid = _extract_native_stream(ole_data)
                    matches.append((native, clsid, item.filename))
                except _NotEquationObject:
                    continue
            if len(matches) != 1:
                raise EquationOleError(
                    f"Equation OLE object候補が一意ではありません: {len(matches)}"
                )
            native, clsid, member = matches[0]
            context = _worksheet_context(archive, member)
            return native, clsid, member, context
    except zipfile.BadZipFile as exc:
        raise EquationOleError("入力が有効なOOXML ZIPではありません") from exc


def recover_equation_ole(
    data: bytes,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """XLSX、OLE、native streamからEquation downloader stageを復元する。"""

    if type(data) is not bytes:
        raise TypeError("dataはbytesで指定してください")
    if not 1 <= len(data) <= MAX_INPUT_SIZE:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "input_size_blocked",
            "input_size": len(data),
            "maximum_input_size": MAX_INPUT_SIZE,
            "sample_executed": False,
            "cpu_emulated": False,
            "network_contacted": False,
        }, []
    try:
        if data.startswith(ZIP_MAGICS):
            native, clsid, member, context = _extract_xlsx_equation_object(data)
            return recover_equation_native_stream(
                native,
                source_kind="xlsx_equation_embedding",
                embedding_member=member,
                clsid=clsid,
                worksheet_context=context,
            )
        if data.startswith(OLE_MAGIC):
            native, clsid = _extract_native_stream(data)
            return recover_equation_native_stream(
                native,
                source_kind="equation_ole_compound_file",
                clsid=clsid,
            )
        return recover_equation_native_stream(data)
    except _NotEquationObject:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "not_equation_ole",
            "input_size": len(data),
            "input_sha256": _sha256(data),
            "sample_executed": False,
            "cpu_emulated": False,
            "network_contacted": False,
        }, []
    except EquationOleError as exc:
        return {
            "schema_version": SCHEMA_VERSION,
            "status": "structure_rejected",
            "reason": str(exc),
            "input_size": len(data),
            "input_sha256": _sha256(data),
            "sample_executed": False,
            "cpu_emulated": False,
            "network_contacted": False,
        }, []


def main(argv: list[str] | None = None) -> int:
    """明示されたrepo外出力へ静的復元reportと任意stageを書き出す。"""

    parser = argparse.ArgumentParser(
        description="Equation Editor OLEのLCG XOR downloader stageを静的に復元します"
    )
    parser.add_argument("input", type=Path, help="XLSX、OLE、またはnative stream")
    parser.add_argument("--json-output", type=Path, required=True, help="JSON report出力先")
    parser.add_argument(
        "--stage-output",
        type=Path,
        help="復号stageの出力先。repository外の隔離先だけを指定してください",
    )
    args = parser.parse_args(argv)
    report, artifacts = recover_equation_ole(args.input.read_bytes())
    args.json_output.parent.mkdir(parents=True, exist_ok=True)
    args.json_output.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    if args.stage_output is not None:
        if len(artifacts) != 1:
            raise EquationOleError("検証済みstageがないためbinaryを出力しません")
        args.stage_output.parent.mkdir(parents=True, exist_ok=True)
        args.stage_output.write_bytes(artifacts[0][1])
    return 0 if report.get("status") == "equation_ole_stage_recovered" else 2


if __name__ == "__main__":
    raise SystemExit(main())
