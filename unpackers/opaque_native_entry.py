#!/usr/bin/env python3
"""importless native PEのentryと動的API resolverを有界に静的解析する。

このmoduleはPEをloadまたは実行せず、Capstoneによる逆アセンブルとPE
header検査だけを行う。API名の照合結果は内蔵した限定corpus内の候補であり、
未知hashを推測で補完しない。
"""

from __future__ import annotations

import hashlib
import struct
from bisect import bisect_right
from collections import Counter, defaultdict, deque
from collections.abc import Iterable, Mapping, Sequence
from typing import Any

try:
    import capstone
    from capstone import x86_const
except ImportError:  # pragma: no cover - dependency status is returned
    capstone = None
    x86_const = None

try:
    import pefile
except ImportError:  # pragma: no cover - dependency status is returned
    pefile = None

from unpackers.bounded_pe_scan import (
    inspect_structural_pe_extent,
    scan_embedded_pe_candidates,
)
from unpackers.static_control_flow import analyze_pe_control_flow

SCHEMA_VERSION = 1
DEFAULT_MAX_INPUT_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_INSTRUCTIONS = 500_000
DEFAULT_MAX_CALLSITES = 16_384
DEFAULT_MAX_CANDIDATES = 256
DEFAULT_FUNCTION_SCAN_BYTES = 32 * 1024
DEFAULT_MAX_FUNCTION_INSTRUCTIONS = 8_192
DEFAULT_ENTRY_CFG_BLOCKS = 8_192
DEFAULT_ENTRY_CFG_INSTRUCTIONS = 100_000
MAX_PUBLIC_CALLSITES = 4_096
MAX_PUBLIC_LOOP_CANDIDATES = 128
MAX_HASH_VALUES = 4_096
_EXECUTE = 0x20000000
_FNV_LIKE_PRIMES = {0x01000193, 0x01000697}
_FIRST_ARGUMENT_REGISTERS_64 = ("rcx", "rdx", "r8", "r9")
_FUNCTION_TERMINATORS = {"ret", "retf", "iret", "iretq"}


# Portable automation uses a deliberately bounded corpus. Case-specific review may
# validate the same hashes against a complete, pinned export inventory separately.
KNOWN_WINDOWS_EXPORTS: Mapping[str, tuple[str, ...]] = {
    "kernel32.dll": (
        "CloseHandle",
        "CreateFileA",
        "CreateFileW",
        "CreateProcessA",
        "CreateProcessW",
        "ExitProcess",
        "GetCommandLineA",
        "GetCommandLineW",
        "GetCurrentProcess",
        "GetCurrentProcessId",
        "GetCurrentThreadId",
        "GetLastError",
        "GetModuleFileNameA",
        "GetModuleFileNameW",
        "GetModuleHandleA",
        "GetModuleHandleW",
        "GetProcAddress",
        "HeapAlloc",
        "HeapFree",
        "LoadLibraryA",
        "LoadLibraryW",
        "ReadFile",
        "SetFilePointer",
        "VirtualAlloc",
        "VirtualFree",
        "VirtualProtect",
        "WaitForSingleObject",
        "WriteFile",
    ),
    "ntdll.dll": (
        "LdrGetProcedureAddress",
        "LdrLoadDll",
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtReadFile",
        "NtWriteFile",
        "RtlAllocateHeap",
        "RtlDecompressBuffer",
        "RtlFreeHeap",
    ),
    "user32.dll": (
        "GetSystemMetrics",
        "MessageBoxA",
        "MessageBoxW",
        "ShowWindow",
    ),
    "advapi32.dll": (
        "OpenProcessToken",
        "RegCreateKeyExA",
        "RegCreateKeyExW",
        "RegSetValueExA",
        "RegSetValueExW",
    ),
    "wininet.dll": (
        "HttpOpenRequestA",
        "HttpSendRequestA",
        "InternetConnectA",
        "InternetOpenA",
        "InternetReadFile",
    ),
    "winhttp.dll": (
        "WinHttpConnect",
        "WinHttpOpen",
        "WinHttpOpenRequest",
        "WinHttpReadData",
        "WinHttpSendRequest",
    ),
    "ws2_32.dll": ("WSAStartup", "closesocket", "connect", "recv", "send", "socket"),
}


def _hex(value: int) -> str:
    return f"0x{value & 0xFFFFFFFF:x}"


def _register_name(engine: Any, register: int) -> str:
    try:
        return str(engine.reg_name(register)).lower()
    except (AttributeError, TypeError, ValueError):
        return ""


def _canonical_register(name: str) -> str:
    aliases = {
        "ecx": "rcx",
        "cx": "rcx",
        "cl": "rcx",
        "edx": "rdx",
        "dx": "rdx",
        "dl": "rdx",
        "r8d": "r8",
        "r8w": "r8",
        "r8b": "r8",
        "r9d": "r9",
        "r9w": "r9",
        "r9b": "r9",
        "eax": "rax",
        "ax": "rax",
        "al": "rax",
        "ebx": "rbx",
        "bx": "rbx",
        "bl": "rbx",
        "edi": "rdi",
        "di": "rdi",
        "dil": "rdi",
        "esi": "rsi",
        "si": "rsi",
        "sil": "rsi",
        "ebp": "rbp",
        "bp": "rbp",
        "bpl": "rbp",
    }
    return aliases.get(name, name)


def hash_ascii_name(name: str, *, seed: int, prime: int) -> int:
    """観測したFNV-1a型更新則でASCII名をhash化する。"""

    if not 0 <= seed <= 0xFFFFFFFF or not 1 <= prime <= 0xFFFFFFFF:
        raise ValueError("seedとprimeは32-bit範囲で指定してください")
    try:
        encoded = name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("API名はASCIIで指定してください") from exc
    value = seed
    for byte in encoded:
        value = ((value ^ byte) * prime) & 0xFFFFFFFF
    return value


def _immediate(operand: Any) -> int | None:
    try:
        if operand.type == x86_const.X86_OP_IMM:
            return int(operand.imm) & 0xFFFFFFFFFFFFFFFF
    except (AttributeError, TypeError, ValueError):
        return None
    return None


def _operands(instruction: Any) -> Sequence[Any]:
    """Capstoneのskipdata疑似命令ではdetail参照を行わない。"""

    try:
        return tuple(instruction.operands)
    except (AttributeError, capstone.CsError):
        return ()


def _direct_target(instruction: Any) -> int | None:
    try:
        operands = _operands(instruction)
        if operands and operands[0].type == x86_const.X86_OP_IMM:
            return int(operands[0].imm)
    except (AttributeError, IndexError, TypeError, ValueError, capstone.CsError):
        return None
    return None


def _mapped_offset(
    mappings: Sequence[tuple[int, int, int]], rva: int
) -> tuple[int, int] | None:
    for start, raw_offset, raw_size in mappings:
        if start <= rva < start + raw_size:
            return raw_offset + rva - start, start + raw_size - rva
    return None


def _pe_layout(
    data: bytes,
) -> tuple[Any, int, int, list[tuple[int, int, int]], list[dict[str, Any]]]:
    image = pefile.PE(data=data, fast_load=False)
    machine = int(image.FILE_HEADER.Machine)
    bits = {0x14C: 32, 0x8664: 64}.get(machine)
    if bits is None:
        raise ValueError("unsupported_architecture")
    imports = sum(
        len(item.imports) for item in getattr(image, "DIRECTORY_ENTRY_IMPORT", [])
    )
    mappings: list[tuple[int, int, int]] = []
    sections: list[dict[str, Any]] = []
    for section in image.sections:
        name = section.Name.rstrip(b"\0").decode(errors="replace")
        executable = bool(int(section.Characteristics) & _EXECUTE)
        raw_offset = int(section.PointerToRawData)
        raw_size = min(int(section.SizeOfRawData), max(0, len(data) - raw_offset))
        rva = int(section.VirtualAddress)
        sections.append(
            {
                "name": name,
                "rva": hex(rva),
                "raw_size": raw_size,
                "virtual_size": int(section.Misc_VirtualSize),
                "executable": executable,
            }
        )
        if executable and raw_size:
            mappings.append((rva, raw_offset, raw_size))
    return image, bits, imports, mappings, sections


def _make_engine(bits: int) -> Any:
    mode = capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32
    engine = capstone.Cs(capstone.CS_ARCH_X86, mode)
    engine.detail = True
    engine.skipdata = True
    return engine


def _record_assignment(engine: Any, instruction: Any, state: dict[str, Any]) -> None:
    mnemonic = instruction.mnemonic.lower()
    operands = _operands(instruction)
    if not operands:
        return
    try:
        destination = operands[0]
        if destination.type != x86_const.X86_OP_REG:
            return
        register = _canonical_register(_register_name(engine, destination.reg))
        if mnemonic == "mov" and len(operands) >= 2:
            value = _immediate(operands[1])
            if value is not None:
                state[register] = value
                return
        if (
            mnemonic == "xor"
            and len(operands) >= 2
            and operands[1].type == x86_const.X86_OP_REG
        ):
            other = _canonical_register(_register_name(engine, operands[1].reg))
            if register == other:
                state[register] = 0
                return
        state.pop(register, None)
    except (AttributeError, IndexError, TypeError, ValueError):
        return


def _scan_calls(
    data: bytes,
    engine: Any,
    mappings: Sequence[tuple[int, int, int]],
    *,
    bits: int,
    max_instructions: int,
    max_callsites: int,
) -> tuple[list[dict[str, Any]], Counter[int], int, bool]:
    records: list[dict[str, Any]] = []
    target_counts: Counter[int] = Counter()
    instruction_count = 0
    exhausted = False
    for section_rva, raw_offset, raw_size in mappings:
        state: dict[str, Any] = {}
        code = memoryview(data)[raw_offset : raw_offset + raw_size]
        for instruction in engine.disasm(bytes(code), section_rva):
            instruction_count += 1
            if instruction_count > max_instructions:
                exhausted = True
                break
            mnemonic = instruction.mnemonic.lower()
            _record_assignment(engine, instruction, state)
            if mnemonic == "call":
                target = _direct_target(instruction)
                if target is not None and _mapped_offset(mappings, target) is not None:
                    target_counts[target] += 1
                    if len(records) < max_callsites:
                        if bits == 64:
                            arguments = {
                                name: _hex(value)
                                for name in _FIRST_ARGUMENT_REGISTERS_64
                                if (value := state.get(name)) is not None
                            }
                        else:
                            arguments = {
                                f"stack_{index}": _hex(value)
                                for index, value in enumerate(
                                    list(state.get("__push_values__", ()))[:4]
                                )
                            }
                        records.append(
                            {
                                "site_rva": hex(int(instruction.address)),
                                "target_rva": hex(target),
                                "arguments": arguments,
                            }
                        )
                if bits == 64:
                    for name in ("rax", "rcx", "rdx", "r8", "r9", "r10", "r11"):
                        state.pop(name, None)
                else:
                    state.pop("__push_values__", None)
            elif bits == 32 and mnemonic == "push":
                operands = _operands(instruction)
                value = _immediate(operands[0]) if operands else None
                if value is not None:
                    values = list(state.get("__push_values__", ()))
                    values.insert(0, value)
                    state["__push_values__"] = tuple(values[:4])  # type: ignore[assignment]
            if mnemonic.startswith("j") or mnemonic in {"ret", "retf", "iret", "iretq"}:
                state.clear()
        if exhausted:
            break
    if len(records) >= max_callsites and sum(target_counts.values()) > len(records):
        exhausted = True
    return records, target_counts, instruction_count, exhausted


def _scan_function(
    data: bytes,
    engine: Any,
    mappings: Sequence[tuple[int, int, int]],
    start: int,
    *,
    max_bytes: int,
    max_instructions: int,
) -> dict[str, Any]:
    located = _mapped_offset(mappings, start)
    if located is None:
        return {"status": "not_mapped", "rva": hex(start)}
    raw_offset, available = located
    code = data[raw_offset : raw_offset + min(available, max_bytes)]
    mnemonics: Counter[str] = Counter()
    immediates: Counter[int] = Counter()
    direct_calls: set[int] = set()
    backward_branches = 0
    memory_writes = 0
    register_seeds: defaultdict[str, list[int]] = defaultdict(list)
    prime_registers: defaultdict[int, set[str]] = defaultdict(set)
    decoded = 0
    exhausted = False
    termination: str | None = None
    for instruction in engine.disasm(code, start):
        decoded += 1
        if decoded > max_instructions:
            exhausted = True
            break
        mnemonic = instruction.mnemonic.lower()
        mnemonics[mnemonic] += 1
        operands = _operands(instruction)
        for operand in operands:
            value = _immediate(operand)
            if value is not None:
                immediates[value & 0xFFFFFFFF] += 1
        if mnemonic == "call":
            target = _direct_target(instruction)
            if target is not None and _mapped_offset(mappings, target) is not None:
                direct_calls.add(target)
        if mnemonic.startswith("j"):
            target = _direct_target(instruction)
            if target is not None and target < int(instruction.address):
                backward_branches += 1
        if operands:
            try:
                if operands[0].type == x86_const.X86_OP_MEM:
                    memory_writes += 1
                if (
                    mnemonic == "mov"
                    and operands[0].type == x86_const.X86_OP_REG
                    and len(operands) >= 2
                    and (value := _immediate(operands[1])) is not None
                ):
                    register_seeds[
                        _canonical_register(_register_name(engine, operands[0].reg))
                    ].append(value & 0xFFFFFFFF)
                if mnemonic == "imul" and operands:
                    prime = next(
                        (
                            value & 0xFFFFFFFF
                            for op in operands
                            if (value := _immediate(op)) is not None
                            and (value & 0xFFFFFFFF) in _FNV_LIKE_PRIMES
                        ),
                        None,
                    )
                    if prime is not None and operands[0].type == x86_const.X86_OP_REG:
                        prime_registers[prime].add(
                            _canonical_register(_register_name(engine, operands[0].reg))
                        )
            except (AttributeError, IndexError, TypeError, ValueError):
                pass
        if mnemonic in _FUNCTION_TERMINATORS:
            termination = mnemonic
            break
    if termination is None and available > max_bytes:
        exhausted = True
    fnv_candidates: list[dict[str, Any]] = []
    for prime, registers in sorted(prime_registers.items()):
        if mnemonics["xor"] == 0 or backward_branches == 0:
            continue
        seeds = sorted(
            {
                value
                for register in registers
                for value in register_seeds.get(register, [])
                if value not in {0, prime}
            }
        )
        fnv_candidates.append(
            {
                "prime": _hex(prime),
                "seed_candidates": [_hex(value) for value in seeds[:16]],
                "accumulator_registers": sorted(registers),
                "xor_instructions": mnemonics["xor"],
                "backward_branches": backward_branches,
                "confidence": "high" if len(seeds) == 1 else "medium",
            }
        )
    return {
        "status": "budget_exhausted" if exhausted else "analyzed",
        "rva": hex(start),
        "instruction_count": min(decoded, max_instructions),
        "termination": termination,
        "direct_call_targets": [hex(value) for value in sorted(direct_calls)],
        "backward_branches": backward_branches,
        "memory_write_instructions": memory_writes,
        "arithmetic_instructions": sum(
            mnemonics[name]
            for name in ("xor", "add", "sub", "imul", "mul", "rol", "ror", "shl", "shr")
        ),
        "mz_magic_compared": immediates[0x5A4D] > 0,
        "pe_magic_compared": immediates[0x4550] > 0,
        "peb_segment_access": False,  # supplemented by a raw instruction scan below
        "fnv_like": fnv_candidates,
    }


def _has_peb_access(
    data: bytes, engine: Any, mappings: Sequence[tuple[int, int, int]], start: int
) -> bool:
    located = _mapped_offset(mappings, start)
    if located is None:
        return False
    raw_offset, available = located
    for instruction in engine.disasm(
        data[raw_offset : raw_offset + min(available, DEFAULT_FUNCTION_SCAN_BYTES)],
        start,
    ):
        for operand in _operands(instruction):
            try:
                if operand.type != x86_const.X86_OP_MEM:
                    continue
                segment = _register_name(engine, operand.mem.segment)
                if segment == "gs" and int(operand.mem.disp) in {0x30, 0x60}:
                    return True
                if segment == "fs" and int(operand.mem.disp) in {0x18, 0x30}:
                    return True
            except (AttributeError, TypeError, ValueError):
                continue
        if instruction.mnemonic.lower() in _FUNCTION_TERMINATORS:
            break
    return False


def _seed_prime_pairs(
    functions: Mapping[int, Mapping[str, Any]],
) -> list[tuple[int, int, int]]:
    pairs: list[tuple[int, int, int]] = []
    for address, report in functions.items():
        for item in report.get("fnv_like", []):
            seeds = item.get("seed_candidates", [])
            if len(seeds) != 1:
                continue
            pairs.append((address, int(seeds[0], 16), int(item["prime"], 16)))
    return pairs


def _match_hashes(
    values: Iterable[int], *, seed: int, prime: int
) -> list[dict[str, Any]]:
    corpus: defaultdict[int, list[tuple[str, str]]] = defaultdict(list)
    for module, names in KNOWN_WINDOWS_EXPORTS.items():
        for name in names:
            corpus[hash_ascii_name(name, seed=seed, prime=prime)].append((module, name))
    result: list[dict[str, Any]] = []
    for value in sorted(set(values)):
        matches = [
            {"module": module, "name": name}
            for module, name in sorted(corpus.get(value, []))
        ]
        result.append(
            {
                "hash": _hex(value),
                "matches": matches,
                "match_status": "unique_in_curated_corpus"
                if len(matches) == 1
                else "collision_in_curated_corpus"
                if matches
                else "unresolved",
                "collision_count_within_corpus": max(0, len(matches) - 1),
            }
        )
    return result


def _bounded_count(total: int, returned: int) -> dict[str, int | bool]:
    """有界collectionの総数、返却数、打切り有無を正規化する。"""

    return {
        "total": total,
        "returned": returned,
        "truncated": returned < total,
    }


def analyze_opaque_native_pe(
    data: bytes,
    *,
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_executable_bytes: int = DEFAULT_MAX_EXECUTABLE_BYTES,
    max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
    max_callsites: int = DEFAULT_MAX_CALLSITES,
    max_candidates: int = DEFAULT_MAX_CANDIDATES,
) -> dict[str, Any]:
    """importless native PEを静的解析し、有界collectionの打切りも返す。

    candidate、function、callsite、loop、hash、entry CFG、埋込み候補の
    coverageを記録し、範囲走査と意味的な復元完了を別々に判定する。
    """

    limits = (
        max_input_bytes,
        max_executable_bytes,
        max_instructions,
        max_callsites,
        max_candidates,
    )
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 1
        for value in limits
    ):
        raise ValueError("解析上限は正の整数で指定してください")
    base = {
        "schema_version": SCHEMA_VERSION,
        "analysis_mode": "bounded_static_disassembly_only",
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "executed": False,
        "emulated": False,
        "network_contacted": False,
        "dependencies": {
            "capstone": getattr(capstone, "__version__", None) if capstone else None,
            "pefile": getattr(pefile, "__version__", None) if pefile else None,
        },
        "budgets": {
            "max_input_bytes": max_input_bytes,
            "max_executable_bytes": max_executable_bytes,
            "max_instructions": max_instructions,
            "max_callsites": max_callsites,
            "max_candidates": max_candidates,
        },
    }
    if len(data) > max_input_bytes:
        return {**base, "status": "input_budget_exceeded", "complete": False}
    if capstone is None or pefile is None:
        return {**base, "status": "dependency_unavailable", "complete": False}
    try:
        image, bits, imports, mappings, sections = _pe_layout(data)
    except (pefile.PEFormatError, OSError, struct.error, ValueError) as exc:
        status = str(exc) if str(exc) == "unsupported_architecture" else "parse_failed"
        return {
            **base,
            "status": status,
            "complete": False,
            "error_type": type(exc).__name__,
        }
    directories = getattr(image.OPTIONAL_HEADER, "DATA_DIRECTORY", ()) or ()
    is_dotnet = bool(
        len(directories) > 14 and getattr(directories[14], "VirtualAddress", 0)
    )
    base["pe"] = {
        "machine": hex(int(image.FILE_HEADER.Machine)),
        "bits": bits,
        "entrypoint_rva": hex(int(image.OPTIONAL_HEADER.AddressOfEntryPoint)),
        "imports": imports,
        "is_dotnet": is_dotnet,
        "sections": sections,
    }
    if imports or is_dotnet:
        return {
            **base,
            "status": "not_applicable",
            "complete": True,
            "reason": "managed_or_static_import_surface_present",
        }
    executable_bytes = sum(size for _, _, size in mappings)
    if not mappings:
        return {**base, "status": "no_executable_section", "complete": False}
    if executable_bytes > max_executable_bytes:
        return {
            **base,
            "status": "executable_byte_budget_exceeded",
            "complete": False,
            "executable_bytes": executable_bytes,
        }

    engine = _make_engine(bits)
    calls, target_counts, instruction_count, linear_exhausted = _scan_calls(
        data,
        engine,
        mappings,
        bits=bits,
        max_instructions=max_instructions,
        max_callsites=max_callsites,
    )
    argument_values: defaultdict[int, defaultdict[str, set[int]]] = defaultdict(
        lambda: defaultdict(set)
    )
    for record in calls:
        target = int(record["target_rva"], 16)
        for register, rendered in record["arguments"].items():
            argument_values[target][register].add(int(rendered, 16))
    entrypoint = int(image.OPTIONAL_HEADER.AddressOfEntryPoint)
    candidate_targets_all = sorted(
        (
            target
            for target, by_register in argument_values.items()
            if target != entrypoint
            and target_counts[target] >= 2
            and any(
                len({value for value in values if value >= 0x10000}) >= 2
                for values in by_register.values()
            )
        ),
        key=lambda target: (
            -max(
                len({value for value in values if value >= 0x10000})
                for values in argument_values[target].values()
            ),
            -target_counts[target],
            target,
        ),
    )
    candidate_targets = candidate_targets_all[: max(0, max_candidates - 1)]
    function_targets = {entrypoint, *candidate_targets}
    known_function_starts = sorted(set(target_counts).union(function_targets))
    function_reports: dict[int, dict[str, Any]] = {}
    pending = deque([entrypoint, *sorted(function_targets - {entrypoint})])
    omitted_function_targets: set[int] = set(
        candidate_targets_all[len(candidate_targets) :]
    )
    while pending and len(function_reports) < max_candidates:
        target = pending.popleft()
        if target in function_reports:
            continue
        next_index = bisect_right(known_function_starts, target)
        function_scan_bytes = DEFAULT_FUNCTION_SCAN_BYTES
        if next_index < len(known_function_starts):
            function_scan_bytes = min(
                function_scan_bytes,
                max(1, known_function_starts[next_index] - target),
            )
        report = _scan_function(
            data,
            engine,
            mappings,
            target,
            max_bytes=function_scan_bytes,
            max_instructions=DEFAULT_MAX_FUNCTION_INSTRUCTIONS,
        )
        report["peb_segment_access"] = _has_peb_access(data, engine, mappings, target)
        function_reports[target] = report
        for rendered in report.get("direct_call_targets", []):
            child = int(rendered, 16)
            if child in function_reports or child in pending:
                continue
            if len(function_reports) + len(pending) < max_candidates:
                pending.append(child)
            else:
                omitted_function_targets.add(child)

    pending_function_targets = set(pending).union(omitted_function_targets)
    function_budget_exhausted = sum(
        report.get("status") == "budget_exhausted"
        for report in function_reports.values()
    )

    fnv_pairs = _seed_prime_pairs(function_reports)
    hash_functions = {address for address, _, _ in fnv_pairs}
    peb_access_functions = {
        address
        for address, report in function_reports.items()
        if report.get("peb_segment_access")
    }
    resolver_records: list[dict[str, Any]] = []
    resolver_targets: set[int] = set()
    for target, report in sorted(function_reports.items()):
        callees = {int(value, 16) for value in report.get("direct_call_targets", [])}
        uses_hash = sorted(callees.intersection(hash_functions))
        uses_peb_helper = []
        if uses_hash:
            uses_peb_helper = sorted(
                {
                    callee
                    for callee in callees
                    if callee in peb_access_functions
                    or _has_peb_access(data, engine, mappings, callee)
                }
            )
        kind = None
        if (report.get("peb_segment_access") or uses_peb_helper) and uses_hash:
            kind = "peb_module_hash_resolver"
        elif (
            report.get("mz_magic_compared")
            and report.get("pe_magic_compared")
            and uses_hash
        ):
            kind = "pe_export_hash_resolver"
        if kind:
            resolver_targets.add(target)
            resolver_records.append(
                {
                    "rva": hex(target),
                    "kind": kind,
                    "hash_function_rvas": [hex(value) for value in uses_hash],
                    "peb_helper_rvas": [hex(value) for value in uses_peb_helper],
                    "call_count": target_counts[target],
                    "confidence": "high",
                    "evidence": [
                        "PEB access (direct or one-hop helper) and hash-function call"
                        if kind.startswith("peb_")
                        else "MZ/PE header comparison and hash-function call"
                    ],
                }
            )
    wrapper_targets: set[int] = set()
    for target, report in sorted(function_reports.items()):
        callees = {int(value, 16) for value in report.get("direct_call_targets", [])}
        if (
            target not in resolver_targets
            and callees.intersection(resolver_targets)
            and int(report.get("instruction_count", 0)) <= 256
            and len(callees) <= 4
            and int(report.get("backward_branches", 0)) <= 2
        ):
            wrapper_targets.add(target)
            resolver_records.append(
                {
                    "rva": hex(target),
                    "kind": "hash_resolver_wrapper",
                    "resolver_rvas": [
                        hex(value)
                        for value in sorted(callees.intersection(resolver_targets))
                    ],
                    "call_count": target_counts[target],
                    "confidence": "medium",
                    "evidence": ["direct call to a structurally identified resolver"],
                }
            )

    relevant_targets = resolver_targets | wrapper_targets
    relevant_calls = [
        record for record in calls if int(record["target_rva"], 16) in relevant_targets
    ]
    api_values_all: set[int] = set()
    module_values_all: set[int] = set()
    module_resolvers = {
        int(item["rva"], 16)
        for item in resolver_records
        if item["kind"] == "peb_module_hash_resolver"
    }
    resolver_argument_registers: dict[int, str] = {}
    for item in resolver_records:
        target = int(item["rva"], 16)
        if item["kind"] == "peb_module_hash_resolver":
            resolver_argument_registers[target] = "rcx"
            item["hash_argument_register"] = "rcx"
        elif item["kind"] == "pe_export_hash_resolver":
            resolver_argument_registers[target] = "rdx" if bits == 64 else "stack_1"
            item["hash_argument_register"] = resolver_argument_registers[target]
        elif item["kind"] == "hash_resolver_wrapper":
            resolver_argument_registers[target] = "rcx" if bits == 64 else "stack_0"
            item["hash_argument_register"] = resolver_argument_registers[target]
    for record in relevant_calls:
        target = int(record["target_rva"], 16)
        register = resolver_argument_registers.get(target)
        rendered = record["arguments"].get(register) if register else None
        if rendered is None:
            continue
        value = int(rendered, 16) & 0xFFFFFFFF
        (module_values_all if target in module_resolvers else api_values_all).add(value)

    api_values = set(sorted(api_values_all)[:MAX_HASH_VALUES])
    module_values = set(sorted(module_values_all)[:MAX_HASH_VALUES])

    selected_pair = (
        fnv_pairs[0]
        if len({(seed, prime) for _, seed, prime in fnv_pairs}) == 1 and fnv_pairs
        else None
    )
    hash_matches = {
        "status": "algorithm_ambiguous_or_unresolved",
        "corpus": "bounded_curated_windows_exports",
        "values": [
            {"hash": _hex(value), "matches": [], "match_status": "unresolved"}
            for value in sorted(api_values)
        ],
    }
    module_matches: list[dict[str, Any]] = []
    if selected_pair:
        _, seed, prime = selected_pair
        hash_matches = {
            "status": "matched_against_bounded_corpus",
            "algorithm": "fnv1a_like_32",
            "seed": _hex(seed),
            "prime": _hex(prime),
            "corpus": "bounded_curated_windows_exports",
            "corpus_size": sum(
                len(values) for values in KNOWN_WINDOWS_EXPORTS.values()
            ),
            "corpus_modules": sorted(KNOWN_WINDOWS_EXPORTS),
            "values": _match_hashes(api_values, seed=seed, prime=prime),
        }
        known_modules = sorted(KNOWN_WINDOWS_EXPORTS)
        for value in sorted(module_values):
            matches = [
                name
                for name in known_modules
                if hash_ascii_name(name.lower(), seed=seed, prime=prime) == value
            ]
            module_matches.append(
                {
                    "hash": _hex(value),
                    "matches": matches,
                    "match_status": "unique_in_curated_corpus"
                    if len(matches) == 1
                    else "collision_in_curated_corpus"
                    if matches
                    else "unresolved",
                    "collision_count_within_corpus": max(0, len(matches) - 1),
                }
            )

    loop_candidates = []
    for target, report in sorted(function_reports.items()):
        score = (
            int(report.get("backward_branches", 0)) * 4
            + int(report.get("memory_write_instructions", 0)) * 2
            + min(20, int(report.get("arithmetic_instructions", 0)))
        )
        if (
            report.get("backward_branches")
            and report.get("memory_write_instructions")
            and score >= 12
        ):
            loop_candidates.append(
                {
                    "rva": hex(target),
                    "score": score,
                    "backward_branches": report["backward_branches"],
                    "memory_write_instructions": report["memory_write_instructions"],
                    "arithmetic_instructions": report["arithmetic_instructions"],
                    "interpretation": "decrypt_or_transform_candidate_not_confirmed",
                }
            )
    loop_candidates.sort(key=lambda item: (-item["score"], item["rva"]))

    embedded, embedded_report = scan_embedded_pe_candidates(
        data,
        lambda blob, offset: inspect_structural_pe_extent(blob, offset).extent,
        start_offset=1,
        max_scan_bytes=min(len(data), max_input_bytes),
        max_candidates=4_096,
        max_results=16,
        max_elapsed_seconds=5.0,
    )
    embedded_items = []
    for offset, extent in embedded:
        blob = data[offset : offset + extent]
        embedded_items.append(
            {
                "offset": hex(offset),
                "size": extent,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "managed_metadata_marker": b"BSJB"
                in blob[: min(len(blob), 16 * 1024 * 1024)],
            }
        )

    try:
        entry_cfg = analyze_pe_control_flow(
            data,
            max_blocks=DEFAULT_ENTRY_CFG_BLOCKS,
            max_instructions=DEFAULT_ENTRY_CFG_INSTRUCTIONS,
            max_input_bytes=max_input_bytes,
            max_block_bytes=65_536,
        )
    except (
        AttributeError,
        IndexError,
        KeyError,
        pefile.PEFormatError,
        struct.error,
        TypeError,
        ValueError,
    ) as exc:
        entry_cfg = {
            "status": "parse_failed",
            "error_type": type(exc).__name__,
            "budgets": {"exhausted": True},
            "metrics": {},
            "techniques": {},
            "method_plan": [],
        }
    cfg_summary = {
        "status": entry_cfg.get("status"),
        "budget_exhausted": (
            entry_cfg.get("status") == "budget_exhausted"
            or (
                isinstance(entry_cfg.get("budgets"), Mapping)
                and entry_cfg["budgets"].get("exhausted") is True
            )
        ),
        "entry_address": entry_cfg.get("entry_address"),
        "budgets": entry_cfg.get("budgets"),
        "metrics": entry_cfg.get("metrics", {}),
        "techniques": entry_cfg.get("techniques", {}),
        "method_plan": entry_cfg.get("method_plan", []),
    }

    unique = sum(
        1
        for item in hash_matches.get("values", [])
        if item.get("match_status") == "unique_in_curated_corpus"
    )
    unresolved = sum(
        1
        for item in hash_matches.get("values", [])
        if item.get("match_status") == "unresolved"
    )
    resolver_callsites = relevant_calls[:MAX_PUBLIC_CALLSITES]
    returned_loop_candidates = loop_candidates[:MAX_PUBLIC_LOOP_CANDIDATES]
    embedded_candidate_total = embedded_report.get("candidate_count")
    if type(embedded_candidate_total) is not int or embedded_candidate_total < 0:
        embedded_candidate_total = len(embedded_items)
    coverage = {
        "candidate_targets": _bounded_count(
            len(candidate_targets_all), len(candidate_targets)
        ),
        "functions": {
            **_bounded_count(
                len(function_reports) + len(pending_function_targets),
                len(function_reports),
            ),
            "budget_exhausted": function_budget_exhausted,
        },
        "resolver_callsites": _bounded_count(
            len(relevant_calls), len(resolver_callsites)
        ),
        "transform_loop_candidates": _bounded_count(
            len(loop_candidates), len(returned_loop_candidates)
        ),
        "hash_values": {
            "api": _bounded_count(len(api_values_all), len(api_values)),
            "module": _bounded_count(len(module_values_all), len(module_values)),
        },
        "linear_scan": {
            "total": instruction_count,
            "returned": instruction_count,
            "truncated": linear_exhausted,
        },
        "entry_control_flow": {
            "total": int(entry_cfg.get("metrics", {}).get("block_count", 0)),
            "returned": int(entry_cfg.get("metrics", {}).get("block_count", 0)),
            "truncated": cfg_summary["budget_exhausted"],
        },
        "embedded_payload_candidates": {
            "total": embedded_candidate_total,
            "returned": len(embedded_items),
            "truncated": (
                embedded_report.get("status") != "complete"
                or embedded_report.get("truncated") is True
            ),
        },
    }
    coverage_complete = not any(
        (
            coverage["candidate_targets"]["truncated"],
            coverage["functions"]["truncated"],
            bool(coverage["functions"]["budget_exhausted"]),
            coverage["resolver_callsites"]["truncated"],
            coverage["transform_loop_candidates"]["truncated"],
            coverage["hash_values"]["api"]["truncated"],
            coverage["hash_values"]["module"]["truncated"],
            coverage["linear_scan"]["truncated"],
            coverage["entry_control_flow"]["truncated"],
            coverage["embedded_payload_candidates"]["truncated"],
        )
    )
    # Static resolver discovery can finish its bounded scan while the terminal
    # payload, every API hash, or reconstructed pointer table remains unknown.
    # Keep semantic completion separate so a collection checkpoint cannot close
    # merely because the byte/instruction budgets were not exhausted.
    iat_rebuild_ready = False
    semantic_resolution_complete = (
        coverage_complete
        and unresolved == 0
        and bool(hash_matches.get("values"))
        and bool(resolver_records)
        and iat_rebuild_ready
    )
    return {
        **base,
        "status": "analyzed_partial" if coverage_complete else "partial",
        "complete": semantic_resolution_complete,
        "coverage_complete": coverage_complete,
        "coverage": coverage,
        "semantic_resolution_complete": semantic_resolution_complete,
        "executable_bytes": executable_bytes,
        "linear_instruction_count": instruction_count,
        "linear_scan_budget_exhausted": linear_exhausted,
        "entry_control_flow": cfg_summary,
        "functions": [
            function_reports[address] for address in sorted(function_reports)
        ],
        "hash_functions": [
            {
                "rva": hex(address),
                "seed": _hex(seed),
                "prime": _hex(prime),
                "algorithm": "fnv1a_like_32",
                "confidence": "high",
            }
            for address, seed, prime in fnv_pairs
        ],
        "resolvers": sorted(
            resolver_records, key=lambda item: (item["rva"], item["kind"])
        ),
        "resolver_callsites": resolver_callsites,
        "api_hash_matches": hash_matches,
        "module_hash_matches": module_matches,
        "transform_loop_candidates": returned_loop_candidates,
        "embedded_payload_candidates": {
            "scan": embedded_report,
            "items": embedded_items,
            "shellcode_status": "not_identified_by_structure",
            "managed_status": "candidate_present"
            if any(item["managed_metadata_marker"] for item in embedded_items)
            else "not_identified",
        },
        "import_reconstruction": {
            "status": "partial_candidate_mapping"
            if unique
            else "resolver_or_api_names_unresolved",
            "unique_api_names_in_curated_corpus": unique,
            "unresolved_hashes": unresolved,
            "iat_rebuild_ready": iat_rebuild_ready,
            "limitation": "dynamic pointer storage and complete export corpus remain unresolved",
        },
        "limitations": [
            "linear disassembly does not execute or emulate computed dataflow",
            "API names are candidates within a bounded corpus, not a complete Windows export proof",
            "transform loop candidates do not prove decoded output boundaries",
        ],
    }


__all__ = ["KNOWN_WINDOWS_EXPORTS", "analyze_opaque_native_pe", "hash_ascii_name"]
