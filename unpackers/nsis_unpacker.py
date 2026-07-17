"""Static recovery helpers for NSIS installers with script-driven byte decoders.

The module never launches an installer or a recovered artifact.  It reconstructs
only transformations that are explicit in the decompiled NSIS script and in a
bounded, statically inspected decoder stub.
"""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
import re
from typing import Any

DEFAULT_WORD_XOR_KEY = 399_936_311
DEFAULT_TERMINATOR = ord("Q")
MAX_STATIC_STAGE = 64 * 1024 * 1024


def sha256_bytes(data: bytes) -> str:
    """Return a lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def decode_nsis_hex_xor_words(
    data: bytes,
    *,
    offset: int = 12,
    read_chars: int = 2048,
    key: int = DEFAULT_WORD_XOR_KEY,
    terminator: int = DEFAULT_TERMINATOR,
) -> tuple[dict[str, Any], bytes]:
    """Reproduce an NSIS ``IntOp``/``IntFmt`` 32-bit XOR text decoder.

    The source is ASCII hexadecimal.  Each eight-character word is XORed as an
    unsigned 32-bit integer and then emitted in the left-to-right byte order of
    NSIS ``IntFmt %08X`` followed by two-character ``%C`` conversions.
    """
    if offset < 0 or read_chars <= 0 or read_chars > MAX_STATIC_STAGE:
        return {"status": "invalid_bounds"}, b""
    window = data[offset : offset + read_chars]
    usable = len(window) - (len(window) % 8)
    if usable == 0 or not re.fullmatch(rb"[0-9A-Fa-f]+", window[:usable]):
        return {"status": "not_ascii_hex_words"}, b""
    output = bytearray()
    for cursor in range(0, usable, 8):
        value = int(window[cursor : cursor + 8], 16) ^ (key & 0xFFFFFFFF)
        output.extend((value & 0xFFFFFFFF).to_bytes(4, "big"))
    groups = bytes(output).split(bytes([terminator]))
    calls = extract_system_call_fragments(bytes(output))
    report = {
        "status": "decoded",
        "source_offset": offset,
        "source_characters": usable,
        "key": f"0x{key & 0xFFFFFFFF:08x}",
        "terminator": chr(terminator) if 32 <= terminator < 127 else terminator,
        "decoded_size": len(output),
        "decoded_sha256": sha256_bytes(bytes(output)),
        "group_count": len(groups),
        "group_sizes": [len(group) for group in groups],
        "system_calls": calls,
    }
    return report, bytes(output)


def extract_system_call_fragments(decoded: bytes) -> list[str]:
    """Extract printable NSIS System-plugin call expressions from decoded data."""
    fragments: list[str] = []
    pattern = re.compile(
        rb"[A-Za-z0-9_.-]+::[A-Za-z0-9_]+\([^\x00\r\n)]{1,512}\)(?:[A-Za-z]\.[rR][0-9])?"
    )
    for match in pattern.finditer(decoded):
        value = match.group(0).decode("ascii", errors="ignore").strip()
        if value.startswith("Q") and "::" in value[1:]:
            value = value[1:]
        if value and value not in fragments:
            fragments.append(value)
    return fragments


def _register_alias(name: str) -> tuple[str, int] | None:
    name = name.lower().strip()
    legacy = {
        "rax": ("rax", 64),
        "eax": ("rax", 32),
        "ax": ("rax", 16),
        "al": ("rax", 8),
        "rbx": ("rbx", 64),
        "ebx": ("rbx", 32),
        "bx": ("rbx", 16),
        "bl": ("rbx", 8),
        "rcx": ("rcx", 64),
        "ecx": ("rcx", 32),
        "cx": ("rcx", 16),
        "cl": ("rcx", 8),
        "rdx": ("rdx", 64),
        "edx": ("rdx", 32),
        "dx": ("rdx", 16),
        "dl": ("rdx", 8),
        "rsi": ("rsi", 64),
        "esi": ("rsi", 32),
        "rdi": ("rdi", 64),
        "edi": ("rdi", 32),
        "rbp": ("rbp", 64),
        "ebp": ("rbp", 32),
        "rsp": ("rsp", 64),
        "esp": ("rsp", 32),
    }
    if name in legacy:
        return legacy[name]
    match = re.fullmatch(r"(r(?:8|9|1[0-5]))(d|w|b)?", name)
    if match:
        return match.group(1), {None: 64, "d": 32, "w": 16, "b": 8}[match.group(2)]
    return None


def _rotate(value: int, count: int, width: int, left: bool) -> int:
    mask = (1 << width) - 1
    count %= width
    value &= mask
    if not count:
        return value
    if left:
        return ((value << count) | (value >> (width - count))) & mask
    return ((value >> count) | (value << (width - count))) & mask


def _read_constant(
    registers: dict[str, int | None], token: str
) -> tuple[int | None, int]:
    alias = _register_alias(token)
    if alias:
        base, width = alias
        value = registers.get(base)
        return (None if value is None else value & ((1 << width) - 1)), width
    try:
        return int(token.strip(), 0), 64
    except ValueError:
        return None, 64


def _write_constant(
    registers: dict[str, int | None], token: str, value: int | None
) -> None:
    alias = _register_alias(token)
    if not alias:
        return
    base, width = alias
    if value is None:
        registers[base] = None
        return
    mask = (1 << width) - 1
    value &= mask
    if width == 64:
        registers[base] = value
    elif width == 32:
        registers[base] = value
    else:
        prior = registers.get(base)
        registers[base] = None if prior is None else (prior & ~mask) | value


def find_static_dword_xor_loop(data: bytes, scan_limit: int = 4096) -> dict[str, Any]:
    """Find a constant-key dword XOR loop by linear static propagation.

    This intentionally handles only register/immediate arithmetic and does not
    emulate instructions, memory, calls, or branches.  It is therefore suitable
    for recognizing an explicit decoder loop while refusing ambiguous stubs.
    """
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
    except ImportError:
        return {"status": "capstone_unavailable"}

    registers: dict[str, int | None] = {}
    pending: dict[str, Any] | None = None
    disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
    for instruction in disassembler.disasm(data[:scan_limit], 0):
        mnemonic = instruction.mnemonic.lower()
        operands = [item.strip() for item in instruction.op_str.split(",")]
        if mnemonic in {"call"}:
            continue
        if mnemonic in {"mov", "movabs"} and len(operands) == 2:
            if _register_alias(operands[0]):
                value, _ = _read_constant(registers, operands[1])
                _write_constant(registers, operands[0], value)
            continue
        if mnemonic in {"inc", "dec", "neg", "not", "bswap"} and len(operands) == 1:
            alias = _register_alias(operands[0])
            if not alias:
                continue
            value, width = _read_constant(registers, operands[0])
            if value is None:
                continue
            mask = (1 << width) - 1
            if mnemonic == "inc":
                value += 1
            elif mnemonic == "dec":
                value -= 1
            elif mnemonic == "neg":
                value = -value
            elif mnemonic == "not":
                value = ~value
            else:
                value = int.from_bytes(
                    (value & mask).to_bytes(width // 8, "little"), "big"
                )
            _write_constant(registers, operands[0], value & mask)
            continue
        if (
            mnemonic in {"add", "sub", "xor", "and", "or", "rol", "ror", "shl", "shr"}
            and len(operands) == 2
        ):
            destination = _register_alias(operands[0])
            if destination:
                left, width = _read_constant(registers, operands[0])
                right, _ = _read_constant(registers, operands[1])
                if left is None or right is None:
                    if mnemonic == "xor" and operands[0].lower() == operands[1].lower():
                        _write_constant(registers, operands[0], 0)
                    else:
                        _write_constant(registers, operands[0], None)
                    continue
                mask = (1 << width) - 1
                if mnemonic == "add":
                    value = left + right
                elif mnemonic == "sub":
                    value = left - right
                elif mnemonic == "xor":
                    value = left ^ right
                elif mnemonic == "and":
                    value = left & right
                elif mnemonic == "or":
                    value = left | right
                elif mnemonic == "rol":
                    value = _rotate(left, right, width, True)
                elif mnemonic == "ror":
                    value = _rotate(left, right, width, False)
                elif mnemonic == "shl":
                    value = left << right
                else:
                    value = left >> right
                _write_constant(registers, operands[0], value & mask)
                continue
            if mnemonic == "xor" and "dword ptr [" in operands[0].lower():
                key, width = _read_constant(registers, operands[1])
                index_match = re.search(
                    r"\+\s*(r(?:ax|bx|cx|dx|si|di|bp|sp|8|9|1[0-5]))\s*\]",
                    operands[0],
                    re.I,
                )
                index = index_match.group(1).lower() if index_match else "rax"
                start, _ = _read_constant(registers, index)
                if key is not None and width in {32, 64} and start is not None:
                    pending = {
                        "status": "candidate",
                        "instruction_offset": instruction.address,
                        "index_register": index,
                        "start": start,
                        "key": key & 0xFFFFFFFF,
                        "word_size": 4,
                    }
                continue
        if mnemonic == "cmp" and len(operands) == 2 and pending:
            if operands[0].lower() == pending["index_register"]:
                end, _ = _read_constant(registers, operands[1])
                current, _ = _read_constant(registers, operands[0])
                step = None if current is None else current - pending["start"]
                if (
                    end is not None
                    and step is not None
                    and step > 0
                    and end > pending["start"]
                    and end <= MAX_STATIC_STAGE
                    and (end - pending["start"]) % step == 0
                ):
                    return {
                        **pending,
                        "status": "identified",
                        "end": end,
                        "length": end - pending["start"],
                        "step": step,
                    }
    return {"status": "not_identified"}


def apply_dword_xor(data: bytes, key: int, length: int) -> bytes:
    """Apply a bounded little-endian dword XOR, zero-padding a short final page."""
    if length <= 0 or length > MAX_STATIC_STAGE or length % 4:
        raise ValueError("invalid dword XOR length")
    if len(data) > length:
        data = data[:length]
    if len(data) < length:
        if length - len(data) > 4096:
            raise ValueError("source is too short for bounded zero padding")
        data += b"\x00" * (length - len(data))
    key_bytes = (key & 0xFFFFFFFF).to_bytes(4, "little")
    return bytes(value ^ key_bytes[index % 4] for index, value in enumerate(data))


def recover_nsis_scripted_layers(
    files: dict[str, bytes],
) -> tuple[dict[str, Any], list[tuple[str, bytes]]]:
    """Recover recognized NSIS-script XOR layers from an extracted file map."""
    script_name = next(
        (name for name in files if name.lower().endswith("[nsis].nsi")), None
    )
    script = (
        files[script_name].decode("utf-8", errors="replace")
        if script_name
        else ""
    )
    decoder_name: str | None = None
    recovery_basis = "decompiled_nsis_script"
    if script_name:
        key_match = re.search(r"StrCpy\s+\$R9\s+(\d+)", script, re.I)
        seek_match = re.search(r"FileSeek\s+\S+\s+(\d+)", script, re.I)
        read_match = re.search(r"FileRead\s+\S+\s+\S+\s+(\d+)", script, re.I)
        decoder_match = re.search(
            r"StrCpy\s+\S+\s+\$INSTDIR\\([^\r\n]+?Drbler)\s*$",
            script,
            re.I | re.M,
        )
        if not (key_match and seek_match and read_match and decoder_match):
            return {"status": "unsupported_nsis_script_pattern"}, []
        decoder_suffix = decoder_match.group(1).replace("\\", "/").lower()
        decoder_name = next(
            (name for name in files if name.lower().endswith(decoder_suffix)), None
        )
        if not decoder_name:
            return {"status": "decoder_data_missing", "expected": decoder_suffix}, []
        word_report, command_stream = decode_nsis_hex_xor_words(
            files[decoder_name],
            offset=int(seek_match.group(1)),
            read_chars=int(read_match.group(1)),
            key=int(key_match.group(1)),
        )
    else:
        # 7-Zip 26.x no longer emits the synthetic [NSIS].nsi stream for this
        # installer family. Recover only the already-supported default layout
        # and require several independent System-plugin call shapes. This is a
        # bounded static signature, not a general NSIS bytecode interpreter.
        candidates: list[tuple[str, dict[str, Any], bytes]] = []
        required_calls = ("setfilepointer", "readfile", "virtualalloc")
        for name, blob in sorted(files.items()):
            candidate_report, candidate_stream = decode_nsis_hex_xor_words(blob)
            calls = [
                str(value).lower()
                for value in candidate_report.get("system_calls", [])
            ]
            if candidate_stream and all(
                any(required in call for call in calls) for required in required_calls
            ):
                candidates.append((name, candidate_report, candidate_stream))
        if not candidates:
            return {
                "status": "no_decompiled_nsis_script",
                "scriptless_fallback": "no_corroborated_command_stream",
            }, []
        if len(candidates) != 1:
            return {
                "status": "ambiguous_scriptless_command_stream",
                "candidate_count": len(candidates),
                "candidate_sha256": [
                    sha256_bytes(stream) for _, _, stream in candidates
                ],
            }, []
        decoder_name, word_report, command_stream = candidates[0]
        recovery_basis = "corroborated_encoded_command_stream"
    report: dict[str, Any] = {
        "status": "command_stream_recovered"
        if command_stream
        else word_report["status"],
        "decoder_data": decoder_name,
        "recovery_basis": recovery_basis,
        "word_decoder": word_report,
    }
    if script_name:
        report["script"] = script_name
    artifacts: list[tuple[str, bytes]] = []
    if command_stream:
        artifacts.append(("nsis-xor-command-stream", command_stream))
    calls = word_report.get("system_calls", [])
    pointer_values = [
        int(value)
        for call in calls
        for value in re.findall(r"SetFilePointer\([^,]+,\s*i?\s*(\d+)", call, re.I)
    ]
    read_sizes = [
        int(value)
        for call in calls
        for value in re.findall(r"ReadFile\([^,]+,[^,]+,\s*i?\s*(\d+)", call, re.I)
    ]
    if len(pointer_values) < 2 or not read_sizes:
        report["stage_recovery"] = {"status": "insufficient_call_parameters"}
        return report, artifacts
    stage_offset, source_offset = pointer_values[0], pointer_values[1]
    stage_size = read_sizes[0]
    payload_match = (
        re.search(r"StrCpy\s+\$4\s+\$INSTDIR\\([^\r\n]+)\s*$", script, re.I | re.M)
        if script
        else None
    )
    payload_suffix = (
        payload_match.group(1).replace("\\", "/").lower() if payload_match else ""
    )
    payload_name = next(
        (
            name
            for name in files
            if payload_suffix and name.lower().endswith(payload_suffix)
        ),
        None,
    )
    decoder_stage: bytes | None = None
    xor_loop: dict[str, Any] | None = None
    if not payload_name:
        excluded = {name for name in (script_name, decoder_name) if name}
        candidate_names = sorted(
            name
            for name in files
            if name not in excluded and not PurePosixPath(name).suffix
        )
        if script_name:
            candidates = [(len(files[name]), name) for name in candidate_names]
            payload_name = max(candidates)[1] if candidates else None
        else:
            # A scriptless extraction does not provide the NSIS variable that
            # names the payload. Validate every extensionless candidate instead
            # of treating file size as identity, then require uniqueness.
            validated: list[tuple[str, bytes, dict[str, Any]]] = []
            for name in candidate_names:
                blob = files[name]
                if (
                    stage_offset < 0
                    or stage_size <= 0
                    or stage_offset + stage_size > len(blob)
                ):
                    continue
                candidate_stage = blob[stage_offset : stage_offset + stage_size]
                candidate_loop = find_static_dword_xor_loop(candidate_stage)
                if candidate_loop.get("status") == "identified":
                    validated.append((name, candidate_stage, candidate_loop))
            if not validated:
                report["stage_recovery"] = {
                    "status": "no_valid_scriptless_payload_candidate",
                    "candidate_count": len(candidate_names),
                }
                return report, artifacts
            if len(validated) != 1:
                report["stage_recovery"] = {
                    "status": "ambiguous_scriptless_payload_candidates",
                    "candidate_count": len(validated),
                    "candidate_names": [name for name, _, _ in validated],
                }
                return report, artifacts
            payload_name, decoder_stage, xor_loop = validated[0]
    if not payload_name:
        report["stage_recovery"] = {"status": "payload_data_missing"}
        return report, artifacts
    payload = files[payload_name]
    if decoder_stage is None or xor_loop is None:
        if stage_offset < 0 or stage_size <= 0 or stage_offset + stage_size > len(payload):
            report["stage_recovery"] = {"status": "invalid_stage_bounds"}
            return report, artifacts
        decoder_stage = payload[stage_offset : stage_offset + stage_size]
        xor_loop = find_static_dword_xor_loop(decoder_stage)
    stage_report: dict[str, Any] = {
        "status": xor_loop["status"],
        "payload_data": payload_name,
        "decoder_stage_offset": stage_offset,
        "decoder_stage_size": stage_size,
        "decoder_stage_sha256": sha256_bytes(decoder_stage),
        "encoded_stage_offset": source_offset,
        "xor_loop": xor_loop,
    }
    if xor_loop.get("status") == "identified":
        try:
            decoded_stage = apply_dword_xor(
                payload[source_offset : source_offset + xor_loop["length"]],
                xor_loop["key"],
                xor_loop["length"],
            )
        except ValueError as exc:
            stage_report["status"] = "bounded_decode_failed"
            stage_report["error"] = str(exc)
        else:
            stage_report.update(
                {
                    "status": "intermediate_recovered",
                    "decoded_size": len(decoded_stage),
                    "decoded_sha256": sha256_bytes(decoded_stage),
                    "decoded_magic": decoded_stage[:4].hex(),
                    "final_payload_recovered": False,
                    "remaining_layer": "native control-flow-obfuscated loader",
                }
            )
            artifacts.append(("nsis-static-dword-xor-stage", decoded_stage))
    report["stage_recovery"] = stage_report
    return report, artifacts
