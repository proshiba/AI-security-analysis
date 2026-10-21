"""PE末尾の厳格なRC4 trailer形式を、検体を実行せず復元する。

このモジュールが証明するのは、PE image直後の固定長header、末尾offset、
RC4と条件付きXORから得られるraw x86 shellcodeまでである。この構造だけで
malware family、C2、終端payloadを確定してはならない。
"""

from __future__ import annotations

import hashlib
import struct
from collections import Counter

from capstone import CS_ARCH_X86, CS_MODE_32, Cs

from unpackers.bounded_pe_scan import inspect_structural_pe_extent

HEADER_SIZE = 500
KEY_SIZE = 32
DECLARED_LENGTH_OFFSET = KEY_SIZE
FOOTER_SIZE = 4
XOR_MARKER = b"\x92\xe9\x7f\x7b\x7b"
XOR_VALUE = 0x7B

MAX_INPUT_SIZE = 128 * 1024 * 1024
MAX_OUTPUT_SIZE = 64 * 1024 * 1024
MIN_SHELLCODE_SIZE = 64
MAX_ENTRY_PROBE_SIZE = 512
MIN_ENTRY_INSTRUCTIONS = 16
# entry blockの後方にはdata tableが連結されるため、probe全域を命令として
# 解釈することは要求しない。代わりに命令数とcontrol-flowを併用する。
MIN_ENTRY_COVERAGE = 0.50


class TrailerRc4Error(ValueError):
    """trailer境界、復号結果またはshellcode構造を検証できない。"""


def _rc4(data: bytes, key: bytes) -> bytes:
    """固定済み入力境界内で標準RC4 KSA／PRGAを適用する。"""

    if len(key) != KEY_SIZE:
        raise TrailerRc4Error("RC4 key lengthが32 byteではありません")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % KEY_SIZE]) & 0xFF
        state[i], state[j] = state[j], state[i]

    output = bytearray(len(data))
    i = j = 0
    for offset, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[offset] = value ^ state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def _validate_x86_shellcode(payload: bytes) -> dict[str, object]:
    """先頭relative jumpと到達先命令列を検証し、data誤復元を拒否する。"""

    if not MIN_SHELLCODE_SIZE <= len(payload) <= MAX_OUTPUT_SIZE:
        raise TrailerRc4Error("復元物sizeがshellcode上限外です")
    if payload[0] != 0xE9:
        raise TrailerRc4Error("復元物先頭がx86 near jumpではありません")
    displacement = struct.unpack_from("<i", payload, 1)[0]
    entry_offset = 5 + displacement
    if not 5 <= entry_offset < len(payload):
        raise TrailerRc4Error("x86 entry jumpの到達先が復元物範囲外です")

    probe = payload[entry_offset : entry_offset + MAX_ENTRY_PROBE_SIZE]
    if len(probe) < MIN_SHELLCODE_SIZE or len(set(probe)) < 4:
        raise TrailerRc4Error("x86 entry probeが短いか情報量不足です")
    engine = Cs(CS_ARCH_X86, CS_MODE_32)
    try:
        instructions = list(engine.disasm(probe, entry_offset))
    except (AttributeError, TypeError, ValueError) as exc:
        raise TrailerRc4Error("x86 entry命令列を解析できません") from exc
    covered = sum(int(item.size) for item in instructions)
    coverage = covered / len(probe)
    control_flow_count = sum(
        item.mnemonic.startswith(("call", "j", "ret", "loop")) for item in instructions
    )
    if (
        len(instructions) < MIN_ENTRY_INSTRUCTIONS
        or coverage < MIN_ENTRY_COVERAGE
        or control_flow_count < 1
    ):
        raise TrailerRc4Error("x86 entry命令列の構造を検証できません")
    return {
        "initial_jump_kind": "near_relative_32",
        "initial_jump_target": entry_offset,
        "initial_jump_target_in_bounds": True,
        "entry_probe_size": len(probe),
        "instruction_count": len(instructions),
        "instruction_coverage": round(coverage, 6),
        "control_flow_count": control_flow_count,
    }


def _base_report() -> dict[str, object]:
    """raw keyやpayloadを含めない公開reportの共通部分を返す。"""

    return {
        "schema_version": 1,
        "status": "no_candidates",
        "profile": "pe-overlay-rc4-optional-xor7b-trailer-v1",
        "candidate_count": 0,
        "evaluated_candidate_count": 0,
        "rejected_candidate_count": 0,
        "rejection_reasons": {},
        "recovered_artifact_count": 0,
        "candidate_set_complete": True,
        "recovery_attempts_complete": True,
        "recovered_artifact_set_complete": True,
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "terminal_payload_confirmed": False,
        "budgets": {
            "max_input_size": MAX_INPUT_SIZE,
            "max_output_size": MAX_OUTPUT_SIZE,
            "header_size": HEADER_SIZE,
            "key_size": KEY_SIZE,
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_key_included": False,
            "raw_payload_included": False,
            "family_or_c2_promoted": False,
        },
    }


def recover_pe_trailer_rc4(
    data: bytes,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """全境界と復号後構造を検証できた場合だけshellcodeを返す。"""

    if type(data) is not bytes:
        raise TypeError("dataはbytesで指定してください")
    report = _base_report()
    rejections: Counter[str] = Counter()
    if len(data) > MAX_INPUT_SIZE:
        report.update(
            {
                "status": "budget_exhausted",
                "candidate_set_complete": False,
                "recovery_attempts_complete": False,
                "recovered_artifact_set_complete": False,
                "limit_reason": "input_size_limit",
            }
        )
        return report, []
    if len(data) < 0x40 + HEADER_SIZE + FOOTER_SIZE + MIN_SHELLCODE_SIZE:
        return report, []

    structural = inspect_structural_pe_extent(data, max_extent=len(data))
    if structural.extent is None:
        return report, []
    image_extent = int(structural.extent)
    trailer_offset = struct.unpack_from("<I", data, len(data) - FOOTER_SIZE)[0]
    if trailer_offset != image_extent:
        return report, []

    report["candidate_count"] = 1
    minimum_end = trailer_offset + HEADER_SIZE + FOOTER_SIZE
    if trailer_offset < 0x40 or minimum_end > len(data):
        rejections["trailer_bounds_invalid"] += 1
    else:
        header_end = trailer_offset + HEADER_SIZE
        header = data[trailer_offset:header_end]
        key = header[:KEY_SIZE]
        declared_length = struct.unpack_from("<I", header, DECLARED_LENGTH_OFFSET)[0]
        if len(key) != KEY_SIZE or not any(key):
            rejections["key_invalid"] += 1
        elif not MIN_SHELLCODE_SIZE <= declared_length <= MAX_OUTPUT_SIZE:
            reason = (
                "declared_output_size_limit"
                if declared_length > MAX_OUTPUT_SIZE
                else "declared_output_size_invalid"
            )
            rejections[reason] += 1
            if reason == "declared_output_size_limit":
                report.update(
                    {
                        "status": "budget_exhausted",
                        "candidate_set_complete": True,
                        "recovery_attempts_complete": False,
                        "recovered_artifact_set_complete": False,
                        "limit_reason": reason,
                    }
                )
        elif trailer_offset + HEADER_SIZE + declared_length + FOOTER_SIZE != len(data):
            rejections["declared_output_boundary_mismatch"] += 1
        else:
            report["evaluated_candidate_count"] = 1
            encrypted = data[header_end : header_end + declared_length]
            try:
                rc4_output = _rc4(encrypted, key)
                xor_applied = rc4_output.startswith(XOR_MARKER)
                payload = (
                    bytes(value ^ XOR_VALUE for value in rc4_output)
                    if xor_applied
                    else rc4_output
                )
                if len(payload) != declared_length:
                    raise TrailerRc4Error("復元物sizeが宣言値と一致しません")
                x86_validation = _validate_x86_shellcode(payload)
            except (MemoryError, OverflowError, TrailerRc4Error, struct.error):
                rejections["decoded_structure_invalid"] += 1
            else:
                artifact_kind = (
                    "pe-trailer-rc4-xor7b-x86-shellcode"
                    if xor_applied
                    else "pe-trailer-rc4-x86-shellcode"
                )
                artifact = {
                    "kind": artifact_kind,
                    "size": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "format": "raw-x86-shellcode",
                    "structure_validated": True,
                    "family_attribution_allowed": False,
                    "c2_confirmation_allowed": False,
                    "terminal_payload_confirmed": False,
                    "raw_payload_included": False,
                }
                report.update(
                    {
                        "status": "recovered_x86_shellcode",
                        "recovered_artifact_count": 1,
                        "trailer": {
                            "footer_offset_matches_pe_extent": True,
                            "header_size": HEADER_SIZE,
                            "key_size": KEY_SIZE,
                            "declared_length_matches_payload": True,
                            "exact_eof_boundary": True,
                            "post_rc4_marker_matched": xor_applied,
                            "raw_key_included": False,
                        },
                        "transforms": (
                            ["rc4", "xor_0x7b_after_exact_marker"]
                            if xor_applied
                            else ["rc4"]
                        ),
                        "artifact": artifact,
                        "x86_validation": x86_validation,
                    }
                )
                return report, [(str(artifact["kind"]), payload)]

    report["rejected_candidate_count"] = sum(rejections.values())
    report["rejection_reasons"] = dict(sorted(rejections.items()))
    if report["status"] != "budget_exhausted":
        report["status"] = "candidate_rejected"
    return report, []


__all__ = [
    "DECLARED_LENGTH_OFFSET",
    "FOOTER_SIZE",
    "HEADER_SIZE",
    "KEY_SIZE",
    "MAX_INPUT_SIZE",
    "MAX_OUTPUT_SIZE",
    "XOR_MARKER",
    "XOR_VALUE",
    "TrailerRc4Error",
    "recover_pe_trailer_rc4",
]
