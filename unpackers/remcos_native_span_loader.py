"""Remcos raw x86 bootstrapがspan2を復号する処理を静的に再現する。

対象は、PowerShell側で別bufferへ配置されたx86 bootstrap（span1）と暗号化
payload（span2）の組合せである。bootstrapはjump間へ大量のSIMD junkを挿入するが、
source/destination copy loopとdword XOR loopのdataflowは明示されている。本moduleは
その二つのloopを命令anchorとbranch整合性で一意に検証し、抽出したlengthとkeyだけを
適用する。bootstrapも復元物も実行しない。
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass

from unpackers.remcos_native_constant_writer import recover_remcos_native_constants
from unpackers.remcos_polymorphic_xor_loader import (
    recover_remcos_polymorphic_xor_loader,
)

_COPY_LOOP = re.compile(
    rb"\x8b\x44\x24\x04"  # mov eax,[esp+4]
    rb".{0,512}?\x89\xc3"  # mov ebx,eax
    rb".{0,512}?\x81\xc3(?P<destination_delta>.{4})"  # add ebx,imm32
    rb".{0,1280}?\x8b\x0c\x10"  # mov ecx,[eax+edx]
    rb".{0,512}?\x89\x0c\x13"  # mov [ebx+edx],ecx
    rb".{0,512}?\x42"  # inc edx
    rb".{0,512}?\x81\xfa(?P<copy_size>.{4})"  # cmp edx,imm32
    rb".{0,512}?(?P<branch>\x0f\x85.{4})",  # jne rel32
    re.DOTALL,
)
_XOR_LOOP = re.compile(
    rb"\xba(?P<stage_size>.{4})"  # mov edx,imm32
    rb".{0,512}?\x31\xc0"  # xor eax,eax
    rb".{0,512}?\x8b\x7c\x24\x0c"  # mov edi,[esp+0xc]
    rb".{0,512}?\x81\x34\x07(?P<xor_key>.{4})"  # xor dword [edi+eax],imm32
    rb".{0,512}?\x83\xc0\x04"  # add eax,4
    rb".{0,512}?\x39\xd0"  # cmp eax,edx
    rb".{0,512}?(?P<branch>\x0f\x85.{4})"  # jne rel32
    rb".{0,1024}?\xff\xd7",  # call edi（cleanup junkを含む）
    re.DOTALL,
)


@dataclass(frozen=True)
class RemcosNativeSpanLimits:
    """bootstrapとpayload復元のhard limit。"""

    max_loader_bytes: int = 4 * 1024 * 1024
    max_payload_bytes: int = 64 * 1024 * 1024
    max_stage_bytes: int = 64 * 1024 * 1024
    max_zero_padding_bytes: int = 16 * 1024 * 1024
    max_pattern_candidates: int = 16
    max_anchor_candidates: int = 4096
    max_work_bytes: int = 256 * 1024 * 1024
    require_constant_writer_validation: bool = True


DEFAULT_LIMITS = RemcosNativeSpanLimits()


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _branch_target(instruction_offset: int, instruction: bytes) -> int | None:
    if len(instruction) != 6 or instruction[:2] != b"\x0f\x85":
        return None
    displacement = int.from_bytes(instruction[2:], "little", signed=True)
    return instruction_offset + 6 + displacement


def _match_offset(match: re.Match[bytes], group: str) -> int:
    return match.start(group)


def _overlapping_matches(
    pattern: re.Pattern[bytes],
    data: bytes,
    anchor: bytes,
    match_limit: int,
    anchor_limit: int,
) -> list[re.Match[bytes]] | None:
    """junk内の同一opcode開始も含め、上限付きで候補を列挙する。"""

    matches: list[re.Match[bytes]] = []
    offset = 0
    anchor_count = 0
    while True:
        offset = data.find(anchor, offset)
        if offset < 0:
            return matches
        anchor_count += 1
        if anchor_count > anchor_limit:
            return None
        match = pattern.match(data, offset)
        if match is not None:
            matches.append(match)
            if len(matches) > match_limit:
                return None
        offset += 1


def _copy_profile(data: bytes, limits: RemcosNativeSpanLimits) -> dict[str, int] | None:
    matches = _overlapping_matches(
        _COPY_LOOP,
        data,
        b"\x8b\x44\x24\x04",
        limits.max_pattern_candidates,
        limits.max_anchor_candidates,
    )
    if not matches:
        return None
    accepted: list[dict[str, int]] = []
    for match in matches:
        copy_size = int.from_bytes(match.group("copy_size"), "little")
        destination_delta = int.from_bytes(match.group("destination_delta"), "little")
        branch_offset = _match_offset(match, "branch")
        branch_target = _branch_target(branch_offset, match.group("branch"))
        load_offset = match.start() + match.group(0).find(b"\x8b\x0c\x10")
        store_offset = match.start() + match.group(0).find(b"\x89\x0c\x13")
        if (
            copy_size < 256
            or copy_size > limits.max_stage_bytes
            or copy_size % 4
            or destination_delta < copy_size
            or branch_target is None
            or not match.start() <= branch_target <= load_offset
            or not load_offset < store_offset < branch_offset
        ):
            continue
        accepted.append(
            {
                "profile_offset": match.start(),
                "copy_load_offset": load_offset,
                "copy_store_offset": store_offset,
                "copy_branch_offset": branch_offset,
                "copy_branch_target": branch_target,
                "destination_delta": destination_delta,
                "stage_size": copy_size,
            }
        )
    return accepted[0] if len(accepted) == 1 else None


def _xor_profile(
    data: bytes,
    expected_size: int,
    limits: RemcosNativeSpanLimits,
) -> tuple[dict[str, int], bytes] | None:
    matches = _overlapping_matches(
        _XOR_LOOP,
        data,
        b"\xba",
        limits.max_pattern_candidates,
        limits.max_anchor_candidates,
    )
    if not matches:
        return None
    accepted: list[tuple[dict[str, int], bytes]] = []
    for match in matches:
        stage_size = int.from_bytes(match.group("stage_size"), "little")
        key = match.group("xor_key")
        xor_offset = match.start() + match.group(0).find(b"\x81\x34\x07")
        branch_offset = _match_offset(match, "branch")
        branch_target = _branch_target(branch_offset, match.group("branch"))
        if (
            stage_size != expected_size
            or not key
            or branch_target is None
            or not match.start() <= branch_target <= xor_offset
            or not xor_offset < branch_offset
        ):
            continue
        accepted.append(
            (
                {
                    "profile_offset": match.start(),
                    "xor_offset": xor_offset,
                    "xor_branch_offset": branch_offset,
                    "xor_branch_target": branch_target,
                    "stage_size": stage_size,
                },
                key,
            )
        )
    return accepted[0] if len(accepted) == 1 else None


def recover_remcos_native_span_stage(
    loader_data: bytes,
    payload_data: bytes,
    *,
    limits: RemcosNativeSpanLimits = DEFAULT_LIMITS,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """span1の一意なcopy/XOR profileに従いspan2から次段raw codeを復元する。"""

    report: dict[str, object] = {
        "schema_version": 1,
        "profile": "remcos-raw-x86-span-copy-dword-xor-v1",
        "status": "rejected",
        "loader_size": len(loader_data) if isinstance(loader_data, bytes) else None,
        "loader_sha256": _sha256(loader_data)
        if isinstance(loader_data, bytes)
        else None,
        "payload_size": len(payload_data) if isinstance(payload_data, bytes) else None,
        "payload_sha256": _sha256(payload_data)
        if isinstance(payload_data, bytes)
        else None,
        "candidate_set_complete": False,
        "candidate_set_truncated": False,
        "candidate_count": 0,
        "limits": asdict(limits),
        "safety": {
            "sample_executed": False,
            "shellcode_executed": False,
            "network_contacted": False,
            "general_emulator_used": False,
            "raw_xor_key_included": False,
        },
        "evidence_boundary": {
            "family_attribution_allowed": False,
            "c2_confirmation_allowed": False,
            "recovered_stage_is_terminal_payload": False,
        },
    }
    if not isinstance(loader_data, bytes) or not isinstance(payload_data, bytes):
        raise TypeError("loader_dataとpayload_dataはbytesである必要があります")
    if (
        not loader_data
        or len(loader_data) > limits.max_loader_bytes
        or not payload_data
        or len(payload_data) > limits.max_payload_bytes
    ):
        report["status"] = "input_size_rejected"
        return report, []
    copy = _copy_profile(loader_data, limits)
    if copy is None:
        report["status"] = "copy_profile_not_unique"
        return report, []
    xor_context = _xor_profile(loader_data, copy["stage_size"], limits)
    if xor_context is None:
        report["status"] = "xor_profile_not_unique"
        return report, []
    xor_profile, key = xor_context
    stage_size = copy["stage_size"]
    padding_size = stage_size - len(payload_data)
    if padding_size < 0:
        report["status"] = "payload_exceeds_stage_size"
        return report, []
    if padding_size > limits.max_zero_padding_bytes:
        report["status"] = "zero_padding_limit_exceeded"
        return report, []
    work_bytes = stage_size * 2
    if work_bytes > limits.max_work_bytes:
        report["status"] = "work_limit_exceeded"
        return report, []
    padded = payload_data + b"\x00" * padding_size
    recovered = bytes(value ^ key[index & 3] for index, value in enumerate(padded))
    validation, _constant_artifacts = recover_remcos_native_constants(recovered)
    cfg_validation, _partial_artifacts = recover_remcos_polymorphic_xor_loader(
        loader_data, payload_data
    )
    constant_writer_accepted = validation.get("status") == "constants_recovered"
    cfg_corroborated = bool(
        cfg_validation.get("status") == "shellcode_recovered"
        and cfg_validation.get("loop_size") == stage_size
        and cfg_validation.get("xor_key_sha256") == _sha256(key)
        and cfg_validation.get("payload_sha256") == _sha256(payload_data)
    )
    validation_accepted = constant_writer_accepted or cfg_corroborated
    if limits.require_constant_writer_validation and not validation_accepted:
        report.update(
            {
                "status": "recovered_stage_validation_failed",
                "candidate_set_complete": True,
                "stage_validation": {
                    "accepted": False,
                    "constant_writer": {
                        "status": validation.get("status"),
                        "profile": validation.get("profile"),
                        "candidate_count": validation.get("candidate_count", 0),
                    },
                    "bounded_cfg": {
                        "status": cfg_validation.get("status"),
                        "profile": cfg_validation.get("profile"),
                        "candidate_count": cfg_validation.get("candidate_count", 0),
                    },
                },
            }
        )
        return report, []
    report.update(
        {
            "status": "stage_recovered",
            "candidate_set_complete": True,
            "candidate_count": 1,
            "copy_profile": copy,
            "xor_profile": {
                **xor_profile,
                "xor_key_sha256": _sha256(key),
            },
            "zero_padding_size": padding_size,
            "work_bytes": work_bytes,
            "recovered_stage": {
                "size": len(recovered),
                "sha256": _sha256(recovered),
                "mz_prefix": recovered.startswith(b"MZ"),
                "terminal_payload_confirmed": False,
            },
            "recovered_payload_prefix": {
                "size": len(payload_data),
                "sha256": _sha256(recovered[: len(payload_data)]),
            },
            "recovered_zero_padding_tail": {
                "size": padding_size,
                "sha256": _sha256(recovered[len(payload_data) :]),
                "derived_from_literal_zero_padding": True,
            },
            "stage_validation": {
                "accepted": validation_accepted,
                "accepted_by": [
                    name
                    for name, accepted in (
                        ("constant_writer", constant_writer_accepted),
                        ("bounded_cfg", cfg_corroborated),
                    )
                    if accepted
                ],
                "constant_writer": {
                    "status": validation.get("status"),
                    "profile": validation.get("profile"),
                    "candidate_count": validation.get("candidate_count", 0),
                    "network_candidate_count": len(
                        validation.get("network_candidates", [])
                    ),
                },
                "bounded_cfg": {
                    "status": cfg_validation.get("status"),
                    "profile": cfg_validation.get("profile"),
                    "candidate_count": cfg_validation.get("candidate_count", 0),
                },
            },
        }
    )
    return report, [("remcos-native-stage-03.bin", recovered)]


__all__ = [
    "DEFAULT_LIMITS",
    "RemcosNativeSpanLimits",
    "recover_remcos_native_span_stage",
]
