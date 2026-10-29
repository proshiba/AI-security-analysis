"""Winos4 ``codecode`` stageの候補設定を実行せず静的に検証する。

このprofileは公開解析で報告された ``codecode`` marker、``x32``／``x64``
module要求、byte XOR ``0x2B`` を同時に要求する。設定構造だけでは終端payload
またはfamilyを確定せず、後続のloader／network lineage検証へ渡すroute候補に限る。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from extractors.valleyrat.nvml_dat import (
    CODECODE,
    MAX_CODEMARK_OCCURRENCES,
    MAX_PAYLOAD_SIZE,
    NvmlDatError,
    parse_codecode_config,
)

MAXIMUM_CODE_PREFIX_SIZE = 8 * 1024 * 1024
MINIMUM_CODE_PREFIX_SIZE = 64
MAXIMUM_REQUEST_LITERAL_OCCURRENCES = 4

_CONTAINER_MAGICS = (
    b"MZ",
    b"PK\x03\x04",
    bytes.fromhex("d0cf11e0a1b11ae1"),
    b"\x7fELF",
)
_REQUESTS = {
    "x86": b"x32\0",
    "x64": b"x64\0",
}
_PEB_ACCESS_SIGNATURES = {
    "x86_fs_peb": (
        b"\x64\xa1\x30\x00\x00\x00",
        b"\x64\x8b\x0d\x30\x00\x00\x00",
    ),
    "x64_gs_peb": (
        b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00",
        b"\x65\x48\x8b\x0c\x25\x60\x00\x00\x00",
    ),
}


class CodecodeConfigError(ValueError):
    """``codecode`` profileの必須証拠が不足または競合した場合の例外。"""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class _RequestEvidence:
    architecture: str
    literal: bytes
    occurrence_count: int
    immediate_materialization_count: int


def _count_occurrences(data: bytes, needle: bytes, *, maximum: int) -> int:
    """候補数を上限付きで数え、上限超過を別値として返す。"""

    count = 0
    cursor = 0
    while count <= maximum:
        offset = data.find(needle, cursor)
        if offset < 0:
            return count
        count += 1
        cursor = offset + len(needle)
    return count


def _immediate_materialization_count(code: bytes, literal: bytes) -> int:
    """x86/x64で4-byte requestを即値として構築する命令形を数える。"""

    count = 0
    for offset in range(max(0, len(code) - 4)):
        opcode = code[offset]
        if opcode == 0x68 and code[offset + 1 : offset + 5] == literal:
            count += 1
            continue
        if 0xB8 <= opcode <= 0xBF and code[offset + 1 : offset + 5] == literal:
            count += 1
            continue
        if (
            code[offset : offset + 3] == b"\xc7\x04\x24"
            and code[offset + 3 : offset + 7] == literal
        ):
            count += 1
    return count


def _modrm_immediate_offset(data: bytes, modrm_offset: int) -> int | None:
    """0x80 group命令のModRM/SIB/disp後にあるimm8位置を返す。"""

    if modrm_offset >= len(data):
        return None
    modrm = data[modrm_offset]
    mod = modrm >> 6
    rm = modrm & 7
    cursor = modrm_offset + 1
    if mod != 3 and rm == 4:
        if cursor >= len(data):
            return None
        sib = data[cursor]
        cursor += 1
        if mod == 0 and (sib & 7) == 5:
            cursor += 4
    if mod == 0 and rm == 5:
        cursor += 4
    elif mod == 1:
        cursor += 1
    elif mod == 2:
        cursor += 4
    return cursor if cursor < len(data) else None


def _xor_2b_instruction_count(code: bytes) -> int:
    """byte XOR immediate 0x2Bの機械語形だけを上限内で数える。"""

    count = 0
    for offset, opcode in enumerate(code):
        if opcode == 0x34 and code[offset + 1 : offset + 2] == b"\x2b":
            count += 1
            continue
        if opcode != 0x80 or offset + 2 >= len(code):
            continue
        modrm = code[offset + 1]
        if ((modrm >> 3) & 7) != 6:
            continue
        immediate_offset = _modrm_immediate_offset(code, offset + 1)
        if immediate_offset is not None and code[immediate_offset] == 0x2B:
            count += 1
    return count


def _peb_access_profile(code: bytes) -> str | None:
    """raw shellcodeで使われるPEB参照形を一意に決定する。"""

    matches = {
        profile
        for profile, signatures in _PEB_ACCESS_SIGNATURES.items()
        if any(signature in code for signature in signatures)
    }
    return next(iter(matches)) if len(matches) == 1 else None


def _request_evidence(code: bytes) -> _RequestEvidence:
    """一つのarchitecture requestだけが命令即値として構築されることを確認する。"""

    candidates: list[_RequestEvidence] = []
    for architecture, literal in _REQUESTS.items():
        occurrence_count = _count_occurrences(
            code,
            literal,
            maximum=MAXIMUM_REQUEST_LITERAL_OCCURRENCES,
        )
        materialization_count = _immediate_materialization_count(code, literal)
        if occurrence_count and materialization_count:
            candidates.append(
                _RequestEvidence(
                    architecture=architecture,
                    literal=literal,
                    occurrence_count=occurrence_count,
                    immediate_materialization_count=materialization_count,
                )
            )
    if len(candidates) != 1:
        raise CodecodeConfigError(
            "module_request_not_unique",
            "x32/x64 module要求を一意な命令即値として検証できません",
        )
    evidence = candidates[0]
    if evidence.occurrence_count > MAXIMUM_REQUEST_LITERAL_OCCURRENCES:
        raise CodecodeConfigError(
            "module_request_scan_limit",
            "module要求literalの出現数が上限を超えています",
        )
    return evidence


def extract_codecode_config(stage: bytes) -> dict[str, Any]:
    """厳格なcode evidenceと相関した``codecode``設定候補を返す。"""

    if len(stage) > MAX_PAYLOAD_SIZE:
        raise CodecodeConfigError(
            "input_size_limit",
            "codecode解析対象が64 MiB上限を超えています",
        )
    if any(stage.startswith(magic) for magic in _CONTAINER_MAGICS):
        raise CodecodeConfigError(
            "container_input_rejected",
            "raw shellcodeではなくcontainer形式です",
        )
    marker_count = _count_occurrences(
        stage,
        CODECODE,
        maximum=MAX_CODEMARK_OCCURRENCES,
    )
    if marker_count == 0:
        raise CodecodeConfigError("marker_missing", "codecode markerがありません")
    if marker_count > MAX_CODEMARK_OCCURRENCES:
        raise CodecodeConfigError(
            "marker_scan_limit",
            "codecode markerの出現数が上限を超えています",
        )
    try:
        config = parse_codecode_config(stage)
    except NvmlDatError as exc:
        raise CodecodeConfigError(
            "config_structure_invalid",
            "codecode設定構造を一意に検証できません",
        ) from exc

    marker_offset = int(config["marker_offset"])
    if not MINIMUM_CODE_PREFIX_SIZE <= marker_offset <= MAXIMUM_CODE_PREFIX_SIZE:
        raise CodecodeConfigError(
            "code_prefix_bounds",
            "codecode前方code領域が許容範囲外です",
        )
    code = stage[:marker_offset]
    request = _request_evidence(code)
    xor_count = _xor_2b_instruction_count(code)
    if xor_count == 0:
        raise CodecodeConfigError(
            "xor_2b_instruction_missing",
            "XOR 0x2Bのbyte変換命令を検証できません",
        )
    peb_profile = _peb_access_profile(code)
    if peb_profile is None:
        raise CodecodeConfigError(
            "peb_access_not_unique",
            "PEB参照profileを一意に検証できません",
        )

    return {
        "schema_version": 1,
        "status": "validated_codecode_route_candidate",
        "variant": "winos_codecode_recovered_stage",
        "family_role": "bootstrap_or_online_module",
        "marker_profile": "codecode",
        "module_request": request.literal[:-1].decode("ascii"),
        "request_architecture": request.architecture,
        "download_transform": "xor_0x2b",
        "config": config,
        "endpoints": list(config["endpoints"]),
        "candidate_config_recovered": True,
        "static_config_recovered": False,
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "terminal_payload_confirmed": False,
        "endpoint_role": "stage_server_candidate",
        "evidence": {
            "marker_profile": "codecode",
            "marker_count": marker_count,
            "peb_access_profile": peb_profile,
            "module_request_immediate_materialized": True,
            "module_request_occurrence_count": request.occurrence_count,
            "module_request_materialization_count": (
                request.immediate_materialization_count
            ),
            "xor_2b_instruction_count": xor_count,
            "config_structure_validated": True,
            "network_lineage_validated": False,
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_config_included": False,
            "raw_payload_included": False,
        },
    }


def probe_codecode_config(stage: bytes) -> dict[str, Any]:
    """detector向けにnetwork値を含まないcodecode候補要約を返す。"""

    try:
        recovered = extract_codecode_config(stage)
    except CodecodeConfigError as exc:
        return {
            "matched": False,
            "status": "rejected",
            "reason_code": exc.code,
            "supports_family_attribution": False,
            "terminal_family_confirmed": False,
            "candidate_config_recovered": False,
            "static_config_recovered": False,
            "endpoint_count": 0,
            "evidence": {},
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "raw_config_included": False,
                "raw_payload_included": False,
            },
        }
    return {
        "matched": True,
        "status": recovered["status"],
        "variant": recovered["variant"],
        "family_role": recovered["family_role"],
        "marker_profile": recovered["marker_profile"],
        "module_request": recovered["module_request"],
        "request_architecture": recovered["request_architecture"],
        "download_transform": recovered["download_transform"],
        "supports_family_attribution": False,
        "terminal_family_confirmed": False,
        "candidate_config_recovered": True,
        "static_config_recovered": False,
        "endpoint_count": len(recovered["endpoints"]),
        "evidence": dict(recovered["evidence"]),
        "safety": dict(recovered["safety"]),
    }
