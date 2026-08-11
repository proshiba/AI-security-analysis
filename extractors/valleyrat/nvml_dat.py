"""NVMLプロキシDLLに付随するDATを、実行せず静的に復元する。"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from extractors.common import valid_host

TRAILER_SIZE = 26
MIN_PAYLOAD_SIZE = 1_000
MAX_PAYLOAD_SIZE = 64 * 1024 * 1024
CODEMARK = b"codemark"
CODEMARK_HEADER_SIZE = 0x38
MAX_CODEMARK_OCCURRENCES = 16
MAX_HOST_BYTES = 256
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class NvmlDatError(ValueError):
    """NVML.DATの構造または復元結果が検証条件を満たさない場合の例外。"""


@dataclass(frozen=True)
class NvmlDatTrailer:
    """DAT末尾26 byteの復号parameter。"""

    payload_size: int
    xor_a: int
    xor_b: int
    permutation_seed: int
    rc4_key: bytes

    @property
    def permutation_applied(self) -> bool:
        """loaderがDWORD permutation分岐へ入る条件を返す。"""

        return bool(
            self.permutation_seed
            and self.permutation_seed <= self.payload_size
            and self.payload_size % 4 == 0
        )

    def public_summary(self) -> dict[str, Any]:
        """秘密値を含めず、trailerの検証済み構造だけを返す。"""

        return {
            "trailer_size": TRAILER_SIZE,
            "payload_size": self.payload_size,
            "xor_parameter_count": 2,
            "permutation_seed_present": bool(self.permutation_seed),
            "permutation_applied": self.permutation_applied,
            "rc4_key_length": len(self.rc4_key),
            "rc4_key_sha256": hashlib.sha256(self.rc4_key).hexdigest(),
        }


@dataclass(frozen=True)
class NvmlDatRecovery:
    """復号stageと公開可能な構造解析結果を保持する。"""

    trailer: NvmlDatTrailer
    stage: bytes
    codemark_config: dict[str, Any]

    @property
    def stage_sha256(self) -> str:
        """復号stageのSHA-256を返す。"""

        return hashlib.sha256(self.stage).hexdigest()

    def public_summary(self, source: bytes) -> dict[str, Any]:
        """stage本体と生鍵を除外した解析結果を返す。"""

        return public_recovery_summary(self, source)


def public_recovery_summary(
    recovery: NvmlDatRecovery,
    source: bytes,
) -> dict[str, Any]:
    """handler監査可能な純関数として、公開可能な復元要約を返す。"""

    trailer = recovery.trailer
    return {
        "schema_version": 1,
        "format": "nvml_compact_dat",
        "input_sha256": hashlib.sha256(source).hexdigest(),
        "input_size": len(source),
        "stage_sha256": hashlib.sha256(recovery.stage).hexdigest(),
        "stage_size": len(recovery.stage),
        "trailer": {
            "trailer_size": TRAILER_SIZE,
            "payload_size": trailer.payload_size,
            "xor_parameter_count": 2,
            "permutation_seed_present": bool(trailer.permutation_seed),
            "permutation_applied": trailer.permutation_applied,
            "rc4_key_length": len(trailer.rc4_key),
            "rc4_key_sha256": hashlib.sha256(trailer.rc4_key).hexdigest(),
        },
        "transform_order": [
            "not_xor_byte_transform",
            "lcg_fisher_yates_dword_scatter",
            "rc4_16byte_key",
        ],
        "codemark_config": recovery.codemark_config,
        "safety": {
            "sample_executed": False,
            "stage_executed": False,
            "network_contacted": False,
            "raw_stage_included": False,
            "raw_key_included": False,
        },
    }


def parse_trailer(data: bytes) -> NvmlDatTrailer:
    """末尾26 byteを境界検証し、loaderのparameterとして解釈する。"""

    if len(data) < TRAILER_SIZE + MIN_PAYLOAD_SIZE:
        raise NvmlDatError("DATがtrailerと最小payload長を満たしていません")
    trailer = data[-TRAILER_SIZE:]
    payload_size = int.from_bytes(trailer[0:4], "little")
    if payload_size != len(data) - TRAILER_SIZE:
        raise NvmlDatError("trailerのpayload sizeが実データ長と一致しません")
    if not MIN_PAYLOAD_SIZE <= payload_size <= MAX_PAYLOAD_SIZE:
        raise NvmlDatError("payload sizeが許容範囲外です")
    return NvmlDatTrailer(
        payload_size=payload_size,
        xor_a=trailer[4],
        xor_b=trailer[5],
        permutation_seed=int.from_bytes(trailer[6:10], "little"),
        rc4_key=bytes(trailer[10:26]),
    )


def looks_like_nvml_dat(data: bytes) -> bool:
    """復号せず、厳密なtrailer長一致だけを事前判定する。"""

    try:
        parse_trailer(data)
    except NvmlDatError:
        return False
    return True


def _rc4(data: bytes, key: bytes) -> bytes:
    """16 byte鍵を含む標準RC4 KSA／PRGAを適用する。"""

    if not key:
        raise NvmlDatError("RC4 keyが空です")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    output = bytearray(data)
    i = j = 0
    for offset in range(len(output)):
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output[offset] ^= state[(state[i] + state[j]) & 0xFF]
    return bytes(output)


def _scatter_dwords(data: bytes, seed: int) -> bytes:
    """loaderと同じLCG／Fisher-Yates表でDWORDをscatterする。"""

    if not seed or seed > len(data) or len(data) % 4:
        return data
    word_count = len(data) // 4
    permutation = list(range(word_count))
    state = seed ^ 0x5A5A5A5A
    for index in range(word_count - 1, 0, -1):
        state = (state * 0x41C64E6D + 0x3039) & 0xFFFFFFFF
        swap_index = state % (index + 1)
        permutation[index], permutation[swap_index] = (
            permutation[swap_index],
            permutation[index],
        )
    output = bytearray(len(data))
    for source, destination in enumerate(permutation):
        output[destination * 4 : destination * 4 + 4] = data[
            source * 4 : source * 4 + 4
        ]
    return bytes(output)


def decrypt_stage(data: bytes) -> tuple[NvmlDatTrailer, bytes]:
    """DATをbyte変換、DWORD scatter、RC4の順で静的復号する。"""

    trailer = parse_trailer(data)
    encrypted = data[: trailer.payload_size]
    transformed = bytes(
        ((~(value ^ trailer.xor_b)) & 0xFF) ^ trailer.xor_a
        for value in encrypted
    )
    transformed = _scatter_dwords(transformed, trailer.permutation_seed)
    stage_size = (
        trailer.permutation_seed
        if trailer.permutation_applied
        else trailer.payload_size
    )
    return trailer, _rc4(transformed[:stage_size], trailer.rc4_key)


def _slot(
    stage: bytes,
    *,
    marker_offset: int,
    index: int,
    host_offset: int,
    host_length: int,
    port_offset: int,
    enabled_offset: int,
) -> tuple[dict[str, Any], int]:
    """codemark内のC2 slotを境界検証して返す。"""

    if not 2 <= host_length <= MAX_HOST_BYTES:
        raise NvmlDatError(f"codemark slot {index}のhost長が不正です")
    end = host_offset + host_length
    if end > len(stage):
        raise NvmlDatError(f"codemark slot {index}がstage境界を超えています")
    raw_host = stage[host_offset:end]
    if raw_host[-1:] != b"\0" or b"\0" in raw_host[:-1]:
        raise NvmlDatError(f"codemark slot {index}のhost終端が不正です")
    try:
        host = raw_host[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise NvmlDatError(f"codemark slot {index}のhostがASCIIではありません") from exc
    if not valid_host(host):
        raise NvmlDatError(f"codemark slot {index}のhost形式が不正です")
    port = int.from_bytes(
        stage[marker_offset + port_offset : marker_offset + port_offset + 4],
        "little",
    )
    enabled_raw = int.from_bytes(
        stage[marker_offset + enabled_offset : marker_offset + enabled_offset + 4],
        "little",
    )
    if not 1 <= port <= 65535:
        raise NvmlDatError(f"codemark slot {index}のportが不正です")
    if enabled_raw not in (0, 1):
        raise NvmlDatError(f"codemark slot {index}の有効flagが不正です")
    enabled = bool(enabled_raw)
    return (
        {
            "index": index,
            "host": host,
            "port": port,
            "enabled": enabled,
            "endpoint": f"{host}:{port}" if enabled else None,
        },
        end,
    )


def _parse_codemark_at(stage: bytes, marker_offset: int) -> dict[str, Any]:
    """指定offsetのcodemark設定を検証する。"""

    if marker_offset + CODEMARK_HEADER_SIZE > len(stage):
        raise NvmlDatError("codemark headerがstage境界を超えています")
    first_length = int.from_bytes(
        stage[marker_offset + 0x20 : marker_offset + 0x24], "little"
    )
    second_length = int.from_bytes(
        stage[marker_offset + 0x2C : marker_offset + 0x30], "little"
    )
    first_offset = marker_offset + CODEMARK_HEADER_SIZE
    first, second_offset = _slot(
        stage,
        marker_offset=marker_offset,
        index=1,
        host_offset=first_offset,
        host_length=first_length,
        port_offset=0x24,
        enabled_offset=0x28,
    )
    second, tail_offset = _slot(
        stage,
        marker_offset=marker_offset,
        index=2,
        host_offset=second_offset,
        host_length=second_length,
        port_offset=0x30,
        enabled_offset=0x34,
    )
    slots = [first, second]
    endpoints = [str(item["endpoint"]) for item in slots if item["endpoint"]]
    if not endpoints:
        raise NvmlDatError("codemarkに有効なC2 slotがありません")
    trailing = stage[tail_offset:]
    return {
        "marker": CODEMARK.decode("ascii"),
        "marker_offset": marker_offset,
        "slots": slots,
        "endpoints": endpoints,
        "trailing_config_offset": tail_offset,
        "trailing_config_size": len(trailing),
        "trailing_config_sha256": hashlib.sha256(trailing).hexdigest(),
        "confidence": "confirmed_static_config",
    }


def parse_codemark_config(stage: bytes) -> dict[str, Any]:
    """復号stageから一意で有効なcodemark C2設定を返す。"""

    valid = []
    cursor = 0
    for _ in range(MAX_CODEMARK_OCCURRENCES):
        offset = stage.find(CODEMARK, cursor)
        if offset < 0:
            break
        try:
            valid.append(_parse_codemark_at(stage, offset))
        except NvmlDatError:
            pass
        cursor = offset + len(CODEMARK)
    if not valid:
        raise NvmlDatError("復号stageに有効なcodemark設定がありません")
    endpoint_sets = {tuple(item["endpoints"]) for item in valid}
    if len(endpoint_sets) != 1:
        raise NvmlDatError("複数の異なるcodemark設定があり一意に決定できません")
    return valid[0]


def recover_nvml_dat(
    data: bytes,
    *,
    expected_stage_sha256: str | None = None,
) -> NvmlDatRecovery:
    """stageとC2設定を復元し、任意の期待SHA-256を厳密に検証する。"""

    trailer, stage = decrypt_stage(data)
    digest = hashlib.sha256(stage).hexdigest()
    if expected_stage_sha256 is not None:
        expected = expected_stage_sha256.lower()
        if not SHA256_RE.fullmatch(expected):
            raise NvmlDatError("期待stage SHA-256の形式が不正です")
        if digest != expected:
            raise NvmlDatError("復号stageのSHA-256が期待値と一致しません")
    config = parse_codemark_config(stage)
    return NvmlDatRecovery(trailer=trailer, stage=stage, codemark_config=config)


def analyze_nvml_dat(
    data: bytes,
    *,
    expected_stage_sha256: str | None = None,
) -> dict[str, Any]:
    """単体DATから公開可能なstage／C2要約を生成する。"""

    recovery = recover_nvml_dat(
        data, expected_stage_sha256=expected_stage_sha256
    )
    return public_recovery_summary(recovery, data)


def resolve_companion_dat(path: Path) -> Path:
    """DAT自身、DLLの同名DAT、またはdirectory内のNVML.DATを一意に選ぶ。"""

    resolved = path.resolve()
    if not resolved.exists():
        raise NvmlDatError("入力pathが存在しません")
    if resolved.is_file() and resolved.suffix.lower() == ".dat":
        return resolved
    directory = resolved if resolved.is_dir() else resolved.parent
    if not directory.is_dir():
        raise NvmlDatError("companion DATを探索するdirectoryが存在しません")
    names = {"nvml.dat"}
    if resolved.is_file():
        names.add(f"{resolved.stem.lower()}.dat")
    candidates = sorted(
        {
            item.resolve()
            for item in directory.iterdir()
            if item.is_file() and item.name.lower() in names
        }
    )
    if not candidates:
        raise NvmlDatError("companion NVML.DATが見つかりません")
    if len(candidates) != 1:
        raise NvmlDatError("companion DAT候補が複数あり一意に決定できません")
    return candidates[0]
