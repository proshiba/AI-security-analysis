"""NVMLプロキシDLLに付随するDATを、実行せず静的に復元する。"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from array import array
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from extractors.common import valid_host

TRAILER_SIZE = 26
MIN_PAYLOAD_SIZE = 1_000
MAX_PAYLOAD_SIZE = 64 * 1024 * 1024
MAX_PERMUTED_PAYLOAD_SIZE = 16 * 1024 * 1024
CODEMARK = b"codemark"
CODEMARK_HEADER_SIZE = 0x38
MAX_CODEMARK_OCCURRENCES = 16
MAX_HOST_BYTES = 256
MAX_TRAILING_WIDE_CANDIDATES = 32
MIN_TRAILING_CONFIG_CHARACTERS = 24
MAX_TRAILING_CONFIG_CHARACTERS = 4_096
MAX_TRAILING_TOTAL_CHARACTERS = 64 * 1024
TRAILING_SCAN_CHUNK_BYTES = 64 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class NvmlDatError(ValueError):
    """NVML.DATの構造または復元結果が検証条件を満たさない場合の例外。"""


class NvmlDatOptionalConfigLimit(NvmlDatError):
    """任意の末尾config補強だけが探索上限へ達した場合の例外。"""


def normalize_host(value: str) -> str | None:
    """domain／IP literalを正規化し、IPv6のzone識別子を拒否する。"""

    raw = value.strip()
    bracketed = raw.startswith("[") and raw.endswith("]")
    if bracketed:
        raw = raw[1:-1]
    if not raw or "%" in raw:
        return None
    try:
        return ipaddress.ip_address(raw).compressed.casefold()
    except ValueError:
        if bracketed:
            return None
        host = raw.casefold().rstrip(".")
        return host if valid_host(host) else None


def render_authority(host: str, port: int | None = None) -> str | None:
    """正規化済みhostをIPv6なら角括弧付きauthorityとして描画する。"""

    normalized = normalize_host(host)
    if normalized is None or (port is not None and not 1 <= port <= 65535):
        return None
    authority = f"[{normalized}]" if ":" in normalized else normalized
    return f"{authority}:{port}" if port is not None else authority


def render_endpoint(host: str, port: int) -> str | None:
    """hostとportから曖昧でない正規化endpointを返す。"""

    return render_authority(host, port)


def parse_endpoint(value: str) -> tuple[str, int] | None:
    """角括弧IPv6またはhost:portを曖昧性なく分解する。"""

    if value.startswith("["):
        closing = value.find("]")
        if closing <= 1 or value[closing + 1 : closing + 2] != ":":
            return None
        raw_host = value[1:closing]
        raw_port = value[closing + 2 :]
    else:
        raw_host, separator, raw_port = value.rpartition(":")
        if not separator or ":" in raw_host:
            return None
    host = normalize_host(raw_host)
    if host is None or (value.startswith("[") and ":" not in host) or not raw_port.isdigit():
        return None
    port = int(raw_port)
    if not 1 <= port <= 65535:
        return None
    return host, port


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


def _scatter_dwords(data: bytes | bytearray, seed: int) -> bytes:
    """loaderと同じLCG／Fisher-Yates表でDWORDをscatterする。"""

    if not seed or seed > len(data) or len(data) % 4:
        return bytes(data)
    if len(data) > MAX_PERMUTED_PAYLOAD_SIZE:
        raise NvmlDatError("DWORD permutation対象が16 MiB上限を超えています")
    word_count = len(data) // 4
    permutation = array("I", range(word_count))
    if permutation.itemsize != 4:
        raise NvmlDatError("32-bit permutation配列を構築できません")
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
    normalized_host = normalize_host(host)
    if normalized_host is None:
        raise NvmlDatError(f"codemark slot {index}のhost形式が不正です")
    host = normalized_host
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
            "active": enabled,
            "header_enabled": enabled,
            "transport_selector": None,
            "transport": "unknown",
            "endpoint": render_endpoint(host, port) if enabled else None,
        },
        end,
    )


def _parse_reversed_trailing_config(
    decoded: str,
    header_slots: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """末尾UTF-16LE全文反転設定をheader先頭2 slotと相関する。"""

    canonical = decoded[::-1]
    if not canonical.startswith("|") or not canonical.endswith("|"):
        return None
    fields: dict[str, str] = {}
    for part in canonical.split("|"):
        if not part:
            continue
        key, separator, value = part.partition(":")
        key = key.casefold()
        if (
            not separator
            or re.fullmatch(r"[a-z][a-z0-9_]{0,15}", key) is None
            or not value
            or len(value) > MAX_HOST_BYTES
        ):
            return None
        if key in fields and fields[key] != value:
            return None
        fields[key] = value
    required = {
        f"{prefix}{index}"
        for index in (1, 2, 3)
        for prefix in ("p", "o", "t")
    }
    if not required.issubset(fields):
        return None
    # codemark headerの2 DWORDだけが固定enabled flagである。反転設定の
    # t1..t3は別物で、0=UDP／1=TCPのtransport selectorとして扱う。
    # header側で無効なslotを末尾設定だけで再有効化しないため、相関対象の
    # 先頭2 slotは両方とも明示的にactiveであることを要求する。
    if any(item.get("header_enabled") is not True for item in header_slots):
        return None

    slots: list[dict[str, Any]] = []
    for index in (1, 2, 3):
        host = normalize_host(fields[f"p{index}"])
        raw_port = fields[f"o{index}"]
        raw_transport = fields[f"t{index}"]
        if (
            host is None
            or not raw_port.isdigit()
            or not 1 <= int(raw_port) <= 65535
            or raw_transport not in {"0", "1"}
        ):
            return None
        selector = int(raw_transport)
        header_enabled = (
            bool(header_slots[index - 1]["header_enabled"])
            if index <= len(header_slots)
            else None
        )
        slots.append(
            {
                "index": index,
                "host": host,
                "port": int(raw_port),
                # 旧schemaとの互換field。t=0も無効ではなくUDP endpointである。
                "enabled": True,
                "active": True,
                "header_enabled": header_enabled,
                "transport_selector": selector,
                "transport": "tcp" if selector == 1 else "udp",
                "endpoint": render_endpoint(host, int(raw_port)),
            }
        )
    header_identity = [
        (item["host"], item["port"])
        for item in header_slots
    ]
    trailing_identity = [
        (item["host"], item["port"])
        for item in slots[:2]
    ]
    if header_identity != trailing_identity:
        return None
    return {
        "slots": slots,
        "field_count": len(fields),
        "decoded_sha256": hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "raw_config_included": False,
    }


def _printable_utf16le_candidates(
    data: bytes | memoryview,
) -> tuple[list[str], dict[str, int]]:
    """全入力をchunk走査し、Unicode候補を有界抽出する。"""

    view = memoryview(data)
    values: list[str] = []
    seen: set[str] = set()
    candidate_count = 0
    total_characters = 0
    scanned_code_units = 0

    def record_candidate(characters: list[str], overflow: bool) -> None:
        nonlocal candidate_count, total_characters
        if len(characters) < MIN_TRAILING_CONFIG_CHARACTERS:
            return
        candidate_count += 1
        if candidate_count > MAX_TRAILING_WIDE_CANDIDATES:
            raise NvmlDatOptionalConfigLimit(
                "末尾UTF-16LE設定候補数が上限を超えています"
            )
        if overflow:
            raise NvmlDatOptionalConfigLimit(
                "末尾UTF-16LE設定候補の文字数が上限を超えています"
            )
        total_characters += len(characters)
        if total_characters > MAX_TRAILING_TOTAL_CHARACTERS:
            raise NvmlDatOptionalConfigLimit(
                "末尾UTF-16LE設定候補の総文字数が上限を超えています"
            )
        value = "".join(characters)
        if value not in seen:
            seen.add(value)
            values.append(value)

    for alignment in (0, 1):
        characters: list[str] = []
        overflow = False
        for chunk_start in range(
            alignment,
            max(alignment, len(view) - 1),
            TRAILING_SCAN_CHUNK_BYTES,
        ):
            chunk_stop = min(len(view) - 1, chunk_start + TRAILING_SCAN_CHUNK_BYTES)
            for offset in range(chunk_start, chunk_stop, 2):
                scanned_code_units += 1
                code_unit = int(view[offset]) | (int(view[offset + 1]) << 8)
                character = chr(code_unit)
                if code_unit and character.isprintable():
                    if len(characters) < MAX_TRAILING_CONFIG_CHARACTERS:
                        characters.append(character)
                    else:
                        overflow = True
                    continue
                record_candidate(characters, overflow)
                characters = []
                overflow = False
        record_candidate(characters, overflow)
    return values, {
        "candidate_count": candidate_count,
        "unique_candidate_count": len(values),
        "total_candidate_characters": total_characters,
        "scanned_bytes": len(view),
        "scanned_code_units": scanned_code_units,
        "scan_chunk_bytes": TRAILING_SCAN_CHUNK_BYTES,
    }


def _recover_reversed_trailing_config(
    trailing: bytes | memoryview,
    header_slots: list[dict[str, Any]],
) -> tuple[dict[str, Any] | None, dict[str, int]]:
    """上限内の一意な3-slot反転設定だけを返す。"""

    recoveries: dict[tuple[tuple[object, ...], ...], dict[str, Any]] = {}
    candidates, scan = _printable_utf16le_candidates(trailing)
    for candidate in candidates:
        recovered = _parse_reversed_trailing_config(candidate, header_slots)
        if recovered is None:
            continue
        identity = tuple(
            (
                item["index"],
                item["host"],
                item["port"],
                item["active"],
                item["header_enabled"],
                item["transport_selector"],
                item["transport"],
            )
            for item in recovered["slots"]
        )
        recoveries[identity] = recovered
    if len(recoveries) > 1:
        raise NvmlDatError("異なる末尾3-slot設定が複数あり一意に決定できません")
    if not recoveries:
        return None, scan
    result = next(iter(recoveries.values()))
    result["candidate_count"] = scan["candidate_count"]
    return result, scan


def _chunked_sha256(data: bytes | memoryview) -> str:
    """大きなtailを複製せず固定chunkでSHA-256化する。"""

    view = memoryview(data)
    digest = hashlib.sha256()
    for offset in range(0, len(view), TRAILING_SCAN_CHUNK_BYTES):
        digest.update(view[offset : offset + TRAILING_SCAN_CHUNK_BYTES])
    return digest.hexdigest()


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
    trailing_size = len(stage) - tail_offset
    trailing = memoryview(stage)[tail_offset:]
    trailing_recovery, trailing_scan = _recover_reversed_trailing_config(
        trailing, slots
    )
    if trailing_recovery is not None:
        slots = list(trailing_recovery["slots"])
    endpoints = [str(item["endpoint"]) for item in slots if item["endpoint"]]
    if not endpoints:
        raise NvmlDatError("codemarkに有効なC2 slotがありません")
    return {
        "marker": CODEMARK.decode("ascii"),
        "marker_offset": marker_offset,
        "slots": slots,
        "endpoints": endpoints,
        "trailing_config_offset": tail_offset,
        "trailing_config_size": trailing_size,
        "trailing_config_sha256": _chunked_sha256(trailing),
        "trailing_config_total_size": trailing_size,
        "trailing_config_scan_limit": MAX_PAYLOAD_SIZE,
        "trailing_config_scan_truncated": False,
        "trailing_config_scan_completed": True,
        "trailing_config_scan_chunk_bytes": trailing_scan["scan_chunk_bytes"],
        "trailing_config_scanned_bytes": trailing_scan["scanned_bytes"],
        "trailing_config": (
            {
                "status": "decoded_correlated_three_slots",
                "format": "reversed_utf16le_vvas",
                "field_count": trailing_recovery["field_count"],
                "candidate_count": trailing_recovery["candidate_count"],
                "unique_candidate_count": trailing_scan["unique_candidate_count"],
                "total_candidate_characters": trailing_scan[
                    "total_candidate_characters"
                ],
                "transport_selector_semantics": {"0": "udp", "1": "tcp"},
                "decoded_sha256": trailing_recovery["decoded_sha256"],
                "raw_config_included": False,
            }
            if trailing_recovery is not None
            else {
                "status": "not_recovered_or_not_correlated",
                "candidate_limit_reached": False,
                "candidate_count": trailing_scan["candidate_count"],
                "unique_candidate_count": trailing_scan["unique_candidate_count"],
                "total_candidate_characters": trailing_scan[
                    "total_candidate_characters"
                ],
                "raw_config_included": False,
            }
        ),
        "confidence": "confirmed_static_config",
    }


def parse_codemark_config(stage: bytes) -> dict[str, Any]:
    """復号stageから一意で有効なcodemark C2設定を返す。"""

    if len(stage) > MAX_PAYLOAD_SIZE:
        raise NvmlDatError("codemark解析対象が64 MiB上限を超えています")
    valid = []
    cursor = 0
    for _ in range(MAX_CODEMARK_OCCURRENCES):
        offset = stage.find(CODEMARK, cursor)
        if offset < 0:
            break
        try:
            valid.append(_parse_codemark_at(stage, offset))
        except NvmlDatOptionalConfigLimit:
            # 1件でも探索が不完全なら、別markerの設定だけを採用して
            # 相反configを見落とす可能性があるためstage全体を拒否する。
            raise
        except NvmlDatError:
            pass
        cursor = offset + len(CODEMARK)
    if stage.find(CODEMARK, cursor) >= 0:
        raise NvmlDatError("codemark出現数が上限を超えています")
    if not valid:
        raise NvmlDatError("復号stageに有効なcodemark設定がありません")
    configuration_identities = {
        tuple(
            (
                int(slot["index"]),
                str(slot["host"]),
                int(slot["port"]),
                bool(slot["active"]),
                slot["header_enabled"],
                slot["transport_selector"],
                str(slot["transport"]),
            )
            for slot in item["slots"]
        )
        for item in valid
    }
    if len(configuration_identities) != 1:
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
