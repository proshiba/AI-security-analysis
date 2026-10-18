"""Microsoft Script Encoder形式のVBE／JSEを有界に静的復号する。

検体や復号結果は実行せず、外部通信も行わない。長さとchecksumを含む完全な
envelopeだけを受理し、壊れたblockを含む入力から部分成果物を返さない。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re

MAX_INPUT_SIZE = 16 * 1024 * 1024
MAX_OUTPUT_SIZE = 16 * 1024 * 1024
MAX_BLOCKS = 64
MAX_TRAILER_CANDIDATES_PER_BLOCK = 32
MAX_CANDIDATE_WORK_FACTOR = 4

_HEADER = re.compile(rb"#@~\^([A-Za-z0-9+/]{6}==)")
_TRAILER = re.compile(rb"([A-Za-z0-9+/]{6}==)\^#~@")

# Microsoft Script Encoderの置換表。値は公開仕様相当の既知decoderと
# Didier Stevens氏のpublic-domain `decode-vbe.py`を照合した。
_DECODE_TABLE = bytes(
    (
        0x57,
        0x6E,
        0x7B,
        0x4A,
        0x4C,
        0x41,
        0x0B,
        0x0B,
        0x0B,
        0x0C,
        0x0C,
        0x0C,
        0x4A,
        0x4C,
        0x41,
        0x0E,
        0x0E,
        0x0E,
        0x0F,
        0x0F,
        0x0F,
        0x10,
        0x10,
        0x10,
        0x11,
        0x11,
        0x11,
        0x12,
        0x12,
        0x12,
        0x13,
        0x13,
        0x13,
        0x14,
        0x14,
        0x14,
        0x15,
        0x15,
        0x15,
        0x16,
        0x16,
        0x16,
        0x17,
        0x17,
        0x17,
        0x18,
        0x18,
        0x18,
        0x19,
        0x19,
        0x19,
        0x1A,
        0x1A,
        0x1A,
        0x1B,
        0x1B,
        0x1B,
        0x1C,
        0x1C,
        0x1C,
        0x1D,
        0x1D,
        0x1D,
        0x1E,
        0x1E,
        0x1E,
        0x1F,
        0x1F,
        0x1F,
        0x2E,
        0x2D,
        0x32,
        0x47,
        0x75,
        0x30,
        0x7A,
        0x52,
        0x21,
        0x56,
        0x60,
        0x29,
        0x42,
        0x71,
        0x5B,
        0x6A,
        0x5E,
        0x38,
        0x2F,
        0x49,
        0x33,
        0x26,
        0x5C,
        0x3D,
        0x49,
        0x62,
        0x58,
        0x41,
        0x7D,
        0x3A,
        0x34,
        0x29,
        0x35,
        0x32,
        0x36,
        0x65,
        0x5B,
        0x20,
        0x39,
        0x76,
        0x7C,
        0x5C,
        0x72,
        0x7A,
        0x56,
        0x43,
        0x7F,
        0x73,
        0x38,
        0x6B,
        0x66,
        0x39,
        0x63,
        0x4E,
        0x70,
        0x33,
        0x45,
        0x45,
        0x2B,
        0x6B,
        0x68,
        0x68,
        0x62,
        0x71,
        0x51,
        0x59,
        0x4F,
        0x66,
        0x78,
        0x09,
        0x76,
        0x5E,
        0x62,
        0x31,
        0x7D,
        0x44,
        0x64,
        0x4A,
        0x23,
        0x54,
        0x6D,
        0x75,
        0x43,
        0x71,
        0x4A,
        0x4C,
        0x41,
        0x7E,
        0x3A,
        0x60,
        0x4A,
        0x4C,
        0x41,
        0x5E,
        0x7E,
        0x53,
        0x40,
        0x4C,
        0x40,
        0x77,
        0x45,
        0x42,
        0x4A,
        0x2C,
        0x27,
        0x61,
        0x2A,
        0x48,
        0x5D,
        0x74,
        0x72,
        0x22,
        0x27,
        0x75,
        0x4B,
        0x37,
        0x31,
        0x6F,
        0x44,
        0x37,
        0x4E,
        0x79,
        0x4D,
        0x3B,
        0x59,
        0x52,
        0x4C,
        0x2F,
        0x22,
        0x50,
        0x6F,
        0x54,
        0x67,
        0x26,
        0x6A,
        0x2A,
        0x72,
        0x47,
        0x7D,
        0x6A,
        0x64,
        0x74,
        0x39,
        0x2D,
        0x54,
        0x7B,
        0x20,
        0x2B,
        0x3F,
        0x7F,
        0x2D,
        0x38,
        0x2E,
        0x2C,
        0x77,
        0x4C,
        0x30,
        0x67,
        0x5D,
        0x6E,
        0x53,
        0x7E,
        0x6B,
        0x47,
        0x6C,
        0x66,
        0x34,
        0x6F,
        0x35,
        0x78,
        0x79,
        0x25,
        0x5D,
        0x74,
        0x21,
        0x30,
        0x43,
        0x64,
        0x23,
        0x26,
        0x4D,
        0x5A,
        0x76,
        0x52,
        0x5B,
        0x25,
        0x63,
        0x6C,
        0x24,
        0x3F,
        0x48,
        0x2B,
        0x7B,
        0x55,
        0x28,
        0x78,
        0x70,
        0x23,
        0x29,
        0x69,
        0x41,
        0x28,
        0x2E,
        0x34,
        0x73,
        0x4C,
        0x09,
        0x59,
        0x21,
        0x2A,
        0x33,
        0x24,
        0x44,
        0x7F,
        0x4E,
        0x3F,
        0x6D,
        0x50,
        0x77,
        0x55,
        0x09,
        0x3B,
        0x53,
        0x56,
        0x55,
        0x7C,
        0x73,
        0x69,
        0x3A,
        0x35,
        0x61,
        0x5F,
        0x61,
        0x63,
        0x65,
        0x4B,
        0x50,
        0x46,
        0x58,
        0x67,
        0x58,
        0x3B,
        0x51,
        0x31,
        0x57,
        0x49,
        0x69,
        0x22,
        0x4F,
        0x6C,
        0x6D,
        0x46,
        0x5A,
        0x4D,
        0x68,
        0x48,
        0x25,
        0x7C,
        0x27,
        0x28,
        0x36,
        0x5C,
        0x46,
        0x70,
        0x3D,
        0x4A,
        0x6E,
        0x24,
        0x32,
        0x7A,
        0x79,
        0x41,
        0x2F,
        0x37,
        0x3D,
        0x5F,
        0x60,
        0x5F,
        0x4B,
        0x51,
        0x4F,
        0x5A,
        0x20,
        0x42,
        0x2C,
        0x36,
        0x65,
        0x57,
    )
)

_POSITION_OFFSETS = (
    0,
    1,
    2,
    0,
    1,
    2,
    1,
    2,
    2,
    1,
    2,
    1,
    0,
    2,
    1,
    2,
    0,
    2,
    1,
    2,
    0,
    0,
    1,
    2,
    2,
    1,
    0,
    2,
    1,
    2,
    2,
    1,
    0,
    0,
    2,
    1,
    2,
    1,
    2,
    0,
    2,
    0,
    0,
    1,
    2,
    0,
    2,
    1,
    0,
    2,
    1,
    2,
    0,
    0,
    1,
    2,
    2,
    0,
    0,
    1,
    2,
    0,
    2,
    1,
)

_UNESCAPE = {
    0x24: 0x40,  # @$ -> @
    0x21: 0x3C,  # @! -> <
    0x2A: 0x3E,  # @* -> >
    0x23: 0x0D,  # @# -> CR
    0x26: 0x0A,  # @& -> LF
}


class _EnvelopeError(ValueError):
    """VBE／JSE envelopeが完全ではない場合の内部例外。"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode_uint32(field: bytes) -> int:
    """canonical Base64の4-byte little-endian値だけを読む。"""

    if len(field) != 8 or not field.endswith(b"=="):
        raise _EnvelopeError("metadata_shape_invalid")
    try:
        raw = base64.b64decode(field, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _EnvelopeError("metadata_base64_invalid") from exc
    if len(raw) != 4 or base64.b64encode(raw) != field:
        raise _EnvelopeError("metadata_base64_noncanonical")
    return int.from_bytes(raw, "little")


def _decode_body(encoded: bytes, *, maximum_size: int) -> tuple[bytes, int]:
    """escapeを解釈し、位置依存置換表を適用する。"""

    decoded = bytearray()
    encoded_index = -1
    escape_count = 0
    cursor = 0
    while cursor < len(encoded):
        value = encoded[cursor]
        cursor += 1
        if value == 0x40:
            if cursor >= len(encoded):
                raise _EnvelopeError("escape_truncated")
            token = encoded[cursor]
            cursor += 1
            try:
                value = _UNESCAPE[token]
            except KeyError as exc:
                raise _EnvelopeError("escape_unknown") from exc
            escape_count += 1

        if value < 0x80:
            encoded_index += 1
        if value == 0x09 or 0x20 <= value < 0x80 and value not in (0x3C, 0x3E, 0x40):
            table_offset = (value - 9) * 3
            value = _DECODE_TABLE[table_offset + _POSITION_OFFSETS[encoded_index % 64]]
        decoded.append(value)
        if len(decoded) > maximum_size:
            raise _EnvelopeError("decoded_size_limit")
    return bytes(decoded), escape_count


def _failure_report(
    *,
    status: str,
    input_size: int,
    reason: str | None = None,
    candidate_headers: int = 0,
) -> dict[str, object]:
    report: dict[str, object] = {
        "status": status,
        "input_size": input_size,
        "candidate_header_count": candidate_headers,
        "block_count": 0,
        "executed": False,
        "network_contacted": False,
    }
    if reason is not None:
        report["reason"] = reason
    return report


def decode_vbe_blocks(
    data: bytes,
    *,
    max_input_size: int = MAX_INPUT_SIZE,
    max_output_size: int = MAX_OUTPUT_SIZE,
    max_blocks: int = MAX_BLOCKS,
) -> tuple[dict[str, object], bytes | None]:
    """完全なVBE／JSE blockをすべて復号し、外側のbyte列を保持する。

    1つでも長さ、checksum、escape、終端が不正な候補blockがあれば、部分的な
    復号結果を返さない。上限引数はテスト時に狭められるが、定数値を超えて
    拡張することはできない。
    """

    if not 1 <= max_input_size <= MAX_INPUT_SIZE:
        raise ValueError("max_input_sizeが許容範囲外です")
    if not 1 <= max_output_size <= MAX_OUTPUT_SIZE:
        raise ValueError("max_output_sizeが許容範囲外です")
    if not 1 <= max_blocks <= MAX_BLOCKS:
        raise ValueError("max_blocksが許容範囲外です")
    if len(data) > max_input_size:
        return (
            _failure_report(
                status="size_blocked",
                input_size=len(data),
                reason="input_size_limit",
            ),
            None,
        )

    first_header = _HEADER.search(data)
    if first_header is None:
        return _failure_report(status="pattern_not_found", input_size=len(data)), None

    output = bytearray()
    blocks: list[dict[str, object]] = []
    cursor = 0
    candidate_headers = 0
    candidate_work = 0
    first_block_start: int | None = None
    last_block_end: int | None = None

    header = first_header
    while header is not None:
        candidate_headers += 1
        if len(blocks) >= max_blocks:
            return (
                _failure_report(
                    status="block_limit_blocked",
                    input_size=len(data),
                    reason="block_count_limit",
                    candidate_headers=candidate_headers,
                ),
                None,
            )
        try:
            declared_size = _decode_uint32(header.group(1))
        except _EnvelopeError as exc:
            return (
                _failure_report(
                    status="malformed_envelope",
                    input_size=len(data),
                    reason=str(exc),
                    candidate_headers=candidate_headers,
                ),
                None,
            )
        if not 1 <= declared_size <= max_output_size:
            status = "output_size_blocked" if declared_size else "malformed_envelope"
            reason = "declared_size_limit" if declared_size else "empty_block"
            return (
                _failure_report(
                    status=status,
                    input_size=len(data),
                    reason=reason,
                    candidate_headers=candidate_headers,
                ),
                None,
            )

        body_start = header.end()
        earliest_trailer = body_start + declared_size
        latest_trailer = min(len(data), body_start + declared_size * 2)
        valid_candidates: list[tuple[re.Match[bytes], bytes, int, int]] = []
        trailer_candidates = 0
        if earliest_trailer <= len(data):
            trailer_end = min(len(data), latest_trailer + 12)
            for trailer in _TRAILER.finditer(data, earliest_trailer, trailer_end):
                if trailer.start() > latest_trailer:
                    break
                trailer_candidates += 1
                if trailer_candidates > MAX_TRAILER_CANDIDATES_PER_BLOCK:
                    return (
                        _failure_report(
                            status="complexity_limit_blocked",
                            input_size=len(data),
                            reason="trailer_candidate_limit",
                            candidate_headers=candidate_headers,
                        ),
                        None,
                    )
                body = data[body_start : trailer.start()]
                candidate_work += len(body)
                if candidate_work > max_input_size * MAX_CANDIDATE_WORK_FACTOR:
                    return (
                        _failure_report(
                            status="complexity_limit_blocked",
                            input_size=len(data),
                            reason="candidate_byte_limit",
                            candidate_headers=candidate_headers,
                        ),
                        None,
                    )
                try:
                    expected_checksum = _decode_uint32(trailer.group(1))
                    decoded, escape_count = _decode_body(
                        body,
                        maximum_size=declared_size,
                    )
                except _EnvelopeError:
                    continue
                if len(decoded) != declared_size:
                    continue
                actual_checksum = sum(decoded) & 0xFFFFFFFF
                if actual_checksum != expected_checksum:
                    continue
                valid_candidates.append(
                    (trailer, decoded, escape_count, actual_checksum)
                )

        if len(valid_candidates) != 1:
            reason = "no_valid_trailer" if not valid_candidates else "ambiguous_trailer"
            return (
                _failure_report(
                    status="malformed_envelope",
                    input_size=len(data),
                    reason=reason,
                    candidate_headers=candidate_headers,
                ),
                None,
            )

        trailer, decoded, escape_count, checksum = valid_candidates[0]
        prefix = data[cursor : header.start()]
        if len(output) + len(prefix) + len(decoded) > max_output_size:
            return (
                _failure_report(
                    status="output_size_blocked",
                    input_size=len(data),
                    reason="combined_output_size_limit",
                    candidate_headers=candidate_headers,
                ),
                None,
            )
        output.extend(prefix)
        output.extend(decoded)
        block_end = trailer.end()
        if first_block_start is None:
            first_block_start = header.start()
        last_block_end = block_end
        blocks.append(
            {
                "source_start": header.start(),
                "source_end": block_end,
                "encoded_body_size": trailer.start() - body_start,
                "declared_decoded_size": declared_size,
                "decoded_size": len(decoded),
                "decoded_sha256": _sha256(decoded),
                "checksum": checksum,
                "escape_count": escape_count,
            }
        )
        cursor = block_end
        header = _HEADER.search(data, cursor)

    suffix = data[cursor:]
    if len(output) + len(suffix) > max_output_size:
        return (
            _failure_report(
                status="output_size_blocked",
                input_size=len(data),
                reason="combined_output_size_limit",
                candidate_headers=candidate_headers,
            ),
            None,
        )
    output.extend(suffix)
    transformed = bytes(output)
    return (
        {
            "status": "decoded",
            "input_size": len(data),
            "input_sha256": _sha256(data),
            "output_size": len(transformed),
            "output_sha256": _sha256(transformed),
            "candidate_header_count": candidate_headers,
            "block_count": len(blocks),
            "prefix_size": first_block_start or 0,
            "suffix_size": len(data) - int(last_block_end or len(data)),
            "blocks": blocks,
            "executed": False,
            "network_contacted": False,
        },
        transformed,
    )


def recover_vbe_script(
    data: bytes,
) -> tuple[dict[str, object], list[tuple[str, bytes]]]:
    """VBE／JSEを復号し、再帰静的解析へ渡す単一script層を返す。"""

    report, decoded = decode_vbe_blocks(data)
    if decoded is None:
        return report, []
    return report, [("windows-script-encoder-decoded", decoded)]
