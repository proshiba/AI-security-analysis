"""RZK carrierからlow-nibble符号化されたLECE envelopeを静的に復元する。

このモジュールは復元byte列を実行せず、ネットワーク通信も行わない。LECEは
配布層の構造として扱い、復元結果だけで終端malware familyを断定しない。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
import stat


LECE_MAGIC = b"LECE\x01"
ENCODED_LECE_MAGIC = bytes(nibble for value in LECE_MAGIC for nibble in (value >> 4, value & 0x0F))
RZK_HEADER_SIZE = 40
DEFAULT_MAX_ENCODED_SIZE = 64 * 1024 * 1024
DEFAULT_MAX_INPUT_SIZE = 128 * 1024 * 1024


def _is_reparse_point(metadata: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return bool(int(getattr(metadata, "st_file_attributes", 0)) & flag)


def _read_bounded_regular_file(path: Path, *, maximum_size: int) -> bytes:
    """単一の通常ファイルだけを、事前検証した上限内で読み込む。"""

    if maximum_size <= 0:
        raise ValueError("maximum_size は正の値である必要があります")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise ValueError(f"入力ファイルを確認できません: {path}") from exc
    if path.is_symlink() or _is_reparse_point(metadata):
        raise ValueError("入力にsymlinkまたはreparse pointは使用できません")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("入力は通常ファイルである必要があります")
    if metadata.st_size > maximum_size:
        raise ValueError("入力ファイルが許容サイズを超えています")

    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(opened.st_mode)
                or _is_reparse_point(opened)
                or not os.path.samestat(metadata, opened)
                or opened.st_size > maximum_size
            ):
                raise ValueError("検証後に入力ファイルの同一性または属性が変化しました")
            data = handle.read(maximum_size + 1)
    except OSError as exc:
        raise ValueError(f"入力ファイルを安全に読み込めません: {path}") from exc
    if len(data) > maximum_size or len(data) != opened.st_size:
        raise ValueError("読込中に入力ファイルのサイズが変化しました")
    return data


@dataclass(frozen=True)
class RzkLeceCandidate:
    """1本のRZK low-nibble streamと、その静的復元結果。"""

    header_offset: int
    data_offset: int
    encoded_size: int
    storage_terminator_size: int
    storage_terminator_status: str
    untrimmed_decoded_size: int
    untrimmed_sha256: str
    header_sha256: str
    data: bytes


def decode_low_nibbles(encoded: bytes) -> bytes:
    """上位nibble、下位nibbleの順に格納されたbyte列を復元する。"""
    if not encoded or len(encoded) % 2:
        raise ValueError("encoded streamは正の偶数byte長である必要があります")
    if any(value > 0x0F for value in encoded):
        raise ValueError("encoded streamにnibble範囲外の値があります")
    return bytes((encoded[index] << 4) | encoded[index + 1] for index in range(0, len(encoded), 2))


def _nibble_run_end(data: bytes, start: int, maximum: int) -> int:
    end = start
    limit = min(len(data), start + maximum)
    while end < limit and data[end] <= 0x0F:
        end += 1
    return end


def _magic_offsets(data: bytes) -> list[int]:
    offsets: list[int] = []
    cursor = 0
    while True:
        offset = data.find(ENCODED_LECE_MAGIC, cursor)
        if offset < 0:
            return offsets
        offsets.append(offset)
        cursor = offset + 1


def find_rzk_lece_streams(
    data: bytes,
    *,
    header_size: int = RZK_HEADER_SIZE,
    maximum_encoded_size: int = DEFAULT_MAX_ENCODED_SIZE,
) -> list[RzkLeceCandidate]:
    """RZK carrier内のLECE streamを列挙し、保存終端を除いて復元する。

    実検体では各streamの直前に40-byte headerがあり、後続streamがある場合は
    そのheader直前を境界にする。最後の40-byte-header stream末尾にある
    ``00 00``はstorage terminator候補として互換出力から除く。ただし、自然に
    0x00で終わるpayloadと静的に区別できないため、statusをambiguousとし、除去前
    size／SHA-256も必ず残す。header内容は鍵素材の可能性があるためreportへ生値を
    出さず、SHA-256だけを残す。
    """
    if header_size < 0:
        raise ValueError("header_sizeは0以上である必要があります")
    if maximum_encoded_size < len(ENCODED_LECE_MAGIC):
        raise ValueError("maximum_encoded_sizeが小さすぎます")

    offsets = _magic_offsets(data)
    candidates: list[RzkLeceCandidate] = []
    consumed_until = -1
    for index, data_offset in enumerate(offsets):
        if data_offset < header_size or data_offset < consumed_until:
            continue
        end = _nibble_run_end(data, data_offset, maximum_encoded_size)
        capped = end == data_offset + maximum_encoded_size and end < len(data) and data[end] <= 0x0F
        if capped:
            continue
        if index + 1 < len(offsets):
            next_header = offsets[index + 1] - header_size
            header_region = data[next_header : offsets[index + 1]]
            if data_offset < next_header <= end and any(value > 0x0F for value in header_region):
                end = next_header
        encoded_size = end - data_offset
        if encoded_size < len(ENCODED_LECE_MAGIC) or encoded_size % 2:
            continue

        terminator_size = 0
        if (
            index == len(offsets) - 1
            and header_size == RZK_HEADER_SIZE
            and encoded_size > len(ENCODED_LECE_MAGIC) + 2
            and end < len(data)
            and data[end] > 0x0F
            and data[end - 2 : end] == b"\x00\x00"
        ):
            terminator_size = 2
        untrimmed = decode_low_nibbles(data[data_offset:end])
        decoded = untrimmed[:-1] if terminator_size else untrimmed
        if not decoded.startswith(LECE_MAGIC):
            continue

        header_offset = data_offset - header_size
        header = data[header_offset:data_offset]
        candidates.append(
            RzkLeceCandidate(
                header_offset=header_offset,
                data_offset=data_offset,
                encoded_size=encoded_size,
                storage_terminator_size=terminator_size,
                storage_terminator_status=(
                    "heuristic_ambiguous_removed" if terminator_size else "not_observed"
                ),
                untrimmed_decoded_size=len(untrimmed),
                untrimmed_sha256=hashlib.sha256(untrimmed).hexdigest(),
                header_sha256=hashlib.sha256(header).hexdigest(),
                data=decoded,
            )
        )
        consumed_until = end
    return candidates


def candidate_report(candidates: list[RzkLeceCandidate]) -> list[dict[str, int | str]]:
    """鍵素材になり得るheader生値を含めず、公開可能なmetadataへ変換する。"""
    return [
        {
            "header_offset": item.header_offset,
            "data_offset": item.data_offset,
            "encoded_size": item.encoded_size,
            "decoded_size": len(item.data),
            "storage_terminator_size": item.storage_terminator_size,
            "storage_terminator_status": item.storage_terminator_status,
            "untrimmed_decoded_size": item.untrimmed_decoded_size,
            "untrimmed_sha256": item.untrimmed_sha256,
            "header_sha256": item.header_sha256,
            "sha256": hashlib.sha256(item.data).hexdigest(),
            "format": "rzk-low-nibble-lece-v1",
        }
        for item in candidates
    ]


def build_parser() -> argparse.ArgumentParser:
    """CLI parserを構築する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--json", type=Path)
    parser.add_argument("--maximum-encoded-size", type=int, default=DEFAULT_MAX_ENCODED_SIZE)
    parser.add_argument("--maximum-input-size", type=int, default=DEFAULT_MAX_INPUT_SIZE)
    return parser


def main(argv: list[str] | None = None) -> int:
    """LECE envelopeを復元し、実行せずにmetadataと任意のartifactを保存する。"""
    args = build_parser().parse_args(argv)
    candidates = find_rzk_lece_streams(
        _read_bounded_regular_file(args.input, maximum_size=args.maximum_input_size),
        maximum_encoded_size=args.maximum_encoded_size,
    )
    report = {
        "format": "rzk-low-nibble-lece-v1",
        "candidates": candidate_report(candidates),
        "executed": False,
        "network_contacted": False,
        "family_classification": "independent_verification_required",
    }
    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for index, item in enumerate(candidates):
            digest = hashlib.sha256(item.data).hexdigest()
            (args.output_dir / f"lece-{index}-{digest}.bin").write_bytes(item.data)
    if args.json:
        args.json.parent.mkdir(parents=True, exist_ok=True)
        args.json.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if candidates else 2


if __name__ == "__main__":
    raise SystemExit(main())
