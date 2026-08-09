#!/usr/bin/env python3
"""RemusStealer のメモリイメージから暗号化 config と C2 を静的復元する。"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import itertools
import json
import os
import re
import stat
import struct
import sys
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import pefile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

DEFAULT_MAX_INPUT_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_IMAGE_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_SLOTS = 16
MAX_SECTIONS = 96
MAX_SLOTS_HARD_LIMIT = 256
CHACHA_CONSTANT = b"expand 32-byte k"
SLOT_SIZE = 64
TOKEN_WINDOW_BYTES = 0x100
FILE_ATTRIBUTE_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)

TAG_RE = re.compile(rb"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32}(?![0-9A-Fa-f])")
UUID_RE = re.compile(
    rb"(?i)(?<![0-9a-f])[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    rb"[0-9a-f]{4}-[0-9a-f]{12}(?![0-9a-f])"
)
SELECTOR_PATTERN = re.compile(
    rb"\x0f\xb6\x05(?P<selector>.{4})"
    rb"\x83\xf0\x16\xc1\xe0\x06"
    rb"\x48\x8d\x15(?P<cipher>.{4})\x48\x01\xc2"
    rb"\x48\x8d\x0d(?P<state>.{4})",
    re.DOTALL,
)

Layout = Literal["auto", "mapped", "file"]


class RemusMemoryConfigError(ValueError):
    """入力が安全条件または Remus config 構造を満たさないことを表す。"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _positive_bounded(value: int, name: str, maximum: int | None = None) -> int:
    if value <= 0:
        raise RemusMemoryConfigError(f"{name} は正の整数である必要があります")
    if maximum is not None and value > maximum:
        raise RemusMemoryConfigError(f"{name} が上限を超えています: {value} > {maximum}")
    return value


def _find_all(data: bytes, needle: bytes) -> list[int]:
    offsets: list[int] = []
    cursor = 0
    while True:
        found = data.find(needle, cursor)
        if found < 0:
            return offsets
        offsets.append(found)
        cursor = found + 1


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(getattr(metadata, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT)


def _reject_reparse_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.parts[0])
    for part in absolute.parts[1:]:
        current /= part
        try:
            current.lstat()
        except FileNotFoundError:
            break
        if _is_reparse_point(current):
            raise RemusMemoryConfigError(f"reparse point を含むパスは扱えません: {current}")


def _read_bounded(path: Path, maximum: int) -> bytes:
    _positive_bounded(maximum, "max_input_bytes")
    _reject_reparse_components(path)
    initial = path.stat()
    if not stat.S_ISREG(initial.st_mode):
        raise RemusMemoryConfigError("入力は通常ファイルである必要があります")
    if initial.st_nlink != 1:
        raise RemusMemoryConfigError("入力は単一リンクの通常ファイルである必要があります")
    if initial.st_size > maximum:
        raise RemusMemoryConfigError(f"入力サイズが上限を超えています: {initial.st_size} > {maximum}")

    with path.open("rb") as handle:
        opened_before = os.fstat(handle.fileno())
        if not stat.S_ISREG(opened_before.st_mode):
            raise RemusMemoryConfigError("入力は通常ファイルである必要があります")
        if not os.path.samestat(initial, opened_before):
            raise RemusMemoryConfigError("読み取り開始前に入力ファイルが置換されました")
        if initial.st_size != opened_before.st_size or initial.st_mtime_ns != opened_before.st_mtime_ns:
            raise RemusMemoryConfigError("読み取り開始前に入力の size/mtime が変化しました")
        data = handle.read(maximum + 1)
        opened_after = os.fstat(handle.fileno())

    final = path.stat()
    if len(data) > maximum:
        raise RemusMemoryConfigError(f"入力サイズが上限を超えています: {len(data)} > {maximum}")
    snapshots = (initial, opened_before, opened_after, final)
    if any(item.st_nlink != 1 for item in snapshots):
        raise RemusMemoryConfigError("読み取り中に入力がhardlink化されました")
    if any(not os.path.samestat(snapshots[0], item) for item in snapshots[1:]):
        raise RemusMemoryConfigError("読み取り中に入力ファイルが置換されました")
    if any(item.st_size != initial.st_size or item.st_mtime_ns != initial.st_mtime_ns for item in snapshots[1:]):
        raise RemusMemoryConfigError("読み取り中に入力の size/mtime が変化しました")
    if len(data) != initial.st_size:
        raise RemusMemoryConfigError("読み取り中に入力サイズが変化しました")
    return data


def _validate_pe(
    data: bytes,
    *,
    max_image_bytes: int,
) -> tuple[pefile.PE, list[dict[str, int | str]]]:
    _positive_bounded(max_image_bytes, "max_image_bytes")
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise RemusMemoryConfigError("入力先頭に MZ ヘッダーがありません")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if not 0x40 <= e_lfanew <= min(len(data) - 24, 0x100000):
        raise RemusMemoryConfigError("e_lfanew が許容範囲外です")
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        raise RemusMemoryConfigError("PE 署名がありません")
    try:
        image = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError as exc:
        raise RemusMemoryConfigError(f"PE ヘッダーを解析できません: {exc}") from exc

    section_count = int(image.FILE_HEADER.NumberOfSections)
    if not 1 <= section_count <= MAX_SECTIONS or len(image.sections) != section_count:
        raise RemusMemoryConfigError("section 数が不正です")
    magic = int(image.OPTIONAL_HEADER.Magic)
    if magic not in {0x10B, 0x20B}:
        raise RemusMemoryConfigError(f"未対応の Optional Header magic です: 0x{magic:x}")
    image_size = int(image.OPTIONAL_HEADER.SizeOfImage)
    header_size = int(image.OPTIONAL_HEADER.SizeOfHeaders)
    section_alignment = int(image.OPTIONAL_HEADER.SectionAlignment)
    file_alignment = int(image.OPTIONAL_HEADER.FileAlignment)
    if not 0 < image_size <= max_image_bytes:
        raise RemusMemoryConfigError(f"SizeOfImage が不正または上限超過です: {image_size}")
    if not 0 < header_size <= min(len(data), image_size):
        raise RemusMemoryConfigError("SizeOfHeaders が入力範囲外です")
    if section_alignment <= 0 or file_alignment <= 0:
        raise RemusMemoryConfigError("section/file alignment が不正です")

    sections: list[dict[str, int | str]] = []
    virtual_ranges: list[tuple[int, int]] = []
    raw_ranges: list[tuple[int, int]] = []
    for index, section in enumerate(image.sections):
        virtual_address = int(section.VirtualAddress)
        virtual_size = int(section.Misc_VirtualSize)
        raw_offset = int(section.PointerToRawData)
        raw_size = int(section.SizeOfRawData)
        characteristics = int(section.Characteristics)
        if min(virtual_address, virtual_size, raw_offset, raw_size) < 0:
            raise RemusMemoryConfigError(f"section {index} に負数があります")
        if virtual_address >= image_size:
            raise RemusMemoryConfigError(f"section {index} の RVA が SizeOfImage 外です")
        virtual_span = max(virtual_size, raw_size)
        if virtual_span and virtual_address + virtual_span > image_size:
            raise RemusMemoryConfigError(f"section {index} の仮想範囲が SizeOfImage 外です")
        if virtual_span:
            virtual_ranges.append((virtual_address, virtual_address + virtual_span))
        if raw_size:
            raw_end = raw_offset + raw_size
            if raw_end < raw_offset:
                raise RemusMemoryConfigError(f"section {index} の raw 範囲がオーバーフローしました")
            raw_ranges.append((raw_offset, raw_end))
        sections.append(
            {
                "index": index,
                "name": bytes(section.Name).rstrip(b"\0").decode("latin-1"),
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "raw_offset": raw_offset,
                "raw_size": raw_size,
                "characteristics": characteristics,
            }
        )

    for ranges, label in ((virtual_ranges, "仮想"), (raw_ranges, "raw")):
        ordered = sorted(ranges)
        for previous, current in itertools.pairwise(ordered):
            if current[0] < previous[1]:
                raise RemusMemoryConfigError(f"section の {label} 範囲が重複しています")
    return image, sections


def _file_layout_viable(data: bytes, sections: list[dict[str, int | str]]) -> bool:
    return all(
        int(section["raw_size"]) == 0 or int(section["raw_offset"]) + int(section["raw_size"]) <= len(data)
        for section in sections
    )


def _mapped_layout_viable(
    data: bytes,
    image_size: int,
    sections: list[dict[str, int | str]],
) -> bool:
    if len(data) < image_size:
        return False
    return all(
        int(section["virtual_address"]) + max(int(section["virtual_size"]), int(section["raw_size"])) <= len(data)
        for section in sections
    )


def _mapped_section_content_score(
    mapped: bytes,
    sections: list[dict[str, int | str]],
) -> int:
    """section RVA 上の実データ量を、layout 自動判定の保守的な指標にする。"""

    score = 0
    for section in sections:
        virtual_address = int(section["virtual_address"])
        span = max(int(section["virtual_size"]), int(section["raw_size"]))
        sample = mapped[virtual_address : virtual_address + min(span, 4096)]
        score += sum(byte != 0 for byte in sample)
    return score


def _normalise_layout(
    data: bytes,
    image: pefile.PE,
    sections: list[dict[str, int | str]],
    layout: Layout,
) -> tuple[bytes, Literal["mapped", "file"]]:
    if layout not in {"auto", "mapped", "file"}:
        raise RemusMemoryConfigError(f"未対応の layout です: {layout}")
    image_size = int(image.OPTIONAL_HEADER.SizeOfImage)
    mapped_viable = _mapped_layout_viable(data, image_size, sections)
    file_viable = _file_layout_viable(data, sections)
    selected: Literal["mapped", "file"]
    if layout == "mapped":
        if not mapped_viable:
            raise RemusMemoryConfigError("入力は完全な mapped layout ではありません")
        selected = "mapped"
    elif layout == "file":
        if not file_viable:
            raise RemusMemoryConfigError("入力は完全な file layout ではありません")
        selected = "file"
    elif mapped_viable and file_viable:
        # file-layout PE が overlay やゼロ padding で SizeOfImage 以上になると、長さだけでは
        # mapped-layout と誤判定する。両候補の section RVA 上にある実データ量を比較し、
        # raw section から再配置した候補の根拠が強い場合は file-layout を選ぶ。
        file_mapped = bytearray(image_size)
        header_size = int(image.OPTIONAL_HEADER.SizeOfHeaders)
        file_mapped[:header_size] = data[:header_size]
        for section in sections:
            raw_size = int(section["raw_size"])
            if raw_size == 0:
                continue
            raw_offset = int(section["raw_offset"])
            virtual_address = int(section["virtual_address"])
            file_mapped[virtual_address : virtual_address + raw_size] = data[
                raw_offset : raw_offset + raw_size
            ]
        mapped_score = _mapped_section_content_score(data[:image_size], sections)
        file_score = _mapped_section_content_score(bytes(file_mapped), sections)
        selected = "file" if file_score > mapped_score else "mapped"
    elif mapped_viable:
        selected = "mapped"
    elif file_viable:
        selected = "file"
    else:
        raise RemusMemoryConfigError("mapped/file のどちらとしても section 範囲が不足しています")

    if selected == "mapped":
        return bytes(data[:image_size]), selected

    mapped = bytearray(image_size)
    header_size = int(image.OPTIONAL_HEADER.SizeOfHeaders)
    mapped[:header_size] = data[:header_size]
    for section in sections:
        raw_size = int(section["raw_size"])
        if raw_size == 0:
            continue
        raw_offset = int(section["raw_offset"])
        virtual_address = int(section["virtual_address"])
        mapped[virtual_address : virtual_address + raw_size] = data[raw_offset : raw_offset + raw_size]
    return bytes(mapped), selected


def _chacha20_original(data: bytes, key: bytes, nonce: bytes, counter: int) -> bytes:
    if len(key) != 32 or len(nonce) != 8:
        raise RemusMemoryConfigError("ChaCha20 key/nonce 長が不正です")
    if not 0 <= counter < 1 << 64:
        raise RemusMemoryConfigError("ChaCha20 counter が範囲外です")
    transform = Cipher(
        algorithms.ChaCha20(key, counter.to_bytes(8, "little") + nonce),
        mode=None,
    ).encryptor()
    return transform.update(data) + transform.finalize()


def _valid_host(host: str) -> bool:
    if host.casefold() == "none":
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    if len(host) > 253 or "." not in host:
        return False
    labels = host.rstrip(".").split(".")
    return all(
        label
        and len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and re.fullmatch(r"[A-Za-z0-9-]+", label) is not None
        for label in labels
    )


def _parse_endpoint_slot(plain: bytes, slot_index: int) -> dict[str, Any] | None:
    terminator = plain.find(b"\0")
    if terminator <= 0:
        return None
    raw_uri = plain[:terminator]
    try:
        uri = raw_uri.decode("ascii")
    except UnicodeDecodeError:
        return None
    if any(ord(character) < 0x20 or ord(character) >= 0x7F for character in uri):
        return None
    try:
        parsed = urlsplit(uri)
        port = parsed.port
    except ValueError:
        return None
    host = parsed.hostname
    if (
        parsed.scheme.casefold() not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or not _valid_host(host)
    ):
        return None
    sentinel = host.casefold() == "none"
    if sentinel and (parsed.port is not None or parsed.path not in {"", "/"} or parsed.query):
        return None
    effective_port = port or (443 if parsed.scheme.casefold() == "https" else 80)
    return {
        "slot_index": slot_index,
        "uri": uri,
        "scheme": parsed.scheme.casefold(),
        "host": host,
        "port": effective_port,
        "explicit_port": port is not None,
        "sentinel": sentinel,
        "uri_sha256": _sha256(raw_uri),
    }


def _section_for_rva(
    sections: list[dict[str, int | str]],
    rva: int,
) -> dict[str, int | str] | None:
    for section in sections:
        start = int(section["virtual_address"])
        end = start + max(int(section["virtual_size"]), int(section["raw_size"]))
        if start <= rva < end:
            return section
    return None


def _selector_evidence(
    mapped: bytes,
    *,
    cipher_rva: int,
    state_rva: int,
    slots: list[dict[str, Any]],
) -> dict[str, Any]:
    matches: list[tuple[int, int]] = []
    for match in SELECTOR_PATTERN.finditer(mapped):
        start = match.start()
        selector_rva = start + 7 + struct.unpack("<i", match.group("selector"))[0]
        referenced_cipher = start + 20 + struct.unpack("<i", match.group("cipher"))[0]
        referenced_state = start + 30 + struct.unpack("<i", match.group("state"))[0]
        if referenced_cipher != cipher_rva or referenced_state != state_rva:
            continue
        if not 0 <= selector_rva < len(mapped):
            raise RemusMemoryConfigError("selector RVA が mapped image 外です")
        matches.append((start, selector_rva))
    if len(matches) > 1:
        raise RemusMemoryConfigError("config selector pattern を一意に決定できません")
    if not matches:
        return {
            "status": "not_recovered",
            "xor_mask": 0x16,
            "reason_ja": "対応する selector code pattern が見つかりませんでした",
        }
    code_rva, selector_rva = matches[0]
    encoded = mapped[selector_rva]
    selected_index = encoded ^ 0x16
    selected = next((slot for slot in slots if slot["slot_index"] == selected_index), None)
    return {
        "status": "recovered",
        "code_rva": code_rva,
        "selector_rva": selector_rva,
        "encoded_value": encoded,
        "xor_mask": 0x16,
        "selected_index": selected_index,
        "selected_slot_recovered": selected is not None,
        "selected_slot_is_sentinel": selected["sentinel"] if selected else None,
        "selected_slot_uri_sha256": selected["uri_sha256"] if selected else None,
    }


def _runtime_evidence(
    mapped: bytes,
    *,
    state_rva: int,
    selector: dict[str, Any],
    slots: list[dict[str, Any]],
) -> dict[str, Any]:
    selected_index = selector.get("selected_index")
    selected = next((slot for slot in slots if slot["slot_index"] == selected_index), None)
    endpoint_hits: list[int] = []
    if selected is not None:
        wide = selected["uri"].encode("utf-16le") + b"\0\0"
        endpoint_hits = _find_all(mapped, wide)
    endpoint = {
        "present": len(endpoint_hits) == 1,
        "occurrence_count": len(endpoint_hits),
        "rva": endpoint_hits[0] if len(endpoint_hits) == 1 else None,
        "length": len(selected["uri"]) if len(endpoint_hits) == 1 and selected else None,
        "sha256": selected["uri_sha256"] if len(endpoint_hits) == 1 and selected else None,
        "value_published": False,
    }

    window_start = max(0, state_rva - TOKEN_WINDOW_BYTES)
    token_matches = list(UUID_RE.finditer(mapped[window_start:state_rva]))
    if len(token_matches) > 1:
        raise RemusMemoryConfigError("ChaCha state 直前の access token 候補が複数あります")
    if token_matches:
        token_match = token_matches[0]
        token = token_match.group()
        token_rva = window_start + token_match.start()
        token_evidence = {
            "present": True,
            "format": "uuid",
            "rva": token_rva,
            "length": len(token),
            "sha256": _sha256(token.lower()),
            "value_published": False,
        }
    else:
        token_evidence = {
            "present": False,
            "format": "uuid",
            "rva": None,
            "length": None,
            "sha256": None,
            "value_published": False,
        }
    return {
        "selected_endpoint": endpoint,
        "access_token": token_evidence,
    }


def _tag_candidate(
    mapped: bytes,
    *,
    key_rva: int,
    sections: list[dict[str, int | str]],
) -> dict[str, Any]:
    matches = list(TAG_RE.finditer(mapped))
    if len(matches) != 1:
        return {
            "status": "not_recovered" if not matches else "ambiguous",
            "candidate_count": len(matches),
            "confidence": "none",
            "assessment": "candidate",
            "reason_ja": "mapped image 全体で 32 桁 hex 値を一意に決定できませんでした",
        }
    match = matches[0]
    value = match.group().decode("ascii").lower()
    rva = match.start()
    section = _section_for_rva(sections, rva)
    distance = rva - key_rva
    non_executable = bool(section) and not (int(section["characteristics"]) & 0x20000000)
    correlated = 0 < distance <= 0x4000 and non_executable
    return {
        "status": "candidate",
        "value": value,
        "rva": rva,
        "sha256": _sha256(value.encode("ascii")),
        "candidate_count": 1,
        "assessment": "candidate",
        "confidence": "high" if correlated else "medium",
        "section_index": int(section["index"]) if section else None,
        "distance_from_static_key": distance,
        "evidence": [
            "mapped_image_unique_32_hex",
            "remus_chacha_config_validated",
            "same_static_config_region" if correlated else "static_config_region_correlation_weak",
        ],
    }


def extract_remus_memory_config(
    data: bytes,
    *,
    layout: Layout = "auto",
    max_input_bytes: int = DEFAULT_MAX_INPUT_BYTES,
    max_image_bytes: int = DEFAULT_MAX_IMAGE_BYTES,
    max_slots: int = DEFAULT_MAX_SLOTS,
) -> dict[str, Any]:
    """Remus の mapped/file-layout PE から endpoint config を復元する。

    検体の実行、エミュレーション、外部通信は行わない。access token の値は
    report に含めず、存在、長さ、SHA-256 だけを返す。
    """

    _positive_bounded(max_input_bytes, "max_input_bytes")
    _positive_bounded(max_slots, "max_slots", MAX_SLOTS_HARD_LIMIT)
    if len(data) > max_input_bytes:
        raise RemusMemoryConfigError(f"入力サイズが上限を超えています: {len(data)} > {max_input_bytes}")
    image, sections = _validate_pe(data, max_image_bytes=max_image_bytes)
    mapped, selected_layout = _normalise_layout(data, image, sections, layout)

    state_candidates = _find_all(mapped, CHACHA_CONSTANT)
    if len(state_candidates) != 1:
        raise RemusMemoryConfigError(f"ChaCha state を一意に決定できません: {len(state_candidates)} 件")
    state_rva = state_candidates[0]
    if state_rva + SLOT_SIZE > len(mapped):
        raise RemusMemoryConfigError("ChaCha state が mapped image 末尾で切れています")
    key = mapped[state_rva + 16 : state_rva + 48]
    counter = struct.unpack_from("<Q", mapped, state_rva + 48)[0]
    nonce = mapped[state_rva + 56 : state_rva + 64]
    if key == b"\0" * 32:
        raise RemusMemoryConfigError("ChaCha key が全てゼロです")

    duplicate_candidates: list[int] = []
    for offset in _find_all(mapped, key):
        if offset == state_rva + 16 or offset + 48 > len(mapped):
            continue
        if mapped[offset + 32 : offset + 40] != nonce:
            continue
        if mapped[offset + 40 : offset + 48] != b"\0" * 8:
            continue
        duplicate_candidates.append(offset)
    if len(duplicate_candidates) != 1:
        raise RemusMemoryConfigError(
            f"静的 key/nonce/padding 構造を一意に決定できません: {len(duplicate_candidates)} 件"
        )
    key_rva = duplicate_candidates[0]
    cipher_rva = key_rva + 48

    slots: list[dict[str, Any]] = []
    stop_index: int | None = None
    for slot_index in range(max_slots):
        offset = cipher_rva + slot_index * SLOT_SIZE
        if offset + SLOT_SIZE > len(mapped):
            stop_index = slot_index
            break
        encrypted = mapped[offset : offset + SLOT_SIZE]
        plain = _chacha20_original(encrypted, key, nonce, slot_index)
        parsed = _parse_endpoint_slot(plain, slot_index)
        if parsed is None:
            stop_index = slot_index
            break
        parsed["cipher_rva"] = offset
        slots.append(parsed)
    sentinels = [slot for slot in slots if slot["sentinel"]]
    endpoints = [slot for slot in slots if not slot["sentinel"]]
    if not sentinels or sentinels[0]["slot_index"] != 0:
        raise RemusMemoryConfigError("先頭の http://none sentinel を復元できません")
    if not endpoints:
        raise RemusMemoryConfigError("実 C2 endpoint を1件も復元できません")

    selector = _selector_evidence(
        mapped,
        cipher_rva=cipher_rva,
        state_rva=state_rva,
        slots=slots,
    )
    runtime = _runtime_evidence(
        mapped,
        state_rva=state_rva,
        selector=selector,
        slots=slots,
    )
    tag = _tag_candidate(mapped, key_rva=key_rva, sections=sections)

    public_sentinels = [{key: value for key, value in slot.items() if key != "sentinel"} for slot in sentinels]
    public_endpoints = [{key: value for key, value in slot.items() if key != "sentinel"} for slot in endpoints]
    return {
        "schema_version": 1,
        "analysis": "remus_memory_config",
        "status": "extracted",
        "input": {
            "sha256": _sha256(data),
            "size": len(data),
            "requested_layout": layout,
            "selected_layout": selected_layout,
        },
        "pe": {
            "machine": f"0x{int(image.FILE_HEADER.Machine):04x}",
            "optional_magic": f"0x{int(image.OPTIONAL_HEADER.Magic):03x}",
            "image_base": f"0x{int(image.OPTIONAL_HEADER.ImageBase):x}",
            "size_of_image": int(image.OPTIONAL_HEADER.SizeOfImage),
            "section_count": len(sections),
            "dotnet": bool(
                len(image.OPTIONAL_HEADER.DATA_DIRECTORY) > 14
                and image.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress
            ),
        },
        "config": {
            "sentinels": public_sentinels,
            "endpoints": public_endpoints,
            "tag": tag,
            "exp": {
                "status": "not_recovered",
                "value": None,
                "reason_ja": "10進 exp は静的 config に存在せず、実行時 epoch の可能性があります",
            },
            "selector": selector,
            "runtime": runtime,
        },
        "crypto": {
            "algorithm": "ChaCha20 original (64-bit counter / 64-bit nonce)",
            "state_rva": state_rva,
            "state_occurrence_count": 1,
            "static_key_rva": key_rva,
            "cipher_rva": cipher_rva,
            "runtime_counter": counter,
            "key_sha256": _sha256(key),
            "nonce_sha256": _sha256(nonce),
            "slot_size": SLOT_SIZE,
            "recovered_slot_count": len(slots),
            "first_non_uri_slot": stop_index,
            "key_published": False,
            "nonce_published": False,
        },
        "safety": {
            "sample_executed": False,
            "emulated": False,
            "network_contacted": False,
            "access_token_value_published": False,
            "runtime_endpoint_value_published": False,
        },
    }


def _write_json_exclusive(input_path: Path, output_path: Path, rendered: str) -> None:
    """既存ファイル、入力自身、reparse point を避けて JSON を排他作成する。"""

    _reject_reparse_components(input_path)
    _reject_reparse_components(output_path)
    input_absolute = os.path.normcase(os.path.abspath(input_path))
    output_absolute = os.path.normcase(os.path.abspath(output_path))
    if input_absolute == output_absolute:
        raise RemusMemoryConfigError("入力と出力に同一パスは指定できません")
    if output_path.exists():
        try:
            if os.path.samefile(input_path, output_path):
                raise RemusMemoryConfigError("入力と出力が同一ファイルを指しています")
        except FileNotFoundError:
            pass
        raise RemusMemoryConfigError(f"既存の出力ファイルは上書きしません: {output_path}")

    _reject_reparse_components(output_path.parent)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    _reject_reparse_components(output_path.parent)
    _reject_reparse_components(output_path)
    try:
        with output_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(rendered)
    except FileExistsError as exc:
        raise RemusMemoryConfigError(f"既存の出力ファイルは上書きしません: {output_path}") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="mapped または file-layout PE")
    parser.add_argument("--output", type=Path, help="JSON report の保存先")
    parser.add_argument("--layout", choices=("auto", "mapped", "file"), default="auto")
    parser.add_argument("--max-input-bytes", type=int, default=DEFAULT_MAX_INPUT_BYTES)
    parser.add_argument("--max-image-bytes", type=int, default=DEFAULT_MAX_IMAGE_BYTES)
    parser.add_argument("--max-slots", type=int, default=DEFAULT_MAX_SLOTS)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        data = _read_bounded(args.input, args.max_input_bytes)
        report = extract_remus_memory_config(
            data,
            layout=args.layout,
            max_input_bytes=args.max_input_bytes,
            max_image_bytes=args.max_image_bytes,
            max_slots=args.max_slots,
        )
        rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.output is not None:
            _write_json_exclusive(args.input, args.output, rendered)
        sys.stdout.write(rendered)
        return 0
    except (OSError, RemusMemoryConfigError) as exc:
        error = {
            "schema_version": 1,
            "analysis": "remus_memory_config",
            "status": "error",
            "error_ja": str(exc),
            "sample_executed": False,
            "network_contacted": False,
        }
        sys.stderr.write(json.dumps(error, ensure_ascii=False) + "\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
