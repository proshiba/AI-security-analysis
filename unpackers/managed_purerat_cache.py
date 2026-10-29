"""PureRAT系managed UTF-16 cacheの検証済み後段を静的復元する。

このmoduleは、別のCIL解析器が一意に束縛したresource名、ordered byte-array
write、Eaz keyed-word transform recipe、cache参照offsetだけを受け取る。検体、
CLR、CIL、復元文字列を実行せず、provider名やprotector名、loose URL一致を
family/C2根拠にしない。

CIL recipeそのものの発見・証明はcallerの責務である。この境界では、曖昧な
resource、未初期化配列、範囲外offset、重複・重なる文字列領域を拒否する。
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Sequence
from dataclasses import dataclass

from malware.purehvnc.managed_resource_recovery import (
    StaticRecoveryError,
    decrypt_keyed_eaz_resource,
)

MAX_RESOURCE_COUNT = 256
MAX_RESOURCE_BYTES = 16 << 20
MAX_TOTAL_RESOURCE_BYTES = 32 << 20
MAX_CACHE_OFFSETS = 4_096
MAX_CACHE_STRING_BYTES = 1 << 20
MAX_CACHE_DECODED_BYTES = 8 << 20
MAX_ORDERED_WRITES = 65_536


class ManagedPureRatCacheError(ValueError):
    """検証済み後段modelから外れた入力をfail-closedで表す。"""


@dataclass(frozen=True)
class VerifiedKeyedWordRecipe:
    """CIL側で証明済みのkeyed-word transform値だけを保持する。"""

    method_token: int
    method_body_sha256: str
    seed: int
    addend: int
    partial_word_profile_verified: bool


def replay_ordered_byte_writes(
    length: int,
    writes: Sequence[tuple[int, int]],
) -> bytes:
    """決定済み単一路上のbyte配列writeを順番どおりに再生する。

    同じindexへの上書きはCILの通常semanticsなので許可する。ただし、各writeの
    index/valueが具体値で、最終的に全indexが初期化済みの場合に限る。分岐集合を
    合流して得た候補値をこの関数へ渡してはならない。
    """

    if (
        isinstance(length, bool)
        or not isinstance(length, int)
        or not 0 < length <= MAX_CACHE_STRING_BYTES
    ):
        raise ManagedPureRatCacheError("ordered_write_length_invalid")
    if (
        not isinstance(writes, Sequence)
        or isinstance(writes, (str, bytes, bytearray))
        or not writes
        or len(writes) > MAX_ORDERED_WRITES
    ):
        raise ManagedPureRatCacheError("ordered_write_count_invalid")
    current: dict[int, int] = {}
    for item in writes:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or isinstance(item[0], bool)
            or not isinstance(item[0], int)
            or isinstance(item[1], bool)
            or not isinstance(item[1], int)
            or not 0 <= item[0] < length
            or not 0 <= item[1] <= 0xFF
        ):
            raise ManagedPureRatCacheError("ordered_write_value_invalid")
        current[item[0]] = item[1]
    if set(current) != set(range(length)):
        raise ManagedPureRatCacheError("ordered_write_final_state_incomplete")
    return bytes(current[index] for index in range(length))


def decode_referenced_utf16_cache(
    data: bytes,
    offsets: Sequence[int],
) -> tuple[str, ...]:
    """完全tableのentry boundaryに一致する参照offsetだけを返す。"""

    if not isinstance(data, bytes) or not data or len(data) > MAX_RESOURCE_BYTES:
        raise ManagedPureRatCacheError("cache_data_bounds")
    if (
        not isinstance(offsets, Sequence)
        or isinstance(offsets, (str, bytes, bytearray))
        or not offsets
        or len(offsets) > MAX_CACHE_OFFSETS
        or any(
            isinstance(offset, bool) or not isinstance(offset, int)
            for offset in offsets
        )
    ):
        raise ManagedPureRatCacheError("cache_offset_set_invalid")
    if len(set(offsets)) != len(offsets):
        raise ManagedPureRatCacheError("cache_offset_set_duplicate")
    table = dict(decode_complete_utf16_cache(data))
    if any(offset not in table for offset in offsets):
        raise ManagedPureRatCacheError("cache_offset_not_entry_boundary")
    return tuple(table[offset] for offset in offsets)


def decode_complete_utf16_cache(data: bytes) -> tuple[tuple[int, str], ...]:
    """offset 0からEOFまで完全消費するlength-prefixed UTF-16LE tableを読む。"""

    if not isinstance(data, bytes) or not data or len(data) > MAX_RESOURCE_BYTES:
        raise ManagedPureRatCacheError("cache_data_bounds")
    position = 0
    total = 0
    entries: list[tuple[int, str]] = []
    while position < len(data):
        if len(entries) >= MAX_CACHE_OFFSETS or position + 4 > len(data):
            raise ManagedPureRatCacheError("cache_table_count_or_header_limit")
        offset = position
        size = struct.unpack_from("<i", data, position)[0]
        position += 4
        end = position + size
        if size < 0 or size > MAX_CACHE_STRING_BYTES or size % 2 or end > len(data):
            raise ManagedPureRatCacheError("cache_string_bounds_or_alignment")
        try:
            value = data[position:end].decode("utf-16le", errors="strict")
        except UnicodeDecodeError as exc:
            raise ManagedPureRatCacheError("cache_string_utf16_invalid") from exc
        total += size
        if total > MAX_CACHE_DECODED_BYTES:
            raise ManagedPureRatCacheError("cache_decoded_byte_limit")
        entries.append((offset, value))
        position = end
    if position != len(data) or not entries:
        raise ManagedPureRatCacheError("cache_table_incomplete")
    return tuple(entries)


def recover_verified_cache_model(
    resources: Sequence[tuple[str, bytes]],
    *,
    resource_name: str,
    key_writes: Sequence[tuple[int, int]],
    mask_writes: Sequence[tuple[int, int]],
    referenced_offsets: Sequence[int],
    recipe: VerifiedKeyedWordRecipe,
) -> tuple[dict[str, object], tuple[str, ...]]:
    """一意に束縛済みのCIL modelからcache文字列を復元する。

    返す文字列はcallerが既存の厳格config schemaへ渡すための内部値である。
    reportにはraw key、mask、resource、文字列、endpointを含めない。この成功だけで
    family/C2を確定してはならない。
    """

    if (
        not isinstance(resources, Sequence)
        or isinstance(resources, (str, bytes, bytearray))
        or not resources
        or len(resources) > MAX_RESOURCE_COUNT
    ):
        raise ManagedPureRatCacheError("resource_set_bounds")
    if (
        not isinstance(resource_name, str)
        or not resource_name
        or len(resource_name) > 1_024
    ):
        raise ManagedPureRatCacheError("resource_name_invalid")
    if not isinstance(recipe, VerifiedKeyedWordRecipe):
        raise ManagedPureRatCacheError("transform_recipe_invalid")
    if (
        isinstance(recipe.method_token, bool)
        or not isinstance(recipe.method_token, int)
        or recipe.method_token >> 24 != 6
        or not recipe.method_token & 0xFFFFFF
        or len(recipe.method_body_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in recipe.method_body_sha256
        )
        or isinstance(recipe.seed, bool)
        or not isinstance(recipe.seed, int)
        or not 0 <= recipe.seed <= 0xFFFFFFFF
        or isinstance(recipe.addend, bool)
        or not isinstance(recipe.addend, int)
        or not 0 <= recipe.addend <= 0xFFFFFFFF
        or recipe.partial_word_profile_verified is not True
    ):
        raise ManagedPureRatCacheError("transform_recipe_not_verified")

    names: set[str] = set()
    selected: bytes | None = None
    total = 0
    for item in resources:
        if (
            not isinstance(item, tuple)
            or len(item) != 2
            or not isinstance(item[0], str)
            or not item[0]
            or len(item[0]) > 1_024
            or not isinstance(item[1], bytes)
            or not item[1]
            or len(item[1]) > MAX_RESOURCE_BYTES
            or item[0] in names
        ):
            raise ManagedPureRatCacheError("resource_set_entry_invalid_or_ambiguous")
        names.add(item[0])
        total += len(item[1])
        if total > MAX_TOTAL_RESOURCE_BYTES:
            raise ManagedPureRatCacheError("resource_set_total_byte_limit")
        if item[0] == resource_name:
            selected = item[1]
    if selected is None:
        raise ManagedPureRatCacheError("bound_resource_missing")

    key = replay_ordered_byte_writes(32, key_writes)
    mask = replay_ordered_byte_writes(16, mask_writes)
    try:
        clear = decrypt_keyed_eaz_resource(
            selected,
            key,
            key_mask=mask[::-1],
            seed=recipe.seed,
            addend=recipe.addend,
            allow_partial_word=True,
        )
    except StaticRecoveryError as exc:
        raise ManagedPureRatCacheError("keyed_word_transform_failed") from exc
    table = decode_complete_utf16_cache(clear)
    values = decode_referenced_utf16_cache(clear, referenced_offsets)
    report: dict[str, object] = {
        "schema_version": 1,
        "status": "recovered_verified_referenced_utf16_cache",
        "recipe": "ordered_key_reverse_mask_eaz_partial_word_utf16_offsets_v1",
        "resource": {
            "name_sha256": hashlib.sha256(resource_name.encode("utf-8")).hexdigest(),
            "size": len(selected),
            "sha256": hashlib.sha256(selected).hexdigest(),
        },
        "transform": {
            "method_token": f"0x{recipe.method_token:08x}",
            "method_body_sha256": recipe.method_body_sha256,
            "seed": recipe.seed,
            "addend": recipe.addend,
            "partial_word_profile_verified": True,
        },
        "ordered_writes": {
            "key_write_count": len(key_writes),
            "mask_write_count": len(mask_writes),
            "key_final_sha256": hashlib.sha256(key).hexdigest(),
            "mask_final_sha256": hashlib.sha256(mask).hexdigest(),
            "ordered_overwrite_semantics_used": True,
            "mask_reversed_before_key_xor": True,
        },
        "cache": {
            "complete_table_consumed": True,
            "complete_table_entry_count": len(table),
            "referenced_offset_count": len(referenced_offsets),
            "decoded_string_count": len(values),
            "decoded_string_sha256": [
                hashlib.sha256(value.encode("utf-8")).hexdigest() for value in values
            ],
            "raw_offsets_published": False,
            "raw_strings_published": False,
        },
        "family_attribution_allowed": False,
        "c2_confirmation_allowed": False,
        "provider_or_protector_label_used": False,
        "sample_executed": False,
        "clr_loaded": False,
        "instruction_emulation_performed": False,
        "network_contacted": False,
        "raw_key_material_published": False,
        "raw_resource_returned": False,
    }
    return report, values


__all__ = [
    "ManagedPureRatCacheError",
    "VerifiedKeyedWordRecipe",
    "decode_complete_utf16_cache",
    "decode_referenced_utf16_cache",
    "recover_verified_cache_model",
    "replay_ordered_byte_writes",
]
