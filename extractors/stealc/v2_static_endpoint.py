"""StealC v2以降の連続RC4文字列表からC2ベースURLだけを静的復元する。"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from extractors.stealc.structural import classify_module_role
from extractors.stealc.v2_memory import (
    STRING_KEY,
    LocatedString,
    _decode_value,
    _encrypted_run,
    _located_strings,
    _valid_http_base,
)

MIN_TABLE_VALUES = 64
MIN_DECODED_VALUES = 60
MIN_DECODED_RATIO = 0.90
MAX_KEYS = 256
PROTOCOL_MARKERS = frozenset(
    {"create", "upload_file", "loader", "done", "access_token", "build", "type"}
)
COLLECTION_MARKERS = frozenset({"login data", "local state", "steam"})


@dataclass(frozen=True)
class V2StaticEndpoint:
    """完全な通信設定ではなく、独立証拠で確認したC2ベースURL。"""

    base_url: str
    key_sha256: str
    key_offset: int
    table_count: int
    decoded_count: int
    protocol_markers: tuple[str, ...]
    collection_markers: tuple[str, ...]

    def public_dict(self) -> dict:
        """秘密鍵や復号された全文字列を含めず、確認根拠だけ返す。"""
        return {
            "generation_candidate": "StealC-v2-or-later",
            "completeness": "endpoint_base_only",
            "method": "contiguous_base64_standard_rc4",
            "c2_base_url": self.base_url,
            "gate_path": None,
            "traffic_key_recovered": False,
            "string_key_sha256": self.key_sha256,
            "key_file_offset": self.key_offset,
            "table_count": self.table_count,
            "decoded_count": self.decoded_count,
            "protocol_markers": list(self.protocol_markers),
            "collection_markers": list(self.collection_markers),
            "executed": False,
            "network_contacted": False,
        }


def recover_from_strings(
    values: list[LocatedString], *, core_role_confirmed: bool
) -> V2StaticEndpoint | None:
    """連続テーブル・復号率・通信/収集マーカーをすべて要求する。"""
    if not core_role_confirmed:
        return None
    candidates: list[V2StaticEndpoint] = []
    tried = 0
    for index, item in enumerate(values):
        if STRING_KEY.fullmatch(item.value) is None:
            continue
        table = _encrypted_run(values, index)
        if len(table) < MIN_TABLE_VALUES:
            continue
        tried += 1
        if tried > MAX_KEYS:
            return None
        decoded = [
            clear
            for entry in table
            if (clear := _decode_value(entry, item.value)) is not None
        ]
        if len(decoded) < MIN_DECODED_VALUES:
            continue
        if len(decoded) / len(table) < MIN_DECODED_RATIO:
            continue
        lowered = {entry.casefold() for entry in decoded}
        protocol = PROTOCOL_MARKERS & lowered
        collection = COLLECTION_MARKERS & lowered
        if len(protocol) < 6 or len(collection) < 2:
            continue
        urls = {entry for entry in decoded if _valid_http_base(entry)}
        if len(urls) != 1:
            continue
        candidates.append(
            V2StaticEndpoint(
                base_url=next(iter(urls)),
                key_sha256=hashlib.sha256(item.value).hexdigest(),
                key_offset=item.offset,
                table_count=len(table),
                decoded_count=len(decoded),
                protocol_markers=tuple(sorted(protocol)),
                collection_markers=tuple(sorted(collection)),
            )
        )
    unique = {(item.base_url, item.key_sha256): item for item in candidates}
    return next(iter(unique.values())) if len(unique) == 1 else None


def extract_v2_static_endpoint(data: bytes) -> V2StaticEndpoint | None:
    """PEを実行せず、StealC core構造が強い場合だけC2ベースを返す。"""
    if len(data) > 32 * 1024 * 1024:
        return None
    structural = classify_module_role(data)
    return recover_from_strings(
        _located_strings(data),
        core_role_confirmed=(
            structural.get("module_role") == "collection_and_c2_core"
            and structural.get("confidence") == "high"
        ),
    )
