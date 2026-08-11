"""StealC v2 の再構築済みメモリPEから設定を静的復元する。

StealC v2 の確認済み構成では、botnet ID、通信RC4鍵、文字列RC4鍵、
Base64化された暗号文字列テーブルが .rdata に連続して配置される。
本モジュールはPEをロード・実行せず、各Base64値を標準RC4で個別に復号し、
独立した複数の特徴群が揃った場合だけ設定を確定する。
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import urllib.parse
from dataclasses import dataclass

import pefile

from extractors.common import valid_host

ASCII_RUN = re.compile(rb"[\x20-\x7e]{4,}")
BASE64_VALUE = re.compile(rb"[A-Za-z0-9+/]+={0,2}")
STRING_KEY = re.compile(rb"[A-Za-z0-9._@-]{8,64}")
TRAFFIC_KEY = re.compile(rb"(?:[0-9A-Fa-f]{2}){4,32}")
BUILD_ID = re.compile(rb"[A-Za-z0-9._-]{1,64}")
GATE_PATH = re.compile(r"/[A-Za-z0-9_-]{1,128}\.php")

MAX_LOCATED_STRINGS = 16_384
MAX_KEY_CANDIDATES = 256
MAX_TABLE_VALUES = 4_096
MAX_ENCODED_LENGTH = 4_096
MIN_ENCRYPTED_RUN = 32
MIN_DECODED_VALUES = 50

TRANSPORT_MARKERS = frozenset(
    {"winhttpsendrequest", "winhttpopenrequest", "winhttpreceiveresponse"}
)
PROTOCOL_MARKERS = frozenset(
    {"create", "hwid", "build", "access_token", "loader", "success"}
)
COLLECTION_MARKERS = frozenset(
    {"login data", "local state", "cookies.sqlite", "passwords.txt", "steam"}
)


@dataclass(frozen=True)
class LocatedString:
    """PE内のファイルオフセットを保持したASCII文字列。"""

    offset: int
    value: bytes


@dataclass(frozen=True)
class V2MemoryProfile:
    """再構築済みメモリPEから復元したStealC v2設定。"""

    base_url: str
    gate_path: str
    build_id: str
    traffic_key_hex: str
    string_key: str
    decoded_count: int
    config_offset: int

    @property
    def c2_url(self) -> str:
        """base URLとgate pathを結合した完全なC2 URLを返す。"""
        return urllib.parse.urljoin(
            self.base_url.rstrip("/") + "/", self.gate_path.lstrip("/")
        )

    @property
    def traffic_key_sha256(self) -> str:
        """通信鍵を照合するためのSHA-256を返す。"""
        return hashlib.sha256(bytes.fromhex(self.traffic_key_hex)).hexdigest()


def rc4(data: bytes, key: bytes) -> bytes:
    """外部暗号ライブラリへ依存せず標準RC4を適用する。"""
    if not key:
        raise ValueError("RC4 key must not be empty")
    state = list(range(256))
    j = 0
    for index in range(256):
        j = (j + state[index] + key[index % len(key)]) & 0xFF
        state[index], state[j] = state[j], state[index]
    output = bytearray()
    i = j = 0
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        output.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(output)


def _printable_ratio(value: bytes) -> float:
    if not value:
        return 0.0
    printable = sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in value)
    return printable / len(value)


def _valid_base64(value: bytes) -> bool:
    if not 4 <= len(value) <= MAX_ENCODED_LENGTH or len(value) % 4:
        return False
    if not BASE64_VALUE.fullmatch(value):
        return False
    try:
        base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return False
    return True


def _decode_value(value: bytes, key: bytes) -> str | None:
    try:
        encrypted = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None
    clear = rc4(encrypted, key).rstrip(b"\0")
    if not clear or _printable_ratio(clear) < 0.9:
        return None
    return clear.decode("ascii", errors="replace")


def _located_strings(data: bytes) -> list[LocatedString]:
    """.rdataと.dataから順序とオフセットを保って文字列を取得する。"""
    try:
        image = pefile.PE(data=data, fast_load=True)
    except pefile.PEFormatError:
        return []
    values: list[LocatedString] = []
    for section in image.sections:
        if section.Name.rstrip(b"\0") not in {b".rdata", b".data"}:
            continue
        raw = section.get_data()
        base_offset = section.PointerToRawData
        for match in ASCII_RUN.finditer(raw):
            values.append(LocatedString(base_offset + match.start(), match.group()))
            if len(values) >= MAX_LOCATED_STRINGS:
                return sorted(values, key=lambda item: item.offset)
    return sorted(values, key=lambda item: item.offset)


def _encrypted_run(values: list[LocatedString], start: int) -> list[bytes]:
    """鍵候補直後に連続するBase64テーブルを上限付きで返す。"""
    encoded: list[bytes] = []
    for item in values[start + 1 : start + 1 + MAX_TABLE_VALUES]:
        if not _valid_base64(item.value):
            break
        encoded.append(item.value)
    return encoded


def _valid_http_base(value: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        return False
    if port is not None and not 0 < port <= 65535:
        return False
    return valid_host(parsed.hostname)


def _same_origin_gate(base_url: str, gate_path: str) -> bool:
    """固定PHP gateをbase URLと同一originへだけ結合できるか検証する。"""

    if GATE_PATH.fullmatch(gate_path) is None:
        return False
    try:
        base = urllib.parse.urlsplit(base_url)
        resolved = urllib.parse.urlsplit(urllib.parse.urljoin(base_url, gate_path))
        return bool(
            resolved.scheme == base.scheme
            and (resolved.hostname or "").casefold()
            == (base.hostname or "").casefold()
            and resolved.port == base.port
            and resolved.username is None
            and resolved.password is None
            and resolved.path == gate_path
            and not resolved.query
            and not resolved.fragment
        )
    except ValueError:
        return False


def _validated_endpoint(decoded: list[str]) -> tuple[str, str] | None:
    base_url = next((value for value in decoded if _valid_http_base(value)), None)
    gate_path = next(
        (value for value in decoded if GATE_PATH.fullmatch(value) is not None),
        None,
    )
    if base_url is None or gate_path is None:
        return None
    if not _same_origin_gate(base_url, gate_path):
        return None
    lower = {value.lower() for value in decoded}
    if len(TRANSPORT_MARKERS & lower) < 2:
        return None
    if len(PROTOCOL_MARKERS & lower) < 4:
        return None
    if len(COLLECTION_MARKERS & lower) < 2:
        return None
    return base_url, gate_path


def _preceding_config(
    values: list[LocatedString], key_index: int
) -> tuple[str, str] | None:
    """文字列鍵の直前からbuild/botnet IDと通信鍵を復元する。"""
    window = values[max(0, key_index - 8) : key_index]
    traffic_index = next(
        (
            index
            for index in range(len(window) - 1, -1, -1)
            if TRAFFIC_KEY.fullmatch(window[index].value.strip())
        ),
        None,
    )
    if traffic_index is None:
        return None
    traffic_key = window[traffic_index].value.strip().decode("ascii").lower()
    for item in reversed(window[:traffic_index]):
        candidate = item.value.strip()
        if BUILD_ID.fullmatch(candidate):
            return candidate.decode("ascii"), traffic_key
    return None


def recover_v2_profile_from_strings(
    values: list[LocatedString],
) -> V2MemoryProfile | None:
    """順序付き文字列列から高確度のStealC v2設定を復元する。"""
    candidates: list[V2MemoryProfile] = []
    key_candidates = 0
    for index, item in enumerate(values):
        if not STRING_KEY.fullmatch(item.value):
            continue
        encoded = _encrypted_run(values, index)
        if len(encoded) < MIN_ENCRYPTED_RUN:
            continue
        key_candidates += 1
        if key_candidates > MAX_KEY_CANDIDATES:
            break
        decoded = [
            clear
            for value in encoded
            if (clear := _decode_value(value, item.value)) is not None
        ]
        if len(decoded) < MIN_DECODED_VALUES:
            continue
        endpoint = _validated_endpoint(decoded)
        preceding = _preceding_config(values, index)
        if endpoint is None or preceding is None:
            continue
        build_id, traffic_key_hex = preceding
        candidates.append(
            V2MemoryProfile(
                base_url=endpoint[0],
                gate_path=endpoint[1],
                build_id=build_id,
                traffic_key_hex=traffic_key_hex,
                string_key=item.value.decode("ascii"),
                decoded_count=len(decoded),
                config_offset=values[max(0, index - 2)].offset,
            )
        )
    unique = {
        (
            profile.c2_url,
            profile.build_id,
            profile.traffic_key_hex,
            profile.string_key,
        ): profile
        for profile in candidates
    }
    return next(iter(unique.values())) if len(unique) == 1 else None


def extract_v2_memory_profile(data: bytes) -> V2MemoryProfile | None:
    """再構築済みPE bytesからStealC v2設定を静的復元する。"""
    values = _located_strings(data)
    if not values:
        return None
    return recover_v2_profile_from_strings(values)


__all__ = [
    "LocatedString",
    "V2MemoryProfile",
    "extract_v2_memory_profile",
    "rc4",
    "recover_v2_profile_from_strings",
]
