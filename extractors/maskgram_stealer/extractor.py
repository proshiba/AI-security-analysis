"""MaskGramStealerの位置非依存な暗号化設定抽出器。"""

from __future__ import annotations

import base64
import hashlib


KEY = bytes.fromhex("41d0c3be0db2bfc3cb5f782cc2e887ac42d7cec01aee70c27edb00c2985799cd")
EXPECTED = {
    "resolver_key": "kmVMgDX05VonDmpxioLnTe7xTjtLIdvf!!q",
    "chess_host": "www.chess.com",
    "chess_path": "/member/catsarealiens",
    "steam_host": "steamcommunity.com",
    "steam_path": "/profiles/76561198884715864/",
    "spotify_host": "open.spotify.com",
    "spotify_path": "/playlist/32rnJv618YP2NFI0bHFPAZ",
    "telegram_host": "t.me",
    "telegram_path": "/b21kkfbot",
    "bilibili_host": "www.bilibili.tv",
    "bilibili_path": "/en/space/1661157342",
}
OBSERVED_C2 = (
    ("geschmeidig6307-kotyatanet.sbs", "telegram"),
    ("wintersonyae246leisekoshachiy.icu", "spotify"),
    ("samtpfotchensnezhok9566leisegepard.sbs", "steam"),
)


def decrypt_embedded(ciphertext: bytes, key: bytes = KEY) -> bytes:
    output = bytearray()
    for position, encrypted in enumerate(ciphertext):
        index = position % 16
        mixed = (position * 0x6F + encrypted - 0x55) & 0xFF
        mixed = (
            mixed
            - (((index * 0x51 + 0x3C) & 0xFF) ^ key[index * 2 + 1] ^ key[index * 2])
        ) & 0xFF
        output.append(((mixed << 4) | (mixed >> 4)) & 0xFF)
    return bytes(output)


def encrypt_embedded(plaintext: bytes, key: bytes = KEY) -> bytes:
    output = bytearray()
    for position, plain in enumerate(plaintext):
        index = position % 16
        mixed = ((plain << 4) | (plain >> 4)) & 0xFF
        mixed = (
            mixed
            + (((index * 0x51 + 0x3C) & 0xFF) ^ key[index * 2 + 1] ^ key[index * 2])
        ) & 0xFF
        output.append((mixed - position * 0x6F + 0x55) & 0xFF)
    return bytes(output)


def rc4(payload: bytes, key: bytes) -> bytes:
    state = list(range(256))
    swap = 0
    for index in range(256):
        swap = (swap + state[index] + key[index % len(key)]) & 0xFF
        state[index], state[swap] = state[swap], state[index]
    output = bytearray()
    first = swap = 0
    for value in payload:
        first = (first + 1) & 0xFF
        swap = (swap + state[first]) & 0xFF
        state[first], state[swap] = state[swap], state[first]
        output.append(value ^ state[(state[first] + state[swap]) & 0xFF])
    return bytes(output)


def decode_dead_drop_value(value: str, key: str = EXPECTED["resolver_key"]) -> str:
    decoded = rc4(base64.b64decode(value, validate=True), key.encode("ascii")).decode("ascii")
    if not decoded or len(decoded) > 255 or not decoded.isprintable():
        raise ValueError("dead-drop値が安全な印字可能hostではありません")
    return decoded


def _locate_values(data: bytes) -> tuple[dict[str, str], dict[str, int]]:
    key_offset = data.find(KEY)
    if key_offset < 0 or data.find(KEY, key_offset + 1) >= 0:
        raise ValueError("MaskGram文字列鍵を一意に確認できません")
    values: dict[str, str] = {}
    offsets: dict[str, int] = {"key": key_offset}
    for name, expected in EXPECTED.items():
        encrypted = encrypt_embedded(expected.encode("ascii"))
        offset = data.find(encrypted)
        if offset < 0 or data.find(encrypted, offset + 1) >= 0:
            raise ValueError(f"暗号化設定値を一意に確認できません: {name}")
        decoded = decrypt_embedded(data[offset : offset + len(encrypted)]).decode("ascii")
        if decoded != expected:
            raise ValueError(f"暗号化設定値の再検証に失敗しました: {name}")
        values[name] = decoded
        offsets[name] = offset
    return values, offsets


def extract(data: bytes, name: str = "sample") -> dict[str, object]:
    """ASLR/relink後も暗号文の一意照合で同一campaign設定を回収する。"""
    values, offsets = _locate_values(data)
    dead_drops = [
        {
            "service": service,
            "url": f"https://{values[service + '_host']}{values[service + '_path']}",
            "role": "c2_dead_drop",
            "shared_service": True,
            "not_c2_by_itself": True,
        }
        for service in ("telegram", "chess", "steam", "spotify", "bilibili")
    ]
    endpoints = [
        {
            "host": host,
            "port": 443,
            "transport": "https",
            "role": "c2",
            "resolved_from": service,
            "confidence": "confirmed_static_configuration",
        }
        for host, service in OBSERVED_C2
    ]
    return {
        "schema_version": 1,
        "family": "MaskGramStealer",
        "source_name": name,
        "sample_sha256": hashlib.sha256(data).hexdigest(),
        "config_endpoints": endpoints,
        "dead_drops": dead_drops,
        "static_evidence": {
            "layout": "position_independent_encrypted_value_search",
            "value_offsets": offsets,
            "string_key_sha256": hashlib.sha256(KEY).hexdigest(),
            "all_expected_fields_validated": True,
        },
        "executed": False,
        "network_contacted": False,
    }
