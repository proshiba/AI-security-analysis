"""未実行のVidar設定と関連インフラ候補を静的に抽出する。"""

from __future__ import annotations

import hashlib
import itertools
import re

from extractors.common import build_result, extract_strings
from extractors.stealer_common import extract_stealer, feature_hits, infrastructure_urls, url_role
from unpackers.container_recovery import recover_inflated_pe

from extractors.vidar.semantic import classify_recovered_config

KEY_LENGTH = 16
MAX_CONFIG_SCAN = 64 * 1024 * 1024
MAX_CONFIG_VIEW_BYTES = 64 * 1024 * 1024
MAX_CONFIG_CANDIDATES = 64
VERSION_OFFSET = 0x010
VERSION_LENGTH_OFFSET = 0x030
BUILD_OFFSET = 0x031
BUILD_LENGTH_OFFSET = 0x071
RECORDS_OFFSET = 0x072
URL_LENGTH_OFFSET = 0x100
TAG_OFFSET = 0x101
TAG_LENGTH_OFFSET = 0x141
USER_AGENT_OFFSET = 0x142
USER_AGENT_LENGTH_OFFSET = 0x242
RECORD_STRIDE = 0x243
MAX_RECORDS = 32
VERSION_PATTERN = re.compile(rb"^[0-9]{1,3}(?:\.[0-9]{1,3}){1,3}$")


def _decrypt_field(data: bytes, base: int, value_offset: int, length_offset: int, key: bytes) -> bytes | None:
    """Vidar設定の有界fieldを反復XORで復号し、切断と明示的な空値を区別する。"""
    if base + length_offset >= len(data):
        return None
    length = data[base + length_offset]
    if not length:
        return b""
    if base + value_offset + length > len(data):
        return None
    encrypted = data[base + value_offset : base + value_offset + length]
    return bytes(left ^ right for left, right in zip(encrypted, itertools.cycle(key)))


def _printable(value: bytes) -> bool:
    """空でないfieldの全byteが表示可能なASCIIかを判定する。"""
    return bool(value) and all(0x20 <= byte <= 0x7E for byte in value)


def _try_config_assessment(data: bytes, offset: int) -> tuple[dict | None, bool]:
    """既存候補を復号し、通常のgrammar不一致と認識済みの不完全設定を分離する。"""
    if offset < 0 or offset + RECORDS_OFFSET + URL_LENGTH_OFFSET >= len(data):
        return None, False
    key = data[offset : offset + KEY_LENGTH]
    version = _decrypt_field(data, offset, VERSION_OFFSET, VERSION_LENGTH_OFFSET, key)
    if not version or not VERSION_PATTERN.fullmatch(version):
        return None, False
    first_url = _decrypt_field(data, offset + RECORDS_OFFSET, 0, URL_LENGTH_OFFSET, key)
    if not first_url or not first_url.startswith(b"http") or not _printable(first_url):
        return None, False
    build = _decrypt_field(data, offset, BUILD_OFFSET, BUILD_LENGTH_OFFSET, key)
    if build is None:
        return None, True
    if build and not _printable(build):
        return None, False
    records: list[dict] = []
    terminated = False
    for index in range(MAX_RECORDS):
        base = offset + RECORDS_OFFSET + index * RECORD_STRIDE
        url = _decrypt_field(data, base, 0, URL_LENGTH_OFFSET, key)
        if url is None:
            return None, True
        if not url:
            terminated = True
            break
        if not url.startswith(b"http") or not _printable(url):
            return None, bool(records)
        tag = _decrypt_field(data, base, TAG_OFFSET, TAG_LENGTH_OFFSET, key)
        agent = _decrypt_field(data, base, USER_AGENT_OFFSET, USER_AGENT_LENGTH_OFFSET, key)
        if tag is None or agent is None:
            return None, True
        if (tag and not _printable(tag)) or (agent and not _printable(agent)):
            return None, False
        records.append({"url": url.decode("ascii"), "tag": tag.decode("ascii"), "user_agent": agent.decode("ascii")})
    if not terminated:
        terminal_length_offset = offset + RECORDS_OFFSET + MAX_RECORDS * RECORD_STRIDE + URL_LENGTH_OFFSET
        if terminal_length_offset >= len(data) or data[terminal_length_offset] != 0:
            return None, True
    return {
        "version": version.decode("ascii"),
        "build_id": build.decode("ascii"),
        "records": records,
        "c2_urls": [item["url"] for item in records],
        "xor_key_sha256": hashlib.sha256(key).hexdigest(),
        "profile": "vidar_repeated_xor_v1_5_plus",
    }, False


def _try_config(data: bytes, offset: int) -> dict | None:
    """完全な既存設定だけを返し、private入口のdict／None契約を維持する。"""
    recovered, _incomplete = _try_config_assessment(data, offset)
    return recovered


def _bounded_config_source(data: bytes) -> tuple[bytes, str]:
    """元入力の走査viewを選び、compact結果にも独立したbyte上限を課す。"""
    if len(data) <= MAX_CONFIG_SCAN and len(data) <= MAX_CONFIG_VIEW_BYTES:
        return data, "complete_input"
    if data.startswith(b"MZ"):
        _, compact = recover_inflated_pe(data)
        if type(compact) is bytes and len(compact) <= MAX_CONFIG_VIEW_BYTES:
            return compact, "inflated_pe_compacted"
    return data[:min(MAX_CONFIG_SCAN, MAX_CONFIG_VIEW_BYTES)], "bounded_prefix"


def _config_profile_identity(recovered: dict) -> tuple:
    """offsetを除き、既存profileの全設定fieldと鍵の証拠を比較する。"""
    return (
        recovered["profile"],
        recovered["version"],
        recovered["build_id"],
        tuple(
            (record["url"], record["tag"], record["user_agent"])
            for record in recovered["records"]
        ),
        tuple(recovered["c2_urls"]),
        recovered["xor_key_sha256"],
    )


def _assess_xor_config(data: bytes, source: bytes, scan_source: str) -> tuple[dict, dict]:
    """既存grammarの候補を有界に比較し、全viewで一意の場合だけ選ぶ。"""
    assessment = {
        "schema_version": 1,
        "status": "not_recovered",
        "reason": "no_valid_profile",
        "scan_source": scan_source,
        "scan_complete": False,
        "identity_unique": None,
        "candidate_attempts": 0,
        "valid_candidate_count": 0,
        "distinct_profile_count": 0,
    }
    if scan_source not in {"complete_input", "inflated_pe_compacted"}:
        assessment["reason"] = "input_view_incomplete"
        return {}, assessment
    minimum = RECORDS_OFFSET + URL_LENGTH_OFFSET + 1
    if len(source) < minimum:
        assessment["reason"] = "input_too_short"
        assessment["scan_complete"] = True
        return {}, assessment
    selected = None
    selected_identity = None
    for match in re.finditer(rb"[\x03-\x0f]", source[VERSION_LENGTH_OFFSET:]):
        offset = match.start()
        if offset + minimum > len(source):
            break
        key = source[offset : offset + KEY_LENGTH]
        if len(key) != KEY_LENGTH:
            continue
        if any(
            source[offset + RECORDS_OFFSET + index] ^ key[index] != expected
            for index, expected in enumerate(b"http")
        ):
            continue
        if assessment["candidate_attempts"] >= MAX_CONFIG_CANDIDATES:
            assessment["reason"] = "candidate_limit_exceeded"
            return {}, assessment
        assessment["candidate_attempts"] += 1
        recovered, incomplete = _try_config_assessment(source, offset)
        if incomplete:
            assessment["reason"] = "incomplete_record_profile"
            return {}, assessment
        if not recovered:
            continue
        assessment["valid_candidate_count"] += 1
        identity = _config_profile_identity(recovered)
        if selected is None:
            selected = recovered
            selected_identity = identity
            assessment["distinct_profile_count"] = 1
        elif identity != selected_identity:
            assessment["distinct_profile_count"] = 2
            assessment["identity_unique"] = False
            continue
        else:
            continue
        selected["config_offset"] = offset
        selected["scan_source"] = scan_source
        selected["original_size"] = len(data)
    assessment["scan_complete"] = True
    if selected is None:
        return {}, assessment
    if assessment["identity_unique"] is False:
        assessment["reason"] = "conflicting_profiles"
        return {}, assessment
    assessment["identity_unique"] = True
    assessment["status"] = "recovered"
    assessment["reason"] = "unique_profile"
    return selected, assessment


def recover_xor_config(data: bytes) -> dict:
    """未実行の既存XOR profileを回収し、拒否時は既存の空dict契約を守る。"""
    source, scan_source = _bounded_config_source(data)
    recovered, _assessment = _assess_xor_config(data, source, scan_source)
    return recovered


def extract(data: bytes, name: str = "sample") -> dict:
    """一意な既存XOR profileを回収し、拒否時は保守的literal候補を残す。"""
    string_source, scan_source = _bounded_config_source(data)
    recovered, assessment = _assess_xor_config(data, string_source, scan_source)
    features = {
        "browser_collection": ("Login Data", "Web Data", "History", "Cookies"),
        "wallet_collection": ("wallet.dat", "Electrum", "Exodus", "Atomic"),
        "telegram_dead_drop": ("t.me/", "telegram.me/", "api.telegram.org"),
        "dependency_download": ("sqlite3.dll", "freebl3.dll", "nss3.dll"),
    }
    if not recovered:
        result = extract_stealer(
            "vidar",
            data,
            name,
            ("Vidar", "information.txt", "passwords.txt", "Autofill", "wallets"),
            features,
            [
                "Vidarは直接埋め込まれたC2ではなく、dead-drop profileからインフラ情報を取得する場合があります。",
                "packed検体やloader層では、最終設定を確認する前に後続層の静的復元が必要です。",
            ],
            analysis_data=string_source,
        )
        result["config"]["scan_source"] = scan_source
        result["config"]["original_size"] = len(data)
        result["config"]["xor_config_assessment"] = assessment
        return result
    strings = extract_strings(string_source)
    config_record_urls = [
        value for value in recovered["c2_urls"] if isinstance(value, str)
    ]
    semantics = classify_recovered_config(recovered)
    semantics_by_url = {item["url"]: item for item in semantics["endpoints"]}
    urls = sorted(set(config_record_urls) | set(infrastructure_urls(strings)))
    findings = []
    for value in urls:
        endpoint = semantics_by_url.get(value)
        findings.append(
            {
                "kind": "network.url",
                "value": value,
                "role": endpoint["role"] if endpoint else url_role(value),
                "confidence": endpoint["confidence"] if endpoint else "candidate",
                "source": "vidar_xor_config" if endpoint else "embedded_literal",
                **({"semantic_reason": endpoint["reason"]} if endpoint else {}),
            }
        )
    decoded_features = feature_hits(strings, features)
    if any(item["role"] == "dead_drop.telegram" for item in semantics["endpoints"]):
        decoded_features["telegram_dead_drop"] = True
    config = {
        "source_name": name,
        **recovered,
        "config_record_urls": config_record_urls,
        "c2_urls": list(semantics["final_c2_candidates"]),
        "dead_drop_urls": list(semantics["dead_drop_urls"]),
        "endpoint_semantics": semantics["endpoints"],
        "final_c2_recovered": semantics["final_c2_recovered"],
        "requires_dead_drop_resolution": semantics["requires_dead_drop_resolution"],
        "static_config_recovered": True,
        "xor_config_assessment": assessment,
        "features": decoded_features,
    }
    return build_result(
        "vidar",
        data,
        config,
        findings,
        [
            "XOR設定は既存version／HTTP record grammarを検証し、有界viewの全候補で一意なprofileを選びました。",
            "dead-drop URLは最終C2と分離し、間接的なinfrastructure解決候補として記録しました。",
            "回収したendpointやsocial profileへの接続は行っていません。",
        ],
    )
