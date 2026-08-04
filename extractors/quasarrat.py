"""QuasarRATと派生版の.NET設定を非実行で復元する。"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - 実行環境の依存関係として報告する
    AES = None

from extractors.common import build_result, endpoint_candidates
from extractors.profiled_family import extract_family
from unpackers.dotnet_static_field_extractor import (
    ManagedMetadataError,
    extract_static_assignments,
    iter_methods,
    load_managed_assembly,
    token_value,
)


SEMANTIC_DECRYPT_ORDER = (
    "tag",
    "version",
    "hosts",
    "subfolder",
    "install_name",
    "mutex",
    "startup_key",
    "log_directory",
)


def decrypt_authenticated_pbkdf2_aes(
    encoded: str,
    password: str,
    salt: bytes,
    iterations: int,
) -> str | None:
    """HMAC検証に成功した場合だけQuasar派生暗号を復号する。"""

    if AES is None or not 1 <= len(salt) <= 1024 or not 1_000 <= iterations <= 10_000_000:
        return None
    try:
        blob = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        return None
    if len(blob) < 64 or (len(blob) - 48) % 16:
        return None
    material = hashlib.pbkdf2_hmac(
        "sha1", password.encode("utf-8"), salt, iterations, dklen=80
    )
    expected = hmac.new(material[16:], blob[32:], hashlib.sha256).digest()
    if not hmac.compare_digest(expected, blob[:32]):
        return None
    try:
        clear = AES.new(material[:16], AES.MODE_CBC, blob[32:48]).decrypt(blob[48:])
    except ValueError:
        return None
    padding = clear[-1] if clear else 0
    if not 1 <= padding <= 16 or clear[-padding:] != bytes([padding]) * padding:
        return None
    try:
        return clear[:-padding].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _opcode(instruction: Any) -> str:
    return str(getattr(getattr(instruction, "opcode", None), "name", "")).lower()


def _initializer_shape(assembly: Any) -> tuple[list[int], int | None, int | None]:
    """同一fieldを復号して書き戻す反復と、その直前の鍵設定callを抽出する。"""

    best: tuple[list[int], int | None, int | None] = ([], None, None)
    for _index, _owner, row, instructions in iter_methods(assembly):
        if str(row.Name) == ".cctor":
            continue
        groups: dict[int, list[int]] = {}
        for position in range(len(instructions) - 2):
            first, second, third = instructions[position : position + 3]
            if _opcode(first) != "ldsfld" or _opcode(second) != "call" or _opcode(third) != "stsfld":
                continue
            field = token_value(first.operand)
            if field and field == token_value(third.operand):
                groups.setdefault(token_value(second.operand), []).append(field)
        if not groups:
            continue
        decrypt_call, fields = max(groups.items(), key=lambda item: len(item[1]))
        if len(fields) < 5 or len(fields) <= len(best[0]):
            continue
        first_position = next(
            position
            for position in range(len(instructions) - 2)
            if token_value(instructions[position].operand) == fields[0]
            and _opcode(instructions[position]) == "ldsfld"
        )
        key_field = None
        setup_call = None
        for position in range(max(0, first_position - 8), first_position - 1):
            if _opcode(instructions[position]) == "ldsfld" and _opcode(instructions[position + 1]) == "call":
                key_field = token_value(instructions[position].operand)
                setup_call = token_value(instructions[position + 1].operand)
        best = (fields, key_field, setup_call)
    return best


def _method_constants(assembly: Any, method_token: int | None) -> list[int]:
    if not method_token or method_token >> 24 != 0x06:
        return []
    rid = method_token & 0xFFFFFF
    rows = assembly.pe.net.mdtables.MethodDef.rows
    if not 0 < rid <= len(rows):
        return []
    for index, _owner, _row, instructions in iter_methods(assembly):
        if index != rid:
            continue
        values: list[int] = []
        for instruction in instructions:
            name = _opcode(instruction)
            if name in {"ldc.i4", "ldc.i4.s"}:
                values.append(int(instruction.operand))
        return values
    return []


def _salt_candidates(assembly: Any, lengths: tuple[int, ...] = (16, 24, 32, 48, 64)) -> list[bytes]:
    candidates: list[bytes] = []
    table = getattr(assembly.pe.net.mdtables, "FieldRva", None)
    for row in getattr(table, "rows", ()) if table is not None else ():
        try:
            offset = int(assembly.pe.get_offset_from_rva(int(row.Rva)))
        except Exception:
            continue
        for length in lengths:
            end = offset + length
            if 0 <= offset < end <= len(assembly.data):
                value = assembly.data[offset:end]
                if value not in candidates:
                    candidates.append(value)
    return candidates


def _assignment_map(assignments: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    result: dict[int, dict[str, Any]] = {}
    for item in assignments:
        try:
            token = int(item["field_token"], 16)
        except (KeyError, TypeError, ValueError):
            continue
        result[token] = item
    return result


def _recover_config(data: bytes) -> dict[str, Any] | None:
    assembly = load_managed_assembly(data)
    fields, key_field, setup_call = _initializer_shape(assembly)
    if len(fields) < len(SEMANTIC_DECRYPT_ORDER) or key_field is None:
        return None
    static = extract_static_assignments(data)
    assignments = _assignment_map(static["assignments"])
    key_item = assignments.get(key_field)
    if not key_item or key_item.get("value_type") != "string":
        return None
    password = str(key_item["value"])
    encrypted: list[str] = []
    for field in fields[: len(SEMANTIC_DECRYPT_ORDER)]:
        item = assignments.get(field)
        if not item or item.get("value_type") != "string":
            return None
        encrypted.append(str(item["value"]))

    iteration_candidates = sorted(
        {value for value in _method_constants(assembly, setup_call) if 1_000 <= value <= 10_000_000},
        reverse=True,
    ) or [50_000]
    chosen: tuple[bytes, int, list[str]] | None = None
    for salt in _salt_candidates(assembly):
        for iterations in iteration_candidates:
            clear = [
                decrypt_authenticated_pbkdf2_aes(value, password, salt, iterations)
                for value in encrypted
            ]
            if all(value is not None for value in clear):
                chosen = (salt, iterations, [str(value) for value in clear])
                break
        if chosen:
            break
    if chosen is None:
        return None

    salt, iterations, clear = chosen
    config = dict(zip(SEMANTIC_DECRYPT_ORDER, clear, strict=True))
    # SettingsのcctorではVERSION、HOSTSに続く整数が再接続間隔である。
    cctor_items = sorted(
        (
            item
            for item in static["assignments"]
            if item.get("owner") == assignments[fields[1]].get("owner")
        ),
        key=lambda item: int(item.get("order", 0)),
    )
    reconnect = next(
        (
            int(item["value"])
            for item in cctor_items
            if item.get("value_type") == "int32" and int(item["value"]) >= 100
        ),
        None,
    )
    config.update(
        {
            "reconnect_delay_ms": reconnect,
            "crypto": {
                "scheme": "PBKDF2-HMAC-SHA1/AES-128-CBC/HMAC-SHA256",
                "iterations": iterations,
                "salt_sha256": hashlib.sha256(salt).hexdigest(),
                "hmac_verified_for_all_fields": True,
                "encryption_key_recovered": True,
            },
            "static_config_recovered": True,
            "decoded_config_recovered": True,
            "metadata_recovery": static["recovery"],
        }
    )
    return config


def extract(data: bytes, source_name: str = "sample.bin") -> dict:
    """QuasarRAT設定を復号し、失敗時は保守的なprofile抽出へ戻す。"""

    try:
        config = _recover_config(data)
    except (ManagedMetadataError, AttributeError, TypeError, ValueError):
        config = None
    if config is None:
        fallback = extract_family("quasarrat", data, source_name)
        fallback["limitations"].append(
            "Quasar設定の静的初期化・認証付き復号を確認できなかったため、profile文字列候補だけを返しました。"
        )
        return fallback

    hosts = str(config.get("hosts") or "")
    endpoints = endpoint_candidates([hosts])
    findings = [
        {
            "kind": "network.endpoint",
            "value": value,
            "role": "c2_endpoint",
            "confidence": "confirmed_static_decryption",
            "source": "authenticated_quasarrat_config",
        }
        for value in endpoints
    ]
    config["source_name"] = source_name
    config["profile"] = "quasarrat"
    config["network_candidates"] = endpoints
    return build_result(
        "quasarrat",
        data,
        config,
        findings,
        [
            "検体は実行せず、CLRメタデータ、cctor IL、PBKDF2、HMAC、AES処理を静的に再現しました。",
            "HMAC検証に成功した値だけを復号済み設定として公開します。",
            "C2の稼働状態はこの抽出器では確認しません。",
        ],
    )
