"""QuasarRATと派生版の.NET設定を非実行で復元する。"""

from __future__ import annotations

import base64
import hashlib
import hmac
from typing import Any

from Cryptodome.Cipher import AES

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

MAXIMUM_SALT_CANDIDATES = 32
MAXIMUM_ITERATION_CANDIDATES = 16
MAXIMUM_METHOD_INTEGER_CONSTANTS = 256
MAXIMUM_PBKDF2_ATTEMPTS = 256


class _StaticRecoveryLimitError(ValueError):
    """細工されたmanaged metadataが静的復元の計算量上限を超えた。"""


QUASAR_V13_PROTOCOL = {
    "version": "1.3",
    "transport": "raw TCP",
    "framing": "LE32 length prefix",
    "authentication": "HMAC-SHA256",
    "encryption": "AES-128-CBC",
    "key_derivation": "PBKDF2-HMAC-SHA1 (50,000 iterations)",
    "compression": "QuickLZ",
    "serialization": "NetSerializer",
    "tls": False,
}


def _apply_versioned_protocol(config: dict[str, Any]) -> None:
    """認証済み静的復号とversionが一致する場合だけ通信方式を付与する。"""

    version = str(config.get("version") or "").strip().lstrip("vV")
    crypto = config.get("crypto")
    verified = (
        config.get("static_config_recovered") is True
        and isinstance(crypto, dict)
        and crypto.get("hmac_verified_for_all_fields") is True
    )
    iterations = crypto.get("iterations") if isinstance(crypto, dict) else None
    if (
        verified
        and (version == "1.3" or version.startswith("1.3."))
        and type(iterations) is int
        and 1_000 <= iterations <= 10_000_000
    ):
        protocol = dict(QUASAR_V13_PROTOCOL)
        protocol["key_derivation"] = f"PBKDF2-HMAC-SHA1 ({iterations:,} iterations)"
        protocol["key_derivation_iterations"] = iterations
        protocol["binding"] = "authenticated_static_config"
        config["transport"] = protocol["transport"]
        config["protocol"] = protocol
        return
    # generic profile文字列やversion候補だけからtransportを確定しない。
    config.pop("transport", None)
    config.pop("protocol", None)


def decrypt_authenticated_pbkdf2_aes(
    encoded: str,
    password: str,
    salt: bytes,
    iterations: int,
) -> str | None:
    """HMAC検証に成功した場合だけQuasar派生暗号を復号する。"""

    if not 1 <= len(salt) <= 1024 or not 1_000 <= iterations <= 10_000_000:
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
            if (
                _opcode(first) != "ldsfld"
                or _opcode(second) != "call"
                or _opcode(third) != "stsfld"
            ):
                continue
            field = token_value(first.operand)
            if field and field == token_value(third.operand):
                decrypt_call = token_value(second.operand)
                fields = groups.get(decrypt_call)
                if fields is None:
                    groups[decrypt_call] = [field]
                else:
                    fields.append(field)
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
            if (
                _opcode(instructions[position]) == "ldsfld"
                and _opcode(instructions[position + 1]) == "call"
            ):
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
                if len(values) >= MAXIMUM_METHOD_INTEGER_CONSTANTS:
                    raise _StaticRecoveryLimitError(
                        "Quasar setup methodの整数定数数が解析上限を超えました"
                    )
                values.append(int(instruction.operand))
        return values
    return []


def _salt_candidates(
    assembly: Any, lengths: tuple[int, ...] = (16, 24, 32, 48, 64)
) -> list[bytes]:
    candidates: list[bytes] = []
    seen: set[bytes] = set()
    table = getattr(assembly.pe.net.mdtables, "FieldRva", None)
    for row in getattr(table, "rows", ()) if table is not None else ():
        try:
            offset = int(assembly.pe.get_offset_from_rva(int(row.Rva)))
        except Exception:  # noqa: BLE001 - third-party PE parsers expose varying errors
            offset = None
        if offset is None:
            continue
        for length in lengths:
            end = offset + length
            if 0 <= offset < end <= len(assembly.data):
                value = assembly.data[offset:end]
                if value in seen:
                    continue
                if len(candidates) >= MAXIMUM_SALT_CANDIDATES:
                    raise _StaticRecoveryLimitError(
                        "Quasar salt候補数が解析上限を超えました"
                    )
                seen.add(value)
                candidates.append(value)
    return candidates


def _iteration_candidates(values: list[int]) -> list[int]:
    candidates: set[int] = set()
    for value in values:
        if not 1_000 <= value <= 10_000_000 or value in candidates:
            continue
        if len(candidates) >= MAXIMUM_ITERATION_CANDIDATES:
            raise _StaticRecoveryLimitError(
                "Quasar PBKDF2 iteration候補数が解析上限を超えました"
            )
        candidates.add(value)
    return sorted(candidates, reverse=True) or [50_000]


def _try_decrypt_candidates(
    encrypted: list[str],
    password: str,
    salts: list[bytes],
    iterations_values: list[int],
) -> tuple[bytes, int, list[str]] | None:
    attempts = 0
    for salt in salts:
        for iterations in iterations_values:
            clear: list[str | None] = []
            for value in encrypted:
                if attempts >= MAXIMUM_PBKDF2_ATTEMPTS:
                    raise _StaticRecoveryLimitError(
                        "Quasar PBKDF2総試行数が解析上限を超えました"
                    )
                attempts += 1
                clear.append(
                    decrypt_authenticated_pbkdf2_aes(
                        value,
                        password,
                        salt,
                        iterations,
                    )
                )
            if all(value is not None for value in clear):
                return salt, iterations, [str(value) for value in clear]
    return None


def _public_source_name(source_name: str) -> str:
    """local directoryを除いた公開可能なbasenameだけを返す。"""

    if not isinstance(source_name, str):
        raise TypeError("source_nameは文字列で指定してください")
    name = source_name.replace("\\", "/").rsplit("/", 1)[-1]
    if (
        not name
        or len(name.encode("utf-8")) > 255
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in name)
    ):
        return "sample.bin"
    return name


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

    iteration_candidates = _iteration_candidates(
        _method_constants(assembly, setup_call)
    )
    chosen = _try_decrypt_candidates(
        encrypted,
        password,
        _salt_candidates(assembly),
        iteration_candidates,
    )
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

    public_source_name = _public_source_name(source_name)
    try:
        config = _recover_config(data)
    except (ManagedMetadataError, AttributeError, TypeError, ValueError):
        config = None
    if config is None:
        fallback = extract_family("quasarrat", data, public_source_name)
        _apply_versioned_protocol(fallback["config"])
        fallback["limitations"].append(
            "Quasar設定の静的初期化・認証付き復号を確認できなかったため、profile文字列候補だけを返しました。"
        )
        fallback["limitations"].append(
            "通信方式はversion別に確認する必要があります。v1.3はraw TCP、LE32 framing、HMAC-SHA256、"
            "AES-128-CBC、PBKDF2-HMAC-SHA1 50,000回、QuickLZ、NetSerializerを使用し、"
            "v1.4以降のTLS/protobufとは分離します。version未確認のprofile結果へtransportを付与しません。"
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
    config["source_name"] = public_source_name
    config["profile"] = "quasarrat"
    config["network_candidates"] = endpoints
    _apply_versioned_protocol(config)
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
