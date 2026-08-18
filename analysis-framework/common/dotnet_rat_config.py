#!/usr/bin/env python3
"""AsyncRAT／VenomRAT／DCRatのSettings静的初期化から公開可能な設定を復元する。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


MAX_INPUT_BYTES = 32 * 1024 * 1024
PROFILES = {
    "asyncrat": {
        "settings_type": "Client.Settings",
        "salt": bytes.fromhex("bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941"),
        "fields": {
            "ports": "Ports",
            "hosts": "Hosts",
            "version": "Version",
            "install": "Install",
            "pastebin": "Pastebin",
            "anti": "Anti",
            "group": "Group",
            "certificate": "Certificate",
        },
    },
    "venomrat": {
        "settings_type": "Client.Settings",
        "salt": b"VenomRATByVenom",
        "fields": {
            "ports": "Por_ts",
            "hosts": "Hos_ts",
            "version": "Ver_sion",
            "install": "In_stall",
            "pastebin": "Paste_bin",
            "anti": "An_ti",
            "group": "Group",
            "certificate": "Certifi_cate",
        },
    },
    "dcrat": {
        "settings_type": "Client.Settings",
        "salt": None,
        "salt_initializer_type": "Client.Algorithm.Aes256",
        "fields": {
            "ports": "Por_ts",
            "hosts": "Hos_ts",
            "version": "Ver_sion",
            "install": "In_stall",
            "pastebin": "Paste_bin",
            "anti": "An_ti",
            "group": "Group",
            "certificate": "Certifi_cate",
        },
    },
}


class ConfigRecoveryError(ValueError):
    """設定metadata、暗号形式、または認証tagが期待形状と一致しない。"""


def _field_owners(pe: dnfile.dnPE) -> dict[int, str]:
    owners: dict[int, str] = {}
    for row in pe.net.mdtables.TypeDef.rows:
        owner = ".".join(
            value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
        )
        for field in row.FieldList:
            owners[field.row_index] = owner
    return owners


def _method_owner(pe: dnfile.dnPE, method_index: int) -> str | None:
    for row in pe.net.mdtables.TypeDef.rows:
        if any(value.row_index == method_index for value in row.MethodList):
            return ".".join(
                value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
            )
    return None


def settings_literals(data: bytes, settings_type: str = "Client.Settings") -> dict[str, str]:
    """Settings型cctorの直接`ldstr`→`stsfld`だけをfield literalとして回収する。"""

    pe = dnfile.dnPE(data=data)
    if pe.net is None or pe.net.mdtables is None:
        raise ConfigRecoveryError("CLR metadataがありません")
    owners = _field_owners(pe)
    values: dict[str, str] = {}
    for index, row in enumerate(pe.net.mdtables.MethodDef.rows, 1):
        if str(row.Name) != ".cctor" or _method_owner(pe, index) != settings_type:
            continue
        body = read_method_body_from_bytes(data[pe.get_offset_from_rva(row.Rva) :])
        pending: str | None = None
        for instruction in body.instructions:
            operand = getattr(instruction.operand, "value", instruction.operand)
            if instruction.opcode.name == "ldstr" and isinstance(operand, int):
                pending = str(pe.net.user_strings.get(operand & 0xFFFFFF).value)
                continue
            if instruction.opcode.name == "stsfld" and isinstance(operand, int) and pending is not None:
                if (operand >> 24) & 0xFF != 0x04:
                    pending = None
                    continue
                row_index = operand & 0xFFFFFF
                if owners.get(row_index) == settings_type:
                    field = pe.net.mdtables.Field.rows[row_index - 1]
                    values[str(field.Name)] = pending
                pending = None
                continue
            if instruction.opcode.name not in {"nop"}:
                pending = None
    if not values:
        raise ConfigRecoveryError("Settings cctorのfield literalを復元できません")
    return values


def _member_name(pe: dnfile.dnPE, token: int, owners: dict[int, str]) -> str:
    """MethodDef／MemberRef tokenを比較用の限定名へ解決する。"""

    table_id = (token >> 24) & 0xFF
    row_id = token & 0xFFFFFF
    if table_id == 0x06:
        table = pe.net.mdtables.MethodDef
        if table is not None and 1 <= row_id <= len(table.rows):
            return f"{owners.get(row_id, '')}.{table.rows[row_id - 1].Name}".strip(".")
    if table_id == 0x0A:
        table = pe.net.mdtables.MemberRef
        if table is not None and 1 <= row_id <= len(table.rows):
            return str(table.rows[row_id - 1].Name)
    return ""


def static_salt(data: bytes, initializer_type: str) -> bytes:
    """暗号classのcctorにあるASCII salt代入だけをfail-closedで復元する。"""

    pe = dnfile.dnPE(data=data)
    if pe.net is None or pe.net.mdtables is None:
        raise ConfigRecoveryError("CLR metadataがありません")
    method_owners = {
        method.row_index: ".".join(
            value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
        )
        for row in pe.net.mdtables.TypeDef.rows
        for method in row.MethodList
    }
    field_owners = _field_owners(pe)
    candidates: list[bytes] = []
    initializer_count = 0
    for index, row in enumerate(pe.net.mdtables.MethodDef.rows, 1):
        if str(row.Name) != ".cctor" or method_owners.get(index) != initializer_type:
            continue
        initializer_count += 1
        body = read_method_body_from_bytes(data[pe.get_offset_from_rva(row.Rva) :])
        literal: str | None = None
        ascii_encoding = False
        encoded_literal: str | None = None
        for instruction in body.instructions:
            opcode = instruction.opcode.name
            operand = getattr(instruction.operand, "value", instruction.operand)
            if opcode == "ldstr" and isinstance(operand, int):
                literal = str(pe.net.user_strings.get(operand & 0xFFFFFF).value)
                encoded_literal = None
                continue
            if opcode in {"call", "callvirt"} and isinstance(operand, int):
                name = _member_name(pe, operand, method_owners).rsplit(".", 1)[-1]
                if name == "get_ASCII":
                    ascii_encoding = True
                    continue
                if name == "GetBytes" and literal is not None and ascii_encoding:
                    encoded_literal = literal
                    continue
                literal = None
                ascii_encoding = False
                encoded_literal = None
                continue
            if opcode == "stsfld" and isinstance(operand, int):
                table_id = (operand >> 24) & 0xFF
                row_id = operand & 0xFFFFFF
                if (
                    table_id == 0x04
                    and 1 <= row_id <= len(pe.net.mdtables.Field.rows)
                    and field_owners.get(row_id) == initializer_type
                    and str(pe.net.mdtables.Field.rows[row_id - 1].Name) == "Salt"
                    and encoded_literal is not None
                ):
                    try:
                        candidate = encoded_literal.encode("ascii")
                    except UnicodeEncodeError as exc:
                        raise ConfigRecoveryError("salt literalがASCIIではありません") from exc
                    if not 8 <= len(candidate) <= 128:
                        raise ConfigRecoveryError("salt literalの長さが範囲外です")
                    candidates.append(candidate)
                literal = None
                ascii_encoding = False
                encoded_literal = None
                continue
            if opcode != "nop":
                literal = None
                ascii_encoding = False
                encoded_literal = None
    if initializer_count != 1 or len(candidates) != 1:
        raise ConfigRecoveryError("暗号classのsalt初期化を一意に復元できません")
    return candidates[0]


def _derive(master_key: str, salt: bytes) -> tuple[bytes, bytes]:
    material = hashlib.pbkdf2_hmac("sha1", master_key.encode("utf-8"), salt, 50_000, 96)
    return material[:32], material[32:]


def decrypt_setting(ciphertext: str, master_key: str, salt: bytes) -> str:
    """AsyncRAT系のHMAC-SHA256＋AES-256-CBC設定を認証後に復号する。"""

    try:
        raw = base64.b64decode(ciphertext, validate=True)
    except ValueError as exc:
        raise ConfigRecoveryError("設定値が正しいBase64ではありません") from exc
    if len(raw) < 64 or len(raw[48:]) % 16:
        raise ConfigRecoveryError("暗号化設定値の長さが不正です")
    encryption_key, authentication_key = _derive(master_key, salt)
    observed_mac, iv, encrypted = raw[:32], raw[32:48], raw[48:]
    expected_mac = hmac.new(authentication_key, raw[32:], hashlib.sha256).digest()
    if not hmac.compare_digest(observed_mac, expected_mac):
        raise ConfigRecoveryError("設定値のHMACが一致しません")
    decryptor = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    try:
        plain = unpadder.update(padded) + unpadder.finalize()
        return plain.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ConfigRecoveryError("設定値のpaddingまたはUTF-8が不正です") from exc


def _split_values(value: str) -> list[str]:
    return sorted({item.strip() for item in value.split(",") if item.strip() and item.strip() != "null"})


def recover(data: bytes, family: str) -> dict[str, Any]:
    """指定familyのreview済みfield mappingで公開可能な設定だけを返す。"""

    profile = PROFILES[family]
    literals = settings_literals(data, str(profile["settings_type"]))
    encoded_key = literals.get("Key")
    if not encoded_key:
        raise ConfigRecoveryError("Settings.Keyがありません")
    try:
        master_key = base64.b64decode(encoded_key, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ConfigRecoveryError("Settings.Keyを復元できません") from exc
    configured_salt = profile.get("salt")
    if isinstance(configured_salt, bytes):
        salt = configured_salt
        salt_source = "reviewed_family_profile"
    else:
        initializer_type = profile.get("salt_initializer_type")
        if not isinstance(initializer_type, str):
            raise ConfigRecoveryError("salt復元profileが不正です")
        salt = static_salt(data, initializer_type)
        salt_source = "reviewed_static_initializer"
    decrypted: dict[str, str] = {}
    for public_name, field_name in profile["fields"].items():
        value = literals.get(field_name)
        if value is None:
            continue
        decrypted[public_name] = decrypt_setting(value, master_key, salt)
    hosts = _split_values(decrypted.get("hosts", ""))
    ports = [int(value) for value in _split_values(decrypted.get("ports", "")) if value.isdigit() and 1 <= int(value) <= 65535]
    endpoints = [
        {"host": host.casefold().rstrip("."), "port": port}
        for host in hosts
        for port in ports
    ]
    certificate_sha256 = None
    certificate_size = None
    if decrypted.get("certificate"):
        try:
            certificate = base64.b64decode(decrypted["certificate"], validate=True)
        except ValueError as exc:
            raise ConfigRecoveryError("復号証明書が正しいBase64ではありません") from exc
        certificate_sha256 = hashlib.sha256(certificate).hexdigest()
        certificate_size = len(certificate)
    dynamic_url = decrypted.get("pastebin")
    if not dynamic_url or dynamic_url == "null":
        dynamic_url = None
    return {
        "schema_version": 1,
        "family": family,
        "sha256": hashlib.sha256(data).hexdigest(),
        "terminal_managed_client": True,
        "static_config_recovered": True,
        "version": decrypted.get("version", "").strip() or None,
        "install": decrypted.get("install", "").strip() or None,
        "group": decrypted.get("group", "").strip() or None,
        "anti_analysis": decrypted.get("anti", "").strip() or None,
        "config_endpoints": endpoints,
        "dynamic_config_url": dynamic_url,
        "certificate": {
            "sha256": certificate_sha256,
            "size": certificate_size,
            "certificate_mismatch_excludes_c2": False,
        },
        "secret_fields_published": False,
        "crypto_profile": {
            "key_derivation": "PBKDF2-HMAC-SHA1",
            "iterations": 50_000,
            "authentication": "HMAC-SHA256",
            "cipher": "AES-256-CBC-PKCS7",
            "salt_source": salt_source,
            "salt_published": False,
        },
        "executed": False,
        "network_contacted": False,
        "limitations": [
            "dynamic_config_urlの内容は別の時点付き取得で確認する必要があります。",
            "証明書不一致だけでは非C2と判定しません。",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--family", required=True, choices=sorted(PROFILES))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.input.stat().st_size > MAX_INPUT_BYTES:
        parser.error("入力が32 MiB上限を超えています")
    try:
        result = recover(args.input.read_bytes(), args.family)
    except (OSError, ConfigRecoveryError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"sha256": result["sha256"], "family": result["family"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())