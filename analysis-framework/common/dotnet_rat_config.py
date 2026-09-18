#!/usr/bin/env python3
"""AsyncRAT／VenomRAT／DCRatのSettings静的初期化から公開可能な設定を復元する。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import ipaddress
import json
import re
import struct
from pathlib import Path
from typing import Any

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7


MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_METHOD_BODY_BYTES = 1024 * 1024
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


def _bounded_method_body_data(data: bytes, pe: dnfile.dnPE, rva: int) -> bytes:
    """宣言されたCIL code範囲を検証し、有界なmethod bodyだけを返す。"""

    if not isinstance(rva, int) or isinstance(rva, bool) or rva <= 0:
        raise ConfigRecoveryError("CIL method RVAが不正です")
    try:
        offset = pe.get_offset_from_rva(rva)
    except Exception as exc:
        raise ConfigRecoveryError("CIL method RVAをfile offsetへ変換できません") from exc
    if (
        not isinstance(offset, int)
        or isinstance(offset, bool)
        or not 0 <= offset < len(data)
    ):
        raise ConfigRecoveryError("CIL method offsetが入力範囲外です")

    first = data[offset]
    header_kind = first & 0x03
    if header_kind == 0x02:  # ECMA-335 tiny format
        header_size = 1
        code_size = first >> 2
        more_sections = False
    elif header_kind == 0x03:  # ECMA-335 fat format
        if offset + 12 > len(data):
            raise ConfigRecoveryError("fat CIL method headerが入力範囲外です")
        flags_and_size = struct.unpack_from("<H", data, offset)[0]
        header_size = ((flags_and_size >> 12) & 0x0F) * 4
        if not 12 <= header_size <= 60 or offset + header_size > len(data):
            raise ConfigRecoveryError("fat CIL method header sizeが不正です")
        code_size = struct.unpack_from("<I", data, offset + 4)[0]
        more_sections = bool(flags_and_size & 0x08)
    else:
        raise ConfigRecoveryError("CIL method header形式が不正です")

    if code_size > MAX_METHOD_BODY_BYTES:
        raise ConfigRecoveryError("CIL method code sizeが上限を超えています")
    code_end = offset + header_size + code_size
    if code_end > len(data):
        raise ConfigRecoveryError("CIL method codeが入力範囲外です")
    if not more_sections:
        return data[offset:code_end]

    # 例外処理sectionはdncilに解析させるが、入力末尾全体は渡さない。
    bounded_end = min(len(data), offset + MAX_METHOD_BODY_BYTES)
    if bounded_end < code_end:
        raise ConfigRecoveryError("CIL method bodyが解析上限を超えています")
    return data[offset:bounded_end]


def read_bounded_method_body(data: bytes, pe: dnfile.dnPE, rva: int) -> object:
    """不正な巨大code sizeをdncilへ渡さずmethod bodyを解析する。"""

    try:
        return read_method_body_from_bytes(_bounded_method_body_data(data, pe, rva))
    except ConfigRecoveryError:
        raise
    except Exception as exc:
        raise ConfigRecoveryError("CIL method bodyを解析できません") from exc


_DOMAIN_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_BUILD_PLACEHOLDER = re.compile(r"(?:%[A-Za-z][A-Za-z0-9_]*%|<[A-Za-z0-9_]+>)\Z")
_CHACHA_CONSTANTS = (1634760805, 857760878, 2036477234, 1797285236)


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
        body = read_bounded_method_body(data, pe, row.Rva)
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
        body = read_bounded_method_body(data, pe, row.Rva)
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


def _rotate_left32(value: int, count: int) -> int:
    return ((value << count) & 0xFFFFFFFF) | (value >> (32 - count))


def _chacha_quarter_round(
    state: list[int], a: int, b: int, c: int, d: int
) -> None:
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotate_left32(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotate_left32(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & 0xFFFFFFFF
    state[d] = _rotate_left32(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & 0xFFFFFFFF
    state[b] = _rotate_left32(state[b] ^ state[c], 7)


def _derive_obfuscated_chacha_key(master_key: str) -> bytes:
    """review済みv0.5.8系constructorと同じ32-byte鍵混合だけを再現する。"""

    raw = master_key.encode("utf-8")
    if not 1 <= len(raw) <= 4096:
        raise ConfigRecoveryError("ChaCha20 master key長が範囲外です")
    key = bytearray(32)
    for index, value in enumerate(raw):
        key[index % 32] ^= value
        target = (index + 7) % 32
        key[target] = (key[target] + value) & 0xFF
    return bytes(key)


def _chacha20_ietf_crypt(
    payload: bytes, key: bytes, nonce: bytes, *, counter: int = 1
) -> bytes:
    """CILで確認したIETF ChaCha20 block関数を有界に静的再現する。"""

    if len(key) != 32 or len(nonce) != 12 or not 0 <= counter <= 0xFFFFFFFF:
        raise ConfigRecoveryError("ChaCha20 key、nonce、counterが不正です")
    if len(payload) > MAX_INPUT_BYTES:
        raise ConfigRecoveryError("ChaCha20 payloadが上限を超えています")
    key_words = list(struct.unpack("<8I", key))
    nonce_words = list(struct.unpack("<3I", nonce))
    output = bytearray(len(payload))
    for offset in range(0, len(payload), 64):
        initial = [*_CHACHA_CONSTANTS, *key_words, counter, *nonce_words]
        state = initial.copy()
        for _ in range(10):
            _chacha_quarter_round(state, 0, 4, 8, 12)
            _chacha_quarter_round(state, 1, 5, 9, 13)
            _chacha_quarter_round(state, 2, 6, 10, 14)
            _chacha_quarter_round(state, 3, 7, 11, 15)
            _chacha_quarter_round(state, 0, 5, 10, 15)
            _chacha_quarter_round(state, 1, 6, 11, 12)
            _chacha_quarter_round(state, 2, 7, 8, 13)
            _chacha_quarter_round(state, 3, 4, 9, 14)
        stream = struct.pack(
            "<16I",
            *((state[index] + initial[index]) & 0xFFFFFFFF for index in range(16)),
        )
        chunk = payload[offset : offset + 64]
        for index, value in enumerate(chunk):
            output[offset + index] = value ^ stream[index]
        counter = (counter + 1) & 0xFFFFFFFF
    return bytes(output)


def decrypt_obfuscated_chacha_setting(ciphertext: str, master_key: str) -> str:
    """12-byte nonce前置のreview済みChaCha20設定を復号する。"""

    try:
        raw = base64.b64decode(ciphertext, validate=True)
    except ValueError as exc:
        raise ConfigRecoveryError("ChaCha20設定値が正しいBase64ではありません") from exc
    if not 13 <= len(raw) <= MAX_INPUT_BYTES:
        raise ConfigRecoveryError("ChaCha20設定値の長さが不正です")
    plain = _chacha20_ietf_crypt(
        raw[12:], _derive_obfuscated_chacha_key(master_key), raw[:12]
    )
    try:
        return plain.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigRecoveryError("ChaCha20設定値がUTF-8ではありません") from exc


def _runtime_base64_text(value: str) -> str:
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise ConfigRecoveryError("runtime Base64文字列を復元できません") from exc


def _method_token(index: int) -> str:
    return f"0x0600{index:04x}"


def _obfuscated_chacha_profile(
    data: bytes,
) -> tuple[list[tuple[str, str]], dict[str, object]]:
    """名前ではなくcctor、初期化、ChaCha20 CIL形状からv0.5.8系を選ぶ。"""

    try:
        pe = dnfile.dnPE(data=data)
    except Exception as exc:
        raise ConfigRecoveryError("PE／CLR metadataを解析できません") from exc
    if pe.net is None or pe.net.mdtables is None:
        raise ConfigRecoveryError("CLR metadataがありません")
    method_rows = pe.net.mdtables.MethodDef.rows
    field_rows = pe.net.mdtables.Field.rows
    if not 1 <= len(method_rows) <= 20_000 or not field_rows:
        raise ConfigRecoveryError("CLR tableが欠落または上限外です")
    method_owners = {
        method.row_index: ".".join(
            value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
        )
        for row in pe.net.mdtables.TypeDef.rows
        for method in row.MethodList
    }
    field_owners = _field_owners(pe)
    bodies: dict[int, object] = {}

    def body_for(index: int) -> object:
        if index not in bodies:
            row = method_rows[index - 1]
            if not row.Rva:
                raise ConfigRecoveryError("review対象methodにCIL bodyがありません")
            try:
                bodies[index] = read_bounded_method_body(data, pe, row.Rva)
            except Exception as exc:
                raise ConfigRecoveryError("review対象CILを解析できません") from exc
        return bodies[index]

    cctor_candidates: list[tuple[int, list[tuple[str, str]]]] = []
    for index, row in enumerate(method_rows, 1):
        if str(row.Name) != ".cctor" or not row.Rva:
            continue
        owner = method_owners.get(index, "")
        assignments: list[tuple[str, str]] = []
        pending: str | None = None
        decoded = False
        for instruction in body_for(index).instructions:
            opcode = instruction.opcode.name
            operand = getattr(instruction.operand, "value", instruction.operand)
            if opcode == "ldstr" and isinstance(operand, int):
                try:
                    pending = str(pe.net.user_strings.get(operand & 0xFFFFFF).value)
                except Exception as exc:
                    raise ConfigRecoveryError("cctor user stringを解析できません") from exc
                decoded = False
                continue
            if opcode in {"call", "callvirt"} and isinstance(operand, int):
                if (
                    pending is not None
                    and _member_name(pe, operand, method_owners)
                    == "<Module>.Decrypt_Base64"
                ):
                    pending = _runtime_base64_text(pending)
                    decoded = True
                    continue
                pending = None
                decoded = False
                continue
            if opcode == "stsfld" and isinstance(operand, int):
                table_id = (operand >> 24) & 0xFF
                field_index = operand & 0xFFFFFF
                if (
                    decoded
                    and pending is not None
                    and table_id == 0x04
                    and 1 <= field_index <= len(field_rows)
                    and field_owners.get(field_index) == owner
                ):
                    assignments.append((str(field_rows[field_index - 1].Name), pending))
                pending = None
                decoded = False
                continue
            if opcode != "nop":
                pending = None
                decoded = False
        if 18 <= len(assignments) <= 32:
            cctor_candidates.append((index, assignments))
    if len(cctor_candidates) != 1:
        raise ConfigRecoveryError("難読化Settings cctorを一意に特定できません")
    cctor_index, assignments = cctor_candidates[0]
    settings_owner = method_owners.get(cctor_index, "")

    crypto_candidates: list[tuple[str, int, int, int, int]] = []
    for core_index, row in enumerate(method_rows, 1):
        if not row.Rva:
            continue
        body = body_for(core_index)
        constants = {
            getattr(instruction.operand, "value", instruction.operand)
            for instruction in body.instructions
            if instruction.opcode.name == "ldc.i4"
        }
        if not set(_CHACHA_CONSTANTS) <= constants:
            continue
        crypto_owner = method_owners.get(core_index, "")
        owner_indices = [
            index
            for index in range(1, len(method_rows) + 1)
            if method_owners.get(index) == crypto_owner and method_rows[index - 1].Rva
        ]
        ctor = []
        string_decrypt = []
        byte_decrypt = []
        for index in owner_indices:
            candidate = body_for(index)
            opcodes = [item.opcode.name for item in candidate.instructions]
            calls = [
                _member_name(
                    pe,
                    getattr(item.operand, "value", item.operand),
                    method_owners,
                )
                for item in candidate.instructions
                if item.opcode.name in {"call", "callvirt", "newobj"}
                and isinstance(getattr(item.operand, "value", item.operand), int)
            ]
            call_leafs = {name.rsplit(".", 1)[-1] for name in calls}
            integer_values = {
                getattr(item.operand, "value", item.operand)
                for item in candidate.instructions
                if item.opcode.name in {"ldc.i4", "ldc.i4.s"}
            }
            for item in candidate.instructions:
                if item.opcode.name.startswith("ldc.i4."):
                    suffix = item.opcode.name.rsplit(".", 1)[-1]
                    if suffix == "m1":
                        integer_values.add(-1)
                    elif suffix.isdigit():
                        integer_values.add(int(suffix))
            if (
                str(method_rows[index - 1].Name) == ".ctor"
                and {"IsNullOrEmpty", "GetBytes"} <= call_leafs
                and {"xor", "add", "rem", "newarr"} <= set(opcodes)
                and {7, 32} <= integer_values
            ):
                ctor.append(index)
            if {"FromBase64String", "GetString"} <= call_leafs:
                string_decrypt.append(index)
            if calls.count("BlockCopy") >= 2 and 12 in integer_values:
                byte_decrypt.append(index)
        if len(string_decrypt) == 1:
            decrypt_calls = {
                getattr(item.operand, "value", item.operand)
                for item in body_for(string_decrypt[0]).instructions
                if item.opcode.name in {"call", "callvirt"}
            }
            byte_decrypt = [
                index
                for index in byte_decrypt
                if (0x06000000 | index) in decrypt_calls
            ]
        if len(ctor) == len(string_decrypt) == len(byte_decrypt) == 1:
            crypto_candidates.append(
                (crypto_owner, ctor[0], string_decrypt[0], byte_decrypt[0], core_index)
            )
    if len(crypto_candidates) != 1:
        raise ConfigRecoveryError("ChaCha20 CIL profileを一意に特定できません")
    crypto_owner, ctor_index, string_decrypt_index, byte_decrypt_index, core_index = (
        crypto_candidates[0]
    )

    initializer_candidates: list[int] = []
    ctor_token = 0x06000000 | ctor_index
    decrypt_token = 0x06000000 | string_decrypt_index
    for index, row in enumerate(method_rows, 1):
        if method_owners.get(index) != settings_owner or not row.Rva:
            continue
        instructions = body_for(index).instructions
        newobjs = [
            getattr(item.operand, "value", item.operand)
            for item in instructions
            if item.opcode.name == "newobj"
        ]
        decrypt_calls = [
            getattr(item.operand, "value", item.operand)
            for item in instructions
            if item.opcode.name == "callvirt"
        ]
        leaf_calls = {
            _member_name(
                pe,
                getattr(item.operand, "value", item.operand),
                method_owners,
            ).rsplit(".", 1)[-1]
            for item in instructions
            if item.opcode.name in {"call", "callvirt", "newobj"}
            and isinstance(getattr(item.operand, "value", item.operand), int)
        }
        if (
            ctor_token in newobjs
            and decrypt_calls.count(decrypt_token) >= 10
            and {"FromBase64String", "GetString"} <= leaf_calls
        ):
            initializer_candidates.append(index)
    if len(initializer_candidates) != 1:
        raise ConfigRecoveryError("難読化Settings initializerを一意に特定できません")

    return assignments, {
        "settings_owner_sha256": hashlib.sha256(settings_owner.encode()).hexdigest(),
        "settings_cctor_token": _method_token(cctor_index),
        "settings_initializer_token": _method_token(initializer_candidates[0]),
        "crypto_owner_sha256": hashlib.sha256(crypto_owner.encode()).hexdigest(),
        "crypto_constructor_token": _method_token(ctor_index),
        "string_decrypt_token": _method_token(string_decrypt_index),
        "byte_decrypt_token": _method_token(byte_decrypt_index),
        "chacha_core_token": _method_token(core_index),
        "literal_assignment_count": len(assignments),
    }


def _recover_obfuscated_chacha_asyncrat(data: bytes) -> dict[str, Any]:
    assignments, shape = _obfuscated_chacha_profile(data)
    values = [value for _field, value in assignments]
    try:
        master_key = base64.b64decode(values[5], validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError, IndexError) as exc:
        raise ConfigRecoveryError("難読化Settings.Keyを復元できません") from exc
    if len(master_key) != 32 or any(not character.isprintable() for character in master_key):
        raise ConfigRecoveryError("難読化Settings.Keyの形状が一致しません")

    def decrypted(index: int) -> str:
        try:
            return decrypt_obfuscated_chacha_setting(values[index], master_key)
        except IndexError as exc:
            raise ConfigRecoveryError("難読化Settings field順が不足しています") from exc

    ports_text = decrypted(0)
    hosts_text = decrypted(1)
    version = decrypted(2).strip()
    install = decrypted(3).strip()
    mutex = decrypted(6)
    certificate_text = decrypted(7)
    signature_text = decrypted(8)
    anti = decrypted(9).strip()
    dynamic_url = decrypted(14).strip()
    group = decrypted(17).strip()
    hosts = _split_values(hosts_text)
    port_values = _split_values(ports_text)
    if not hosts or any(not _valid_host(host) for host in hosts):
        raise ConfigRecoveryError("難読化Settingsのhostが不正です")
    if not port_values or any(not value.isdigit() for value in port_values):
        raise ConfigRecoveryError("難読化Settingsのportが不正です")
    ports = [int(value) for value in port_values]
    if any(not 1 <= port <= 65_535 for port in ports) or len(hosts) * len(ports) > 64:
        raise ConfigRecoveryError("難読化Settingsのendpoint数またはport範囲が不正です")
    if not 1 <= len(version) <= 128 or len(group) > 512 or not 1 <= len(mutex) <= 512:
        raise ConfigRecoveryError("難読化Settingsのversion、group、mutexが不正です")
    if install.casefold() not in {"true", "false"} or anti.casefold() not in {
        "true",
        "false",
    }:
        raise ConfigRecoveryError("難読化Settingsのbooleanが不正です")
    try:
        certificate = base64.b64decode(certificate_text, validate=True)
        signature = base64.b64decode(signature_text, validate=True)
    except ValueError as exc:
        raise ConfigRecoveryError("難読化Settingsの証明書または署名が不正です") from exc
    if not 128 <= len(certificate) <= 16 * 1024 * 1024 or not 64 <= len(signature) <= 8192:
        raise ConfigRecoveryError("難読化Settingsの証明書または署名長が範囲外です")
    if dynamic_url.casefold() == "null" or not dynamic_url:
        dynamic_url = None
    elif (
        len(dynamic_url) > 2_048
        or not dynamic_url.casefold().startswith(("https://", "http://"))
    ):
        raise ConfigRecoveryError("難読化Settingsのdynamic config URLが不正です")
    return {
        "schema_version": 1,
        "family": "asyncrat",
        "sha256": hashlib.sha256(data).hexdigest(),
        "terminal_managed_client": True,
        "static_config_recovered": True,
        "config_mode": "chacha20_obfuscated_v058",
        "version": version,
        "install": install,
        "group": group,
        "anti_analysis": anti,
        "config_endpoints": [
            {"host": host.casefold().rstrip("."), "port": port}
            for host in hosts
            for port in ports
        ],
        "dynamic_config_url": dynamic_url,
        "certificate": {
            "sha256": hashlib.sha256(certificate).hexdigest(),
            "size": len(certificate),
            "validation": "embedded_certificate_present",
            "certificate_mismatch_excludes_c2": False,
        },
        "secret_fields_published": False,
        "crypto_profile": {
            "settings_storage": "encrypted",
            "key_derivation": "reviewed_xor_add_32_byte_mixing",
            "authentication": "none_per_setting",
            "cipher": "ChaCha20-IETF",
            "nonce_size": 12,
            "initial_counter": 1,
            "salt_source": "not_applicable",
            "salt_published": False,
        },
        "static_shape_evidence": shape,
        "executed": False,
        "network_contacted": False,
        "limitations": [
            "各設定blob自体にはMACがなく、CIL形状、復号後の型、証明書、署名を相互検証しました。",
            "dynamic_config_urlの内容は別の時点付き取得で確認する必要があります。",
            "証明書不一致だけでは非C2と判定しません。",
        ],
    }


def _split_values(value: str) -> list[str]:
    return sorted({item.strip() for item in value.split(",") if item.strip() and item.strip() != "null"})


def _valid_host(value: str) -> bool:
    """URL、placeholder、空labelを除外したIPまたはDNS名だけを受理する。"""

    host = value.strip().rstrip(".")
    if not host or len(host) > 253 or host != value.strip().rstrip("."):
        return False
    if any(character in host for character in "/:@%<>{}[] \t\r\n"):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        labels = host.split(".")
        return len(labels) >= 2 and all(_DOMAIN_LABEL.fullmatch(label) for label in labels)


def _method_opcode_shape(
    data: bytes,
    pe: dnfile.dnPE,
    owner: str,
    name: str,
) -> tuple[str, ...]:
    """一意なmanaged methodのopcode列を限定取得する。"""

    candidates = []
    for index, row in enumerate(pe.net.mdtables.MethodDef.rows, 1):
        if str(row.Name) != name or _method_owner(pe, index) != owner or not row.Rva:
            continue
        try:
            body = read_bounded_method_body(data, pe, row.Rva)
        except Exception as exc:
            raise ConfigRecoveryError(f"{owner}.{name}のCILを解析できません") from exc
        candidates.append(
            tuple(
                instruction.opcode.name
                for instruction in body.instructions
                if instruction.opcode.name != "nop"
            )
        )
    if len(candidates) != 1:
        raise ConfigRecoveryError(f"{owner}.{name}を一意に確認できません")
    return candidates[0]


def _asyncrat_plaintext_profile(data: bytes, literals: dict[str, str]) -> dict[str, object]:
    """v0.5.7B系developer buildの平文Settings形状をfail-closedで確認する。"""

    pe = dnfile.dnPE(data=data)
    if pe.net is None or pe.net.mdtables is None:
        raise ConfigRecoveryError("CLR metadataがありません")
    accepted_true_shapes = {
        ("ldc.i4.1", "ret"),
        ("ldc.i4.1", "stloc.0", "br.s", "ldloc.0", "ret"),
        ("ldc.i4.1", "stloc.0", "br", "ldloc.0", "ret"),
    }
    initialize_shape = _method_opcode_shape(
        data, pe, "Client.Settings", "InitializeSettings"
    )
    certificate_shape = _method_opcode_shape(
        data,
        pe,
        "Client.Connection.ClientSocket",
        "ValidateServerCertificate",
    )
    if initialize_shape not in accepted_true_shapes:
        raise ConfigRecoveryError("平文Settings初期化methodが既知のreturn true形状ではありません")
    if certificate_shape not in accepted_true_shapes:
        raise ConfigRecoveryError("TLS証明書callbackが既知のaccept-all形状ではありません")
    key = literals.get("Key")
    if (
        not isinstance(key, str)
        or not 8 <= len(key) <= 128
        or any(not 0x20 <= ord(character) <= 0x7E for character in key)
    ):
        raise ConfigRecoveryError("平文buildの非公開Key形状が一致しません")
    for field in ("Certificate", "Serversignature"):
        value = literals.get(field)
        if not isinstance(value, str) or _BUILD_PLACEHOLDER.fullmatch(value) is None:
            raise ConfigRecoveryError(f"平文build placeholderが一致しません: {field}")
    return {
        "settings_initializer": "trivial_return_true",
        "tls_certificate_validation": "accept_all",
        "placeholder_fields_validated": True,
    }


def _recover_plaintext_asyncrat(
    data: bytes,
    literals: dict[str, str],
    profile: dict[str, Any],
) -> dict[str, Any]:
    shape = _asyncrat_plaintext_profile(data, literals)
    fields = profile["fields"]
    plain = {
        public_name: literals.get(field_name, "")
        for public_name, field_name in fields.items()
        if public_name != "certificate"
    }
    hosts = _split_values(plain.get("hosts", ""))
    port_values = _split_values(plain.get("ports", ""))
    if not hosts or any(not _valid_host(host) for host in hosts):
        raise ConfigRecoveryError("平文Settingsのhostが不正です")
    if not port_values or any(not value.isdigit() for value in port_values):
        raise ConfigRecoveryError("平文Settingsのportが不正です")
    ports = [int(value) for value in port_values]
    if any(not 1 <= port <= 65_535 for port in ports) or len(hosts) * len(ports) > 64:
        raise ConfigRecoveryError("平文Settingsのendpoint数またはport範囲が不正です")
    version = plain.get("version", "").strip()
    group = plain.get("group", "").strip()
    if not 1 <= len(version) <= 128 or len(group) > 512:
        raise ConfigRecoveryError("平文Settingsのversionまたはgroupが不正です")
    for field in ("install", "anti"):
        if plain.get(field, "").strip().casefold() not in {"true", "false"}:
            raise ConfigRecoveryError(f"平文Settingsのbooleanが不正です: {field}")
    dynamic_url = plain.get("pastebin", "").strip()
    if dynamic_url.casefold() == "null" or not dynamic_url:
        dynamic_url = None
    elif (
        len(dynamic_url) > 2_048
        or not dynamic_url.casefold().startswith(("https://", "http://"))
    ):
        raise ConfigRecoveryError("平文Settingsのdynamic config URLが不正です")
    return {
        "schema_version": 1,
        "family": "asyncrat",
        "sha256": hashlib.sha256(data).hexdigest(),
        "terminal_managed_client": True,
        "static_config_recovered": True,
        "config_mode": "plaintext_static_v057b",
        "version": version,
        "install": plain.get("install", "").strip(),
        "group": group,
        "anti_analysis": plain.get("anti", "").strip(),
        "config_endpoints": [
            {"host": host.casefold().rstrip("."), "port": port}
            for host in hosts
            for port in ports
        ],
        "dynamic_config_url": dynamic_url,
        "certificate": {
            "sha256": None,
            "size": None,
            "validation": "accept_all",
            "certificate_mismatch_excludes_c2": False,
        },
        "secret_fields_published": False,
        "crypto_profile": {
            "settings_storage": "plaintext",
            "key_derivation": "not_applicable",
            "authentication": "not_applicable",
            "cipher": "not_applicable",
            "salt_source": "not_applicable",
            "salt_published": False,
        },
        "static_shape_evidence": shape,
        "executed": False,
        "network_contacted": False,
        "limitations": [
            "dynamic_config_urlの内容は別の時点付き取得で確認する必要があります。",
            "このbuildはTLS server証明書をaccept-allで受理し、証明書pinを持ちません。",
        ],
    }


def recover(data: bytes, family: str) -> dict[str, Any]:
    """指定familyのreview済みfield mappingで公開可能な設定だけを返す。"""

    profile = PROFILES[family]
    try:
        literals = settings_literals(data, str(profile["settings_type"]))
    except ConfigRecoveryError:
        if family == "asyncrat":
            return _recover_obfuscated_chacha_asyncrat(data)
        raise
    encoded_key = literals.get("Key")
    if not encoded_key:
        if family == "asyncrat":
            return _recover_obfuscated_chacha_asyncrat(data)
        raise ConfigRecoveryError("Settings.Keyがありません")
    try:
        master_key = base64.b64decode(encoded_key, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        if family == "asyncrat":
            return _recover_plaintext_asyncrat(data, literals, profile)
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
        "config_mode": "hmac_encrypted",
        "version": decrypted.get("version", "").strip() or None,
        "install": decrypted.get("install", "").strip() or None,
        "group": decrypted.get("group", "").strip() or None,
        "anti_analysis": decrypted.get("anti", "").strip() or None,
        "config_endpoints": endpoints,
        "dynamic_config_url": dynamic_url,
        "certificate": {
            "sha256": certificate_sha256,
            "size": certificate_size,
            "validation": "embedded_certificate_present",
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
