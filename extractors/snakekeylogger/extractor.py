"""Snake Keylogger／VIPKeyloggerの多段chainとSMTP設定を静的に復元する。"""

from __future__ import annotations

import base64
import hashlib
import re
from typing import Any

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes
import pefile
from Cryptodome.Cipher import DES

from extractors.common import build_result
from unpackers.donut_unpacker import recover_donut_payloads
from unpackers.javascript_reverse_base64 import recover_reverse_base64
from unpackers.luajit_polyrot_structural import recover_bytes as recover_lua

HANDLER_CONTRACT = {
    "input_formats": ["script", "data", "pe"],
    "minimum_evidence_score": 30_000,
}

MAXIMUM_INPUT_SIZE = 16 * 1024 * 1024
MAXIMUM_LAYER_SIZE = 32 * 1024 * 1024
MAXIMUM_METHOD_BODY_SIZE = 2 * 1024 * 1024
MAXIMUM_RECOVERED_ARTIFACTS = 32
VIP_EXACT_TERMINAL_SHA256 = (
    "0acab73175c36331fb8a46f78d0eb6c02f76e79cf1f52bdd0ef27d61ca8c10df"
)
_EMAIL = re.compile(r"[^\s@]+@[^\s@]+\.[^\s@]+\Z")
_DOMAIN = re.compile(r"(?:[a-z0-9-]+\.)+[a-z]{2,63}\Z", re.I)


class SnakeStaticRecoveryError(ValueError):
    """Snake Keyloggerの静的構造を一意に検証できない場合の例外。"""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _operand(instruction: object) -> object:
    try:
        value = instruction.operand
        return value.value
    except AttributeError:
        return value


def _strict_token(value: object, table: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SnakeStaticRecoveryError("CIL tokenの型が不正です")
    if value <= 0 or (value & 0xFFFFFF) == 0:
        raise SnakeStaticRecoveryError("CIL tokenのRIDが不正です")
    if table is not None and value >> 24 != table:
        raise SnakeStaticRecoveryError("CIL tokenのtableが不正です")
    return value


def _is_dotnet(data: bytes) -> bool:
    if len(data) > MAXIMUM_LAYER_SIZE or not data.startswith(b"MZ"):
        return False
    try:
        image = pefile.PE(data=data, fast_load=True)
        directory = image.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        return bool(directory.VirtualAddress and directory.Size)
    except (AttributeError, ValueError, pefile.PEFormatError):
        return False


def _bounded_strings(data: bytes) -> set[str]:
    if len(data) > MAXIMUM_LAYER_SIZE:
        return set()
    values = {
        match.group().decode("ascii", errors="strict")
        for match in re.finditer(rb"[\x20-\x7e]{4,}", data)
    }
    values.update(
        match.group().decode("utf-16le", errors="strict")
        for match in re.finditer(rb"(?:[\x20-\x7e]\x00){4,}", data)
    )
    return values


def structural_evidence(data: bytes) -> dict[str, object]:
    """VIPKeylogger v4.4の独立したmanaged code markerを照合する。"""

    strings = _bounded_strings(data)
    lowered = {value.casefold() for value in strings}
    literal_groups = {
        "builder": {"stub version: ", "vip recovery"},
        "telegram": {"https://api.telegram.org/bot", "/sendmessage?chat_id="},
        "smtp": {"smtpclient", "mailmessage"},
        "ftp": {"ftpwebrequest"},
        "keylogging": {"setwindowshookexa", "keylogger"},
    }
    hits = {
        group: sorted(value for value in values if any(value.casefold() in item for item in lowered))
        for group, values in literal_groups.items()
    }
    matched_groups = sorted(group for group, values in hits.items() if values)
    managed = _is_dotnet(data)
    matched = bool(
        managed
        and len(hits["builder"]) == 2
        and len(hits["telegram"]) == 2
        and len({"smtp", "ftp", "keylogging"}.intersection(matched_groups)) >= 2
    )
    return {
        "managed_pe": managed,
        "matched": matched,
        "matched_groups": matched_groups,
        "builder_marker_count": len(hits["builder"]),
        "telegram_marker_count": len(hits["telegram"]),
        "sample_executed": False,
        "network_contacted": False,
    }


def _owner_name(row: object) -> str:
    try:
        owner_row = row.Class.row
        namespace = str(owner_row.TypeNamespace)
        name = str(owner_row.TypeName)
    except AttributeError:
        return ""
    return ".".join(
        value
        for value in (
            namespace,
            name,
        )
        if value
    )


def _token_description(image: dnfile.dnPE, token: int) -> str:
    tables = {
        0x01: image.net.mdtables.TypeRef,
        0x04: image.net.mdtables.Field,
        0x06: image.net.mdtables.MethodDef,
        0x0A: image.net.mdtables.MemberRef,
    }
    table = tables.get(token >> 24)
    row_id = token & 0xFFFFFF
    if table is None or not 1 <= row_id <= len(table.rows):
        return ""
    row = table.rows[row_id - 1]
    return f"{_owner_name(row)}.{row.Name}".strip(".")


def _method_instructions(
    image: dnfile.dnPE, data: bytes, method_row: object
) -> list[object]:
    rva = method_row.Rva
    if isinstance(rva, bool) or not isinstance(rva, int) or rva <= 0:
        raise SnakeStaticRecoveryError("managed method RVAが不正です")
    offset = image.get_offset_from_rva(rva)
    if not isinstance(offset, int) or not 0 <= offset < len(data):
        raise SnakeStaticRecoveryError("managed method offsetが不正です")
    window = data[offset : min(len(data), offset + MAXIMUM_METHOD_BODY_SIZE)]
    body = read_method_body_from_bytes(window)
    return list(body.instructions)


def _user_string(image: dnfile.dnPE, token: object) -> str:
    value = _strict_token(token, 0x70)
    record = image.net.user_strings.get(value & 0xFFFFFF)
    text = record.value
    if not isinstance(text, str) or len(text) > 8192:
        raise SnakeStaticRecoveryError("managed user stringが不正です")
    return text


def _pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size:
        raise SnakeStaticRecoveryError("暗号文のblock長が不正です")
    width = data[-1]
    if not 1 <= width <= block_size or data[-width:] != bytes([width]) * width:
        raise SnakeStaticRecoveryError("PKCS#7 paddingが不正です")
    return data[:-width]


def _decrypt_des_ecb(ciphertext: str, master_key: str) -> str:
    try:
        encoded = ciphertext.encode("ascii", errors="strict")
        raw = base64.b64decode(encoded, validate=True)
        digest = hashlib.md5(master_key.encode("ascii", errors="strict")).digest()[:8]
        plaintext = _pkcs7_unpad(DES.new(digest, DES.MODE_ECB).decrypt(raw), 8)
        value = plaintext.decode("ascii", errors="strict")
    except (UnicodeError, ValueError) as exc:
        raise SnakeStaticRecoveryError("設定fieldのDES復号に失敗しました") from exc
    if len(value) > 1024 or any(ord(char) < 0x20 for char in value):
        raise SnakeStaticRecoveryError("復号設定fieldが公開可能な文字列ではありません")
    return value


def _verify_decryptor(
    image: dnfile.dnPE, data: bytes, decryptor_token: int
) -> dict[str, object]:
    token = _strict_token(decryptor_token, 0x06)
    row_id = token & 0xFFFFFF
    methods = image.net.mdtables.MethodDef.rows
    if not 1 <= row_id <= len(methods):
        raise SnakeStaticRecoveryError("設定decryptor tokenが範囲外です")
    instructions = _method_instructions(image, data, methods[row_id - 1])
    calls: list[str] = []
    mode_is_ecb = False
    for index, instruction in enumerate(instructions):
        if instruction.opcode.name not in {"call", "callvirt", "newobj"}:
            continue
        description = _token_description(image, _strict_token(_operand(instruction)))
        calls.append(description.casefold())
        if description.casefold().endswith(".set_mode") and index:
            mode_is_ecb = instructions[index - 1].opcode.name == "ldc.i4.2"
    required = (
        "descryptoserviceprovider",
        "md5cryptoserviceprovider",
        "frombase64string",
        "computehash",
        "set_key",
        "createdecryptor",
    )
    missing = [marker for marker in required if not any(marker in call for call in calls)]
    if missing or not mode_is_ecb:
        raise SnakeStaticRecoveryError("DES/MD5/ECB設定decryptorの構造が一致しません")
    return {
        "method_token": f"0x{token:08x}",
        "instruction_count": len(instructions),
        "algorithm": "MD5-derived DES-ECB with PKCS#7",
    }


def _recover_cctor_blocks(
    image: dnfile.dnPE, data: bytes
) -> tuple[str, int, list[str], dict[str, object]]:
    candidates: list[tuple[str, int, list[str], dict[str, object]]] = []
    for row in image.net.mdtables.MethodDef.rows:
        if str(row.Name) != ".cctor":
            continue
        instructions = _method_instructions(image, data, row)
        direct: dict[int, str] = {}
        blocks: list[tuple[int, int, str]] = []
        literals: list[str] = []
        for index, instruction in enumerate(instructions):
            if instruction.opcode.name != "ldstr":
                continue
            literal = _user_string(image, _operand(instruction))
            literals.append(literal)
            tail = instructions[index + 1 : index + 4]
            if tail and tail[0].opcode.name == "stsfld":
                field = _strict_token(_operand(tail[0]), 0x04)
                direct[field] = literal
            if len(tail) == 3 and [item.opcode.name for item in tail] == [
                "ldsfld",
                "call",
                "stsfld",
            ]:
                master_field = _strict_token(_operand(tail[0]), 0x04)
                decryptor = _strict_token(_operand(tail[1]), 0x06)
                _strict_token(_operand(tail[2]), 0x04)
                blocks.append((master_field, decryptor, literal))
        if "Stub Version: " not in literals or "4.4" not in literals:
            continue
        grouped: dict[tuple[int, int], list[str]] = {}
        for master_field, decryptor, literal in blocks:
            key = (master_field, decryptor)
            values = grouped.get(key)
            if values is None:
                values = []
                grouped[key] = values
            values.append(literal)
        viable = [
            (key, values)
            for key, values in grouped.items()
            if len(values) >= 5 and key[0] in direct
        ]
        if len(viable) != 1:
            continue
        (master_field, decryptor), encrypted = viable[0]
        proof = _verify_decryptor(image, data, decryptor)
        candidates.append((direct[master_field], decryptor, encrypted, proof))
    if len(candidates) != 1:
        raise SnakeStaticRecoveryError("VIPKeylogger v4.4設定initializerを一意に特定できません")
    return candidates[0]


def _public_config(values: list[str], proof: dict[str, object]) -> dict[str, object]:
    placeholders = [
        value
        for value in values
        if not value or (value.startswith("%") and value.endswith("%"))
    ]
    real = [value for value in values if value and value not in placeholders]
    emails = [value for value in real if _EMAIL.fullmatch(value)]
    domains = [value.casefold() for value in real if _DOMAIN.fullmatch(value)]
    ports = [int(value) for value in real if value.isdigit() and 1 <= int(value) <= 65535]
    secrets = [
        value
        for value in real
        if value not in emails
        and value.casefold() not in domains
        and not (value.isdigit() and 1 <= int(value) <= 65535)
    ]
    if len(emails) != 2 or len(domains) != 1 or len(ports) != 1 or len(secrets) < 1:
        raise SnakeStaticRecoveryError("SMTP設定fieldの意味分類が一意ではありません")
    return {
        "recovery_status": "confirmed_static_config",
        "family": "snakekeylogger",
        "variant": "vipkeylogger",
        "builder_version": "4.4",
        "config_endpoints": [
            {
                "protocol": "smtp",
                "host": domains[0],
                "port": ports[0],
                "role": "credential_exfiltration",
                "confidence": "confirmed_static_config",
            }
        ],
        "smtp_identity_present": True,
        "smtp_recipient_present": True,
        "smtp_password_present": True,
        "credential_values_published": False,
        "telegram": {
            "api_host": "api.telegram.org",
            "path_template": "/bot{token}/sendMessage",
            "token_configured": not any("TeleToken" in item or "Tele_token" in item for item in placeholders),
            "chat_id_configured": not any("TeleID" in item or "Tele_ID" in item for item in placeholders),
            "credential_values_published": False,
        },
        "backend_capabilities": ["smtp", "ftp", "telegram", "http"],
        "decrypted_field_count": len(values),
        "placeholder_field_count": len(placeholders),
        "decryptor": proof,
        "sample_executed": False,
        "network_contacted": False,
    }


def recover_terminal_config(data: bytes) -> dict[str, object]:
    """managed terminalから秘密値を保持せずVIPKeylogger設定を復元する。"""

    evidence = structural_evidence(data)
    if not evidence["matched"]:
        raise SnakeStaticRecoveryError("VIPKeyloggerの独立marker構造が一致しません")
    try:
        image = dnfile.dnPE(data=data)
        if image.net is None:
            raise SnakeStaticRecoveryError("CLR metadataがありません")
        master, _decryptor, encrypted, proof = _recover_cctor_blocks(image, data)
        values = [
            value
            if re.fullmatch(r"%(?:\$)?[A-Za-z0-9_]+(?:\$)?%", value)
            else _decrypt_des_ecb(value, master)
            for value in encrypted
        ]
    except SnakeStaticRecoveryError:
        raise
    except (AttributeError, IndexError, TypeError, ValueError) as exc:
        raise SnakeStaticRecoveryError("CLR設定構造を検証できません") from exc
    config = _public_config(values, proof)
    config["terminal_sha256"] = _sha256(data)
    config["terminal_size"] = len(data)
    config["exact_reviewed_terminal"] = _sha256(data) == VIP_EXACT_TERMINAL_SHA256
    config["structural_evidence"] = evidence
    return config


def _layer(role: str, data: bytes) -> dict[str, object]:
    return {"role": role, "sha256": _sha256(data), "size": len(data)}


def _bounded_artifacts(
    artifacts: list[tuple[str, bytes]], *, label: str
) -> list[tuple[str, bytes]]:
    if len(artifacts) > MAXIMUM_RECOVERED_ARTIFACTS:
        raise SnakeStaticRecoveryError(f"{label}の復元件数が上限を超えました")
    if any(len(blob) > MAXIMUM_LAYER_SIZE for _kind, blob in artifacts):
        raise SnakeStaticRecoveryError(f"{label}の復元sizeが上限を超えました")
    return artifacts


def analyze_chain(data: bytes) -> dict[str, object]:
    """JS→LuaJIT→Donut→managed terminalを実行せず静的に追跡する。"""

    if len(data) > MAXIMUM_INPUT_SIZE:
        raise SnakeStaticRecoveryError("入力が16 MiB上限を超えています")
    layers = [_layer("submitted", data)]
    terminals: list[bytes] = [data] if _is_dotnet(data) else []
    js_report: dict[str, Any] = {"status": "not_attempted_direct_managed_input"}
    lua_reports: list[dict[str, object]] = []
    donut_reports: list[dict[str, object]] = []
    if not terminals:
        js_report, js_artifacts = recover_reverse_base64(data)
        js_artifacts = _bounded_artifacts(js_artifacts, label="JavaScript")
        for role, artifact in js_artifacts:
            layers.append(_layer(role, artifact))
        lua_inputs = [(role, blob) for role, blob in js_artifacts if role.endswith("-lua")]
        if not lua_inputs:
            lua_inputs = [("submitted-lua-candidate", data)]
        for source, lua_data in lua_inputs:
            lua_report, shellcodes = recover_lua(lua_data)
            if lua_report.get("status") == "pattern_not_found":
                continue
            lua_reports.append({"source": source, **lua_report})
            for shell_role, shellcode in _bounded_artifacts(shellcodes, label="LuaJIT"):
                layers.append(_layer(shell_role, shellcode))
                donut_report, payloads = recover_donut_payloads(shellcode)
                donut_reports.append({"source": shell_role, **donut_report})
                for payload_role, payload in _bounded_artifacts(payloads, label="Donut"):
                    layers.append(_layer(payload_role, payload))
                    if _is_dotnet(payload):
                        terminals.append(payload)
    unique_terminals = { _sha256(item): item for item in terminals }
    recovered: list[tuple[bytes, dict[str, object]]] = []
    for terminal in unique_terminals.values():
        try:
            recovered.append((terminal, recover_terminal_config(terminal)))
        except SnakeStaticRecoveryError:
            continue
    if len(recovered) > 1:
        raise SnakeStaticRecoveryError("複数のVIPKeylogger terminal設定が一致しました")
    return {
        "schema_version": 1,
        "family": "snakekeylogger",
        "variant": "vipkeylogger",
        "status": "final_config_recovered" if recovered else "not_applicable",
        "input": _layer("submitted", data),
        "layers": layers,
        "javascript_reverse_base64": js_report,
        "luajit_polyrot": lua_reports,
        "donut": donut_reports,
        "terminal_config": recovered[0][1] if recovered else None,
        "safety": {
            "sample_executed": False,
            "javascript_executed": False,
            "lua_executed": False,
            "managed_payload_executed": False,
            "network_contacted": False,
            "credentials_published": False,
            "recovered_bytes_published": False,
        },
    }


def extract(data: bytes, name: str = "sample") -> dict[str, object]:
    """共通handler向けに公開可能な設定・hash・構造だけを返す。"""

    try:
        chain = analyze_chain(data)
    except (SnakeStaticRecoveryError, ValueError):
        chain = {
            "status": "rejected_or_not_recovered",
            "layers": [_layer("submitted", data)],
            "terminal_config": None,
            "safety": {
                "sample_executed": False,
                "network_contacted": False,
                "credentials_published": False,
                "recovered_bytes_published": False,
            },
        }
    config = chain.get("terminal_config")
    config = config if isinstance(config, dict) else {
        "recovery_status": str(chain["status"]),
        "config_endpoints": [],
        "static_config_recovered": False,
    }
    config = {
        "source_name": name,
        **config,
        "static_config_recovered": chain["status"] == "final_config_recovered",
        "chain_status": chain["status"],
        "layers": chain["layers"],
        "credentials_published": False,
        "recovered_bytes_published": False,
    }
    findings = [
        {
            "kind": "network.endpoint",
            "value": f"{item['host']}:{item['port']}",
            "role": "credential_exfiltration",
            "protocol": "smtp",
            "confidence": "confirmed_static_config",
            "source": "validated_vipkeylogger_des_config",
        }
        for item in config.get("config_endpoints", [])
        if isinstance(item, dict)
    ]
    return build_result(
        "snakekeylogger",
        data,
        config,
        findings,
        [
            "SMTP endpointは復号済み静的設定であり、サービス稼働や認証成功を示しません。",
            "Telegram API code pathは確認済みですが、未設定token／chat IDを公開または補完しません。",
            "復元layerとmanaged payloadは実行せず、外部hostへ接続していません。",
        ],
    )


__all__ = [
    "HANDLER_CONTRACT",
    "SnakeStaticRecoveryError",
    "analyze_chain",
    "extract",
    "recover_terminal_config",
    "structural_evidence",
]
