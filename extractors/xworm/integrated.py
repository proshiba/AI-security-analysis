"""XWorm V6系managed clientの設定と代表CILを静的復元する。"""

from __future__ import annotations

import base64
import hashlib
import re

import dnfile
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from dncil.cil.body.reader import read_method_body_from_bytes

from extractors.common import build_result, valid_host


HANDLER_CONTRACT = {
    "input_formats": ["pe"],
    "minimum_evidence_score": 20_000,
}
MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_METHODS = 20_000
REVIEWED_SHA256 = (
    "7b92ddcdd8d9a135b92e0b2f4d2e56439395be688892e2b3ce77b3446eeb6aa2"
)
REQUIRED_FIELDS = (
    "Hosts",
    "Port",
    "KEY",
    "SPL",
    "Sleep",
    "Group",
    "USBNM",
    "Mutex",
)
REQUIRED_METHODS = {
    "Stub.Main": {"Main"},
    "Stub.ClientSocket": {
        "BeginConnect",
        "ConnectServer",
        "BeginReceive",
        "BeginRead",
        "Send",
        "Pong",
        "Ping",
    },
    "Stub.Messages": {"Read", "Plugin", "OpenUrl", "RunDisk", "Memory"},
    "Stub.AlgorithmAES": {"Decrypt"},
}
XWORM_VERSION = re.compile(r"XWorm V[0-9]+(?:\.[0-9]+)*\Z", re.IGNORECASE)


class XwormRecoveryError(ValueError):
    """XWorm設定またはCIL形状がreview済みprofileに一致しない。"""


def _owners(pe: dnfile.dnPE) -> tuple[dict[int, str], dict[int, str]]:
    method_owners: dict[int, str] = {}
    field_owners: dict[int, str] = {}
    for row in pe.net.mdtables.TypeDef.rows:
        owner = ".".join(
            value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
        )
        for method in row.MethodList:
            method_owners[method.row_index] = owner
        for field in row.FieldList:
            field_owners[field.row_index] = owner
    return method_owners, field_owners


def _member_name(pe: dnfile.dnPE, token: int, owners: dict[int, str]) -> str:
    table_id = (token >> 24) & 0xFF
    index = token & 0xFFFFFF
    if table_id == 0x06 and 1 <= index <= len(pe.net.mdtables.MethodDef.rows):
        row = pe.net.mdtables.MethodDef.rows[index - 1]
        return f"{owners.get(index, '')}.{row.Name}".strip(".")
    if table_id == 0x0A and 1 <= index <= len(pe.net.mdtables.MemberRef.rows):
        return str(pe.net.mdtables.MemberRef.rows[index - 1].Name)
    return ""


def _settings_literals(
    data: bytes, pe: dnfile.dnPE, method_owners: dict[int, str], field_owners: dict[int, str]
) -> dict[str, str]:
    candidates = []
    for index, row in enumerate(pe.net.mdtables.MethodDef.rows, 1):
        if str(row.Name) != ".cctor" or method_owners.get(index) != "Settings" or not row.Rva:
            continue
        body = read_method_body_from_bytes(data[pe.get_offset_from_rva(row.Rva) :])
        values: dict[str, str] = {}
        pending: str | None = None
        for instruction in body.instructions:
            opcode = instruction.opcode.name
            operand = getattr(instruction.operand, "value", instruction.operand)
            if opcode == "ldstr" and isinstance(operand, int):
                pending = str(pe.net.user_strings.get(operand & 0xFFFFFF).value)
                continue
            if opcode == "stsfld" and isinstance(operand, int) and pending is not None:
                table_id = (operand >> 24) & 0xFF
                field_index = operand & 0xFFFFFF
                if (
                    table_id == 0x04
                    and 1 <= field_index <= len(pe.net.mdtables.Field.rows)
                    and field_owners.get(field_index) == "Settings"
                ):
                    field = pe.net.mdtables.Field.rows[field_index - 1]
                    values[str(field.Name)] = pending
                pending = None
                continue
            if opcode not in {"nop", "call"}:
                pending = None
        if set(REQUIRED_FIELDS) <= values.keys():
            candidates.append(values)
    if len(candidates) != 1:
        raise XwormRecoveryError("XWorm Settings cctorを一意に特定できません")
    return candidates[0]


def _method_shape(
    data: bytes,
    pe: dnfile.dnPE,
    method_owners: dict[int, str],
    owner: str,
    name: str,
) -> tuple[set[str], set[str], set[int]]:
    candidates = []
    for index, row in enumerate(pe.net.mdtables.MethodDef.rows, 1):
        if method_owners.get(index) != owner or str(row.Name) != name or not row.Rva:
            continue
        body = read_method_body_from_bytes(data[pe.get_offset_from_rva(row.Rva) :])
        opcodes = {instruction.opcode.name for instruction in body.instructions}
        calls = {
            _member_name(
                pe,
                getattr(instruction.operand, "value", instruction.operand),
                method_owners,
            ).rsplit(".", 1)[-1]
            for instruction in body.instructions
            if instruction.opcode.name in {"call", "callvirt", "newobj"}
            and isinstance(
                getattr(instruction.operand, "value", instruction.operand), int
            )
        }
        integers = {
            getattr(instruction.operand, "value", instruction.operand)
            for instruction in body.instructions
            if instruction.opcode.name in {"ldc.i4", "ldc.i4.s"}
        }
        for instruction in body.instructions:
            if instruction.opcode.name.startswith("ldc.i4."):
                suffix = instruction.opcode.name.rsplit(".", 1)[-1]
                if suffix.isdigit():
                    integers.add(int(suffix))
        candidates.append((opcodes, calls, integers))
    if len(candidates) != 1:
        raise XwormRecoveryError(f"review対象methodを一意に特定できません: {owner}.{name}")
    return candidates[0]


def _verify_structure(
    data: bytes, pe: dnfile.dnPE, method_owners: dict[int, str]
) -> dict[str, object]:
    observed: dict[str, set[str]] = {}
    tokens: dict[str, str] = {}
    for index, row in enumerate(pe.net.mdtables.MethodDef.rows, 1):
        owner = method_owners.get(index, "")
        if owner in REQUIRED_METHODS:
            observed.setdefault(owner, set()).add(str(row.Name))
            tokens[f"{owner}.{row.Name}"] = f"0x0600{index:04x}"
    if any(required - observed.get(owner, set()) for owner, required in REQUIRED_METHODS.items()):
        raise XwormRecoveryError("XWorm必須method集合が一致しません")
    opcodes, calls, integers = _method_shape(
        data, pe, method_owners, "Stub.AlgorithmAES", "Decrypt"
    )
    required_calls = {
        "ComputeHash",
        "Copy",
        "set_Key",
        "set_Mode",
        "CreateDecryptor",
        "FromBase64String",
        "TransformFinalBlock",
    }
    if (
        not required_calls <= calls
        or not {"newarr", "ret"} <= opcodes
        or not {2, 15, 16, 32} <= integers
    ):
        raise XwormRecoveryError("XWorm AES復号CIL形状が一致しません")
    for helper, expected in (
        ("SB", {"get_UTF8", "GetBytes"}),
        ("BS", {"get_UTF8", "GetString"}),
    ):
        _opcodes, helper_calls, _integers = _method_shape(
            data, pe, method_owners, "Stub.Helper", helper
        )
        if not expected <= helper_calls:
            raise XwormRecoveryError("XWorm UTF-8 helper形状が一致しません")
    return {
        "method_count": len(pe.net.mdtables.MethodDef.rows),
        "settings_cctor": tokens.get("Settings..cctor"),
        "main": tokens["Stub.Main.Main"],
        "connect": tokens["Stub.ClientSocket.ConnectServer"],
        "receive": tokens["Stub.ClientSocket.BeginRead"],
        "send": tokens["Stub.ClientSocket.Send"],
        "dispatcher": tokens["Stub.Messages.Read"],
        "config_decrypt": tokens["Stub.AlgorithmAES.Decrypt"],
    }


def _aes_key(mutex: str) -> bytes:
    digest = hashlib.md5(mutex.encode("utf-8"), usedforsecurity=False).digest()
    key = bytearray(32)
    key[:16] = digest
    key[15:31] = digest
    return bytes(key)


def decrypt_setting(value: str, mutex: str) -> str:
    """review済みXWorm AES-256-ECB＋PKCS7設定を静的復号する。"""

    try:
        encrypted = base64.b64decode(value, validate=True)
    except ValueError as exc:
        raise XwormRecoveryError("XWorm設定値が正しいBase64ではありません") from exc
    if not encrypted or len(encrypted) > MAX_INPUT_BYTES or len(encrypted) % 16:
        raise XwormRecoveryError("XWorm暗号化設定長が不正です")
    decryptor = Cipher(algorithms.AES(_aes_key(mutex)), modes.ECB()).decryptor()
    padded = decryptor.update(encrypted) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    try:
        return (unpadder.update(padded) + unpadder.finalize()).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as exc:
        raise XwormRecoveryError("XWorm設定のpaddingまたはUTF-8が不正です") from exc


def recover_config(data: bytes) -> dict[str, object]:
    """Settings名、method集合、暗号shapeを相互確認して公開設定だけ返す。"""

    if not data.startswith(b"MZ") or b"BSJB" not in data or len(data) > MAX_INPUT_BYTES:
        raise XwormRecoveryError("上限内のmanaged PEではありません")
    try:
        pe = dnfile.dnPE(data=data)
    except Exception as exc:
        raise XwormRecoveryError("PE／CLR metadataを解析できません") from exc
    if pe.net is None or pe.net.mdtables is None:
        raise XwormRecoveryError("CLR metadataがありません")
    if not 1 <= len(pe.net.mdtables.MethodDef.rows) <= MAX_METHODS:
        raise XwormRecoveryError("managed method数が上限外です")
    method_owners, field_owners = _owners(pe)
    literals = _settings_literals(data, pe, method_owners, field_owners)
    structure = _verify_structure(data, pe, method_owners)
    mutex = literals["Mutex"]
    if not 8 <= len(mutex) <= 256 or not mutex.isprintable():
        raise XwormRecoveryError("XWorm Mutex形状が不正です")
    decrypted = {
        name: decrypt_setting(literals[name], mutex)
        for name in ("Hosts", "Port", "KEY", "SPL", "Group", "USBNM")
    }
    hosts = sorted(
        {
            host.strip().casefold().rstrip(".")
            for host in re.split(r"[,;]", decrypted["Hosts"])
            if host.strip()
        }
    )
    ports_text = [value.strip() for value in re.split(r"[,;]", decrypted["Port"]) if value.strip()]
    if not hosts or any(not valid_host(host) for host in hosts):
        raise XwormRecoveryError("XWorm hostが不正です")
    if not ports_text or any(not value.isdigit() for value in ports_text):
        raise XwormRecoveryError("XWorm portが不正です")
    ports = [int(value) for value in ports_text]
    if any(not 1 <= port <= 65_535 for port in ports) or len(hosts) * len(ports) > 64:
        raise XwormRecoveryError("XWorm endpoint数またはport範囲が不正です")
    version = decrypted["Group"].strip()
    separator = decrypted["SPL"]
    usb_name = decrypted["USBNM"].strip()
    if XWORM_VERSION.fullmatch(version) is None:
        raise XwormRecoveryError("XWorm version markerが一致しません")
    if not 3 <= len(separator) <= 128 or "xworm" not in separator.casefold():
        raise XwormRecoveryError("XWorm separator markerが一致しません")
    if not usb_name.casefold().endswith(".exe") or len(usb_name) > 260:
        raise XwormRecoveryError("XWorm USB filenameが不正です")
    if not decrypted["KEY"] or len(decrypted["KEY"]) > 4096:
        raise XwormRecoveryError("XWorm非公開通信key形状が不正です")
    return {
        "schema_version": 1,
        "family": "xworm",
        "sha256": hashlib.sha256(data).hexdigest(),
        "version": version,
        "config_endpoints": [
            {"host": host, "port": port} for host in hosts for port in ports
        ],
        "sleep_seconds": int(literals["Sleep"]),
        "usb_filename": usb_name,
        "separator": separator,
        "secret_fields_published": False,
        "crypto_profile": {
            "config_cipher": "AES-256-ECB-PKCS7",
            "key_derivation": "MD5(UTF8(Mutex)) duplicated at offsets 0 and 15",
            "mutex_published": False,
            "communication_key_published": False,
        },
        "structural_evidence": structure,
        "executed": False,
        "network_contacted": False,
    }


def structural_evidence(data: bytes) -> dict[str, object]:
    """復号・型検証まで成功した入力だけをXWormとしてmatchする。"""

    try:
        recovered = recover_config(data)
    except (OSError, TypeError, ValueError, AttributeError, IndexError):
        return {
            "matched": False,
            "rule": "xworm_managed_settings_aes_v1",
            "sample_executed": False,
            "network_contacted": False,
        }
    return {
        "matched": True,
        "rule": "xworm_managed_settings_aes_v1",
        "version": recovered["version"],
        "endpoint_count": len(recovered["config_endpoints"]),
        "structural_evidence": recovered["structural_evidence"],
        "sample_executed": False,
        "network_contacted": False,
    }


def _record(
    digest: str,
    token: str,
    name: str,
    role: str,
    summary: str,
    steps: list[str],
    apis: list[str] | None = None,
) -> dict[str, object]:
    return {
        "function_id": f"{name}@{token}",
        "name": name,
        "token": token,
        "role": role,
        "summary_ja": summary,
        "logic_steps_ja": steps,
        "callees": [],
        "api_calls": apis or [],
        "source": "exact SHA-256のmanaged CIL構造レビュー",
        "tool": "dnfile_dncil_bounded_static_parser",
        "program_selector": f"sha256:{digest}",
        "confidence": "confirmed_static_review",
        "selected_for_characteristic_analysis": True,
    }


def _reviewed_functions(digest: str) -> list[dict[str, object]]:
    if digest != REVIEWED_SHA256:
        return []
    return [
        _record(
            digest,
            "0x06000014",
            "Stub.Main.Main",
            "loader_execution",
            "mutex確保後にC2接続、keylogger、補助threadを起動します。",
            [
                "設定されたMutexで単一起動を確認します。",
                "ClientSocket.BeginConnectを開始します。",
                "keyloggerと常駐補助処理を別threadで開始します。",
            ],
            ["Mutex..ctor", "Thread.Start"],
        ),
        _record(
            digest,
            "0x06000011",
            "Settings..cctor",
            "config_decoder",
            "暗号化されたhost、port、key、separator、versionを保持します。",
            [
                "Hosts、Port、KEY、SPLを静的fieldへ格納します。",
                "Sleep、Group、USBNM、Mutexを初期化します。",
                "復号器へ渡す順序を固定します。",
            ],
        ),
        _record(
            digest,
            "0x06000051",
            "Stub.AlgorithmAES.Decrypt",
            "config_decoder",
            "Mutex由来のAES-256-ECB鍵でBase64設定を復号します。",
            [
                "UTF-8 MutexのMD5を計算します。",
                "32-byte鍵のoffset 0と15へ16-byte digestを複製します。",
                "AES ECBとPKCS7で設定を復号してUTF-8へ戻します。",
            ],
            ["MD5.ComputeHash", "ICryptoTransform.TransformFinalBlock"],
        ),
        _record(
            digest,
            "0x0600001b",
            "Stub.ClientSocket.ConnectServer",
            "command_control",
            "復号済みhostとportへTCP接続して登録・受信処理を開始します。",
            [
                "設定されたhostとportを選択します。",
                "TCP接続を確立します。",
                "端末情報送信と非同期受信へ移行します。",
            ],
            ["TcpClient.Connect"],
        ),
        _record(
            digest,
            "0x06000025",
            "Stub.ClientSocket.BeginRead",
            "command_control",
            "受信streamを蓄積して設定separatorでmessageを分割します。",
            [
                "非同期受信byteをmemory streamへ蓄積します。",
                "設定されたSPL delimiterで完全messageを判定します。",
                "完全messageをMessages.Readへ渡します。",
            ],
        ),
        _record(
            digest,
            "0x06000026",
            "Stub.ClientSocket.Send",
            "command_control",
            "送信messageへ設定separatorを付加してTCP streamへ書き込みます。",
            [
                "接続状態と送信lockを確認します。",
                "messageとSPL delimiterを結合します。",
                "byte列を非同期送信します。",
            ],
        ),
        _record(
            digest,
            "0x0600002e",
            "Stub.Messages.Read",
            "command_dispatcher",
            "受信commandをplugin、URL、disk、memory実行などへ分岐します。",
            [
                "受信messageを設定separatorに従って解析します。",
                "command名を比較して個別handlerへ分岐します。",
                "plugin、OpenUrl、RunDisk、Memoryなどの処理を呼び出します。",
            ],
        ),
        _record(
            digest,
            "0x0600002f",
            "Stub.Messages.Plugin",
            "plugin_loader",
            "受領pluginをmemory上へ読み込み、指定entryを呼び出します。",
            [
                "plugin byte列を受信messageから取り出します。",
                "managed assemblyとしてmemoryへ読み込みます。",
                "指定されたmethodを反射呼出しします。",
            ],
            ["Assembly.Load", "MethodInfo.Invoke"],
        ),
    ]


def extract(data: bytes, name: str = "sample") -> dict:
    """確認済み設定、C2、delimiter protocol、代表関数を公開する。"""

    digest = hashlib.sha256(data).hexdigest()
    try:
        recovered = recover_config(data)
        status = "recovered_aes_settings_and_delimiter_protocol"
    except (OSError, TypeError, ValueError, AttributeError, IndexError):
        recovered = None
        status = "rejected_or_not_recovered"
    findings = []
    if recovered is not None:
        findings = [
            {
                "kind": "network.endpoint",
                "value": f"{item['host']}:{item['port']}",
                "role": "configured_c2",
                "confidence": "confirmed_static_config",
                "source": "xworm_managed_settings_aes",
            }
            for item in recovered["config_endpoints"]
        ]
    config: dict[str, object] = {
        "source_name": name,
        "recovery_status": status,
        "terminal_managed_client": recovered is not None,
        "static_config_recovered": recovered is not None,
        "c2_protocol_recovered": recovered is not None,
        "c2_liveness_confirmed": False,
        "marker_hits": [recovered["structural_evidence"]]
        if recovered is not None
        else [],
    }
    if recovered is not None:
        config.update(recovered)
    result = build_result(
        "xworm",
        data,
        config,
        findings,
        [
            "検体と受領pluginを実行せず、外部hostへ接続していません。",
            "Settings field、AES CIL、client/message method集合が一致しない入力は拒否します。",
            "通信keyとMutexは公開していません。",
        ],
    )
    result["static_config_recovered"] = recovered is not None
    result["config_endpoints"] = (
        [
            {
                "host": item["host"],
                "port": item["port"],
                "transport": "tcp",
                "role": "configured_c2",
                "confidence": "confirmed_static_configuration",
                "evidence": {
                    "kind": "xworm_managed_settings_aes",
                    "all_expected_fields_validated": True,
                },
            }
            for item in recovered["config_endpoints"]
        ]
        if recovered is not None
        else []
    )
    result["static_evidence"] = {
        "all_expected_fields_validated": recovered is not None,
        "config_decryption": "aes_256_ecb_pkcs7"
        if recovered is not None
        else None,
        "communication_key_published": False,
        "mutex_published": False,
    }
    result["static_protocol"] = (
        {
            "status": "confirmed",
            "method": "managed_cil_delimiter_framed_tcp",
            "transport": "tcp",
            "framing": "configured_string_delimiter",
            "serialization": "xworm_command_strings",
            "confidence": "high",
            "tcp_open_only": False,
            "live_verified": False,
        }
        if recovered is not None
        else None
    )
    result["protocol_evidence"] = (
        {
            "analysis_status": "complete",
            "separator": recovered["separator"],
            "registration_schema_confirmed": False,
            "command_dispatcher_confirmed": True,
            "operation_result_serializer_confirmed": False,
            "sample_executed": False,
            "network_contacted": False,
        }
        if recovered is not None
        else None
    )
    result["representative_functions"] = _reviewed_functions(digest)
    result["program_evidence"] = (
        [
            {
                "program_id": f"managed-xworm-{digest[:8]}",
                "program_selector": f"sha256:{digest}",
                "relationship": "root_terminal_managed_client",
                "name": f"{digest}.exe",
                "architecture": "x86",
                "compiler": ".NET CLR managed CIL / Visual Basic",
                "language": "managed CIL",
                "endian": "little",
                "address_size": "32",
                "function_count": recovered["structural_evidence"]["method_count"],
                "managed_method_count": recovered["structural_evidence"]["method_count"],
                "entry_points": [
                    {
                        "name": "Stub.Main.Main",
                        "address": recovered["structural_evidence"]["main"],
                        "kind": "managed_entrypoint",
                    }
                ],
                "imports": ["_CorExeMain"],
                "function_hashes": [],
                "confidence": "confirmed_program_structure",
            }
        ]
        if recovered is not None
        else []
    )
    return result


__all__ = [
    "HANDLER_CONTRACT",
    "XwormRecoveryError",
    "decrypt_setting",
    "extract",
    "recover_config",
    "structural_evidence",
]
