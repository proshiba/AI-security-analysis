#!/usr/bin/env python3
"""AsyncRAT／VenomRATの登録fieldとcommand dispatcherをCILから復元する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes

MAXIMUM_INPUT_BYTES = 32 * 1024 * 1024
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

FAMILY_PROFILES: dict[str, dict[str, Any]] = {
    "asyncrat": {
        "registration_method": ("Client.Helper.IdSender", "SendInfo"),
        "dispatcher_method": ("Client.Handle_Packet.Packet", "Read"),
        "heartbeat_method": ("Client.Connection.ClientSocket", "KeepAlivePacket"),
        "packet_key": "Packet",
        "client_info_value": "ClientInfo",
        "required_registration_fields": (
            "Packet",
            "HWID",
            "User",
            "OS",
            "Path",
            "Admin",
            "Performance",
            "Pastebin",
            "Antivirus",
            "Installed",
            "Pong",
            "Group",
        ),
        "optional_registration_fields": ("Version",),
        "command_markers": (
            "winUpdate",
            "pong",
            "plugin",
            "savePlugin",
        ),
        "heartbeat_request_packet": "Ping",
        "heartbeat_request_message": "",
        "heartbeat_response_markers": ("pong",),
        "transfer_markers": ("winUpdate", "plugin", "savePlugin"),
    },
    "venomrat": {
        "registration_method": ("Client.Helper.IdSender", "SendInfo"),
        "dispatcher_method": ("Client.Connection.ClientSocket", "Read"),
        "heartbeat_method": ("Client.Connection.ClientSocket", "KeepAlivePacket"),
        "packet_key": "Pac_ket",
        "client_info_value": "ClientInfo",
        "required_registration_fields": (
            "Pac_ket",
            "ClientType",
            "HWID",
            "DesktopName",
            "User",
            "OS",
            "Camera",
            "Path",
            "Version",
            "Admin",
            "Perfor_mance",
            "Paste_bin",
            "Anti_virus",
            "Install_ed",
            "Po_ng",
            "Group",
            "CPU",
            "GPU",
            "RAM",
            "apps",
            "running",
            "keylogsetting",
        ),
        "optional_registration_fields": (),
        "command_markers": (
            "init_reg",
            "loadofflinelog",
            "Po_ng",
            "plu_gin",
            "save_Plugin",
            "HVNCStop",
            "keylogsetting",
            "runningapp",
            "filterinfo",
        ),
        "heartbeat_request_packet": "Ping",
        "heartbeat_request_message": "",
        "heartbeat_response_markers": ("Po_ng",),
        "transfer_markers": ("plu_gin", "save_Plugin", "loadofflinelog"),
    },
}


class ProtocolEvidenceError(ValueError):
    """CLR metadataまたはreview対象methodが期待形状と一致しない。"""


def _method_owners(pe: dnfile.dnPE) -> dict[int, str]:
    owners: dict[int, str] = {}
    typedef = getattr(getattr(pe.net, "mdtables", None), "TypeDef", None)
    for row in getattr(typedef, "rows", []) or []:
        owner = ".".join(
            value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
        )
        for method in row.MethodList:
            owners[method.row_index] = owner
    return owners


def _token_name(pe: dnfile.dnPE, token: int, owners: dict[int, str]) -> str:
    table_id = (token >> 24) & 0xFF
    row_id = token & 0xFFFFFF
    if table_id == 0x06:
        table = getattr(pe.net.mdtables, "MethodDef", None)
        if table is not None and 1 <= row_id <= len(table.rows):
            return f"{owners.get(row_id, '')}.{table.rows[row_id - 1].Name}".strip(".")
    if table_id == 0x0A:
        table = getattr(pe.net.mdtables, "MemberRef", None)
        if table is not None and 1 <= row_id <= len(table.rows):
            return str(table.rows[row_id - 1].Name)
    if table_id == 0x2B:
        return "MethodSpec"
    return f"token:{token:#x}"


def _user_string(pe: dnfile.dnPE, token: int) -> str:
    try:
        return str(pe.net.user_strings.get(token & 0xFFFFFF).value)
    except Exception as exc:
        raise ProtocolEvidenceError("CIL user stringを復号できません") from exc


def _semantic_digest(parts: list[str]) -> str:
    return hashlib.sha256("\n".join(parts).encode("utf-8")).hexdigest()


def extract_method_records(data: bytes) -> list[dict[str, Any]]:
    """選択に必要なmethodについて、秘密値を出さないCIL要約を返す。"""

    try:
        pe = dnfile.dnPE(data=data)
    except Exception as exc:
        raise ProtocolEvidenceError("PE／CLR metadataを解析できません") from exc
    if pe.net is None or pe.net.mdtables is None:
        raise ProtocolEvidenceError("CLR metadataがありません")
    method_table = getattr(pe.net.mdtables, "MethodDef", None)
    if method_table is None or not method_table.rows:
        raise ProtocolEvidenceError("MethodDef tableがありません")
    owners = _method_owners(pe)
    records: list[dict[str, Any]] = []
    for index, row in enumerate(method_table.rows, 1):
        if not row.Rva:
            continue
        try:
            body = read_method_body_from_bytes(data[pe.get_offset_from_rva(row.Rva) :])
        except Exception:  # noqa: BLE001, S112 - malformed non-target methods are skipped
            continue
        literals: list[str] = []
        path_keys: list[str] = []
        calls: list[str] = []
        semantic: list[str] = []
        last_literal: str | None = None
        for instruction in body.instructions:
            opcode = instruction.opcode.name
            operand = getattr(instruction.operand, "value", instruction.operand)
            semantic.append(opcode)
            if opcode == "ldstr" and isinstance(operand, int):
                last_literal = _user_string(pe, operand)
                literals.append(last_literal)
                semantic.append(f"str_sha256:{hashlib.sha256(last_literal.encode('utf-8')).hexdigest()}")
                continue
            if opcode in {"call", "callvirt", "newobj"} and isinstance(operand, int):
                call_name = _token_name(pe, operand, owners)
                calls.append(call_name)
                semantic.append(f"call:{call_name}")
                if call_name.rsplit(".", 1)[-1] == "ForcePathObject" and last_literal is not None:
                    path_keys.append(last_literal)
                last_literal = None
                continue
            if opcode != "nop":
                last_literal = None
        records.append(
            {
                "token": f"0x0600{index:04x}",
                "owner": owners.get(index, ""),
                "name": str(row.Name),
                "literals": literals,
                "path_keys": path_keys,
                "calls": calls,
                "cil_semantic_sha256": _semantic_digest(semantic),
            }
        )
    return records


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _select_record(
    records: list[dict[str, Any]], owner: str, name: str
) -> dict[str, Any]:
    candidates = [
        item for item in records if item.get("owner") == owner and item.get("name") == name
    ]
    if not candidates:
        raise ProtocolEvidenceError(f"review対象methodがありません: {owner}.{name}")
    return max(candidates, key=lambda item: len(item.get("path_keys") or []))


def summarize_records(
    records: list[dict[str, Any]], family: str, sample_sha256: str
) -> dict[str, Any]:
    """method recordをfamily別の公開可能なprotocol証拠へ正規化する。"""

    if family not in FAMILY_PROFILES:
        raise ProtocolEvidenceError("未対応familyです")
    digest = sample_sha256.casefold()
    if not SHA256_RE.fullmatch(digest):
        raise ProtocolEvidenceError("sample SHA-256が不正です")
    profile = FAMILY_PROFILES[family]
    registration = _select_record(records, *profile["registration_method"])
    dispatcher = _select_record(records, *profile["dispatcher_method"])
    keepalive = _select_record(records, *profile["heartbeat_method"])
    registration_keys = _unique([str(value) for value in registration["path_keys"]])
    dispatcher_literals = {str(value) for value in dispatcher["literals"]}
    required = list(profile["required_registration_fields"])
    optional = list(profile["optional_registration_fields"])
    commands = list(profile["command_markers"])
    observed_required = [value for value in required if value in registration_keys]
    observed_optional = [value for value in optional if value in registration_keys]
    observed_commands = [value for value in commands if value in dispatcher_literals]
    missing_required = [value for value in required if value not in registration_keys]
    missing_commands = [value for value in commands if value not in dispatcher_literals]
    heartbeat = [
        value
        for value in profile["heartbeat_response_markers"]
        if value in dispatcher_literals
    ]
    transfers = [
        value for value in profile["transfer_markers"] if value in dispatcher_literals
    ]
    keepalive_literals = {str(value) for value in keepalive["literals"]}
    keepalive_calls = {
        str(value).rsplit(".", 1)[-1] for value in keepalive["calls"]
    }
    required_heartbeat_literals = {
        str(profile["packet_key"]),
        str(profile["heartbeat_request_packet"]),
        "Message",
    }
    required_heartbeat_calls = {"GetActiveWindowTitle", "Encode2Bytes", "Send"}
    heartbeat_request_confirmed = (
        required_heartbeat_literals <= keepalive_literals
        and required_heartbeat_calls <= keepalive_calls
    )
    complete = (
        not missing_required
        and not missing_commands
        and heartbeat_request_confirmed
        and bool(heartbeat)
    )
    return {
        "schema_version": 1,
        "family": family,
        "sample_sha256": digest,
        "analysis_status": "complete" if complete else "partial",
        "registration": {
            "packet_key": profile["packet_key"],
            "packet_value": profile["client_info_value"],
            "method": f"{registration['owner']}.{registration['name']}",
            "method_token": registration["token"],
            "cil_semantic_sha256": registration["cil_semantic_sha256"],
            "observed_required_fields": observed_required,
            "observed_optional_fields": observed_optional,
            "missing_required_fields": missing_required,
            "synthetic_values_required": True,
            "real_host_metadata_allowed": False,
        },
        "dispatcher": {
            "method": f"{dispatcher['owner']}.{dispatcher['name']}",
            "method_token": dispatcher["token"],
            "cil_semantic_sha256": dispatcher["cil_semantic_sha256"],
            "observed_command_markers": observed_commands,
            "missing_command_markers": missing_commands,
            "heartbeat_request": {
                "method": f"{keepalive['owner']}.{keepalive['name']}",
                "method_token": keepalive["token"],
                "cil_semantic_sha256": keepalive["cil_semantic_sha256"],
                "packet_key": profile["packet_key"],
                "packet_value": profile["heartbeat_request_packet"],
                "message_key": "Message",
                "message_source": "active_window_title",
                "emulator_message_value": profile["heartbeat_request_message"],
                "sanitized_for_privacy": True,
                "schema_confirmed": heartbeat_request_confirmed,
            },
            "heartbeat_response_markers": heartbeat,
            "file_or_plugin_transfer_markers": transfers,
        },
        "emulator_readiness": {
            "registration_schema_confirmed": not missing_required,
            "command_dispatcher_confirmed": not missing_commands,
            "heartbeat_request_response_confirmed": (
                heartbeat_request_confirmed and bool(heartbeat)
            ),
            "operation_result_serializer_confirmed": False,
            "live_operation_fake_result_allowed": False,
            "unknown_command_reply_allowed": False,
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_cil_published": False,
            "unreviewed_literals_published": False,
        },
    }


def recover(data: bytes, family: str, expected_sha256: str) -> dict[str, Any]:
    """hash確認済みPEからprotocol証拠を復元する。"""

    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_sha256.casefold():
        raise ProtocolEvidenceError(
            f"sample SHA-256が一致しません: expected={expected_sha256}, actual={actual}"
        )
    return summarize_records(extract_method_records(data), family, actual)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--family", required=True, choices=sorted(FAMILY_PROFILES))
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.input.stat().st_size > MAXIMUM_INPUT_BYTES:
        parser.error("入力が32 MiB上限を超えています")
    try:
        result = recover(args.input.read_bytes(), args.family, args.expected_sha256)
    except (OSError, ProtocolEvidenceError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "family": result["family"],
                "sample_sha256": result["sample_sha256"],
                "analysis_status": result["analysis_status"],
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
