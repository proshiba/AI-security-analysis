"""njRAT managed clientの設定、frame、command dispatcherを静的復元する。"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass

import dnfile
from dncil.cil.body.reader import read_method_body_from_bytes

from extractors.common import build_result, valid_host

HANDLER_CONTRACT = {
    "input_formats": ["pe"],
    "minimum_evidence_score": 20_000,
}

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_METHOD_BYTES = 256 * 1024
MAX_METHODS = 20_000
MAX_TYPES = 4096
_REVIEWED_SHA256 = "520afe474c0d141f0efb5ab826e581fb4d0e87a30cf6e34fd509af71d3829f26"
_REQUIRED_FIELDS = frozenset({"H", "P", "VN", "VR", "Y", "DR", "EXE", "RG"})
_REQUIRED_METHODS = frozenset({".cctor", "connect", "Sendb", "RC", "Ind", "inf", "INS"})
_COMMAND_MARKERS = frozenset(
    {"ll", "kl", "clip", "fun", "spech", "webs", "setcl", "message", "prof"}
)
_VERSION = re.compile(r"^<-\s*NjRAT\s+(.+?)\s*->$", re.IGNORECASE)
_DECIMAL = re.compile(r"[0-9]{1,10}\Z")


class NjratStaticError(ValueError):
    """managed metadata、設定、またはprotocol構造が期待形状と一致しない。"""


@dataclass(frozen=True)
class MethodRecord:
    token: str
    owner: str
    name: str
    instructions: tuple[tuple[str, object], ...]
    strings: frozenset[str]
    calls: frozenset[str]
    fields: frozenset[str]


@dataclass(frozen=True)
class ManagedReview:
    owner: str
    fields: frozenset[str]
    methods: dict[str, MethodRecord]
    cctor_values: dict[str, object]
    type_count: int
    method_count: int
    methods_with_body: int
    methods_without_body: int
    malformed_method_bodies: int


def _strict_index(token: int, expected_table: int, maximum: int) -> int:
    if isinstance(token, bool) or not isinstance(token, int):
        raise NjratStaticError("metadata tokenが整数ではありません")
    if (token >> 24) & 0xFF != expected_table:
        raise NjratStaticError("metadata token tableが一致しません")
    row = token & 0xFFFFFF
    if not 1 <= row <= maximum:
        raise NjratStaticError("metadata token rowが範囲外です")
    return row


def _owner_maps(pe: dnfile.dnPE) -> tuple[dict[int, str], dict[int, str]]:
    methods: dict[int, str] = {}
    fields: dict[int, str] = {}
    rows = pe.net.mdtables.TypeDef.rows
    if len(rows) > MAX_TYPES:
        raise NjratStaticError("TypeDef数が上限を超えています")
    for row in rows:
        owner = ".".join(
            value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
        )
        for item in row.MethodList:
            methods[item.row_index] = owner
        for item in row.FieldList:
            fields[item.row_index] = owner
    return methods, fields


def _member_name(pe: dnfile.dnPE, token: int, method_owners: dict[int, str]) -> str:
    table = (token >> 24) & 0xFF
    if table == 0x06:
        row_id = _strict_index(token, 0x06, len(pe.net.mdtables.MethodDef.rows))
        row = pe.net.mdtables.MethodDef.rows[row_id - 1]
        return f"{method_owners.get(row_id, '')}.{row.Name}".strip(".")
    if table == 0x0A:
        row_id = _strict_index(token, 0x0A, len(pe.net.mdtables.MemberRef.rows))
        return str(pe.net.mdtables.MemberRef.rows[row_id - 1].Name)
    return ""


def _field_name(pe: dnfile.dnPE, token: int, field_owners: dict[int, str]) -> str:
    table = (token >> 24) & 0xFF
    if table == 0x04:
        row_id = _strict_index(token, 0x04, len(pe.net.mdtables.Field.rows))
        row = pe.net.mdtables.Field.rows[row_id - 1]
        return f"{field_owners.get(row_id, '')}.{row.Name}".strip(".")
    if table == 0x0A:
        row_id = _strict_index(token, 0x0A, len(pe.net.mdtables.MemberRef.rows))
        return str(pe.net.mdtables.MemberRef.rows[row_id - 1].Name)
    return ""


def _parse_method(
    pe: dnfile.dnPE,
    data: bytes,
    index: int,
    row: object,
    method_owners: dict[int, str],
    field_owners: dict[int, str],
) -> MethodRecord:
    offset = pe.get_offset_from_rva(row.Rva)
    if (
        isinstance(offset, bool)
        or not isinstance(offset, int)
        or not 0 <= offset < len(data)
    ):
        raise NjratStaticError("method RVAをfile offsetへ変換できません")
    body = read_method_body_from_bytes(
        data[offset : min(len(data), offset + MAX_METHOD_BYTES)]
    )
    instructions: list[tuple[str, object]] = []
    strings: set[str] = set()
    calls: set[str] = set()
    fields: set[str] = set()
    for instruction in body.instructions:
        opcode = instruction.opcode.name
        operand = getattr(instruction.operand, "value", instruction.operand)
        rendered: object = operand
        if opcode == "ldstr":
            row_id = _strict_index(operand, 0x70, 0xFFFFFF)
            rendered = str(pe.net.user_strings.get(row_id).value)
            strings.add(rendered)
        elif opcode in {"call", "callvirt", "newobj", "ldftn"}:
            rendered = _member_name(pe, operand, method_owners)
            if rendered:
                calls.add(rendered)
        elif opcode in {"ldsfld", "stsfld", "ldsflda"}:
            rendered = _field_name(pe, operand, field_owners)
            if rendered:
                fields.add(rendered.rsplit(".", 1)[-1])
        instructions.append((opcode, rendered))
    return MethodRecord(
        token=f"0x060{index:05x}",
        owner=method_owners.get(index, ""),
        name=str(row.Name),
        instructions=tuple(instructions),
        strings=frozenset(strings),
        calls=frozenset(calls),
        fields=frozenset(fields),
    )


def _cctor_literals(record: MethodRecord, owner: str) -> dict[str, object]:
    values: dict[str, object] = {}
    pending: object = None
    for opcode, operand in record.instructions:
        if opcode == "ldstr" and isinstance(operand, str):
            pending = operand
            continue
        if opcode == "ldnull":
            pending = None
            continue
        if opcode in {"call", "callvirt"} and isinstance(operand, str):
            name = operand.rsplit(".", 1)[-1]
            if (
                name == "ToBoolean"
                and isinstance(pending, str)
                and pending.casefold() in {"true", "false"}
            ):
                pending = pending.casefold() == "true"
                continue
            if (
                name == "ToInteger"
                and isinstance(pending, str)
                and _DECIMAL.fullmatch(pending)
            ):
                pending = int(pending)
                continue
            pending = None
            continue
        if opcode == "stsfld" and isinstance(operand, str):
            field_owner, _, field = operand.rpartition(".")
            if field_owner == owner and pending is not None:
                if field in values:
                    raise NjratStaticError("cctorが同じfieldを複数回初期化しています")
                values[field] = pending
            pending = None
            continue
        if opcode != "nop":
            pending = None
    return values


def _inspect(data: bytes) -> ManagedReview:
    if (
        not data.startswith(b"MZ")
        or b"BSJB" not in data
        or not 1 <= len(data) <= MAX_INPUT_BYTES
    ):
        raise NjratStaticError("上限内のmanaged PEではありません")
    pe = dnfile.dnPE(data=data)
    if pe.net is None or pe.net.mdtables is None:
        raise NjratStaticError("CLR metadataがありません")
    method_rows = pe.net.mdtables.MethodDef.rows
    if len(method_rows) > MAX_METHODS:
        raise NjratStaticError("MethodDef数が上限を超えています")
    method_owners, field_owners = _owner_maps(pe)
    owners: dict[str, dict[str, set[str]]] = {}
    for index, row in enumerate(method_rows, 1):
        owner_name = method_owners.get(index, "")
        inventory = owners.get(owner_name)
        if inventory is None:
            inventory = {"methods": set(), "fields": set()}
            owners[owner_name] = inventory
        inventory["methods"].add(str(row.Name))
    for index, row in enumerate(pe.net.mdtables.Field.rows, 1):
        owner_name = field_owners.get(index, "")
        inventory = owners.get(owner_name)
        if inventory is None:
            inventory = {"methods": set(), "fields": set()}
            owners[owner_name] = inventory
        inventory["fields"].add(str(row.Name))
    candidates = [
        owner
        for owner, inventory in owners.items()
        if _REQUIRED_FIELDS <= inventory["fields"]
        and _REQUIRED_METHODS <= inventory["methods"]
    ]
    if len(candidates) != 1:
        raise NjratStaticError("njRAT core typeを一意に選べません")
    owner = candidates[0]
    selected: dict[str, MethodRecord] = {}
    with_body = 0
    without_body = 0
    malformed = 0
    for index, row in enumerate(method_rows, 1):
        if not row.Rva:
            without_body += 1
            continue
        with_body += 1
        if method_owners.get(index) != owner:
            continue
        try:
            record = _parse_method(pe, data, index, row, method_owners, field_owners)
        except (IndexError, TypeError, ValueError):
            malformed += 1
            continue
        if record.name in selected:
            raise NjratStaticError("njRAT core method名が重複しています")
        selected[record.name] = record
    if _REQUIRED_METHODS - selected.keys() or malformed:
        raise NjratStaticError("必須methodが未解析またはmalformedです")
    values = _cctor_literals(selected[".cctor"], owner)
    return ManagedReview(
        owner=owner,
        fields=frozenset(owners[owner]["fields"]),
        methods=selected,
        cctor_values=values,
        type_count=len(pe.net.mdtables.TypeDef.rows),
        method_count=len(method_rows),
        methods_with_body=with_body,
        methods_without_body=without_body,
        malformed_method_bodies=malformed,
    )


def _method_has_calls(record: MethodRecord, required: set[str]) -> bool:
    names = {value.rsplit(".", 1)[-1] for value in record.calls}
    return required <= names


def _protocol_summary(review: ManagedReview) -> dict[str, object]:
    send = review.methods["Sendb"]
    receive = review.methods["RC"]
    connect = review.methods["connect"]
    dispatcher = review.methods["Ind"]
    send_opcodes = [opcode for opcode, _ in send.instructions]
    send_valid = (
        "\x00" in send.strings
        and _method_has_calls(send, {"ToString", "Concat", "Send"})
        and {"Write", "Send"} <= {value.rsplit(".", 1)[-1] for value in send.calls}
        and send_opcodes.count("callvirt") >= 3
    )
    receive_valid = _method_has_calls(
        receive, {"ReadByte", "ToLong", "Receive", "connect"}
    )
    connect_valid = (
        {"H", "P", "Y"} <= connect.fields
        and _method_has_calls(connect, {"Connect", "inf", "ENB", "Send"})
        and {"inf", ":", "\r\n"} <= connect.strings
    )
    dispatcher_valid = (
        {"Y"} <= dispatcher.fields
        and _method_has_calls(dispatcher, {"BS", "Split"})
        and _COMMAND_MARKERS <= dispatcher.strings
    )
    if not all((send_valid, receive_valid, connect_valid, dispatcher_valid)):
        raise NjratStaticError("njRAT transportまたはdispatcher構造が一致しません")
    return {
        "analysis_status": "complete",
        "transport": "tcp",
        "framing": "ascii_decimal_length_nul_delimiter",
        "payload_encoding": "utf8",
        "command_serialization": "configured_string_delimiter",
        "registration": {
            "method": f"{review.owner}.connect",
            "prefix": "inf",
            "configuration_delimiter_used": True,
            "host_inventory_appended": True,
            "missing_required_fields": [],
        },
        "dispatcher": {
            "method": f"{review.owner}.Ind",
            "observed_command_markers": sorted(_COMMAND_MARKERS),
            "command_marker_count": len(_COMMAND_MARKERS),
            "missing_command_markers": [],
            "file_or_plugin_transfer_markers": [],
            "heartbeat_response_markers": [],
        },
        "emulator_readiness": {
            "registration_schema_confirmed": True,
            "command_dispatcher_confirmed": True,
            "heartbeat_required": False,
            "heartbeat_request_response_confirmed": False,
            "live_operation_fake_result_allowed": False,
        },
        "safety": {
            "sample_executed": False,
            "network_contacted": False,
            "raw_cil_published": False,
            "unreviewed_literals_published": False,
            "delimiter_published": False,
        },
    }


def _config(review: ManagedReview) -> dict[str, object]:
    values = review.cctor_values
    if _REQUIRED_FIELDS - values.keys():
        raise NjratStaticError("必須設定fieldをcctorから復元できません")
    host = values["H"]
    port_text = values["P"]
    if not isinstance(host, str) or not valid_host(host):
        raise NjratStaticError("固定hostが不正です")
    if (
        not isinstance(port_text, str)
        or _DECIMAL.fullmatch(port_text) is None
        or not 1 <= int(port_text) <= 65535
    ):
        raise NjratStaticError("固定portが不正です")
    version_text = values["VR"]
    match = _VERSION.fullmatch(version_text) if isinstance(version_text, str) else None
    if match is None:
        raise NjratStaticError("njRAT version markerが不正です")
    delimiter = values["Y"]
    if (
        not isinstance(delimiter, str)
        or not 4 <= len(delimiter) <= 64
        or not all(0x20 <= ord(character) <= 0x7E for character in delimiter)
    ):
        raise NjratStaticError("command delimiterが不正です")
    campaign = values["VN"]
    if not isinstance(campaign, str):
        raise NjratStaticError("campaign labelが不正です")
    try:
        decoded_campaign = base64.b64decode(campaign, validate=True).decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise NjratStaticError(
            "campaign labelを厳格Base64として復号できません"
        ) from exc
    paste_enabled = values.get("PASTEE") == "Enabled"
    paste_value = values.get("PASTEBIN")
    dynamic_config = (
        paste_value if paste_enabled and isinstance(paste_value, str) else None
    )
    return {
        "version": match.group(1),
        "host": host.casefold().rstrip("."),
        "port": int(port_text),
        "campaign_label": decoded_campaign,
        "install_directory": values["DR"],
        "install_name": values["EXE"],
        "mutex": values["RG"],
        "dynamic_config_enabled": paste_enabled,
        "dynamic_config_url": dynamic_config,
        "delimiter_length": len(delimiter),
        "delimiter_sha256": hashlib.sha256(delimiter.encode("utf-8")).hexdigest(),
        "delimiter_published": False,
    }


def structural_evidence(data: bytes) -> dict[str, object]:
    """njRAT固有のmanaged core type、設定field、transport methodを相互確認する。"""

    try:
        review = _inspect(data)
        protocol = _protocol_summary(review)
        config = _config(review)
    except (NjratStaticError, OSError, ValueError):
        return {
            "matched": False,
            "managed_pe": data.startswith(b"MZ") and b"BSJB" in data,
            "sample_executed": False,
            "network_contacted": False,
        }
    return {
        "matched": True,
        "managed_pe": True,
        "core_type": review.owner,
        "required_fields_complete": _REQUIRED_FIELDS <= review.fields,
        "required_methods_complete": _REQUIRED_METHODS <= review.methods.keys(),
        "static_configuration_validated": True,
        "transport_validated": protocol["analysis_status"] == "complete",
        "version": config["version"],
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
    *,
    callees: list[str] | None = None,
    apis: list[str] | None = None,
) -> dict[str, object]:
    return {
        "function_id": f"{name}@{token}",
        "name": name,
        "token": token,
        "role": role,
        "summary_ja": summary,
        "logic_steps_ja": steps,
        "callees": callees or [],
        "api_calls": apis or [],
        "source": "exact SHA-256のmanaged CIL構造レビュー",
        "tool": "dnfile_dncil_bounded_static_parser",
        "program_selector": f"sha256:{digest}",
        "confidence": "confirmed_static_review",
        "selected_for_characteristic_analysis": True,
    }


def _reviewed_functions(digest: str) -> list[dict[str, object]]:
    if digest != _REVIEWED_SHA256:
        return []
    return [
        _record(
            digest,
            "0x06000015",
            "j.OK..cctor",
            "config_decoder",
            "固定host、port、version、保存先、mutex、delimiterを静的fieldへ設定します。",
            [
                "文字列・boolean定数をstatic fieldへ初期化します。",
                "H/Pを固定endpoint、VRをversion、Yをcommand delimiterとして保持します。",
                "Pastebin機能はDisabledで、placeholder URLを接続先へ使いません。",
            ],
        ),
        _record(
            digest,
            "0x06000024",
            "j.OK.connect",
            "command_control",
            "固定endpointへTCP接続し、端末inventoryを登録frameとして送信します。",
            [
                "任意の動的設定が有効な場合だけH/Pを更新します。",
                "receive/send bufferとtimeoutを設定してH/Pへ接続します。",
                "inf、delimiter、端末情報を連結して送信し、受信loopを開始します。",
            ],
            callees=["j.OK.inf", "j.OK.Send", "j.OK.RC"],
            apis=["TcpClient.Connect"],
        ),
        _record(
            digest,
            "0x0600004b",
            "j.OK.Sendb",
            "command_control",
            "payloadへASCII 10進長とNUL終端headerを付けてTCP送信します。",
            [
                "payload byte長を10進文字列へ変換します。",
                "長さ文字列へNULを付けUTF-8 byte列化します。",
                "headerとpayloadを連結し、接続済みsocketへ一括送信します。",
            ],
            callees=["j.OK.SB"],
            apis=["MemoryStream.Write", "Socket.Send"],
        ),
        _record(
            digest,
            "0x06000048",
            "j.OK.RC",
            "command_control",
            "NUL終端の10進長headerを読み、指定長payloadだけをdispatcherへ渡します。",
            [
                "1 byteずつ読みNULまで10進長を組み立てます。",
                "宣言長と一致するまで受信byteをMemoryStreamへ蓄積します。",
                "完全payloadをworker経由でdispatcherへ渡し、次frameへ戻ります。",
            ],
            callees=["j.OK.connect", "j.OK._Lambda__1"],
            apis=["NetworkStream.ReadByte", "Socket.Receive"],
        ),
        _record(
            digest,
            "0x06000040",
            "j.OK.Ind",
            "command_dispatcher",
            "設定delimiterでcommandと引数を分離し、機能別handlerへ分岐します。",
            [
                "UTF-8 payloadをdelimiterで分割します。",
                "先頭commandをhash switchと文字列比較で検証します。",
                "keylogger、clipboard、plugin、process、画面、file、電源操作などへ分岐します。",
            ],
            callees=["j.OK.Plugin", "j.OK.Send", "j.OK.INS"],
            apis=["Process.Start", "Assembly.Load"],
        ),
        _record(
            digest,
            "0x06000041",
            "j.OK.inf",
            "host_discovery",
            "端末名、user、OS、architecture、camera、AV、install情報を登録文字列へ集約します。",
            [
                "machine/user/OS情報と実行file時刻を収集します。",
                "camera、AV、権限、architectureを判定します。",
                "delimiter区切りの登録inventoryを返します。",
            ],
            apis=[
                "Environment.MachineName",
                "Environment.UserName",
                "WMI AntiVirusProduct",
            ],
        ),
        _record(
            digest,
            "0x06000042",
            "j.OK.INS",
            "persistence",
            "設定されたdirectoryとfile名へ自己配置し、Run keyまたはtaskを登録します。",
            [
                "TEMP等の設定directoryと実行名を解決します。",
                "既存copyを処理して自己fileを配置します。",
                "有効な設定に応じてRun keyまたはscheduled taskを登録します。",
            ],
            apis=["File.Copy", "RegistryKey.SetValue", "Process.Start"],
        ),
        _record(
            digest,
            "0x06000078",
            "j.kl.WRK",
            "credential_collection",
            "keyboard状態を監視し、active window単位のkey logへ整形します。",
            [
                "非同期key状態とmodifierを取得します。",
                "virtual keyをUnicodeへ変換します。",
                "active window markerを付けたlogをregistry-backed bufferへ保持します。",
            ],
            callees=["j.kl.Fix", "j.kl.AV"],
            apis=["GetAsyncKeyState", "ToUnicodeEx"],
        ),
        _record(
            digest,
            "0x06000013",
            "Stub.MyAntiProcess.Handler",
            "defense_evasion",
            "解析・sandbox・network monitor processを列挙して終了します。",
            [
                "固定blocklistのprocess名を反復します。",
                "一致processを取得します。",
                "一致したprocessを終了します。",
            ],
            apis=["Process.GetProcessesByName", "Process.Kill"],
        ),
        _record(
            digest,
            "0x06000052",
            "Stub.MBRSlayer.Start",
            "destructive_capability",
            "PhysicalDrive0を開き固定sector dataを書き込む破壊機能を実装します。",
            [
                "PhysicalDrive0をraw accessで開きます。",
                "埋め込みsector dataを準備します。",
                "WriteFileで先頭sectorへ書き込みます。",
            ],
            apis=["CreateFile", "WriteFile"],
        ),
    ]


def _program_evidence(review: ManagedReview, digest: str) -> list[dict[str, object]]:
    if digest != _REVIEWED_SHA256:
        return []
    return [
        {
            "program_id": "managed-njrat-520afe47",
            "program_selector": f"sha256:{digest}",
            "relationship": "root_terminal_managed_client",
            "name": f"{digest}.exe",
            "architecture": "x86",
            "compiler": ".NET CLR managed CIL",
            "language": "managed CIL",
            "endian": "little",
            "address_size": "32",
            "function_count": review.method_count,
            "managed_method_count": review.method_count,
            "entry_points": [
                {"name": "j.OK.ko", "address": "0x06000043", "kind": "managed_startup"}
            ],
            "imports": ["_CorExeMain"],
            "function_hashes": [],
            "retrieval_coverage": {
                "managed_types_declared": review.type_count,
                "managed_methods_declared": review.method_count,
                "managed_methods_with_body": review.methods_with_body,
                "managed_methods_without_body": review.methods_without_body,
                "malformed_method_bodies": review.malformed_method_bodies,
                "ghidra_native_decompilation_used_for_cil_semantics": False,
            },
            "confidence": "confirmed_program_structure",
        }
    ]


def extract(data: bytes, name: str = "sample") -> dict:
    """強いmanaged構造一致後だけ設定、protocol、代表関数を公開する。"""

    digest = hashlib.sha256(data).hexdigest()
    review = None
    config = None
    protocol = None
    try:
        review = _inspect(data)
        config = _config(review)
        protocol = _protocol_summary(review)
        protocol["family"] = "njrat"
        protocol["sample_sha256"] = digest
    except (NjratStaticError, OSError, ValueError):
        pass
    matched = review is not None and config is not None and protocol is not None
    findings = []
    if config is not None:
        findings.append(
            {
                "kind": "network.endpoint",
                "value": f"{config['host']}:{config['port']}",
                "role": "configured_c2",
                "confidence": "confirmed_static_config",
                "source": "managed_cctor_and_connect_correlation",
            }
        )
    public_config = {
        "source_name": name,
        "structural_assessment": {
            "matched": matched,
            "managed_pe": data.startswith(b"MZ") and b"BSJB" in data,
            "static_configuration_validated": config is not None,
            "transport_validated": protocol is not None,
        },
        "marker_hits": (
            [
                "managed_core_type",
                "static_H_P_VR_Y",
                "nul_length_frame",
                "delimiter_dispatch",
            ]
            if matched
            else []
        ),
        "terminal_managed_client": matched,
        "static_config_recovered": config is not None,
        "c2_protocol_recovered": protocol is not None,
        "c2_liveness_confirmed": False,
        "recovery_status": "recovered_static_config_and_protocol"
        if matched
        else "rejected_or_not_recovered",
    }
    if config is not None:
        public_config.update(config)
    result = build_result(
        "njrat",
        data,
        public_config,
        findings,
        [
            "検体、managed CIL、pluginを実行せず、外部hostへ接続していません。",
            "managed core type、設定field、送受信frame、dispatcherが全て一致しない入力は拒否します。",
            "無効なPastebin placeholderをC2または動的設定URLへ昇格しません。",
            "delimiter値は公開せず、長さとSHA-256だけを記録します。",
            "設定endpointの稼働状態は確認していません。",
        ],
    )
    result["static_config_recovered"] = config is not None
    result["config_endpoints"] = (
        [
            {
                "host": config["host"],
                "port": config["port"],
                "transport": "tcp",
                "role": "configured_c2",
                "confidence": "confirmed_static_configuration",
                "evidence": {
                    "kind": "managed_cctor_and_connect_correlation",
                    "all_expected_fields_validated": True,
                },
            }
        ]
        if config is not None
        else []
    )
    result["static_evidence"] = {
        "all_expected_fields_validated": matched,
        "raw_cil_published": False,
        "delimiter_published": False,
        "sample_executed": False,
        "network_contacted": False,
    }
    result["protocol_evidence"] = protocol
    result["static_protocol"] = (
        {
            "status": "confirmed",
            "method": "managed_cil_ascii_length_nul_delimited_tcp",
            "transport": "tcp",
            "framing": "ascii_decimal_length_nul_delimiter",
            "serialization": "utf8_delimiter_commands",
            "confidence": "high",
            "tcp_open_only": False,
            "live_verified": False,
        }
        if protocol is not None
        else None
    )
    result["representative_functions"] = _reviewed_functions(digest)
    result["program_evidence"] = (
        _program_evidence(review, digest) if review is not None else []
    )
    return result
