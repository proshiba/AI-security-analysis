"""AsyncRAT終端managed clientの設定、protocol、代表関数を静的復元する。"""

from __future__ import annotations

import hashlib
import importlib.util
import re
import sys
from functools import cache
from pathlib import Path
from types import ModuleType

import dnfile

from extractors.common import build_result, extract_strings, valid_host

HANDLER_CONTRACT = {
    "input_formats": ["pe"],
    "minimum_evidence_score": 20_000,
}

MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_METHODS = 20_000
MAX_METHOD_BODY_BYTES = 256 * 1024
_REVIEWED_SHA256 = "ff8235089a02e71d422a0c227f177f14052b58d1558324a6001ded65418bb498"
_CHACHA_REVIEWED_SHA256 = (
    "00180c06765fed73c87dec265fb389be957c9fdca36bd3b00f8c421e812631e2"
)
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PLAINTEXT_V057B_METHOD_PROFILE = {
    "Client.Program.Main": ("0x06000001", "8df99caf45aa115ab2689d8a7e3c52c75bf1362f8c799ff2a3619555ce71f294", 101),
    "Client.Settings.InitializeSettings": ("0x06000003", "0442fe31c2819114e052aa21a037c1548e2a0875d74dbfa500bb73b3cfcf1ef4", 6),
    "Client.Settings.VerifyHash": ("0x06000004", "a7e00cda640158a05971a9f0c58105d880f7ccbe70a8964e26bcc2e920b478c8", 26),
    "Client.Connection.ClientSocket.InitializeClient": ("0x0600001b", "4ac7749d2fe175fb477a0b6c354b8738c09ef9da79a5748195a127fe48818cf8", 298),
    "Client.Connection.ClientSocket.ReadServertData": ("0x0600001f", "cd89cee8fa4fb6241b38bc139350f22f311af0de2e8a51663d251b0a8defe29a", 217),
    "Client.Connection.ClientSocket.Send": ("0x06000020", "4e02df6d23912373698ca513c96dea5f06335b426d2e503eb35694fbe7d39662", 139),
    "Client.Connection.ClientSocket.KeepAlivePacket": ("0x06000021", "4b641e5cc5498782b40b2f98a3ae07abe88cfa35c742c08489b89334892092f9", 32),
    "Client.Install.NormalStartup.Install": ("0x06000024", "0a600b78741d6c2fd4e74c437be3ba6cf0965235c03262e2d65c37163c9288b0", 260),
    "Client.Helper.Anti_Analysis.RunAntiAnalysis": ("0x06000026", "5c5277cc28a8c6cef2c2cd3043435f90c06fa843edf392d1f6fa49c55ec8bf4e", 19),
    "Client.Helper.IdSender.SendInfo": ("0x0600002f", "8e99030590429a3215d2fbcd6a143b27f179f9a36f34c8da16f01ea5cbabb4bd", 123),
    "Client.Handle_Packet.Packet.Read": ("0x06000046", "608d18feae2ae9c2ac1c8d6dcb3a70d5e30483d0416d4f79cbb9808b9b21fb54", 177),
    "Client.Handle_Packet.Packet.Invoke": ("0x06000047", "6754801f9ac724759a4458e1e58f0c2c1030fe81e1581092a51c833a0f0d2e1b", 104),
}
_SETTINGS = frozenset(
    {
        "Key",
        "Ports",
        "Hosts",
        "Version",
        "Install",
        "Pastebin",
        "Anti",
        "Group",
        "Certificate",
    }
)
_PROTOCOL = frozenset({"Packet", "pong", "plugin", "savePlugin"})
_REQUIRED_METHODS = {
    "Client.Settings": frozenset({".cctor", "InitializeSettings", "VerifyHash"}),
    "Client.Connection.ClientSocket": frozenset(
        {"InitializeClient", "ReadServertData", "Send", "KeepAlivePacket"}
    ),
    "Client.Handle_Packet.Packet": frozenset({"Read", "Invoke"}),
    "Client.Helper.IdSender": frozenset({"SendInfo"}),
}


def _common_directory() -> Path:
    repository = Path(__file__).resolve().parents[2]
    common = (repository / "analysis-framework" / "common").resolve(strict=True)
    common.relative_to(repository)
    if not common.is_dir():
        raise ImportError("analysis-framework/commonがdirectoryではありません")
    return common


@cache
def _load_common_module(name: str) -> ModuleType:
    """固定common directory直下のreview済みmoduleだけを遅延読込する。"""

    if name not in {"dotnet_rat_config", "dotnet_rat_protocol_evidence"}:
        raise ImportError("許可されていないcommon moduleです")
    common = _common_directory()
    module_path = (common / f"{name}.py").resolve(strict=True)
    if module_path.parent != common or not module_path.is_file():
        raise ImportError("common module pathが不正です")
    import_name = f"_analysis_common_{name}_for_asyncrat"
    existing = sys.modules.get(import_name)
    if existing is not None:
        source = getattr(existing, "__file__", None)
        if source is None or Path(source).resolve(strict=True) != module_path:
            raise ImportError("common moduleが予期しないpathから読み込まれています")
        return existing
    spec = importlib.util.spec_from_file_location(import_name, module_path)
    if spec is None or spec.loader is None:
        raise ImportError("common moduleのload specを作成できません")
    module = importlib.util.module_from_spec(spec)
    sys.modules[import_name] = module
    try:
        spec.loader.exec_module(module)
    except Exception:
        if sys.modules.get(import_name) is module:
            del sys.modules[import_name]
        raise
    return module


def _managed_structure(data: bytes) -> dict[str, object]:
    """CLR metadataからAsyncRAT固有type、field、method集合を有界取得する。"""

    if not data.startswith(b"MZ") or b"BSJB" not in data or len(data) > MAX_INPUT_BYTES:
        raise ValueError("上限内のmanaged PEではありません")
    pe = dnfile.dnPE(data=data)
    return _structure_from_metadata(pe)


def _structure_from_metadata(pe: object) -> dict[str, object]:
    try:
        tables = pe.net.mdtables
        required_tables = (("TypeDef", tables.TypeDef), ("MethodDef", tables.MethodDef), ("Field", tables.Field))
    except AttributeError as error:
        raise ValueError("CLRの必須tableが欠落しています") from error
    table_rows = {}
    for name, table in required_tables:
        rows = None if table is None else table.rows
        if rows is None or not 1 <= len(rows) <= MAX_METHODS:
            raise ValueError("CLRの必須tableが欠落または上限外です")
        table_rows[name] = rows

    def names_for(references: object, table: str) -> frozenset[str]:
        rows = table_rows[table]
        if not isinstance(references, (list, tuple)) or len(references) > len(rows):
            raise ValueError("CLR tableの参照一覧が不正です")
        names = set()
        for reference in references:
            index = reference.row_index
            if not isinstance(index, int) or isinstance(index, bool) or not 1 <= index <= len(rows):
                raise ValueError("CLR tableの参照indexが範囲外です")
            names.add(str(rows[index - 1].Name))
        return frozenset(names)

    observed_methods: dict[str, frozenset[str]] = {}
    settings_fields: frozenset[str] = frozenset()
    for row in table_rows["TypeDef"]:
        owner = ".".join(
            value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
        )
        if owner not in _REQUIRED_METHODS:
            continue
        observed_methods[owner] = names_for(row.MethodList, "MethodDef")
        if owner == "Client.Settings":
            settings_fields = names_for(row.FieldList, "Field")
    missing_types = sorted(_REQUIRED_METHODS.keys() - observed_methods.keys())
    missing_methods = {
        owner: sorted(required - observed_methods.get(owner, frozenset()))
        for owner, required in _REQUIRED_METHODS.items()
        if required - observed_methods.get(owner, frozenset())
    }
    return {
        "settings_fields": sorted(_SETTINGS.intersection(settings_fields)),
        "settings_fields_complete": _SETTINGS <= settings_fields,
        "missing_types": missing_types,
        "missing_methods": missing_methods,
        "methods_complete": not missing_types and not missing_methods,
    }


def structural_evidence(data: bytes) -> dict[str, object]:
    """AsyncRAT固有Settings、MessagePack field、managed PEを相互確認する。"""

    strings = set(extract_strings(data, minimum=3))
    protocol = sorted(_PROTOCOL.intersection(strings))
    managed_pe = data.startswith(b"MZ") and b"BSJB" in data
    protocol_complete = _PROTOCOL.issubset(strings)
    try:
        structure = _managed_structure(data)
        metadata_status = "parsed"
        metadata_error_type = None
    except (OSError, TypeError, ValueError, AttributeError, IndexError) as error:
        metadata_status = "unavailable_or_invalid"
        metadata_error_type = type(error).__name__
        structure = {
            "settings_fields": [],
            "settings_fields_complete": False,
            "missing_types": sorted(_REQUIRED_METHODS),
            "missing_methods": {},
            "methods_complete": False,
        }
    result = {
        "matched": managed_pe
        and structure["settings_fields_complete"] is True
        and structure["methods_complete"] is True
        and protocol_complete,
        "managed_pe": managed_pe,
        "metadata_status": metadata_status,
        "metadata_error_type": metadata_error_type,
        **structure,
        "protocol_fields": protocol,
        "protocol_fields_complete": protocol_complete,
        "rule": "asyncrat_settings_messagepack_crypto_v1",
    }
    if result["matched"] is True or not managed_pe or len(data) > MAX_INPUT_BYTES:
        return result
    try:
        recovery = _validated_recovery(data)
        protocol_evidence = _validated_protocol(data, hashlib.sha256(data).hexdigest())
    except Exception:  # noqa: BLE001 - third-party PE parser failureはprofile不一致
        return result
    if (
        recovery.get("config_mode") == "chacha20_obfuscated_v058"
        and protocol_evidence.get("protocol_variant")
        == "compact_v058_chacha20"
    ):
        result.update(
            {
                "matched": True,
                "obfuscated_profile_confirmed": True,
                "config_mode": "chacha20_obfuscated_v058",
                "protocol_variant": "compact_v058_chacha20",
                "rule": "asyncrat_obfuscated_chacha20_compact_v058",
            }
        )
    return result


def _validated_recovery(data: bytes) -> dict[str, object]:
    module = _load_common_module("dotnet_rat_config")
    recovered = module.recover(data, "asyncrat")
    digest = hashlib.sha256(data).hexdigest()
    if (
        not isinstance(recovered, dict)
        or recovered.get("schema_version") != 1
        or recovered.get("family") != "asyncrat"
        or recovered.get("sha256") != digest
        or recovered.get("terminal_managed_client") is not True
        or recovered.get("static_config_recovered") is not True
        or recovered.get("secret_fields_published") is not False
        or recovered.get("executed") is not False
        or recovered.get("network_contacted") is not False
    ):
        raise ValueError("AsyncRAT設定復元の安全契約が一致しません")
    crypto = recovered.get("crypto_profile")
    config_mode = recovered.get("config_mode")
    if not isinstance(crypto, dict) or crypto.get("salt_published") is not False:
        raise ValueError("AsyncRAT暗号profileの検証契約が一致しません")
    if config_mode == "hmac_encrypted":
        if crypto.get("salt_source") != "reviewed_family_profile":
            raise ValueError("AsyncRAT暗号profileの検証契約が一致しません")
    elif config_mode == "chacha20_obfuscated_v058":
        if (
            crypto.get("settings_storage") != "encrypted"
            or crypto.get("key_derivation") != "reviewed_xor_add_32_byte_mixing"
            or crypto.get("authentication") != "none_per_setting"
            or crypto.get("cipher") != "ChaCha20-IETF"
            or crypto.get("nonce_size") != 12
            or crypto.get("initial_counter") != 1
            or crypto.get("salt_source") != "not_applicable"
        ):
            raise ValueError("AsyncRAT ChaCha20 profileの検証契約が一致しません")
        shape = recovered.get("static_shape_evidence")
        required_shape = {
            "settings_cctor_token",
            "settings_initializer_token",
            "crypto_constructor_token",
            "string_decrypt_token",
            "byte_decrypt_token",
            "chacha_core_token",
            "literal_assignment_count",
        }
        if not isinstance(shape, dict) or not required_shape <= shape.keys():
            raise ValueError("AsyncRAT ChaCha20 CIL形状の検証契約が一致しません")
    elif config_mode == "plaintext_static_v057b":
        if (
            crypto.get("settings_storage") != "plaintext"
            or crypto.get("key_derivation") != "not_applicable"
            or crypto.get("authentication") != "not_applicable"
            or crypto.get("cipher") != "not_applicable"
            or crypto.get("salt_source") != "not_applicable"
        ):
            raise ValueError("AsyncRAT平文profileの検証契約が一致しません")
        shape = recovered.get("static_shape_evidence")
        if not isinstance(shape, dict) or (
            shape.get("settings_initializer") != "trivial_return_true"
            or shape.get("tls_certificate_validation") != "accept_all"
            or shape.get("placeholder_fields_validated") is not True
        ):
            raise ValueError("AsyncRAT平文CIL形状の検証契約が一致しません")
    else:
        raise ValueError("AsyncRAT設定modeが未対応です")
    endpoints = recovered.get("config_endpoints")
    if not isinstance(endpoints, list) or not endpoints or len(endpoints) > 64:
        raise ValueError("AsyncRAT endpoint一覧が不正です")
    normalized = []
    for item in endpoints:
        if not isinstance(item, dict):
            raise ValueError("AsyncRAT endpointがobjectではありません")
        host = item.get("host")
        port = item.get("port")
        if (
            not isinstance(host, str)
            or not valid_host(host)
            or not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65_535
        ):
            raise ValueError("AsyncRAT endpointのhostまたはportが不正です")
        normalized.append({"host": host.casefold().rstrip("."), "port": port})
    certificate = recovered.get("certificate")
    if not isinstance(certificate, dict):
        raise ValueError("AsyncRAT証明書情報が不正です")
    cert_hash = certificate.get("sha256")
    cert_size = certificate.get("size")
    if certificate.get("certificate_mismatch_excludes_c2") is not False:
        raise ValueError("AsyncRAT証明書判定契約が不正です")
    if config_mode in {"hmac_encrypted", "chacha20_obfuscated_v058"}:
        if (
            not isinstance(cert_hash, str)
            or _SHA256.fullmatch(cert_hash) is None
            or not isinstance(cert_size, int)
            or isinstance(cert_size, bool)
            or not 1 <= cert_size <= 16 * 1024 * 1024
            or certificate.get("validation") != "embedded_certificate_present"
        ):
            raise ValueError("AsyncRAT証明書pinが不正です")
    elif (
        cert_hash is not None
        or cert_size is not None
        or certificate.get("validation") != "accept_all"
    ):
        raise ValueError("AsyncRAT accept-all証明書契約が不正です")
    version = recovered.get("version")
    group = recovered.get("group")
    if not isinstance(version, str) or not 1 <= len(version) <= 128:
        raise ValueError("AsyncRAT versionが不正です")
    if not isinstance(group, str) or len(group) > 512:
        raise ValueError("AsyncRAT groupが不正です")
    return {
        "config_mode": config_mode,
        "version": version,
        "install": recovered.get("install"),
        "group": group,
        "anti_analysis": recovered.get("anti_analysis"),
        "endpoints": normalized,
        "dynamic_config_present": recovered.get("dynamic_config_url") is not None,
        "certificate": {
            "sha256": cert_hash,
            "size": cert_size,
            "validation": certificate.get("validation"),
            "certificate_mismatch_excludes_c2": False,
        },
        "crypto_profile": crypto,
        "static_shape_evidence": recovered.get("static_shape_evidence"),
    }


def _validated_protocol(data: bytes, digest: str) -> dict[str, object]:
    module = _load_common_module("dotnet_rat_protocol_evidence")
    result = module.recover(data, "asyncrat", digest)
    if (
        not isinstance(result, dict)
        or result.get("family") != "asyncrat"
        or result.get("sample_sha256") != digest
        or result.get("analysis_status") != "complete"
        or result.get("safety", {}).get("sample_executed") is not False
        or result.get("safety", {}).get("network_contacted") is not False
    ):
        raise ValueError("AsyncRAT protocol証拠が完全一致しません")
    return result


def _read_bounded_method_body(data: bytes, pe: dnfile.dnPE, rva: int) -> object:
    """共通のCIL header／code size境界検証後にmethod bodyを読む。"""

    module = _load_common_module("dotnet_rat_config")
    return module.read_bounded_method_body(data, pe, rva)


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


def _method_owners(pe: dnfile.dnPE) -> dict[int, str]:
    return {
        method.row_index: ".".join(
            value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
        )
        for row in pe.net.mdtables.TypeDef.rows
        for method in row.MethodList
    }


def _call_name(pe: dnfile.dnPE, token: int, owners: dict[int, str]) -> str:
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
    if table_id == 0x2B:
        return "MethodSpec"
    return f"token:{token:#x}"


def _plaintext_v057b_profile_matches(data: bytes) -> bool:
    """公開済み9件で一致したopcode/call形状だけをv0.5.7B代表関数へ昇格する。"""

    try:
        pe = dnfile.dnPE(data=data)
        if pe.net is None or pe.net.mdtables is None:
            return False
        methods = pe.net.mdtables.MethodDef.rows
        if len(methods) != 83:
            return False
        owners = _method_owners(pe)
        observed: dict[str, tuple[str, str, int]] = {}
        for index, row in enumerate(methods, 1):
            qualified = f"{owners.get(index, '')}.{row.Name}".strip(".")
            if qualified not in _PLAINTEXT_V057B_METHOD_PROFILE:
                continue
            if not row.Rva:
                return False
            body = _read_bounded_method_body(data, pe, row.Rva)
            if len(body.instructions) > MAX_METHOD_BODY_BYTES:
                return False
            semantic: list[str] = []
            for instruction in body.instructions:
                opcode = instruction.opcode.name
                semantic.append(opcode)
                operand = getattr(instruction.operand, "value", instruction.operand)
                if opcode in {"call", "callvirt", "newobj"} and isinstance(operand, int):
                    semantic.append(f"call:{_call_name(pe, operand, owners)}")
            observed[qualified] = (
                f"0x0600{index:04x}",
                hashlib.sha256("\n".join(semantic).encode("utf-8")).hexdigest(),
                len(body.instructions),
            )
        return observed == _PLAINTEXT_V057B_METHOD_PROFILE
    except Exception:  # noqa: BLE001 - profile mismatchはfail-closedで扱う
        return False


def _reviewed_functions(
    digest: str,
    *,
    data: bytes | None = None,
    config_mode: str | None = None,
) -> list[dict[str, object]]:
    if digest == _CHACHA_REVIEWED_SHA256:
        if data is None or config_mode != "chacha20_obfuscated_v058":
            return []
        return _reviewed_chacha_functions(digest, data)
    plaintext_profile = digest != _REVIEWED_SHA256
    if plaintext_profile and not (
        config_mode == "plaintext_static_v057b"
        and data is not None
        and _plaintext_v057b_profile_matches(data)
    ):
        return []
    records = [
        _record(
            digest,
            "0x06000001",
            "Client.Program.Main",
            "loader_execution",
            "設定検証、解析回避、永続化、C2再接続を統括します。",
            [
                "起動遅延後に暗号化Settingsを復号・検証します。",
                "任意の解析回避、critical process化、永続化を適用します。",
                "接続が成立するまで初期化を再試行します。",
            ],
            callees=[
                "Client.Settings.InitializeSettings",
                "Client.Install.NormalStartup.Install",
                "Client.Connection.ClientSocket.InitializeClient",
            ],
            apis=["Thread.Sleep", "Environment.Exit"],
        ),
        _record(
            digest,
            "0x06000003",
            "Client.Settings.InitializeSettings",
            "config_decoder",
            "master keyから認証付きSettingsと証明書を復元します。",
            [
                "Base64 master keyをUTF-8へ変換します。",
                "各Settings fieldをHMAC検証後にAES-CBC復号します。",
                "証明書と署名を検証し、失敗時はfalseを返します。",
            ],
            callees=[
                "Client.Algorithm.Aes256..ctor",
                "Client.Algorithm.Aes256.Decrypt",
                "Client.Settings.VerifyHash",
            ],
            apis=["Convert.FromBase64String", "X509Certificate2..ctor"],
        ),
        _record(
            digest,
            "0x06000004",
            "Client.Settings.VerifyHash",
            "config_authentication",
            "証明書公開鍵で設定署名を検証します。",
            [
                "証明書公開鍵と検証対象を取得します。",
                "SHA-256を計算し、Base64署名を復号します。",
                "RSA VerifyHashの結果だけを返します。",
            ],
            apis=["SHA256.ComputeHash", "RSACryptoServiceProvider.VerifyHash"],
        ),
        _record(
            digest,
            "0x0600001b",
            "Client.Connection.ClientSocket.InitializeClient",
            "command_control",
            "復号済みendpointへTLS接続し登録と受信loopを開始します。",
            [
                "固定host／portを選択し、domainならDNS解決します。",
                "TCPをSslStreamで包み埋め込み証明書と相互確認します。",
                "ClientInfo送信後にkeepalive、ping、4 byte header読取を開始します。",
            ],
            callees=[
                "Client.Helper.IdSender.SendInfo",
                "Client.Connection.ClientSocket.Send",
                "Client.Connection.ClientSocket.ReadServertData",
            ],
            apis=[
                "Dns.GetHostAddresses",
                "TcpClient.Connect",
                "SslStream.AuthenticateAsClient",
            ],
        ),
        _record(
            digest,
            "0x0600001f",
            "Client.Connection.ClientSocket.ReadServertData",
            "command_control",
            "4 byte little-endian長でTLS受信frameを再構成します。",
            [
                "headerまたはbodyの残byteを読みます。",
                "headerをInt32長へ変換してbufferを割り当てます。",
                "完全frameだけをdispatcherへ渡して次のheader読取へ戻ります。",
            ],
            apis=["SslStream.EndRead", "BitConverter.ToInt32", "SslStream.BeginRead"],
        ),
        _record(
            digest,
            "0x06000020",
            "Client.Connection.ClientSocket.Send",
            "command_control",
            "bodyへ4 byte little-endian長を付けTLS送信します。",
            [
                "送信lockと接続状態を確認します。",
                "body長をheaderへ変換します。",
                "headerとbodyを書き込み、例外時は接続状態を落とします。",
            ],
            apis=["Monitor.Enter", "BitConverter.GetBytes", "SslStream.Write"],
        ),
        _record(
            digest,
            "0x06000021",
            "Client.Connection.ClientSocket.KeepAlivePacket",
            "command_control",
            "Packet=Pingとactive window情報をMessagePack化します。",
            [
                "MessagePack mapを作成します。",
                "PacketへPing、Messageへactive window titleを設定します。",
                "圧縮frameを送信しpong待ちへ移行します。",
            ],
            callees=["Client.Connection.ClientSocket.Send"],
            apis=["Methods.GetActiveWindowTitle", "MsgPack.Encode2Bytes"],
        ),
        _record(
            digest,
            "0x0600002f",
            "Client.Helper.IdSender.SendInfo",
            "host_discovery",
            "端末属性をPacket=ClientInfoの登録MessagePackへ集約します。",
            [
                "HWID、user、OS、path、権限を収集します。",
                "AV、install時刻、active window、groupを設定します。",
                "登録mapを圧縮MessagePackへ変換します。",
            ],
            apis=[
                "Environment.UserName",
                "Process.GetCurrentProcess",
                "MsgPack.Encode2Bytes",
            ],
        ),
        _record(
            digest,
            "0x06000046",
            "Client.Handle_Packet.Packet.Read",
            "command_dispatcher",
            "受信MessagePackをpong、plugin要求、plugin保存へ分岐します。",
            [
                "受信bodyをMessagePackへ復号します。",
                "pongではheartbeat状態を更新します。",
                "plugin cacheの有無に応じて要求、保存、Invokeへ分岐します。",
            ],
            callees=[
                "Client.Handle_Packet.Packet.Invoke",
                "Client.Connection.ClientSocket.Send",
            ],
            apis=[
                "MsgPack.DecodeFromBytes",
                "SetRegistry.GetValue",
                "SetRegistry.SetValue",
            ],
        ),
        _record(
            digest,
            "0x06000047",
            "Client.Handle_Packet.Packet.Invoke",
            "plugin_loader",
            "圧縮pluginをmanaged assemblyとして反射呼出しします。",
            [
                "registry-backed cacheからpluginを取得します。",
                "展開後にAssembly.Loadします。",
                "Plugin.Plugin.Runへsocketと受信MsgPackを渡します。",
            ],
            apis=["Zip.Decompress", "Assembly.Load", "Type.InvokeMember"],
        ),
        _record(
            digest,
            "0x06000024",
            "Client.Install.NormalStartup.Install",
            "persistence",
            "設定pathへ自己複製しRun keyまたはscheduled taskへ登録します。",
            [
                "install directoryとfile名を解決します。",
                "競合processと既存copyを処理します。",
                "権限に応じてscheduled taskまたはHKCU Runへ登録します。",
            ],
            apis=["RegistryKey.SetValue", "File.ReadAllBytes", "Process.Start"],
        ),
        _record(
            digest,
            "0x06000026",
            "Client.Helper.Anti_Analysis.RunAntiAnalysis",
            "defense_evasion",
            "disk容量、OS、manufacturer、debugger、Sandboxieを順に検査します。",
            [
                "小容量diskとWindows XPを検査します。",
                "virtual machineに多いmanufacturerを確認します。",
                "debuggerとSandboxie moduleを確認し一致時はtrueを返します。",
            ],
            callees=[
                "Client.Helper.Anti_Analysis.IsSmallDisk",
                "Client.Helper.Anti_Analysis.DetectManufacturer",
                "Client.Helper.Anti_Analysis.DetectDebugger",
            ],
        ),
    ]
    if plaintext_profile:
        for item in records:
            item["source"] = "9検体で一致を確認したv0.5.7B managed CIL opcode／call構造profile"
            item["confidence"] = "confirmed_static_profile_match"
        by_name = {str(item["name"]): item for item in records}
        by_name["Client.Program.Main"].update(
            {
                "summary_ja": "平文Settingsの妥当性確認、任意の解析回避・永続化、C2再接続を統括します。",
                "logic_steps_ja": [
                    "起動遅延後にInitializeSettingsの結果を確認します。",
                    "設定に応じて解析回避、critical process化、永続化を適用します。",
                    "接続が成立するまで初期化を再試行します。",
                ],
            }
        )
        by_name["Client.Settings.InitializeSettings"].update(
            {
                "summary_ja": "この平文設定buildでは追加復号を行わずtrueを返します。",
                "logic_steps_ja": [
                    "method本体は定数trueを返す6命令の形状です。",
                    "設定値はSettings型の静的field初期化から別途回収します。",
                    "暗号化設定の復号や署名検証はこの経路では呼び出しません。",
                ],
                "callees": [],
                "api_calls": [],
            }
        )
        by_name["Client.Settings.VerifyHash"].update(
            {
                "summary_ja": "署名検証補助関数は残存しますが、平文InitializeSettingsからの到達は確認できません。",
                "logic_steps_ja": [
                    "証明書公開鍵と検証対象を受け取る補助処理です。",
                    "SHA-256とRSA VerifyHashの実装形状を保持しています。",
                    "本平文設定経路からの呼出しは静的に確認していません。",
                ],
            }
        )
        by_name["Client.Connection.ClientSocket.InitializeClient"].update(
            {
                "summary_ja": "設定endpointへTLS接続し、証明書を許可して登録と受信loopを開始します。",
                "logic_steps_ja": [
                    "固定host／portを選択し、domainならDNS解決します。",
                    "TCPをSslStreamで包み、常にtrueを返す検証callbackでTLSを確立します。",
                    "ClientInfo送信後にkeepalive、ping、4 byte header読取を開始します。",
                ],
            }
        )
    return records


def _reviewed_chacha_functions(
    digest: str, data: bytes
) -> list[dict[str, object]]:
    """exact hashでreviewした難読化v0.5.8の代表CILを公開する。"""

    pe = dnfile.dnPE(data=data)
    if pe.net is None or pe.net.mdtables is None:
        return []
    rows = pe.net.mdtables.MethodDef.rows
    if len(rows) != 210:
        return []
    owners = _method_owners(pe)

    def qualified(index: int) -> str:
        if not 1 <= index <= len(rows) or not rows[index - 1].Rva:
            raise ValueError("review済みmethod tokenが不正です")
        return f"{owners.get(index, '')}.{rows[index - 1].Name}".strip(".")

    definitions = [
        (
            0x02,
            "loader_execution",
            ".NET 4.8確認、設定初期化、任意の回避・永続化、C2接続を統括します。",
            [
                "AssemblyResolve handlerとTLS security protocolを初期化します。",
                ".NET 4.8未導入時はMicrosoft配布installerを取得し、`/q /norestart`で起動します。",
                "遅延後に設定を復号し、設定flagに応じた機能を経て接続loopへ進みます。",
            ],
            ["Thread.Sleep", "Process.Start", "Environment.Exit"],
        ),
        (
            0x0A,
            "config_decoder",
            "Base64 keyからChaCha20鍵を生成し、設定、証明書、署名を復元します。",
            [
                "KeyをBase64からUTF-8へ戻して暗号classを初期化します。",
                "18個の静的設定fieldのうち暗号化fieldを順次復号します。",
                "証明書をX509Certificate2へ読み込み、署名検証へ渡します。",
            ],
            ["Convert.FromBase64String", "Encoding.UTF8.GetString"],
        ),
        (
            0x0B,
            "config_authentication",
            "埋め込み証明書の公開鍵でkey署名をSHA-256／RSA検証します。",
            [
                "証明書公開鍵と設定Keyのbyte列を取得します。",
                "KeyのSHA-256 digestとBase64署名を準備します。",
                "RSA VerifyHashの真偽を初期化結果として返します。",
            ],
            ["SHA256.ComputeHash", "RSACryptoServiceProvider.VerifyHash"],
        ),
        (
            0x22,
            "command_control",
            "復号済みendpointへTCP/TLS接続し、登録と受信loopを開始します。",
            [
                "hostとportを選択し、domainを名前解決してTCP接続します。",
                "SslStreamを作成してAuthenticateAsClientを呼び出します。",
                "登録送信後に4-byte headerの非同期読取を開始します。",
            ],
            ["Dns.GetHostAddresses", "TcpClient.Connect", "SslStream.AuthenticateAsClient"],
        ),
        (
            0x26,
            "command_control",
            "4-byte little-endian長を使ってTLS受信frameを再構成します。",
            [
                "headerの残byteを非同期に読み取ります。",
                "BitConverter.ToInt32でbody長を決定します。",
                "完全なbodyだけをdispatcherへ渡します。",
            ],
            ["SslStream.BeginRead", "BitConverter.ToInt32"],
        ),
        (
            0x27,
            "command_control",
            "MessagePack bodyへ4-byte長を付けてTLS streamへ送信します。",
            [
                "接続状態と送信lockを確認します。",
                "body長をlittle-endian byte列へ変換します。",
                "headerとbodyを順にSslStreamへ書き込みます。",
            ],
            ["BitConverter.GetBytes", "SslStream.Write"],
        ),
        (
            0x28,
            "command_control",
            "compact schemaの`T=hb` heartbeatと`Msg`を送信します。",
            [
                "packet種別key `T`へ`hb`を設定します。",
                "`Msg`へactive window情報を設定します。",
                "MessagePack化したframeを送信します。",
            ],
            [],
        ),
        (
            0x59,
            "host_discovery",
            "compact schemaの`T=ci`登録MessagePackを構築します。",
            [
                "HWID、User、OS、Path、Adminを収集します。",
                "Performance、Antivirus、Installed、Pongを設定します。",
                "Pastebin相当`Pb`とGroup相当`Grp`を加えて送信します。",
            ],
            ["Environment.UserName", "Process.GetCurrentProcess"],
        ),
        (
            0x6E,
            "command_dispatcher",
            "compact command marker `hbr`、`wu`、`sp`、`sv`を分岐します。",
            [
                "受信MessagePackのpacket種別`T`を取得します。",
                "`hbr`でheartbeat状態を更新します。",
                "`wu`、`sp`、`sv`で更新・plugin取得・保存経路へ分岐します。",
            ],
            [],
        ),
        (
            0x6F,
            "plugin_loader",
            "受領したmanaged pluginの`Plugin.Plugin.Run`を反射呼出しします。",
            [
                "`Dll`と`Msgpack` fieldを受信mapから取得します。",
                "plugin assemblyを読み込み`Plugin.Plugin`型を解決します。",
                "`Run`へsocketと受信MessagePackを渡します。",
            ],
            ["Assembly.Load", "Type.InvokeMember"],
        ),
        (
            0x78,
            "config_decoder",
            "UTF-8 master keyをXORと加算で32-byte ChaCha20鍵へ混合します。",
            [
                "空のmaster keyを拒否します。",
                "32-byte bufferへ各byteをindex modulo 32でXORします。",
                "7 byteずらした位置へ同じbyteを加算します。",
            ],
            ["Encoding.UTF8.GetBytes"],
        ),
        (
            0x7C,
            "config_decoder",
            "Base64 blob先頭の12-byte nonceを分離して設定を復号します。",
            [
                "12 byte未満の入力を拒否します。",
                "先頭12 byteをnonce、残りをciphertextへ分離します。",
                "counter 1でChaCha20 coreを呼び出します。",
            ],
            ["Buffer.BlockCopy"],
        ),
        (
            0x7D,
            "config_decoder",
            "IETF ChaCha20の20-round block関数で設定byte列を復号します。",
            [
                "`expand 32-byte k`定数、8 key word、counter、3 nonce wordを配置します。",
                "column roundとdiagonal roundを10回繰り返します。",
                "64-byte keystreamをciphertextへXORしcounterを増加します。",
            ],
            ["BitConverter.ToUInt32", "BitConverter.GetBytes"],
        ),
    ]
    records = []
    try:
        for index, role, summary, steps, apis in definitions:
            records.append(
                _record(
                    digest,
                    f"0x0600{index:04x}",
                    qualified(index),
                    role,
                    summary,
                    steps,
                    apis=apis,
                )
            )
    except (IndexError, ValueError):
        return []
    return records


def _managed_inventory(
    data: bytes, digest: str, config_mode: str | None = None
) -> list[dict[str, object]]:
    pe = dnfile.dnPE(data=data)
    if pe.net is None or pe.net.mdtables is None:
        raise ValueError("CLR metadataがありません")
    method_rows = pe.net.mdtables.MethodDef.rows
    if len(method_rows) > MAX_METHODS:
        raise ValueError("managed method数が上限を超えています")
    with_body = 0
    without_body = 0
    malformed = 0
    for row in method_rows:
        if not row.Rva:
            without_body += 1
            continue
        with_body += 1
        try:
            _read_bounded_method_body(data, pe, row.Rva)
        except (IndexError, TypeError, ValueError):
            malformed += 1
    entry_token = "0x06000002" if config_mode == "chacha20_obfuscated_v058" else "0x06000001"
    entry_name = (
        f"{_method_owners(pe).get(2, '')}.{method_rows[1].Name}".strip(".")
        if config_mode == "chacha20_obfuscated_v058" and len(method_rows) >= 2
        else "Client.Program.Main"
    )
    return [
        {
            "program_id": f"managed-asyncrat-{digest[:8]}",
            "program_selector": f"sha256:{digest}",
            "relationship": "root_terminal_managed_client",
            "name": f"{digest}.exe",
            "architecture": "x86",
            "compiler": ".NET CLR managed CIL",
            "language": "managed CIL",
            "endian": "little",
            "address_size": "32",
            "function_count": len(method_rows),
            "managed_method_count": len(method_rows),
            "entry_points": [
                {
                    "name": entry_name,
                    "address": entry_token,
                    "kind": "managed_entrypoint",
                }
            ],
            "imports": ["_CorExeMain"],
            "function_hashes": [],
            "retrieval_coverage": {
                "managed_types_declared": len(pe.net.mdtables.TypeDef.rows),
                "managed_methods_declared": len(method_rows),
                "managed_methods_with_body": with_body,
                "managed_methods_without_body": without_body,
                "malformed_method_bodies": malformed,
                "inventory_complete": malformed == 0,
                "ghidra_native_decompilation_used_for_cil_semantics": False,
            },
            "confidence": (
                "confirmed_program_structure"
                if malformed == 0
                else "partial_program_structure_inventory"
            ),
        }
    ]


def extract(data: bytes, name: str = "sample") -> dict:
    """強い内部構造一致後だけ認証済み設定・protocol・review結果を公開する。"""

    digest = hashlib.sha256(data).hexdigest()
    structural = structural_evidence(data)
    recovery = None
    protocol = None
    recovery_diagnostics = None
    status = "not_attempted_structural_mismatch"
    if (
        structural.get("managed_pe") is True
        and 1 <= len(data) <= MAX_INPUT_BYTES
    ):
        try:
            candidate_recovery = _validated_recovery(data)
        except (ImportError, OSError, ValueError) as error:
            recovery_diagnostics = {
                "stage": "config_recovery",
                "error_type": type(error).__name__,
                "exception_message_published": False,
            }
            status = "rejected_or_not_recovered"
        else:
            try:
                candidate_protocol = _validated_protocol(data, digest)
            except (ImportError, OSError, ValueError) as error:
                recovery_diagnostics = {
                    "stage": "protocol_evidence",
                    "error_type": type(error).__name__,
                    "exception_message_published": False,
                }
                status = "rejected_or_not_recovered"
            else:
                # configとprotocolが双方の安全契約を満たした後にだけ公開状態へ移す。
                recovery = candidate_recovery
                protocol = candidate_protocol
                recovery_diagnostics = {
                    "stage": "complete",
                    "error_type": None,
                    "exception_message_published": False,
                }
                status_by_mode = {
                    "hmac_encrypted": "recovered_hmac_and_protocol_verified",
                    "plaintext_static_v057b": (
                        "recovered_plaintext_and_protocol_verified"
                    ),
                    "chacha20_obfuscated_v058": (
                        "recovered_chacha20_and_protocol_verified"
                    ),
                }
                status = status_by_mode[recovery["config_mode"]]
                if structural["matched"] is not True:
                    mode = recovery["config_mode"]
                    structural["matched"] = True
                    structural["recovered_profile_confirmed"] = True
                    if mode == "chacha20_obfuscated_v058":
                        structural["obfuscated_profile_confirmed"] = True
                        structural["rule"] = (
                            "asyncrat_obfuscated_chacha20_compact_v058"
                        )
                    elif mode == "plaintext_static_v057b":
                        structural["plaintext_profile_confirmed"] = True
                        structural["rule"] = (
                            "asyncrat_plaintext_v057b_protocol_verified"
                        )
                    else:
                        structural["authenticated_profile_confirmed"] = True
                        structural["rule"] = (
                            "asyncrat_hmac_settings_protocol_verified"
                        )
    findings = []
    if recovery is not None:
        evidence_source = (
            "hmac_verified_dotnet_settings"
            if recovery["config_mode"] == "hmac_encrypted"
            else (
                "reviewed_chacha20_dotnet_settings"
                if recovery["config_mode"] == "chacha20_obfuscated_v058"
                else "reviewed_plaintext_dotnet_settings"
            )
        )
        findings.extend(
            {
                "kind": "network.endpoint",
                "value": f"{item['host']}:{item['port']}",
                "role": "configured_c2",
                "confidence": "confirmed_static_config",
                "source": evidence_source,
            }
            for item in recovery["endpoints"]
        )
        if recovery["certificate"]["sha256"] is not None:
            findings.append(
                {
                    "kind": "certificate.sha256",
                    "value": recovery["certificate"]["sha256"],
                    "role": "tls_certificate_pin",
                    "confidence": "confirmed_static_config",
                    "source": evidence_source,
                }
            )
    config: dict[str, object] = {
        "source_name": name,
        "structural_assessment": structural,
        "marker_hits": [structural] if structural["matched"] is True else [],
        "recovery_status": status,
        "recovery_diagnostics": recovery_diagnostics,
        "terminal_managed_client": recovery is not None,
        "static_config_recovered": recovery is not None,
        "c2_protocol_recovered": protocol is not None,
        "c2_liveness_confirmed": False,
    }
    if recovery is not None:
        config.update(recovery)
    result = build_result(
        "asyncrat",
        data,
        config,
        findings,
        [
            "検体、managed CIL、pluginを実行せず、外部hostへ接続していません。",
            "Settings field、packet field、登録、heartbeat、dispatcherが一致しない入力は拒否します。",
            "暗号化SettingsはCILで確定したAESまたはChaCha20方式を静的再現し、平文developer buildは既知のCIL形状とplaceholderを追加確認します。",
            "動的設定URLは存在有無だけを公開し、値やqueryを公開しません。",
            "証明書不一致だけでは非C2と判定しません。",
        ],
    )
    result["static_config_recovered"] = recovery is not None
    result["config_endpoints"] = (
        [
            {
                "host": item["host"],
                "port": item["port"],
                "transport": "tls",
                "role": "configured_c2",
                "confidence": "confirmed_static_configuration",
                "evidence": {
                    "kind": (
                        "hmac_verified_dotnet_settings"
                        if recovery["config_mode"] == "hmac_encrypted"
                        else (
                            "reviewed_chacha20_dotnet_settings"
                            if recovery["config_mode"]
                            == "chacha20_obfuscated_v058"
                            else "reviewed_plaintext_dotnet_settings"
                        )
                    ),
                    "all_expected_fields_validated": True,
                },
            }
            for item in recovery["endpoints"]
        ]
        if recovery is not None
        else []
    )
    result["static_evidence"] = {
        "all_expected_fields_validated": recovery is not None,
        "config_mode": recovery["config_mode"] if recovery is not None else None,
        "authentication": (
            "hmac_sha256"
            if recovery is not None and recovery["config_mode"] == "hmac_encrypted"
            else (
                "none_per_setting"
                if recovery is not None
                and recovery["config_mode"] == "chacha20_obfuscated_v058"
                else "not_applicable"
            )
        ),
        "decryption": (
            "aes_256_cbc_pkcs7"
            if recovery is not None and recovery["config_mode"] == "hmac_encrypted"
            else (
                "chacha20_ietf"
                if recovery is not None
                and recovery["config_mode"] == "chacha20_obfuscated_v058"
                else "not_applicable"
            )
        ),
        "tls_certificate_validation": (
            recovery["certificate"]["validation"] if recovery is not None else None
        ),
        "secret_fields_published": False,
    }
    result["protocol_evidence"] = protocol
    result["static_protocol"] = (
        {
            "status": "confirmed",
            "method": "managed_cil_tls_le32_messagepack",
            "transport": "tls",
            "framing": "little_endian_uint32_length_prefix",
            "serialization": "messagepack",
            "confidence": "high",
            "tcp_open_only": False,
            "live_verified": False,
        }
        if protocol is not None
        else None
    )
    result["representative_functions"] = _reviewed_functions(
        digest,
        data=data,
        config_mode=recovery["config_mode"] if recovery is not None else None,
    )
    result["program_evidence"] = (
        _managed_inventory(
            data,
            digest,
            recovery["config_mode"] if recovery is not None else None,
        )
        if protocol is not None
        else []
    )
    return result
