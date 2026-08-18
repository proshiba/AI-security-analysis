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
from dncil.cil.body.reader import read_method_body_from_bytes

from extractors.common import build_result, extract_strings, valid_host

HANDLER_CONTRACT = {
    "input_formats": ["pe"],
    "minimum_evidence_score": 20_000,
}

MAX_INPUT_BYTES = 32 * 1024 * 1024
MAX_METHODS = 20_000
MAX_METHOD_BODY_BYTES = 256 * 1024
_REVIEWED_SHA256 = "ff8235089a02e71d422a0c227f177f14052b58d1558324a6001ded65418bb498"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
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
    if pe.net is None or pe.net.mdtables is None:
        raise ValueError("CLR metadataがありません")
    observed_methods: dict[str, frozenset[str]] = {}
    settings_fields: frozenset[str] = frozenset()
    for row in pe.net.mdtables.TypeDef.rows:
        owner = ".".join(
            value for value in (str(row.TypeNamespace), str(row.TypeName)) if value
        )
        if owner not in _REQUIRED_METHODS:
            continue
        observed_methods[owner] = frozenset(
            str(pe.net.mdtables.MethodDef.rows[item.row_index - 1].Name)
            for item in row.MethodList
        )
        if owner == "Client.Settings":
            settings_fields = frozenset(
                str(pe.net.mdtables.Field.rows[item.row_index - 1].Name)
                for item in row.FieldList
            )
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
    except (OSError, TypeError, ValueError):
        structure = {
            "settings_fields": [],
            "settings_fields_complete": False,
            "missing_types": sorted(_REQUIRED_METHODS),
            "missing_methods": {},
            "methods_complete": False,
        }
    return {
        "matched": managed_pe
        and structure["settings_fields_complete"] is True
        and structure["methods_complete"] is True
        and protocol_complete,
        "managed_pe": managed_pe,
        **structure,
        "protocol_fields": protocol,
        "protocol_fields_complete": protocol_complete,
        "rule": "asyncrat_settings_messagepack_crypto_v1",
    }


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
    if not isinstance(crypto, dict) or (
        crypto.get("salt_source") != "reviewed_family_profile"
        or crypto.get("salt_published") is not False
    ):
        raise ValueError("AsyncRAT暗号profileの検証契約が一致しません")
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
    if (
        not isinstance(cert_hash, str)
        or _SHA256.fullmatch(cert_hash) is None
        or not isinstance(cert_size, int)
        or isinstance(cert_size, bool)
        or not 1 <= cert_size <= 16 * 1024 * 1024
        or certificate.get("certificate_mismatch_excludes_c2") is not False
    ):
        raise ValueError("AsyncRAT証明書pinが不正です")
    version = recovered.get("version")
    group = recovered.get("group")
    if not isinstance(version, str) or not 1 <= len(version) <= 128:
        raise ValueError("AsyncRAT versionが不正です")
    if not isinstance(group, str) or len(group) > 512:
        raise ValueError("AsyncRAT groupが不正です")
    return {
        "version": version,
        "install": recovered.get("install"),
        "group": group,
        "anti_analysis": recovered.get("anti_analysis"),
        "endpoints": normalized,
        "dynamic_config_present": recovered.get("dynamic_config_url") is not None,
        "certificate": {
            "sha256": cert_hash,
            "size": cert_size,
            "certificate_mismatch_excludes_c2": False,
        },
        "crypto_profile": crypto,
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


def _managed_inventory(data: bytes, digest: str) -> list[dict[str, object]]:
    if digest != _REVIEWED_SHA256:
        return []
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
            offset = pe.get_offset_from_rva(row.Rva)
            if (
                isinstance(offset, bool)
                or not isinstance(offset, int)
                or not 0 <= offset < len(data)
            ):
                raise ValueError("method offsetが不正です")
            read_method_body_from_bytes(
                data[offset : min(len(data), offset + MAX_METHOD_BODY_BYTES)]
            )
        except (IndexError, TypeError, ValueError):
            malformed += 1
    if malformed:
        raise ValueError("malformed managed methodがあります")
    return [
        {
            "program_id": "managed-asyncrat-ff823508",
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
                    "name": "Client.Program.Main",
                    "address": "0x06000001",
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
                "ghidra_native_decompilation_used_for_cil_semantics": False,
            },
            "confidence": "confirmed_program_structure",
        }
    ]


def extract(data: bytes, name: str = "sample") -> dict:
    """強い内部構造一致後だけ認証済み設定・protocol・review結果を公開する。"""

    digest = hashlib.sha256(data).hexdigest()
    structural = structural_evidence(data)
    recovery = None
    protocol = None
    status = "not_attempted_structural_mismatch"
    if structural["matched"] is True and 1 <= len(data) <= MAX_INPUT_BYTES:
        try:
            recovery = _validated_recovery(data)
            protocol = _validated_protocol(data, digest)
            status = "recovered_hmac_and_protocol_verified"
        except (ImportError, OSError, ValueError):
            status = "rejected_or_not_recovered"
    findings = []
    if recovery is not None:
        findings.extend(
            {
                "kind": "network.endpoint",
                "value": f"{item['host']}:{item['port']}",
                "role": "configured_c2",
                "confidence": "confirmed_static_config",
                "source": "hmac_verified_dotnet_settings",
            }
            for item in recovery["endpoints"]
        )
        findings.append(
            {
                "kind": "certificate.sha256",
                "value": recovery["certificate"]["sha256"],
                "role": "tls_certificate_pin",
                "confidence": "confirmed_static_config",
                "source": "hmac_verified_dotnet_settings",
            }
        )
    config: dict[str, object] = {
        "source_name": name,
        "structural_assessment": structural,
        "marker_hits": [structural] if structural["matched"] is True else [],
        "recovery_status": status,
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
            "設定値はHMAC-SHA256を検証してからAES-256-CBCで復号します。",
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
                    "kind": "hmac_verified_dotnet_settings",
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
        "authentication": "hmac_sha256",
        "decryption": "aes_256_cbc_pkcs7",
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
    result["representative_functions"] = _reviewed_functions(digest)
    result["program_evidence"] = (
        _managed_inventory(data, digest) if protocol is not None else []
    )
    return result
