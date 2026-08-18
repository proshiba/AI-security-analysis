"""DCRat終端managed clientの設定、protocol、代表関数を静的復元する。"""

from __future__ import annotations

import hashlib
import importlib.util
import re
import sys
from functools import cache
from pathlib import Path
from types import ModuleType

from extractors.common import build_result, extract_strings, valid_host

HANDLER_CONTRACT = {
    "input_formats": ["pe"],
    "minimum_evidence_score": 20_000,
}

_REVIEWED_SHA256 = "85cd6c3229f9ab547cc54f2cbdcf6ef2937987c0181e5ffa3c4205105df8e8fe"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_SETTINGS = frozenset(
    {"Por_ts", "Hos_ts", "Ver_sion", "In_stall", "Certifi_cate"}
)
_PROTOCOL = frozenset({"Pac_ket", "Po_ng", "plu_gin", "save_Plugin"})
_REVIEWED_SALT_SHA256 = "665fa81321fa818c45b35a3ed7f7c0df53fc5b7721333fd7bc5051e3dbf18702"


def _reviewed_salt_present(strings: set[str]) -> bool:
    return any(
        hashlib.sha256(value.encode("utf-8")).hexdigest() == _REVIEWED_SALT_SHA256
        for value in strings
    )


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
    import_name = f"_analysis_common_{name}_for_dcrat"
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


def structural_evidence(data: bytes) -> dict[str, object]:
    """DCRat固有の暗号化Settings、packet field、salt hashを相互確認する。"""

    strings = set(extract_strings(data, minimum=3))
    settings = sorted(_SETTINGS.intersection(strings))
    protocol = sorted(_PROTOCOL.intersection(strings))
    managed_pe = data.startswith(b"MZ") and b"BSJB" in data
    settings_complete = _SETTINGS.issubset(strings)
    protocol_complete = _PROTOCOL.issubset(strings)
    salt_present = _reviewed_salt_present(strings)
    return {
        "matched": managed_pe and settings_complete and protocol_complete and salt_present,
        "managed_pe": managed_pe,
        "settings_fields": settings,
        "settings_fields_complete": settings_complete,
        "protocol_fields": protocol,
        "protocol_fields_complete": protocol_complete,
        "reviewed_crypto_initializer": salt_present,
        "rule": "dcrat_settings_messagepack_crypto_v1",
    }


def _validated_recovery(data: bytes) -> dict[str, object]:
    module = _load_common_module("dotnet_rat_config")
    recovered = module.recover(data, "dcrat")
    digest = hashlib.sha256(data).hexdigest()
    if (
        not isinstance(recovered, dict)
        or recovered.get("schema_version") != 1
        or recovered.get("family") != "dcrat"
        or recovered.get("sha256") != digest
        or recovered.get("terminal_managed_client") is not True
        or recovered.get("static_config_recovered") is not True
        or recovered.get("secret_fields_published") is not False
        or recovered.get("executed") is not False
        or recovered.get("network_contacted") is not False
    ):
        raise ValueError("DCRat設定復元の安全契約が一致しません")
    crypto = recovered.get("crypto_profile")
    if not isinstance(crypto, dict) or (
        crypto.get("salt_source") != "reviewed_static_initializer"
        or crypto.get("salt_published") is not False
    ):
        raise ValueError("DCRat暗号initializerの検証契約が一致しません")
    endpoints = recovered.get("config_endpoints")
    if not isinstance(endpoints, list) or not endpoints or len(endpoints) > 64:
        raise ValueError("DCRat endpoint一覧が不正です")
    normalized = []
    for item in endpoints:
        if not isinstance(item, dict):
            raise ValueError("DCRat endpointがobjectではありません")
        host = item.get("host")
        port = item.get("port")
        if (
            not isinstance(host, str)
            or not valid_host(host)
            or not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65_535
        ):
            raise ValueError("DCRat endpointのhostまたはportが不正です")
        normalized.append(
            {
                "host": host.casefold().rstrip("."),
                "port": port,
                "confidence": "confirmed_static_configuration",
                "evidence": {
                    "kind": "hmac_verified_dotnet_settings",
                    "all_expected_fields_validated": True,
                },
            }
        )
    certificate = recovered.get("certificate")
    if not isinstance(certificate, dict):
        raise ValueError("DCRat証明書情報が不正です")
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
        raise ValueError("DCRat証明書pinが不正です")
    return {
        "version": recovered.get("version"),
        "install": recovered.get("install"),
        "group": recovered.get("group"),
        "anti_analysis": recovered.get("anti_analysis"),
        "endpoints": normalized,
        "dynamic_config_url": recovered.get("dynamic_config_url"),
        "certificate": {
            "sha256": cert_hash,
            "size": cert_size,
            "certificate_mismatch_excludes_c2": False,
        },
        "crypto_profile": crypto,
    }


def _validated_protocol(data: bytes, digest: str) -> dict[str, object]:
    module = _load_common_module("dotnet_rat_protocol_evidence")
    result = module.recover(data, "dcrat", digest)
    if (
        not isinstance(result, dict)
        or result.get("family") != "dcrat"
        or result.get("sample_sha256") != digest
        or result.get("analysis_status") != "complete"
        or result.get("safety", {}).get("sample_executed") is not False
        or result.get("safety", {}).get("network_contacted") is not False
    ):
        raise ValueError("DCRat protocol証拠が完全一致しません")
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
    constants: list[str] | None = None,
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
        "constants": constants or [],
        "source": "exact SHA-256のmanaged CILとGhidra MCP構造レビュー",
        "tool": "dnfile_dncil_bounded_static_parser+ghidra-mcp",
        "program_selector": f"sha256:{digest}",
        "confidence": "confirmed_static_review",
        "selected_for_characteristic_analysis": True,
    }


def _reviewed_functions(digest: str) -> list[dict[str, object]]:
    """完全SHA一致で確認した代表methodを公開可能な処理要約へ変換する。"""

    if digest != _REVIEWED_SHA256:
        return []
    return [
        _record(digest, "0x06000001", "Client.Program.Main", "loader_execution", "設定検証、解析回避、永続化、C2再接続を統括します。", ["起動遅延を適用します。", "暗号化Settingsを復号・検証し、失敗時は終了します。", "任意のVM判定、process blocking、critical process化を適用します。", "永続化、sleep防止、設定消去、AMSI patchを実行します。", "接続が成立するまで初期化を再試行します。"], callees=["Client.Settings.InitializeSettings", "Client.Install.NormalStartup.Install", "Client.Connection.Amsi.Bypass", "Client.Connection.ClientSocket.InitializeClient"], apis=["Thread.Sleep", "Environment.Exit"]),
        _record(digest, "0x06000003", "Client.Settings.InitializeSettings", "config_decoder", "Settingsのmaster key、暗号化field、証明書署名を認証付きで復元します。", ["Base64 master keyをUTF-8へ変換します。", "PBKDF2由来keyで各Settings fieldをHMAC検証後にAES-CBC復号します。", "HWIDを導出し、埋め込み証明書をX509Certificate2へ読み込みます。", "署名検証に失敗した場合はfalseを返します。"], callees=["Client.Algorithm.Aes256..ctor", "Client.Algorithm.Aes256.Decrypt", "Client.Settings.VerifyHash"], apis=["Convert.FromBase64String", "X509Certificate2..ctor"]),
        _record(digest, "0x06000004", "Client.Settings.VerifyHash", "config_authentication", "証明書公開鍵で設定署名を検証し、改変設定を拒否します。", ["証明書公開鍵を取得します。", "設定対象のSHA-256を計算します。", "埋め込み署名をBase64復号します。", "RSA VerifyHashの結果だけを返します。"], apis=["SHA256.ComputeHash", "RSACryptoServiceProvider.VerifyHash"]),
        _record(digest, "0x0600006c", "Client.Algorithm.Aes256..ctor", "config_key_derivation", "PBKDF2-HMAC-SHA1を50,000回適用し、暗号鍵と認証鍵を分離します。", ["空のmaster keyを拒否します。", "review済みcctorのASCII saltを使用します。", "32 byteのAES鍵と64 byteのHMAC鍵を順に導出します。"], apis=["Rfc2898DeriveBytes..ctor", "Rfc2898DeriveBytes.GetBytes"], constants=["50000 iterations", "32-byte encryption key", "64-byte authentication key"]),
        _record(digest, "0x0600001b", "Client.Connection.ClientSocket.InitializeClient", "command_control", "固定または動的設定から接続先を選び、TLS sessionとread loopを開始します。", ["host／port候補を選択し、domainはDNS解決します。", "必要時だけ動的設定URLを取得してhost／portを更新します。", "TCP接続をSslStreamで包みAuthenticateAsClientを実行します。", "ClientInfoを送信し、keepaliveとping timerを開始します。", "4 byte headerの非同期readを開始します。"], callees=["Client.Helper.IdSender.SendInfo", "Client.Connection.ClientSocket.Send", "Client.Connection.ClientSocket.ReadServertData"], apis=["Dns.GetHostAddresses", "TcpClient.Connect", "SslStream.AuthenticateAsClient", "SslStream.BeginRead"]),
        _record(digest, "0x0600001f", "Client.Connection.ClientSocket.ReadServertData", "command_control", "4 byte little-endian長でTLS受信frameを再構成し、完全なbodyだけをdispatcherへ渡します。", ["Tls streamからheaderまたはbodyの残byteを読みます。", "headerをInt32長へ変換してbufferを割り当てます。", "bodyが揃うまでoffsetを更新します。", "完全frameを別threadのReadへ渡し、次のheader readを再開します。"], callees=["Client.Connection.ClientSocket.Read"], apis=["SslStream.EndRead", "BitConverter.ToInt32", "SslStream.BeginRead"]),
        _record(digest, "0x06000020", "Client.Connection.ClientSocket.Send", "command_control", "送信bodyへ4 byte little-endian長を付け、TLS streamへ上限付きで書き込みます。", ["送信lockを取得し、接続状態を確認します。", "body長をlittle-endian headerへ変換します。", "headerとbodyをSslStreamへ書き込みflushします。", "例外時は接続状態をfalseへ落とします。"], apis=["Monitor.Enter", "BitConverter.GetBytes", "SslStream.Write", "SslStream.Flush"]),
        _record(digest, "0x06000021", "Client.Connection.ClientSocket.KeepAlivePacket", "command_control", "`Pac_ket=Ping`とactive window情報をMessagePack化してheartbeatを送ります。", ["MessagePack mapを作成します。", "packet keyへPingを設定します。", "Messageへactive window titleを設定します。", "圧縮MessagePackを送信し、pong待ち状態へ移行します。"], callees=["Client.Connection.ClientSocket.Send"], apis=["MsgPack.ForcePathObject", "Methods.GetActiveWindowTitle", "MsgPack.Encode2Bytes"]),
        _record(digest, "0x06000023", "Client.Connection.ClientSocket.Read", "command_dispatcher", "受信MessagePackをheartbeat、plugin要求、plugin保存へ分岐します。", ["受信bodyをMessagePackへ復号します。", "Po_ngでは待ち状態とintervalを更新します。", "plu_ginではregistry cacheを参照し、欠落時はsendPlugin要求を返します。", "save_Pluginではplugin byte列をregistryへ保存します。", "利用可能なpluginをInvokeへ渡します。"], callees=["Client.Connection.ClientSocket.Invoke", "Client.Connection.ClientSocket.Send"], apis=["MsgPack.DecodeFromBytes", "SetRegistry.GetValue", "SetRegistry.SetValue"]),
        _record(digest, "0x06000024", "Client.Connection.ClientSocket.Invoke", "plugin_loader", "registryから得た圧縮pluginを展開し、managed assemblyとして反射呼出しします。", ["Dll識別子でplugin cacheを取得します。", "plugin byte列を展開してAssembly.Loadします。", "Plugin.Plugin型のRun methodを反射で呼び出します。", "socketと受信MsgPackだけを引数へ渡します。"], apis=["Zip.Decompress", "Assembly.Load", "Type.InvokeMember"]),
        _record(digest, "0x06000054", "Client.Helper.IdSender.SendInfo", "host_discovery", "端末属性を`Pac_ket=ClientInfo`の登録MessagePackへ集約します。", ["HWID、user、OS、camera、実行pathを収集します。", "version、権限、active window、AV、install時刻、groupを設定します。", "登録mapを圧縮MessagePackへ変換します。"], apis=["Environment.UserName", "Process.GetCurrentProcess", "Methods.GetActiveWindowTitle", "Methods.Antivirus", "MsgPack.Encode2Bytes"]),
        _record(digest, "0x06000035", "Client.Install.NormalStartup.Install", "persistence", "AppData配下へ自己複製し、権限に応じてscheduled taskまたはRun keyを登録します。", ["展開済みinstall directoryとfile名を結合します。", "同一pathの既存processを停止します。", "管理者ではlogon scheduled task、非管理者ではHKCU Runを設定します。", "自己複製後に一時batchで元file削除を予約して終了します。"], apis=["Process.GetProcesses", "RegistryKey.SetValue", "File.ReadAllBytes", "Process.Start"]),
        _record(digest, "0x06000028", "Client.Connection.Amsi.Bypass", "defense_evasion", "architecture別patch byte列を復号してAmsiScanBufferへ適用します。", ["process architectureを判定します。", "該当する固定patch byte列をBase64復号します。", "PatchAへ渡してAMSI entryを更新します。"], callees=["Client.Connection.Amsi.PatchA"], apis=["Convert.FromBase64String"]),
        _record(digest, "0x0600003b", "Client.Helper.AntiProcess.Block", "defense_evasion", "process snapshotを反復し、指定解析・防御tool名と一致するprocessを終了します。", ["Toolhelp snapshotを作成します。", "process名をreview済みblocklistと比較します。", "一致processをTerminateProcessで終了します。", "Enabled中はsleepを挟んで反復します。"], apis=["CreateToolhelp32Snapshot", "Process32First", "Process32Next", "TerminateProcess"]),
    ]


def _program_evidence(digest: str) -> list[dict[str, object]]:
    if digest != _REVIEWED_SHA256:
        return []
    return [
        {
            "program_id": "ghidra-dcrat-85cd6c32",
            "program_selector": "/DailyAnalysis/20260818/AsyncRAT/85cd6c32/85cd6c3229f9ab547cc54f2cbdcf6ef2937987c0181e5ffa3c4205105df8e8fe.exe",
            "relationship": "root_terminal_managed_client",
            "name": "85cd6c32.exe",
            "architecture": "x86",
            "compiler": ".NET CLR managed CIL",
            "language": "x86:LE:32:default",
            "endian": "little",
            "address_size": "32",
            "function_count": 167,
            "ghidra_function_count": 167,
            "managed_method_count": 194,
            "mcp_responses_valid": True,
            "entry_points": [
                {"name": "Client.Program.Main", "address": "0x06000001", "kind": "managed_entrypoint"}
            ],
            "imports": ["_CorExeMain"],
            "function_hashes": [],
            "retrieval_coverage": {
                "managed_methods_declared": 194,
                "managed_methods_with_body": 175,
                "managed_methods_without_body": 19,
                "malformed_method_bodies": 0,
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
    if structural["matched"] is True:
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
                "value": f'{item["host"]}:{item["port"]}',
                "role": "configured_c2",
                "confidence": "confirmed_static_config",
                "source": "hmac_verified_dotnet_settings",
            }
            for item in recovery["endpoints"]
        )
        certificate = recovery["certificate"]
        findings.append(
            {
                "kind": "certificate.sha256",
                "value": certificate["sha256"],
                "role": "tls_certificate_pin",
                "confidence": "confirmed_static_config",
                "source": "hmac_verified_dotnet_settings",
            }
        )
    config = {
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
        "dcrat",
        data,
        config,
        findings,
        [
            "検体、managed CIL、pluginを実行せず、外部hostへ接続していません。",
            "完全なSettings、packet field、暗号initializer構造が揃わない入力では復号しません。",
            "設定値はHMAC-SHA256を検証してからAES-256-CBCで復号します。",
            "providerのAsyncRATラベルは分類根拠に使用しません。",
            "Ghidraのnative decompilerはmanaged CILの意味復元へ使用していません。",
        ],
    )
    result["static_config_recovered"] = recovery is not None
    result["config_endpoints"] = (
        [
            {
                **item,
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
    result["program_evidence"] = _program_evidence(digest)
    return result