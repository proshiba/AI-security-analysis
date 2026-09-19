#!/usr/bin/env python3
"""2026-09-19日次50件の未完了caseを、隔離済み原本から再点検する。"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from pathlib import Path

import pefile

FRAMEWORK = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FRAMEWORK))
from ioc_markdown import render_canonical_ioc_document
from recover_clipboard_xor_strings import recover_strings
from recover_ror13_peb_api_hashes import load_export_map, review_sample

from malware.nanocore.detect import detect as detect_nanocore
from malware.nanocore.extract_config import extract_config as extract_nanocore

COLLECTION = "malwarebazaar-windows-20260919-0050"
CLIPBOARD_APIS = {
    "GetClipboardSequenceNumber", "OpenClipboard", "GetClipboardData",
    "EmptyClipboard", "SetClipboardData",
}
VSHELL_APIS = {
    "ws2_32.dll!WSAStartup", "ws2_32.dll!WSASocketA", "ws2_32.dll!connect",
    "ws2_32.dll!send", "ws2_32.dll!recv", "kernel32.dll!VirtualAlloc",
}
CLIPBOARD_ENTRY_CODE_SHA256 = "8d27434975b183425a9133f9771c49e1e384ad37c80bece41a5ac4b80d44b58b"


def _json(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"JSON objectが必要です: {path.name}")
    return value


def _render_json(value: dict[str, object]) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _defang(host: str) -> str:
    return host.replace(".", "[.]")


def _review_case(
    item: dict[str, object],
    case_dir: Path,
    sample_path: Path,
    exports: dict[int, list[str]],
) -> tuple[dict[str, object], str]:
    digest = str(item["sha256"])
    data = sample_path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise ValueError(f"隔離入力SHA-256がmanifestと一致しません: {digest}")
    image = pefile.PE(data=data, fast_load=False)
    try:
        is_dll = bool(image.FILE_HEADER.Characteristics & 0x2000)
        is_managed = bool(image.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress)
        imports = {
            symbol.name.decode("ascii", errors="replace")
            for entry in getattr(image, "DIRECTORY_ENTRY_IMPORT", [])
            for symbol in entry.imports
            if symbol.name
        }
        pe = {
            "machine": f"0x{image.FILE_HEADER.Machine:04x}",
            "is_dll": is_dll,
            "is_managed": is_managed,
            "entrypoint_rva": f"0x{image.OPTIONAL_HEADER.AddressOfEntryPoint:x}",
            "size": len(data),
            "import_names": sorted(imports),
        }
        entry_code_sha256 = hashlib.sha256(image.sections[0].get_data()[:0x300]).hexdigest()
    finally:
        image.close()

    base = {
        "schema_version": 1,
        "collection": COLLECTION,
        "sha256": digest,
        "pe": pe,
        "provider_label": item.get("metadata", {}).get("signature"),
        "provider_tags": item.get("metadata", {}).get("tags", []),
        "safety": {"sample_executed": False, "network_contacted": False, "raw_payload_published": False},
        "source_evidence": [
            "隔離原本のSHA-256とPEヘッダー",
            "個別caseのstatic-logic.jsonおよびstatic-layers.json",
        ],
    }
    lines = [f"# 追加静的解析：{digest}", "", "前回の日次解析後に隔離済み原本を再点検した結果です。検体の実行や外部接続は行っていません。", ""]

    if is_managed:
        detection = detect_nanocore(data, sample_path)
        if detection.get("matched") and detection.get("observations", {}).get("encrypted_resource_config_verified"):
            config = extract_nanocore(data)
            base.update({
                "group": "nanocore_confirmed_by_config",
                "family_attribution": "confirmed_static_configuration_format",
                "config": config["config"],
                "c2_static": config["c2"],
                "resource": config["resource"],
                "limitations": ["C2の到達性・稼働は未確認", "実行時の親子プロセスと後続指令は未観測"],
            })
            lines += [
                "## 判定", "", "- NanoCore RAT：暗号化resourceをDES-CBCで復号し、型付き設定列と接続設定を検証したため、静的に確認。",
                f"- Version：`{config['version']}`、group：`{config['campaign']}`、mutex：`{config['mutex']}`",
                "- 接続先は設定値であり、到達性や稼働の確認結果ではありません。", "", "## 静的C2設定", "",
            ]
            for endpoint in config["c2"]:
                lines.append(f"- `{_defang(endpoint['host'])}:{endpoint['port']}`（{endpoint['transport']}、設定由来）")
            lines += ["", "## 実行設定", ""]
            for key in (
                "RunOnStartup", "RequestElevation", "BypassUserAccountControl",
                "ClearZoneIdentifier", "PreventSystemSleep", "RunDelay",
                "ConnectDelay", "RestartDelay", "KeepAliveTimeout", "UseCustomDnsServer",
                "PrimaryDnsServer", "BackupDnsServer",
            ):
                if key in config["config"]:
                    lines.append(f"- `{key}`：`{config['config'][key]}`")
            lines += ["", "復号したpluginやpayloadの生bytesは公開していません。", ""]
            return base, "\n".join(lines)

    if is_dll and CLIPBOARD_APIS.issubset(imports):
        if pe["entrypoint_rva"] != "0x1010" or entry_code_sha256 != CLIPBOARD_ENTRY_CODE_SHA256:
            raise ValueError("clipboard DLL入口コードの指紋が既知群と異なります")
        logic = _json(case_dir / "static-logic.json")
        observed = {name for function in logic.get("functions", []) for name in function.get("api_calls", [])}
        if CLIPBOARD_APIS.issubset(observed):
            recovered = recover_strings(sample_path)
            address_values = sorted(item["value"] for item in recovered["strings"])
            base.update({
                "group": "clipboard_replacement_dll",
                "family_attribution": "not_confirmed",
                "behavior": "clipboard_poll_read_transform_write",
                "process_context": "dll_process_attach_entrypoint_direct_poll_loop",
                "entry_code_sha256": entry_code_sha256,
                "obfuscated_address_literals": recovered["strings"],
                "address_literal_profile_sha256": hashlib.sha256(
                    "\n".join(address_values).encode("utf-8")
                ).hexdigest(),
                "c2_static": [],
                "limitations": [
                    "実際にロードしたホストプロセスは未観測",
                    "復号された各文字列がどの条件分岐で使用されるかは未確定",
                    "Remus本体のファミリー帰属には使用しない",
                ],
            })
            lines += [
                "## 判定", "", "- PEヘッダーはDLLです。提供元の`exe`ラベルとは一致しません。",
                "- 関数証跡とimportに`GetClipboardSequenceNumber`、`GetClipboardData`、`EmptyClipboard`、`SetClipboardData`が共存します。",
                "- `DLL_PROCESS_ATTACH`（入口RVA `0x1010`）から直接、`GetClipboardSequenceNumber`の変更待ちと`Sleep(1)`のポーリングへ入ります。新規プロセス生成ではなく、ロード元プロセス内で動く形です。attach経路に通常のreturnは見えません。",
                "- `GetClipboardData(13)`でUnicode文字列を読み、内部変換後に`EmptyClipboard`／`SetClipboardData(13)`で再設定する構造です。",
                "- `dropped-by-Remus`は提供元の関連タグです。このDLL自体をRemusStealer本体とは確定しません。",
                "- 文字列構築ループの二系列XORを静的再現し、埋め込まれたアドレス形式文字列を復元しました。各値の実際の置換条件・到達可能性は未確定です。", "",
                "## 復元したアドレス形式文字列", "",
            ]
            for string in recovered["strings"]:
                lines.append(f"- `{string['value']}`（参照RVA `{string['pointer_slot_rva']}`）")
            lines += ["", "このDLLから静的C2接続先は確認できません。実際のロード元プロセスは未観測です。", ""]
            return base, "\n".join(lines)

    if not is_dll and len(data) < 20_000:
        network = review_sample(sample_path, exports)
        resolved = {name for entry in network.get("matches", []) for name in entry.get("exports", [])}
        endpoint = network.get("endpoint_candidate")
        if VSHELL_APIS.issubset(resolved) and endpoint:
            provider_vs = str(item.get("metadata", {}).get("signature") or "").casefold() == "vshell"
            base.update({
                "group": "vshell_like_network_loader",
                "family_attribution": (
                    "provider_reported_static_code_profile" if provider_vs else "static_code_profile_only"
                ),
                "api_hashes": network["matches"],
                "c2_static": [endpoint],
                "memory_xor_byte_constants": network["memory_xor_byte_constants"],
                "limitations": [
                    "接続先は静的復元候補であり稼働未確認",
                    "受信後stageの内容・ファミリー・実行結果は未確認",
                ],
            })
            lines += [
                "## 判定", "", "- PEBを走査するROR13 APIハッシュ解決関数を逆アセンブルで確認しました。",
                "- `WSAStartup`、`WSASocketA`、`connect`、`send`、`recv`、`VirtualAlloc`をexport表とのハッシュ照合で回収しました。",
                "- stack上のIP断片と`sockaddr`ポートから、次の接続先候補を復元しました。",
                f"- `{_defang(endpoint['host'])}:{endpoint['port']}`（TCP、静的候補。稼働・C2応答は未確認）",
                f"- 受信バッファに対する1-byte XOR定数：`{', '.join(network['memory_xor_byte_constants'])}`。",
                "- 代表的なx86/x64亜種には、HTTP GET組立、送信、HTTPヘッダー境界までの受信、後続bodyの復号、実行可能メモリ確保と間接転送が見えます。後続stageは取得・実行していません。",
                (
                    "- VShellは提供元ラベルと静的コード類似に基づくprofileです。受信後stageのファミリー確認とは区別します。"
                    if provider_vs else
                    "- この検体にVShellの提供元ラベルはありません。同群との静的コード類似によるprofileであり、受信後stageのファミリー確認ではありません。"
                ), "",
            ]
            return base, "\n".join(lines)

    layers = _json(case_dir / "static-layers.json").get("layers", [])
    embedded = []
    for layer in layers:
        if layer.get("parent_sha256") != digest:
            continue
        child_path = sample_path.parent / "layers" / f"{layer['sha256']}.quarantine.bin"
        child_data = child_path.read_bytes()
        if hashlib.sha256(child_data).hexdigest() != layer["sha256"] or len(child_data) != layer["size"]:
            raise ValueError("埋め込みPEのSHA-256または長さが一致しません")
        wix_evidence = all(
            token in child_data
            for token in (b"wixca.pdb", b"WixQuietExec", b"WixRegisterRestartResources")
        )
        embedded.append({
            "sha256": layer["sha256"], "size": layer["size"], "format": layer["format"],
            "wix_custom_action_runtime_evidence": wix_evidence,
        })
    fleetdeck_installer = all(
        token in data
        for token in (b"FleetDeck Agent", b"fleetdeck_agent_svc.exe", b"WIX_UPGRADE_DETECTED")
    )
    base.update({
        "group": "other_go_embedded_pe_followup",
        "family_attribution": "unresolved",
        "embedded_layers": embedded,
        "fleetdeck_installer_metadata_observed": fleetdeck_installer,
        "c2_static": [],
        "limitations": ["配布経路と実際のインストール結果は未確認", "悪性・無害判定と終端C2は未確認"],
    })
    lines += [
        "## 判定", "", "- Go製のルートPEに埋め込みPEがあります。",
        "- 親PEには`FleetDeck Agent`、`fleetdeck_agent_svc.exe`、`WIX_UPGRADE_DETECTED`が共存し、MSI構成情報と整合します。",
        "- 埋め込みDLLには`wixca.pdb`、`WixQuietExec`、`WixRegisterRestartResources`が共存し、WiXカスタムアクションruntimeの証跡です。",
        "- 以上は埋め込みPEの役割を絞る静的証拠ですが、悪性・無害の結論やC2の確認にはなりません。",
        "- 間接分岐を含む関数1件はGhidra逆コンパイルが制約付きで、実際のインストール結果は未解決です。", "",
        "## 復元層", "",
    ]
    for layer in embedded:
        lines.append(f"- `{layer['sha256']}`、{layer['size']} bytes、{layer['format']}")
    lines.append("")
    return base, "\n".join(lines)


def _emit(path: Path, content: str, *, check: bool) -> None:
    if check:
        if not path.is_file() or path.read_text(encoding="utf-8") != content:
            raise ValueError(f"追加解析成果物が一致しません: {path}")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", newline="\n")


def _readme_with_followup(path: Path, note: str) -> str:
    original = path.read_text(encoding="utf-8")
    marker = "<!-- static-followup-20260919 -->"
    lines = original.splitlines(keepends=True)
    if not lines or not lines[0].startswith("# "):
        raise ValueError(f"READMEの見出しを特定できません: {path}")
    if marker in original:
        if len(lines) < 5 or lines[2].strip() != marker or lines[4].strip():
            raise ValueError(f"READMEの追加解析注記が不正です: {path}")
        lines = [lines[0], *lines[5:]]
    insert = f"\n{marker}\n{note}\n\n"
    return lines[0] + insert + "".join(lines[1:])


def _verified_nanocore_iocs(case_dir: Path, record: dict[str, object]) -> dict[str, object]:
    existing = _json(case_dir / "iocs.json")
    if existing.get("sha256") != [record["sha256"]] or existing.get("sample_executed") is not False:
        raise ValueError("既存IOCのcase IDまたは安全境界が一致しません")
    if existing.get("network_contacted") is not False:
        raise ValueError("既存IOCで外部接続が報告されています")
    network = []
    for endpoint in record["c2_static"]:
        network.append({
            "host": endpoint["host"],
            "port": endpoint["port"],
            "transport": endpoint["transport"],
            "role": "configured_c2",
            "confidence": "confirmed_static_configuration",
            "source": "handler:nanocore:extract_config",
            "evidence": {"kind": "des_cbc_typed_resource_config"},
            "contacted": False,
            "liveness_confirmed": False,
        })
    if len(network) != 2:
        raise ValueError("NanoCore設定の接続先2件を確認できません")
    return {
        "schema_version": 1,
        "sha256": existing["sha256"],
        "sample_executed": False,
        "network_contacted": False,
        "assessment": "暗号化resourceの型付き設定からC2を静的に確認。到達性は未検証",
        "network": network,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--private-root", required=True, type=Path)
    parser.add_argument("--dll-dir", type=Path, default=Path("C:/Windows/System32"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    repository = args.repository.resolve()
    collection_dir = repository / "analysis-results" / "collections" / COLLECTION
    manifest = _json(collection_dir / "manifest.json")
    summary = _json(collection_dir / "publication-summary.json")
    case_paths = {item["sha256"]: repository / item["case_path"] for item in summary["cases"]}
    exports = load_export_map(args.dll_dir)
    records: list[dict[str, object]] = []
    rows: list[str] = []
    for item in manifest["acquisition_items"]:
        digest = item["sha256"]
        case_dir = case_paths[digest]
        if not case_dir.resolve().is_relative_to((repository / "analysis-results" / "malware").resolve()):
            raise ValueError("case公開先がmalware tree外です")
        sample_path = args.private_root / digest / "ghidra-input" / f"{digest}.quarantine.bin"
        if not sample_path.is_file():
            raise ValueError(f"隔離済み原本がありません: {digest}")
        record, markdown = _review_case(item, case_dir, sample_path, exports)
        _emit(case_dir / "followup-static-review.json", _render_json(record), check=args.check)
        _emit(case_dir / "FOLLOWUP-STATIC-REVIEW.md", markdown, check=args.check)
        if record["group"] == "nanocore_confirmed_by_config":
            canonical = _verified_nanocore_iocs(case_dir, record)
            _emit(case_dir / "iocs.json", _render_json(canonical), check=args.check)
            _emit(
                case_dir / "IOC-LIST.md",
                render_canonical_ioc_document(canonical, expected_sha256=digest),
                check=args.check,
            )
        status = {
            "nanocore_confirmed_by_config": "NanoCoreの設定および静的C2を確認しました。",
            "vshell_like_network_loader": "network loaderの接続先候補を復元しました。到達性と後続stageは未確認です。",
            "clipboard_replacement_dll": "PEヘッダーからDLLと確認しました。clipboard改変処理は確認、ホスト過程は未確認です。",
            "other_go_embedded_pe_followup": "埋め込みPEを確認しましたが、ファミリーと終端C2は未解決です。",
        }[record["group"]]
        note = f"追加静的解析：{status} [詳細](FOLLOWUP-STATIC-REVIEW.md)。以下は初回解析時点の記録です。"
        _emit(case_dir / "README.md", _readme_with_followup(case_dir / "README.md", note), check=args.check)
        records.append(record)
        endpoint = ", ".join(
            f"{_defang(str(value['host']))}:{value['port']}" for value in record["c2_static"]
        ) or "未確認"
        detail = Path(os.path.relpath(case_dir / "FOLLOWUP-STATIC-REVIEW.md", collection_dir)).as_posix()
        rows.append(f"| [`{digest}`]({detail}) | `{record['group']}` | {endpoint} |")
    counts = Counter(str(record["group"]) for record in records)
    if len(records) != 50 or counts != {
        "clipboard_replacement_dll": 37,
        "vshell_like_network_loader": 10,
        "nanocore_confirmed_by_config": 2,
        "other_go_embedded_pe_followup": 1,
    }:
        raise ValueError(f"今回の静的群別件数が期待値と異なります: {dict(counts)}")
    clipboard_records = [item for item in records if item["group"] == "clipboard_replacement_dll"]
    literal_profiles = Counter(item["address_literal_profile_sha256"] for item in clipboard_records)
    distinct_literals = {
        string["value"]
        for item in clipboard_records
        for string in item["obfuscated_address_literals"]
    }
    if len(literal_profiles) != 4 or len(distinct_literals) != 30:
        raise ValueError("clipboard難読化文字列の群別集計が期待値と異なります")
    vshell_provider_labeled = sum(
        item["group"] == "vshell_like_network_loader"
        and str(item.get("provider_label") or "").casefold() == "vshell"
        for item in records
    )
    if vshell_provider_labeled != 8:
        raise ValueError("VShell提供元ラベル件数が期待値と異なります")
    report = [
        "# 2026-09-19未完了50検体の追加静的解析", "",
        "日次解析で未解決だった50件を、SHA-256照合済み隔離原本と既存関数証跡で再点検しました。検体実行と外部通信は行っていません。", "",
        "- NanoCore 2件：暗号化設定を復号し、各2件の設定C2と実行フラグを確認。",
        "- VShell類似network loader 10件（提供元VShellラベル8件、ラベルなし2件）：ROR13 APIハッシュ、HTTP/ソケット処理、XOR `0x99`、7種類の静的接続先候補を確認。後続stageは未取得・未実行。",
        "- clipboard改変DLL 37件：PEヘッダーはDLLで、日次取得メタデータのEXE表記を訂正。二系列XORで難読化されたアドレス形式文字列を検体別に復元。`dropped-by-Remus`は関連タグであり本体帰属ではありません。",
        "- Go製埋め込みPE 1件：関数の間接分岐と終端役割が未解決。", "",
        (
            "clipboard DLL 37件では、復元文字列の集合で4群（29／4／2／2件）に分かれ、異なるアドレス形式文字列は30値です。"
            "各値の実際の置換条件・到達可能性は静的な文字列復元だけでは確定しません。"
        ), "",
        "従来の`manifest.json`／`publication-summary.json`は初回解析時点のsnapshotです。下記の追加解析結果が、新規に確認した事実について優先します。静的接続先は稼働確認ではありません。", "",
        "| SHA-256 | 追加解析群 | 静的接続先 |", "|---|---|---|", *rows, "",
    ]
    _emit(collection_dir / "FOLLOWUP-STATIC-ANALYSIS.md", "\n".join(report), check=args.check)
    _emit(
        collection_dir / "README.md",
        _readme_with_followup(
            collection_dir / "README.md",
            "追加静的解析で内訳を更新しました：NanoCore 2件、network loader 10件、clipboard改変DLL 37件、未解決のGo製1件。"
            "[追加解析の全件一覧](FOLLOWUP-STATIC-ANALYSIS.md)。以下の形式・判定・C2件数は初回解析時点の記録です。",
        ),
        check=args.check,
    )
    _emit(
        collection_dir / "followup-static-manifest.json",
        _render_json({
            "schema_version": 1,
            "collection": COLLECTION,
            "case_count": len(records),
            "group_counts": dict(sorted(counts.items())),
            "clipboard_address_literal_profile_counts": dict(sorted(literal_profiles.items())),
            "clipboard_distinct_address_literal_count": len(distinct_literals),
            "records": [{"sha256": item["sha256"], "group": item["group"]} for item in records],
            "safety": {"sample_executed": False, "network_contacted": False},
        }),
        check=args.check,
    )
    print(json.dumps({"case_count": len(records), "group_counts": counts, "check": args.check}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
