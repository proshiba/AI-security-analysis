#!/usr/bin/env python3
"""2026-07-23に取得したValleyRAT／ACRStealer各10件を標準caseへ公開する。"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any

COMMON = Path(__file__).resolve().parent
REPOSITORY = COMMON.parents[1]
if str(COMMON) not in sys.path:
    sys.path.insert(0, str(COMMON))

from case_features import build_case_profile, render_features_markdown  # noqa: E402
from static_logic import build_static_logic_report, render_static_logic_markdown  # noqa: E402


FAMILY_DISPLAY = {"valleyrat": "ValleyRAT", "acrstealer": "ACRStealer"}
ACR_TAG_URL = "https://bazaar.abuse.ch/browse/tag/ACRStealer/"
VALLEY_SIGNATURE_URL = "https://bazaar.abuse.ch/browse/signature/ValleyRAT/"
GHIDRA_ACR_LOADER = (
    "/Malware/ACRStealer/20260723/06f6a0dc/"
    "06f6a0dc417bf0c8d1fa54754f53d37d190a3b9bf66658e00a630ae0bb56dfab.dll"
)
GHIDRA_VALLEY_DLL = (
    "/Malware/ValleyRAT/20260723/0f963f03/"
    "0f963f03d73f3f874928d744e8188b3f61470f982ab1100a5645d0a3c27ee611.dll"
)
VALLEY_ROLES = {
    "12b920865bc8bd9bad20650a0f7849fe2856de3d72bc5f1a93bb288e8eefaca2": "installer_protected_pe",
    "5876be168613a5e77024f79dad518662e8fd418f01d5839fc7e73ecb0f085a92": "multi_pe_software_bundle",
    "9a9d372cc821b6d2f7e30abb80aff7cae841703db0fb78bd859e6581420fbc07": "high_entropy_installer",
    "0f963f03d73f3f874928d744e8188b3f61470f982ab1100a5645d0a3c27ee611": "native_dll_rat_worker",
    "a0eb29beacb4463ed88b579625a1483245dff067697b85d93fd62992c5512489": "protected_pe_resource_delivery",
    "5f8daf53ef216151a72cb3fbb953886c74488b9d91b3a8afbc9bbf39e8d5eacf": "msi_embedded_pe_delivery",
    "b3369a20d7c603b4d1078010b008a9db1b49dccf694a05e6bd49ede2762a8075": "direct_pe_confirmed_vvas_config",
    "8715bb53fad907f12ab1b5ec7bad49d2a4f72bf07f81bb2a6621fd1f9f55ffa1": "resource_zip_pe_png_delivery",
    "edb371be39673ca248b4dcb168de0efd90e9d7a39d7cc096c83c435bd6fe260b": "high_entropy_installer",
    "a0d1e6b471522635bcf7ca0176d6ee8febcf90184078b5e8ce24e0eca970b532": "high_entropy_direct_pe",
}
DEPUMPED_PROGRAMS = {
    "1220d2250778f214b8ef2d37cf6c0904fb6080a42ad4e1e9bd253f84c8e7e10e": (
        "/Malware/ACRStealer/20260723/1220d225/depumped/"
        "cd768f5f29565902678d40878c444e18ba9b885613bfa6c4afb86ebef752cf98.quarantine.bin"
    ),
    "14ac0c55100d957d1b198583461b2605e6e72c2538039b54c538dc7e356ddce3": (
        "/Malware/ACRStealer/20260723/14ac0c55/depumped/"
        "3bd0fdae5015a39c2c8797a908a6f33044fac422ee7a0c96fc806ae1db60e1fd.quarantine.bin"
    ),
    "7c9a76145f39a052020aed4eb60927ad678c792c15bdf4f192d36a569e0457f8": (
        "/Malware/ACRStealer/20260723/7c9a7614/depumped/"
        "5f6e38705ca2fd3d555b50b694096206208f0f60fb8953ccaefab18012ffcda6.quarantine.bin"
    ),
    "c4b117f30786d0b328d90c2818e4c454e81d29ed5921d8f8847e80333a12ee86": (
        "/Malware/ACRStealer/20260723/c4b117f3/depumped/"
        "5c1680f7baedf86742d84a0b30f8972bb214a9b869da52e9e4e59400b24c5f1a.quarantine.bin"
    ),
}


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8-sig"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def load_handler_result(case: Path, report: dict[str, Any]) -> dict[str, Any]:
    for execution in report.get("handler_executions", []):
        relative = execution.get("result")
        if execution.get("status") == "succeeded" and relative:
            return load_json(case / relative)
    return {}


def record(
    name: str,
    address: str,
    role: str,
    summary: str,
    steps: list[str],
    *,
    selector: str,
    tool: str,
    callees: list[str] | None = None,
    api_calls: list[str] | None = None,
    confidence: str = "confirmed_static_review",
) -> dict[str, Any]:
    return {
        "name": name,
        "address": address,
        "role": role,
        "summary_ja": summary,
        "logic_steps_ja": steps,

        "callees": callees or [],
        "api_calls": api_calls or [],
        "source": "2026-07-23追加静的解析",
        "tool": tool,
        "program_selector": selector,
        "confidence": confidence,
    }


def reviewed_records(
    family: str, digest: str, role: str, result: dict[str, Any]
) -> tuple[list[dict[str, Any]], bool]:
    """関数または処理単位のレビュー記録と、関数本体レビュー済みかを返す。"""

    if digest == "06f6a0dc417bf0c8d1fa54754f53d37d190a3b9bf66658e00a630ae0bb56dfab":
        selector = GHIDRA_ACR_LOADER
        return [
            record("RunExport", "6657f33e", "export_entry", "Run exportから主処理を起動して待機する。", ["ProcessRunRequestを呼ぶ。", "1秒待機してexport呼出しを終了する。"], selector=selector, tool="ghidra-mcp", callees=["ProcessRunRequest"], api_calls=["Sleep"]),
            record("ProcessRunRequest", "6657f26a", "single_instance_and_delay", "名前付きeventで多重起動を抑止し、21秒後に主処理へ進む。", ["OpenEventAで既存eventを確認する。", "存在しない場合はeventを作成する。", "21秒sleepする。", "runtime初期化後にExecutePrimaryWorkflowを呼ぶ。"], selector=selector, tool="ghidra-mcp", callees=["InitializeRuntimeState", "InitializeWorkerState", "ExecutePrimaryWorkflow"], api_calls=["OpenEventA", "CreateEventA", "Sleep"]),
            record("InitializeWorkerState", "6657f1c5", "anti_analysis_setup", "NtTraceEventを動的解決し、vectored exception handlerを登録する。", ["ntdll.dll名を構築する。", "NtTraceEventを解決する。", "AddVectoredExceptionHandlerを登録する。"], selector=selector, tool="ghidra-mcp", api_calls=["GetProcAddress", "AddVectoredExceptionHandler"]),
            record("AllocateDecodedPayload", "6657e750", "memory_permission_change", "固定宛先領域をRWXへ変更する。", ["宛先0x6658A020、長さ0xBD152を選ぶ。", "VirtualProtectでPAGE_EXECUTE_READWRITEを付与する。"], selector=selector, tool="ghidra-mcp", api_calls=["VirtualProtect"]),
            record("ExecutePrimaryWorkflow", "6657e7a4", "dword_substitution_decoder", "256要素DWORD表を逆引きし、0xBD153 byteのshellcodeを復元する。", ["DWORD置換表を走査する。", "各encoded DWORDと一致する表indexを1 byteとして宛先へ書く。", "一致しない18要素は既存宛先byteを保持する。", "復元先を間接callする。"], selector=selector, tool="ghidra-mcp", callees=["AllocateDecodedPayload", "MapDecodedPayload"]),
            record("MapDecodedPayload", "6657e790", "payload_dispatch", "復元済みbufferを関数pointerとして実行する。", ["復元先addressを受け取る。", "間接callで制御を移す。"], selector=selector, tool="ghidra-mcp"),
        ], True
    if digest == "0f963f03d73f3f874928d744e8188b3f61470f982ab1100a5645d0a3c27ee611":
        return [
            record("RunExport", "1000e4c0", "export_entry", "worker threadを作成し、終了を待ってから短時間sleepする。", ["ExecuteWorkerThreadをCreateThreadへ渡す。", "WaitForSingleObjectでworkerを待つ。", "300ms sleepする。"], selector=GHIDRA_VALLEY_DLL, tool="ghidra-mcp", callees=["ExecuteWorkerThread"], api_calls=["CreateThread", "WaitForSingleObject", "Sleep"]),
            record("InitializeDllEntry", "100111f2", "dll_entry", "process attach時の初期化と共通DLL終了処理を分岐する。", ["reasonがPROCESS_ATTACHなら初期化routineを呼ぶ。", "共通DLL処理へmodule handleを渡す。"], selector=GHIDRA_VALLEY_DLL, tool="ghidra-mcp"),
            record("ExecuteWorkerThread", "1000df10", "rat_connection_workflow", "待機、handler選択、window監視、接続試行、registry条件、retryを反復する主worker。", ["設定由来の秒数をsleepする。", "local timeと例外handlerを初期化する。", "2組の設定bufferを交互に複製し、200回ごとに第3組へ切り替える。", "設定値により2つの通信handler候補を切り替える。", "必要時はEnumWindowsが0になるまで20秒間隔で待つ。", "選択handlerの接続判定を3秒間隔で反復する。", "eventと接続contextを作成し、registry値を4秒間隔で確認する。", "失敗時はhandlerを破棄して先頭へ戻り、成功／timeoutに応じ後処理と再待機を行う。"], selector=GHIDRA_VALLEY_DLL, tool="ghidra-mcp", api_calls=["Sleep", "EnumWindows", "CreateEventA", "RegOpenKeyExW", "RegQueryValueExW", "WaitForSingleObject"]),
        ], True
    if family == "valleyrat" and result.get("config", {}).get("static_config_recovered"):
        return [record("DecodeReversedVvasConfig", "python:decode_vvas_reversed_config", "config_decoder", "反転key/value文字列から検証済みC2 endpointを復元する。", ["文字列中の:p1と:o1 markerを確認する。", "文字列全体を反転して縦棒区切りfieldへ分割する。", "p1..p3とo1..o3を組み合わせる。", "hostと1～65535のportを検証し、loopbackを除外する。"], selector=f"sha256:{digest}", tool="valleyrat_static_extractor", confidence="confirmed_static_transform")], False
    if digest in DEPUMPED_PROGRAMS:
        return [
            record("RecoverPumpedPythonRuntime", "archive:python37.dll", "file_pump_recovery", "巨大宣言memberをPE section境界へ縮約し、証明書directoryを除外する。", ["32MiBまでのprefixだけを読む。", "raw sizeがvirtual sizeの8倍超かつ16MiB超のsectionを整合alignmentへ縮約する。", "security directoryをzero化する。", "正常PE境界までを復元する。"], selector=f"sha256:{digest}", tool="acrstealer_static_unpacker"),
            record("PythonRuntimeEntry", "101bc689", "python_runtime_entry", "4件で同一のPython runtime DLL entryを確認した。", ["PROCESS_ATTACH時にruntime初期化を呼ぶ。", "全reasonで共通DLL処理を呼ぶ。", "悪性C2処理はentry本体から確認できない。"], selector=DEPUMPED_PROGRAMS[digest], tool="ghidra-mcp", confidence="confirmed_static_review"),
            record("EnumerateEmbeddedPEResources", "pe:.rsrc", "resource_recovery", "縮約PEの.rsrcからsize-validな内包PEを回収し、hashで重複排除する。", ["resource directoryを上限付きで列挙する。", "MZとPE headerの整合性を検証する。", "内包PEのSHA-256とsizeだけを公開する。", "復元PEを実行しない。"], selector=f"sha256:{digest}", tool="bounded_static_unpacker"),
        ], False
    steps_by_role = {
        "sfx_autoit_delivery": ["SFX resourceからCABを回収する。", "CAB内のAutoIt3.exeとA3Xを分離する。", "A3X scriptのXOR文字列を復号する。", "RC4後にLZNT1展開して最終PEを復元する。"],
        "file_pumped_sfx_autoit_delivery": ["巨大化SFXのprefixからCABをcarveする。", "共通AutoIt delivery CABへ相関する。", "RC4/LZNT1後の保護PE hashを記録する。"],
        "msi_delivery": ["MSI/OLE streamを列挙する。", "CustomActionとCABを回収する。", "内包Go PEを静的解析し、net/http、net.Dial、os/exec不在を確認する。"],
        "synthetic_go_decoy_or_loader_unconfirmed": ["Go build情報とmain symbolを列挙する。", "30個の人工的main関数と倉庫業務文字列を確認する。", "network package、process起動、C2 literalがないためACR本体とは確定しない。"],
        "related_payload_zigclipper_reported": ["64-bit PEのCRT startupと大規模runtimeを確認する。", "ACRStealer tagではなくdropped-by-ACRStealer／ZigClipper関係として分離する。", "ACR本体の機能・C2へ昇格しない。"],
    }
    steps = steps_by_role.get(role, ["外層形式とsectionを解析する。", "既知の静的復元手順を適用する。", "設定未回収のためC2を確定しない。"])
    return [record("AnalyzeDeliveryOrPayload", "reviewed_static_unit", role or "unresolved", "レビュー済み配布役割に沿って外層と回収層を評価する。", steps, selector=f"sha256:{digest}", tool="bounded_static_review", confidence="reviewed_role_partial_function_logic")], False


def _safe_metadata(item: dict[str, Any], family: str) -> dict[str, Any]:
    metadata = item.get("metadata", {})
    keys = ("sha256_hash", "sha1_hash", "md5_hash", "first_seen", "last_seen", "file_name", "file_size", "file_type", "file_format", "file_arch", "imphash", "tlsh", "ssdeep", "tags")
    return {
        "schema_version": 1,
        "family": family,
        "version": "unknown",
        "source": "MalwareBazaar Community API",
        "source_url": ACR_TAG_URL if family == "acrstealer" else VALLEY_SIGNATURE_URL,
        "acquired_at": "2026-07-23",
        **{key: metadata.get(key) for key in keys},
        "sample_executed": False,
        "network_contacted": False,
    }


def _ioc_markdown(digest: str, findings: list[dict[str, Any]], artifacts: list[dict[str, Any]]) -> str:
    lines = [
        "# IOC 一覧",
        "",
        "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |",
        "|---|---|---|---|---|",
        f"| SHA-256 | {digest} | 提出検体 | 確認済み | MalwareBazaar取得検体 |",
    ]
    for artifact in artifacts:
        if artifact.get("sha256"):
            lines.append(
                f"| SHA-256 | {artifact['sha256']} | "
                f"{artifact.get('kind', 'recovered')} | 確認済み | 静的復元 |"
            )
    network = [
        item
        for item in findings
        if item.get("confidence") == "confirmed_static_config"
        and str(item.get("kind", "")).startswith("network.")
    ]
    if network:
        for item in network:
            lines.append(
                f"| {item.get('kind')} | {item.get('value')} | "
                f"{item.get('role')} | 確認済み | 静的設定復元 |"
            )
    else:
        lines.extend(
            [
                "",
                "今回の静的解析では、設定構造で裏付けられたC2を回収できませんでした。",
            ]
        )
    lines.extend(
        [
            "",
            "候補文字列、証明書URL、製品更新URLはC2として掲載していません。",
            "検体実行と外部接続は行っていません。",
            "",
        ]
    )
    return "\n".join(lines)

def _readme(family: str, digest: str, metadata: dict[str, Any], role: str, result: dict[str, Any], logic: dict[str, Any], layers: dict[str, Any]) -> str:
    display = FAMILY_DISPLAY[family]
    config = result.get("config", {})
    artifacts = config.get("recovered_artifacts", [])
    findings = result.get("findings", [])
    endpoint_count = sum(item.get("confidence") == "confirmed_static_config" for item in findings)
    attribution = (
        "MalwareBazaarのタグ集合には本体、配布物、デコイ、別payloadが混在します。本ケースの役割を越えてACRStealer本体へ一般化しません。"
        if family == "acrstealer"
        else "提出元のValleyRAT分類を保持しますが、設定または関数ロジックで裏付けられない部分は未確認のままにします。"
    )
    lines = [
        f"# {display} ケース {digest}", "", "## 概要", "",
        f"- 元ファイル名: `{metadata.get('file_name')}`",
        f"- SHA-256: `{digest}`",
        f"- 初回観測: `{metadata.get('first_seen')}`",
        f"- 形式: `{metadata.get('file_type') or metadata.get('file_format') or 'unknown'}`",
        f"- 解析上の役割: `{role}`",
        f"- 静的ロジック状態: `{logic['status']}`",
        f"- 復元層: {layers.get('counts', {}).get('recovered_layers', 0)}",
        f"- ファミリー固有復元物: {len(artifacts)}",
        f"- 設定構造で確認したネットワーク所見: {endpoint_count}",
        "- 検体実行: `false`", "- 外部ネットワーク接続: `false`", "",
        "## 帰属境界", "", attribution, "",
        "## 詳細静的解析", "",
    ]
    for function in logic.get("functions", []):
        lines.append(f"- `{function['name']}`: {function['summary_ja']}")
        for step in function.get("logic_steps_ja", []):
            lines.append(f"  - {step}")
    lines.extend(["", "関数別の処理順、call関係、コード類似性fingerprintは [STATIC-LOGIC.md](STATIC-LOGIC.md) を参照してください。", "", "## 復元物", ""])
    if artifacts:
        lines.extend(["| 種別 | SHA-256 | サイズ |", "|---|---|---:|"])
        for artifact in artifacts:
            lines.append(f"| `{artifact.get('kind')}` | `{artifact.get('sha256')}` | {artifact.get('size', 0)} |")
    else:
        lines.append("ファミリー固有の復元物はありません。")
    lines.extend(["", "## C2評価", ""])
    if endpoint_count:
        lines.append("設定構造から静的に回収した候補があります。現在の稼働状態、所有者、到達性は未確認です。詳細は [IOC-LIST.md](IOC-LIST.md) を参照してください。")
    else:
        lines.append("今回の検体から、設定構造で裏付けられたC2は回収できませんでした。一般URLやタグ由来ホストをC2へ昇格していません。")
    lines.extend(["", "## 関連成果物", "", "- [解析データ](analysis.json)", "- [静的ロジック](STATIC-LOGIC.md)", "- [検体特徴](FEATURES.md)", "- [IOC一覧](IOC-LIST.md)", "", "## 制約", "", "- 検体と復元物は実行していません。", "- C2、dead-drop resolver、配布先へ接続していません。", "- 保護層や未復元設定が残るケースは、関数ロジックを完了扱いにしていません。", ""])
    return "\n".join(lines)


def publish_family(manifest_path: Path, one_shot: Path, family: str, results: Path) -> list[dict[str, Any]]:
    manifest = load_json(manifest_path)
    published = []
    family_root = results / "malware" / family / "versions" / "unknown" / "cases"
    for item in manifest["items"]:
        digest = item["sha256"].casefold()
        source = one_shot / "cases" / digest
        report = load_json(source / "report.json")
        generic = load_json(source / "generic-triage.json")
        classification = load_json(source / "classification.json")
        layers = load_json(source / "static-layers.json")
        handler = load_handler_result(source, report)
        result = handler.get("result", {})
        role = (VALLEY_ROLES.get(digest) if family == "valleyrat" else None) or result.get("config", {}).get("artifact_role") or classification.get("classification", {}).get("campaign_type") or "unresolved_variant"
        metadata = _safe_metadata(item, family)
        records, function_reviewed = reviewed_records(family, digest, role, result)
        logic = build_static_logic_report(sha256=digest, family=family, source_name=str(metadata.get("file_name") or digest), records=records, analysis_source="reviewed_static_analysis_20260723")
        if not function_reviewed:
            logic["status"] = "function_logic_review_required"
            logic["coverage"]["function_bodies_reviewed"] = False
            logic["limitations"] = ["配布・復元処理単位は記録しましたが、最終binaryの全関数逆コンパイルは完了していません。", "未復元保護層または別payloadの関数意味付けを、ACRStealer／ValleyRAT本体へ一般化しません。"]
        destination = family_root / digest
        destination.mkdir(parents=True, exist_ok=True)

        write_json(destination / "metadata.json", metadata)
        write_json(destination / "static-logic.json", logic)
        (destination / "STATIC-LOGIC.md").write_text(render_static_logic_markdown(logic), encoding="utf-8")
        config = result.get("config", {})
        artifacts = config.get("recovered_artifacts", [])
        campaign_labels = {"schema_version": 1, "sha256": digest, "labels": [{"campaign_id": role, "confidence": "high" if metadata.get("sha256_hash") == digest else "medium", "basis": "reviewed_role_20260723"}], "status": "reviewed_role_assigned", "executed_sample": False, "network_contacted": False}
        write_json(destination / "campaign-labels.json", campaign_labels)
        analysis = {
            "schema_version": 1,
            "case": {
                "sha256": digest,
                "family": family,
                "version": "unknown",
                "artifact_role": role,
                "campaign": role,
                "format": metadata.get("file_type") or metadata.get("file_format") or "unknown",
                "packing_suspected": any(
                    marker in role
                    for marker in ("protected", "high_entropy", "file_pumped", "sfx_autoit")
                ),
                "unpack_status": (
                    "recovered_artifacts"
                    if artifacts
                    else "no_family_specific_artifact_recovered"
                ),
                "recovered_artifacts": len(artifacts),
                "static_config_recovered": bool(config.get("static_config_recovered")),
                "layer_count": layers.get("counts", {}).get("recovered_layers", 0),
                "declarative_status": (
                    "ready"
                    if function_reviewed or config.get("static_config_recovered")
                    else "needs_review"
                ),
                "sample_executed": False,
                "network_contacted": False,
            },
            "metadata": metadata,
            "classification": classification,
            "generic_triage": generic,
            "static_layers": layers,
            "family_analysis": handler,
            "static_logic": "static-logic.json",
            "attribution_boundary": (
                "source tag is context; reviewed role and static evidence govern conclusions"
            ),
        }
        write_json(destination / "analysis.json", analysis)
        (destination / "IOC-LIST.md").write_text(_ioc_markdown(digest, result.get("findings", []), artifacts), encoding="utf-8")
        (destination / "README.md").write_text(_readme(family, digest, metadata, role, result, logic, layers), encoding="utf-8")
        profile = build_case_profile(destination)
        write_json(destination / "features.json", profile)
        (destination / "FEATURES.md").write_text(
            render_features_markdown(profile), encoding="utf-8"
        )
        published.append({"sha256": digest, "family": family, "role": role, "case": destination.relative_to(results).as_posix(), "static_logic_status": logic["status"], "sample_executed": False, "network_contacted": False})
    return published


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--valley-manifest", required=True, type=Path)
    parser.add_argument("--valley-one-shot", required=True, type=Path)
    parser.add_argument("--acr-manifest", required=True, type=Path)
    parser.add_argument("--acr-one-shot", required=True, type=Path)
    parser.add_argument("--results", default=REPOSITORY / "analysis-results", type=Path)
    args = parser.parse_args(argv)
    published = publish_family(args.valley_manifest, args.valley_one_shot, "valleyrat", args.results)
    published += publish_family(args.acr_manifest, args.acr_one_shot, "acrstealer", args.results)
    collection = args.results / "collections" / "valleyrat-acrstealer-20260723"
    write_json(collection / "manifest.json", {"schema_version": 1, "date": "2026-07-23", "requested": {"valleyrat": 10, "acrstealer_tag": 10}, "published": published, "counts": {"total": len(published), "valleyrat": sum(item["family"] == "valleyrat" for item in published), "acrstealer": sum(item["family"] == "acrstealer" for item in published)}, "samples_executed": False, "network_contacted": False})
    lines = ["# ValleyRAT／ACRStealer追加解析（2026-07-23）", "", "MalwareBazaarから各10件を取得し、実行せずに静的解析しました。ACRStealerタグ集合は本体、配布物、デコイ、別payloadを役割分離しています。", "", "| ファミリー | SHA-256 | 役割 | 静的ロジック |", "|---|---|---|---|"]
    for item in published:
        lines.append(f"| `{item['family']}` | [`{item['sha256']}`](../../{item['case']}/README.md) | `{item['role']}` | `{item['static_logic_status']}` |")
    lines.extend(["", "- 検体実行: なし", "- C2／外部ホスト接続: なし", "- 暗号化受け入れZIPはリポジトリ外で保持", ""])
    collection.mkdir(parents=True, exist_ok=True)
    (collection / "README.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({"published": len(published), "collection": str(collection)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
