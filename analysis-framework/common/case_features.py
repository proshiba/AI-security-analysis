#!/usr/bin/env python3
"""公開済みcase成果物から、挙動と検体特徴だけを正規化する。

検体、復元バイナリ、外部インフラには触れない。READMEと公開JSONの根拠を
case単位でまとめ、解析の不足理由も同じ判定基準で評価する。
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping


SCHEMA_VERSION = 1
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
NEGATIVE_MARKERS = (
    "未確認",
    "確認できず",
    "確認できない",
    "回収できず",
    "回収できない",
    "行っていない",
    "実施していない",
    "実行していない",
    "接続していない",
    "not observed",
    "not recovered",
    "not confirmed",
    "no artifact",
)
BEHAVIOR_HEADINGS = (
    "挙動",
    "動作",
    "実行ロジック",
    "静的解析ロジック",
    "詳細静的解析",
    "静的解析で確認したチェーン",
    "感染チェーン",
    "配送経路",
    "観測した",
    "静的な処理能力の手掛かり",
)
EXCLUDED_HEADINGS = (
    "制約",
    "検知",
    "yara",
    "sigma",
    "ioc",
    "osint",
    "出典",
    "公開情報",
    "shodan",
)
URL_VALUE_RE = re.compile(r"(?i)\b(?:https?|ftp)://[^\s<>`\"']+")
IPV4_VALUE_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
DOMAIN_ENDPOINT_VALUE_RE = re.compile(
    r"(?i)\b(?:[a-z0-9-]+\.)+[a-z]{2,63}:\d{1,5}\b"
)
SHA256_VALUE_RE = re.compile(r"(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])")


@dataclass(frozen=True)
class VocabularyFeature:
    """文書上の陽性根拠から抽出する標準特徴。"""

    feature_id: str
    category: str
    label: str
    patterns: tuple[str, ...]


SAMPLE_VOCABULARY = (
    VocabularyFeature("format:pe", "ファイル形式", "PE実行形式", (r"\bpe\b", r"\bmz\b")),
    VocabularyFeature("format:elf", "ファイル形式", "ELF実行形式", (r"\belf\b",)),
    VocabularyFeature("format:macho", "ファイル形式", "Mach-O実行形式", (r"mach-o", r"macho")),
    VocabularyFeature(
        "format:script", "ファイル形式", "スクリプト", (r"javascript", r"jscript", r"vbscript", r"\bvbs\b", r"powershell")
    ),
    VocabularyFeature("container:zip", "コンテナ", "ZIPアーカイブ", (r"\bzip\b",)),
    VocabularyFeature("container:msi", "コンテナ", "MSIパッケージ", (r"\bmsi\b", r"ole/msi")),
    VocabularyFeature("container:cab", "コンテナ", "CABアーカイブ", (r"\bcab\b",)),
    VocabularyFeature("container:iso", "コンテナ", "ISOイメージ", (r"\biso\b",)),
    VocabularyFeature("packer:upx", "保護・圧縮", "UPX", (r"\bupx\b",)),
    VocabularyFeature("packer:themida", "保護・圧縮", "Themida", (r"themida",)),
    VocabularyFeature("installer:inno", "インストーラ", "Inno Setup", (r"inno setup", r"inno_installer")),
    VocabularyFeature("installer:nsis", "インストーラ", "NSIS", (r"\bnsis\b",)),
    VocabularyFeature("runtime:dotnet", "ランタイム", ".NET／CLR", (r"\.net", r"\bclr\b", r"cil")),
    VocabularyFeature("runtime:go", "ランタイム", "Go", (r"go製", r"golang", r"go_pe_loader")),
    VocabularyFeature("runtime:python", "ランタイム", "Python／PyInstaller", (r"python", r"pyinstaller")),
    VocabularyFeature("runtime:electron", "ランタイム", "Electron", (r"electron",)),
    VocabularyFeature("resource:rcdata", "リソース", "RCDATAリソース", (r"rcdata",)),
    VocabularyFeature("obfuscation:base64", "難読化・復号", "Base64", (r"base64",)),
    VocabularyFeature("obfuscation:xor", "難読化・復号", "XOR", (r"\bxor\b", r"xor鍵")),
    VocabularyFeature("crypto:aes", "暗号", "AES", (r"\baes(?:-cbc|-gcm)?\b",)),
    VocabularyFeature("crypto:rc4", "暗号", "RC4", (r"\brc4\b",)),
    VocabularyFeature("crypto:chacha20", "暗号", "ChaCha20", (r"chacha20",)),
    VocabularyFeature("delivery:dll_sideload", "配布構造", "DLLサイドロード", (r"dll side[- ]?load", r"dllサイドロード", r"sideload")),
    VocabularyFeature("delivery:office_macro", "配布構造", "Officeマクロ", (r"office.*macro", r"macro_office", r"マクロ")),
    VocabularyFeature("delivery:script", "配布構造", "スクリプト配布", (r"script_delivery", r"スクリプト配布")),
)

BEHAVIOR_VOCABULARY = (
    VocabularyFeature("execution:worker_thread", "実行", "ワーカースレッド起動", (r"worker thread", r"createthread")),
    VocabularyFeature("execution:single_instance_event", "実行", "イベントによる多重起動制御", (r"名前付きevent", r"多重起動.*event")),
    VocabularyFeature("execution:memory_permission_change", "実行", "実行可能メモリへの権限変更", (r"virtualprotect", r"\brwx\b", r"page_execute")),
    VocabularyFeature("execution:indirect_payload_dispatch", "実行", "復元ペイロードへの間接制御移行", (r"間接call", r"間接実行", r"関数pointer")),
    VocabularyFeature("execution:autoit_payload", "実行", "AutoItペイロード処理", (r"autoit", r"\ba3x\b")),
    VocabularyFeature("execution:payload_decode", "実行", "ペイロードの復号・展開", (r"lznt1", r"rc4.*(?:展開|復元)", r"復号.*最終pe")),
    VocabularyFeature("evasion:execution_delay", "防御回避", "実行遅延", (r"\bsleep\b", r"秒後.*主処理", r"秒.*待機")),
    VocabularyFeature("evasion:exception_or_trace_guard", "防御回避", "例外・トレース監視の設定", (r"nttraceevent", r"vectored exception", r"addvectoredexceptionhandler")),
    VocabularyFeature("discovery:window_enumeration", "探索", "ウィンドウ列挙", (r"enumwindows", r"window監視")),
    VocabularyFeature("discovery:registry_query", "探索", "レジストリ照会", (r"regopenkey", r"regqueryvalue", r"registry値")),
    VocabularyFeature("network:connection_retry", "通信", "接続先選択と再試行", (r"接続試行", r"接続判定", r"通信handler", r"connection.*retry")),
    VocabularyFeature("network:configured_endpoint", "通信", "静的設定からの接続先復元", (r"c2 endpoint", r"検証済み.*接続先", r"endpointを復元")),
    VocabularyFeature("execution:powershell", "実行", "PowerShellによる処理", (r"powershell",)),
    VocabularyFeature("execution:wscript", "実行", "WScript／CScriptによる処理", (r"wscript", r"cscript")),
    VocabularyFeature("execution:wmi", "実行", "WMIを介した実行", (r"\bwmi\b",)),
    VocabularyFeature("execution:runpe", "実行", "RunPE／プロセス置換", (r"runpe", r"process hollow")),
    VocabularyFeature("execution:process_creation", "実行", "プロセス起動API", (r"process_creation", r"プロセス起動api")),
    VocabularyFeature("execution:process_injection", "実行", "プロセス注入", (r"process injection", r"process_injection", r"プロセス注入", r"virtualallocex", r"writeprocessmemory")),
    VocabularyFeature("network:api_access", "通信", "ネットワークAPI", (r"network_access", r"ネットワーク接続・取得api")),
    VocabularyFeature("persistence:registry_access", "永続化", "Registry更新API", (r"registry_access", r"registry更新api")),
    VocabularyFeature("evasion:anti_debug", "防御回避", "デバッガ確認API", (r"anti_debug", r"デバッガ確認")),
    VocabularyFeature("execution:cryptographic_api", "実行", "暗号処理API", (r"cryptography", r"暗号処理api")),
    VocabularyFeature("execution:dll_sideload", "実行", "DLLサイドロード実行", (r"dll side[- ]?load", r"dllサイドロード", r"sideload host")),
    VocabularyFeature("execution:single_instance_mutex", "実行", "mutexによる多重起動制御", (r"mutex", r"ミューテックス")),
    VocabularyFeature("persistence:auto_start", "永続化", "自動起動", (r"自動起動", r"auto[- ]?start")),
    VocabularyFeature("persistence:run_key", "永続化", "Runキー永続化", (r"run key", r"runキー")),
    VocabularyFeature("persistence:scheduled_task", "永続化", "スケジュールタスク", (r"scheduled task", r"スケジュールタスク")),
    VocabularyFeature("persistence:startup", "永続化", "Startupフォルダ", (r"startup", r"スタートアップ")),
    VocabularyFeature("persistence:service", "永続化", "サービス登録", (r"service install", r"サービス登録", r"winsvc")),
    VocabularyFeature("persistence:cron", "永続化", "cron永続化", (r"\bcron\b",)),
    VocabularyFeature("evasion:defender_exclusion", "防御回避", "Defender除外の変更", (r"defender.*除外", r"add-mppreference")),
    VocabularyFeature("evasion:uac_bypass", "防御回避", "UAC回避", (r"uac.*回避", r"uac bypass")),
    VocabularyFeature("evasion:zone_identifier_remove", "防御回避", "Zone.Identifier削除", (r"zone\.identifier.*削除",)),
    VocabularyFeature("evasion:sleep_prevention", "防御回避", "system sleep阻止", (r"sleep.*(?:阻止|防止)",)),
    VocabularyFeature("evasion:anti_vm", "防御回避", "仮想環境回避", (r"anti[- ]?vm", r"仮想環境.*回避")),
    VocabularyFeature("credential_access:browser", "認証情報窃取", "ブラウザ情報の収集", (r"browser", r"ブラウザ.*(?:cookie|認証|password|資格)")),
    VocabularyFeature("credential_access:ftp_smtp", "認証情報窃取", "FTP／SMTP設定の窃取・悪用", (r"ftp.*credential", r"smtp.*credential", r"ftp設定", r"smtp設定")),
    VocabularyFeature("collection:keylogging", "収集", "キーロギング", (r"keylog", r"キー入力")),
    VocabularyFeature("collection:screenshot", "収集", "画面キャプチャ", (r"screenshot", r"画面キャプチャ")),
    VocabularyFeature("network:tor", "通信", "Tor経由通信", (r"tor v[23]", r"\.onion")),
    VocabularyFeature("network:doh", "通信", "DNS over HTTPS", (r"\bdoh\b", r"dns over https")),
    VocabularyFeature("network:custom_dns", "通信", "custom DNS設定", (r"custom dns", r"独自dns")),
    VocabularyFeature("network:ftp", "通信", "FTP通信", (r"\bftp\b",)),
    VocabularyFeature("network:smtp", "通信", "SMTP通信", (r"\bsmtp\b",)),
    VocabularyFeature("propagation:telnet_scan", "横展開", "Telnet探索", (r"telnet.*(?:scan|走査|探索)",)),
    VocabularyFeature("impact:ddos", "影響", "DDoS攻撃機能", (r"\bddos\b", r"攻撃id")),
    VocabularyFeature("impact:ransomware", "影響", "暗号化・ランサムウェア機能", (r"ransom", r"ファイル暗号化")),
)


def _read_json(path: Path) -> tuple[Any | None, str | None]:
    if not path.is_file():
        return None, None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), None
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return None, f"{path.name}: {type(exc).__name__}"


def _sections(markdown: str) -> dict[str, list[str]]:
    output: dict[str, list[str]] = {"": []}
    heading = ""
    for line in markdown.splitlines():
        match = re.match(r"^#{1,4}\s+(.+?)\s*$", line)
        if match:
            heading = match.group(1).strip()
            output.setdefault(heading, [])
        else:
            output.setdefault(heading, []).append(line)
    return output


def _positive_lines(lines: Iterable[str]) -> list[str]:
    output = []
    for line in lines:
        cleaned = re.sub(r"^\s*(?:[-*]|\d+[.)])\s*", "", line).strip()
        if not cleaned or cleaned.startswith(("|", "```", "~~~", "<!--")):
            continue
        lowered = cleaned.casefold()
        if any(marker in lowered for marker in NEGATIVE_MARKERS):
            continue
        output.append(cleaned)
    return output


def _redact_concrete_values(value: str) -> str:
    """挙動の説明を維持しつつ、IOCになり得る具体値を除く。"""

    output = URL_VALUE_RE.sub("[URLはIOC-LIST.mdを参照]", value)
    output = DOMAIN_ENDPOINT_VALUE_RE.sub("[接続先はIOC-LIST.mdを参照]", output)
    output = IPV4_VALUE_RE.sub("[IPはIOC-LIST.mdを参照]", output)
    return SHA256_VALUE_RE.sub("[SHA-256はcase識別子を参照]", output)


def _match_vocabulary(
    lines: Iterable[str], vocabulary: Iterable[VocabularyFeature], source: str
) -> list[dict[str, Any]]:
    output: dict[str, dict[str, Any]] = {}
    for line in lines:
        lowered = line.casefold()
        for feature in vocabulary:
            if feature.feature_id in output:
                continue
            if feature.feature_id == "runtime:dotnet" and re.search(
                r"\.net\s*[:=]\s*`?(?:false|no|なし)\b", lowered, re.IGNORECASE
            ):
                continue
            if any(re.search(pattern, lowered, re.IGNORECASE) for pattern in feature.patterns):
                output[feature.feature_id] = {
                    "id": feature.feature_id,
                    "category": feature.category,
                    "label": feature.label,
                    "confidence": "documented",
                    "source": source,
                    "evidence": _redact_concrete_values(line)[:300],
                }
    return list(output.values())


def _add_characteristic(
    output: dict[tuple[str, str], dict[str, Any]],
    feature_id: str,
    category: str,
    label: str,
    value: Any,
    source: str,
    confidence: str = "observed",
) -> None:
    if value is None or value == "" or value == [] or value == {}:
        return
    if isinstance(value, Mapping):
        return
    if isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, list):
        rendered = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        rendered = str(value)
    if _redact_concrete_values(rendered) != rendered:
        return
    key = (feature_id, rendered)
    output.setdefault(
        key,
        {
            "id": feature_id,
            "category": category,
            "label": label,
            "value": rendered,
            "confidence": confidence,
            "source": source,
        },
    )


def _structured_characteristics(
    metadata: Mapping[str, Any], analysis: Mapping[str, Any]
) -> list[dict[str, Any]]:
    output: dict[tuple[str, str], dict[str, Any]] = {}
    version = metadata.get("malware_version")
    if isinstance(version, Mapping):
        _add_characteristic(
            output,
            "version:status",
            "版管理",
            "版判定状態",
            version.get("status"),
            "metadata.json",
        )
        _add_characteristic(
            output,
            "version:key",
            "版管理",
            "版キー",
            version.get("normalized_key"),
            "metadata.json",
        )
    case = analysis.get("case")
    if isinstance(case, Mapping):
        fields = (
            ("campaign:delivery", "配布構造", "配布・外層パターン", "campaign"),
            ("format:reported", "ファイル形式", "静的判定形式", "format"),
            ("packing:suspected", "保護・圧縮", "パッキングの疑い", "packing_suspected"),
            ("packing:classification", "保護・圧縮", "パッキング分類", "packing_classification"),
            ("unpack:status", "静的復元", "アンパック状態", "unpack_status"),
            ("unpack:artifacts", "静的復元", "復元artifact数", "recovered_artifacts"),
            ("config:recovered", "設定", "静的設定回収", "static_config_recovered"),
            ("layers:count", "静的復元", "解析レイヤー数", "layer_count"),
            ("analysis:status", "解析状態", "宣言型解析状態", "declarative_status"),
        )
        for feature_id, category, label, key in fields:
            _add_characteristic(output, feature_id, category, label, case.get(key), "analysis.json")
    unpack = analysis.get("unpack")
    if isinstance(unpack, Mapping):
        for feature_id, category, label, key in (
            ("format:unpack", "ファイル形式", "unpacker判定形式", "format"),
            ("size:bytes", "ファイル特徴", "サイズ（byte）", "size"),
            ("entropy:value", "ファイル特徴", "エントロピー", "entropy"),
            ("unpack:status", "静的復元", "アンパック状態", "unpack_status"),
        ):
            _add_characteristic(output, feature_id, category, label, unpack.get(key), "analysis.json")
    config = analysis.get("config")
    if isinstance(config, Mapping):
        nested = config.get("config")
        if isinstance(nested, Mapping):
            for feature_id, category, label, key in (
                ("profile:name", "ファミリー構造", "解析プロファイル", "profile"),
                ("profile:category", "ファミリー構造", "機能カテゴリ", "category"),
                ("protocol:transport", "通信構造", "想定transport", "transport"),
                ("profile:markers", "ファミリー構造", "相関marker", "marker_hits"),
                ("config:keys", "設定", "観測した設定key", "observed_config_keys"),
            ):
                _add_characteristic(output, feature_id, category, label, nested.get(key), "analysis.json")
    return sorted(output.values(), key=lambda item: (item["category"], item["id"], item["value"]))


def _campaign_type(
    analysis: Mapping[str, Any], history_entry: Mapping[str, Any] | None, markdown: str
) -> tuple[str, str]:
    case = analysis.get("case")
    if isinstance(case, Mapping) and case.get("campaign"):
        return str(case["campaign"]), "analysis.json"
    classification = analysis.get("classification")
    if isinstance(classification, Mapping) and classification.get("campaign"):
        return str(classification["campaign"]), "analysis.json"
    if history_entry and history_entry.get("campaign_type"):
        return str(history_entry["campaign_type"]), "analysis_history.yaml"
    for line in markdown.splitlines():
        lowered = line.casefold()
        if ("配布・外層の形" in line or "campaign" in lowered) and "`" in line:
            pieces = line.split("`")
            if len(pieces) >= 3 and pieces[1].strip():
                return pieces[1].strip(), "README.md"
    return "unknown", "not_observed"


def _family(metadata: Mapping[str, Any], case_dir: Path) -> str:
    value = metadata.get("family")
    if value:
        return str(value)
    parts = case_dir.parts
    if "malware" in parts:
        index = parts.index("malware")
        if index + 1 < len(parts):
            return parts[index + 1]
    return "unknown"


def _assessment(
    *,
    case_dir: Path,
    metadata: Mapping[str, Any],
    analysis: Mapping[str, Any],
    markdown: str,
    characteristics: list[dict[str, Any]],
    behaviors: list[dict[str, Any]],
    parse_errors: list[str],
) -> dict[str, Any]:
    sections = _sections(markdown)
    headings = tuple(sections)
    checks = {
        "identity": bool(metadata) and SHA256_RE.fullmatch(case_dir.name.lower()) is not None,
        "structured_or_detailed_static_analysis": bool(analysis)
        or any("静的解析" in heading or "挙動" in heading for heading in headings),
        "sample_characteristics": len(characteristics) >= 2,
        "behaviors": bool(behaviors),
        "limitations": any("制約" in heading or "未解決" in heading for heading in headings),
        "network_role_assessed": "c2" in markdown.casefold() or isinstance(analysis.get("c2"), Mapping),
        "unpack_or_config_assessed": any(
            token in markdown.casefold() for token in ("アンパック", "復元", "静的設定", "config")
        )
        or any(key in analysis for key in ("unpack", "config", "layers")),
        "ioc_list": (case_dir / "IOC-LIST.md").is_file(),
        "source_traceability": bool(markdown) and bool(metadata),
        "parseable_public_artifacts": not parse_errors,
    }
    weights = {
        "identity": 1,
        "structured_or_detailed_static_analysis": 1,
        "sample_characteristics": 2,
        "behaviors": 2,
        "limitations": 1,
        "network_role_assessed": 1,
        "unpack_or_config_assessed": 1,
        "ioc_list": 1,
        "source_traceability": 1,
        "parseable_public_artifacts": 1,
    }
    score = sum(weights[key] for key, passed in checks.items() if passed)
    maximum = sum(weights.values())
    missing = [key for key, passed in checks.items() if not passed]
    unresolved = []
    case = analysis.get("case") if isinstance(analysis.get("case"), Mapping) else {}
    if case.get("static_config_recovered") is False:
        unresolved.append("static_config_not_recovered")
    if case.get("packing_suspected") is True and not case.get("recovered_artifacts"):
        unresolved.append("packed_or_protected_inner_payload_not_recovered")
    if str(case.get("declarative_status", "")).casefold() == "needs_review":
        unresolved.append("declarative_analysis_needs_review")
    if not behaviors:
        unresolved.append("behavior_not_documented")
    if len(characteristics) < 2:
        unresolved.append("sample_characteristics_insufficient")
    if parse_errors:
        unresolved.append("public_artifact_parse_error")
    if score >= 9 and checks["behaviors"] and checks["sample_characteristics"]:
        status = "complete"
    elif score >= 6:
        status = "partial"
    else:
        status = "insufficient"
    next_actions = []
    if "static_config_not_recovered" in unresolved:
        next_actions.append("終端payloadまたは設定blobを静的に復元し、ファミリー固有decoderを適用する。")
    if "packed_or_protected_inner_payload_not_recovered" in unresolved:
        next_actions.append("保護外層と終端payloadを分離し、認証した子要素を別レイヤーとして解析する。")
    if "behavior_not_documented" in unresolved:
        next_actions.append("静的なcontrol flowまたはスクリプト処理順を根拠付きで記録する。")
    if "sample_characteristics_insufficient" in unresolved:
        next_actions.append("形式、サイズ、保護、import／resource／script構造の特徴を追加する。")
    if parse_errors:
        next_actions.append("解析不能な公開JSONを修復し、schemaを明示する。")
    return {
        "status": status,
        "score": score,
        "maximum_score": maximum,
        "checks": checks,
        "missing": missing,
        "unresolved": sorted(set(unresolved)),
        "next_actions": next_actions,
    }


def build_case_profile(
    case_dir: Path, history_entry: Mapping[str, Any] | None = None
) -> dict[str, Any]:
    """1 caseの公開成果物から挙動・検体特徴profileを構築する。"""

    case_dir = case_dir.resolve()
    digest = case_dir.name.lower()
    metadata_value, metadata_error = _read_json(case_dir / "metadata.json")
    analysis_value, analysis_error = _read_json(case_dir / "analysis.json")
    report_value, report_error = _read_json(case_dir / "report.json")
    metadata = metadata_value if isinstance(metadata_value, Mapping) else {}
    analysis = analysis_value if isinstance(analysis_value, Mapping) else {}
    if not analysis and isinstance(report_value, Mapping):
        analysis = report_value
    readme = case_dir / "README.md"
    markdown = readme.read_text(encoding="utf-8-sig", errors="replace") if readme.is_file() else ""
    sections = _sections(markdown)
    behavior_lines = []
    sample_lines = []
    for heading, lines in sections.items():
        lowered = heading.casefold()
        if any(excluded in lowered for excluded in EXCLUDED_HEADINGS):
            continue
        positives = _positive_lines(lines)
        sample_lines.extend(positives)
        if any(marker in heading for marker in BEHAVIOR_HEADINGS):
            behavior_lines.extend(positives)
    characteristics = _structured_characteristics(metadata, analysis)
    vocabulary_characteristics = _match_vocabulary(sample_lines, SAMPLE_VOCABULARY, "README.md")
    existing_ids = {item["id"] for item in characteristics}
    for item in vocabulary_characteristics:
        if item["id"] in existing_ids:
            continue
        characteristics.append(
            {
                "id": item["id"],
                "category": item["category"],
                "label": item["label"],
                "value": "observed",
                "confidence": item["confidence"],
                "source": item["source"],
                "evidence": item["evidence"],
            }
        )
    characteristics.sort(key=lambda item: (item["category"], item["id"], item["value"]))
    behaviors = _match_vocabulary(behavior_lines, BEHAVIOR_VOCABULARY, "README.md")
    campaign, campaign_source = _campaign_type(analysis, history_entry, markdown)
    parse_errors = [
        error for error in (metadata_error, analysis_error, report_error) if error is not None
    ]
    assessment = _assessment(
        case_dir=case_dir,
        metadata=metadata,
        analysis=analysis,
        markdown=markdown,
        characteristics=characteristics,
        behaviors=behaviors,
        parse_errors=parse_errors,
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "case_id": str(metadata.get("case_id") or f"sha256:{digest}"),
        "sha256": digest,
        "family": _family(metadata, case_dir),
        "campaign_type": campaign,
        "campaign_type_source": campaign_source,
        "sample_characteristics": characteristics,
        "behaviors": behaviors,
        "analysis_assessment": assessment,
        "source_artifacts": sorted(
            path.name
            for path in case_dir.iterdir()
            if path.is_file() and path.name not in {"FEATURES.md", "features.json", "campaign-labels.json", "STATIC-LOGIC.md", "static-logic.json"}
        ),
        "parse_errors": parse_errors,
        "safety": {
            "samples_opened": False,
            "samples_executed": False,
            "emulated": False,
            "network_contacted": False,
            "source_scope": "public_repository_artifacts_only",
        },
    }


def render_features_markdown(profile: Mapping[str, Any]) -> str:
    """profileをIOC／YARA／Sigmaを含まない日本語Markdownへ描画する。"""

    assessment = profile["analysis_assessment"]
    lines = [
        f"# 挙動・検体特徴：{profile['sha256']}",
        "",
        "このファイルは、既存の公開解析成果物から確認できた挙動と検体特徴だけを整理したものです。",
        "IOC、YARA、Sigma、C2の具体値、OSINT帰属情報は含めません。",
        "",
        "## 対象",
        "",
        f"- ファミリー: `{profile['family']}`",
        f"- SHA-256: `{profile['sha256']}`",
        f"- 配布・解析パターン: `{profile['campaign_type']}`",
        f"- 解析充足度: `{assessment['status']}`（{assessment['score']}/{assessment['maximum_score']}）",
        "",
        "## 検体の特徴",
        "",
        "| 分類 | 特徴 | 値 | 確度 | 根拠 |",
        "|---|---|---|---|---|",
    ]
    characteristics = profile.get("sample_characteristics") or []
    if characteristics:
        for item in characteristics:
            value = str(item.get("value", "-")).replace("|", "\\|")
            source = str(item.get("source", "-")).replace("|", "\\|")
            lines.append(
                f"| {item['category']} | `{item['id']}` / {item['label']} | {value} | "
                f"{item['confidence']} | {source} |"
            )
    else:
        lines.append("| - | 特徴を十分に抽出できず | - | 未確認 | 既存成果物 |")
    lines.extend(
        [
            "",
            "## 特徴的な振る舞い",
            "",
            "| 分類 | 振る舞い | 確度 | 根拠抜粋 |",
            "|---|---|---|---|",
        ]
    )
    behaviors = profile.get("behaviors") or []
    if behaviors:
        for item in behaviors:
            evidence = str(item.get("evidence", "-")).replace("|", "\\|")
            lines.append(
                f"| {item['category']} | `{item['id']}` / {item['label']} | "
                f"{item['confidence']} | {evidence} |"
            )
    else:
        lines.append("| - | 既存成果物だけでは特徴的な振る舞いを確認できず | 未確認 | - |")
    lines.extend(["", "## 不足している解析", ""])
    if assessment["unresolved"]:
        lines.extend(f"- `{item}`" for item in assessment["unresolved"])
    else:
        lines.append("- 現在の判定基準で必須の不足はありません。")
    if assessment["next_actions"]:
        lines.extend(["", "## 推奨する追加確認", ""])
        lines.extend(f"- {item}" for item in assessment["next_actions"])
    lines.extend(
        [
            "",
            "## 範囲と制約",
            "",
            "- 公開済みのREADMEとJSONだけを再評価しました。",
            "- 検体または復元バイナリの読込み・実行は行っていません。",
            "- 外部ホストへの接続、C2 probe、stage取得は行っていません。",
            "- 記述がない機能を、ファミリーの一般論から補完していません。",
            "",
        ]
    )
    return "\n".join(lines)


def discover_case_directories(results_root: Path) -> list[Path]:
    """固定caseとresearch内のSHA-256 caseを決定的順序で列挙する。"""

    output = []
    for path in results_root.rglob("*"):
        if not path.is_dir() or not SHA256_RE.fullmatch(path.name.lower()):
            continue
        if (path / "README.md").is_file():
            output.append(path.resolve())
    return sorted(set(output), key=lambda item: item.as_posix().casefold())
