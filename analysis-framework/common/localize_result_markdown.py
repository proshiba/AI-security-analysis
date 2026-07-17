"""解析結果 Markdown を既知の定型表現だけで安全かつ決定的に日本語化する。

既定は dry-run である。コード、URL、ハッシュ、機械可読値を維持し、未知の英語説明が
残る場合は完全な相対パス・行番号・原文を報告して書き込みを拒否する。``--write`` 時は
計画時ハッシュを再確認し、原子的に置換して、途中失敗時には元の内容へ戻す。
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile
from typing import Callable, Iterable, Sequence

from audit_japanese_docs import JAPANESE, _english_prose_candidate
from _ja_collection_patterns import translate_line as _translate_collection_line
from _ja_family_residual_patterns import translate_line as _translate_family_residual_line
from _ja_hard_case_patterns import translate_line as _translate_hard_case_line
from _ja_legacy_family_patterns import translate_line as _translate_legacy_family_line
from _ja_other_family_patterns import translate_line as _translate_other_family_line
from _ja_research_patterns import translate_line as _translate_research_line
from _ja_remaining_family_patterns import translate_line as _translate_remaining_family_line
from _ja_unclassified_patterns import translate_line as _translate_unclassified_line


FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
INLINE_CODE = re.compile(r"(`+)([^\r\n]*?)\1")
BARE_URL = re.compile(r"https?://[^\s<>)]+")
MARKDOWN_DESTINATION = re.compile(r"(?<=\]\()[^\r\n)]+(?=\))")
LONG_HASH = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])")
TECHNICAL_ENUM = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b")
TECHNICAL_FILENAME = re.compile(
    r"\b[A-Za-z0-9_.-]+\.(?:json|ya?ml|md|ps1|py|exe|dll|bin|zip|asp)\b", re.I
)
DOTTED_IDENTIFIER = re.compile(
    r"\b[A-Za-z_$<>][A-Za-z0-9_$<>]*(?:\.[A-Za-z_$<>][A-Za-z0-9_$<>]*)+\b"
)
REPOSITORY_IDENTIFIER = re.compile(
    r"\b(?:AI-security-analysis|VX-Underground)\b"
)
ABBREVIATED_HASH = re.compile(
    r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{8}\.\.\.(?![0-9A-Fa-f])"
)
RULE_IDENTIFIER = re.compile(
    r"\b(?:rule|ruleset|id|name)\s*[:=]\s*([A-Za-z_][A-Za-z0-9_.-]+)", re.I
)
CASE_TITLE = re.compile(r"^(#\s+)(.+?)\s+case\s+([0-9A-Fa-f]{32,})(\s*)$", re.I)
ANALYSIS_TITLE = re.compile(
    r"^(#\s+)(.+?)\s+analysis(?:\s+results)?(\s*)$", re.I
)
SIMPLE_PRODUCT_TITLE = re.compile(r"^(#\s+)([A-Za-z][A-Za-z0-9 ._+/-]{1,80})(\s*)$")
BULLET_FIELD = re.compile(r"^(\s*[-*+]\s+)([^:]{1,100})(:\s*)(.*)$")
HARD_CASE_TABLE_ROW = re.compile(
    r"^\|\s*[0-9A-Fa-f]{64}\s*\|\s*[a-z0-9-]+\s*\|"
    r"\s*[a-z0-9_+-]+\s*\|\s*analyzed\s*\|\s*[0-9]+\s*\|"
    r"\s*(?:-|Enigma|KoiVM|SmartAssembly|Themida|UPX|nsPack)\s*\|"
    r"\s*-\s*\|$"
)
LOCALIZED_HARD_CASE_LAYER = re.compile(
    r"^-\s+レイヤー\s+[0-9A-Fa-f]{64}:\s+"
    r"形式=[A-Za-z0-9+.-]+;\s+"
    r"マーカー=(?:-|Enigma|KoiVM|SmartAssembly|Themida|UPX|nsPack);\s+"
    r"ネイティブルーティング=[a-z0-9_:+, -]+;\s+"
    r"マネージドルーティング=[a-z0-9_:+, -]+$"
)
SPYGLACE_CONFIG_TABLE_ROW = re.compile(
    r"^\|\s*[0-9A-Fa-f]{64}\s*\|\s*[0-9A-Fa-f]{64}\s*\|"
    r"\s*(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s*\|\s*[A-Z]+\s*\|"
    r"\s*[A-Za-z0-9.]+\.asp(?:,\s*[A-Za-z0-9.]+\.asp){3}\s*\|"
    r"\s*[A-Z0-9]+\s*\|$"
)
TECHNICAL_COMMAND_LIST = re.compile(
    r"^-\s+[a-z]+(?:\s+on/off)?(?:、[a-z]+(?:\s+on/off)?)+$"
)
LOCALIZED_RESEARCH_HEADING = re.compile(
    r"^###\s+(?:VenomRAT の再評価|ValleyRAT 3件の再評価|"
    r"RemcosRAT（\x60[0-9a-f]{8}\.\.\.\x60）の再評価)$"
)
LOCALIZED_CVE_HEADING = re.compile(
    r"^#\s+ネットスケーラー CVE-[0-9]{4}-[0-9]+ の防御的評価$"
)
LOCALIZED_SUPPLY_CHAIN_HEADING = re.compile(
    r"^#\s+(?:axios / plain-crypto-js|Trivy / TeamPCP) 供給網侵害$"
)
ATLASCROSS_ENDPOINT_IOC_ROW = re.compile(
    r"^\|\s*endpoint\s*\|\s*(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|"
    r"[A-Za-z0-9.-]+):9899\s*\|\s*c2\s*\|\s*recorded\s*\|\s*"
    r"iocs\.json\s*\|$"
)
NPM_ENDPOINT_IOC_ROW = re.compile(
    r"^\|\s*endpoint\s*\|\s*sfrclak\.com:8000\s*\|\s*"
    r"c2_or_infrastructure_as_recorded\s*\|\s*recorded\s*\|\s*"
    r"analysis_history\s*\|$"
)
REMAINING_FAMILY_ENDPOINT_IOC_ROW = re.compile(
    r"^\|\s*endpoint\s*\|\s*80\.234\.41\.242:7895\s*\|\s*"
    r"c2_candidate\s*\|\s*candidate\s*\|\s*config\.json\s*\|$"
)
LOCALIZED_FAMILY_DOC_TITLE = re.compile(
    r"^#\s+(?:QuasarRAT|HijackLoader|RedLine Stealer|Snake Keylogger|"
    r"njRAT|XWorm|AsyncRAT|DarkComet|DCRat|GuLoader|Atlas RAT)"
    r"：(?:公開情報の詳細|版・検体一覧|概要|技術解析)$"
)
JAPANESE_TITLE_CITATION = re.compile(
    r"\[出典：[^\]\r\n]*「[^\]\r\n]*"
    + JAPANESE.pattern
    + r"[^\]\r\n]*」\]\((?:[^()]|\([^()]*\))*\)"
)


HEADING_TRANSLATIONS = {
    "# Overview": "# 概要",
    "# IOC list": "# IOC 一覧",
    "# IOC list index": "# IOC 一覧索引",
    "## Overview": "## 概要",
    "## Limitations": "## 制約",
    "## Config and C2 evidence": "## 設定および C2 の根拠",
    "## Static config snapshot": "## 静的設定のスナップショット",
    "## Recovered layers": "## 復元したレイヤー",
    "### Recovered layers": "### 復元したレイヤー",
    "## Unpacking details": "## アンパック詳細",
    "## Unpacking status": "## アンパック状況",
    "## Collection/behavior features": "## 収集・挙動の特徴",
    "## Detection considerations": "## 検知時の考慮事項",
    "## Static behavior and config": "## 静的挙動と設定",
    "### Candidate infrastructure": "### 候補インフラストラクチャ",
    "## Network indicators": "## ネットワーク指標",
    "## Attribution evidence": "## 帰属の根拠",
    "## Static chain": "## 静的解析で確認したチェーン",
    "## Detection inputs": "## 検知入力",
    "## Hash OSINT enrichment": "## ハッシュ OSINT 情報の補強",
    "### Source status": "### 情報源の状態",
    "### Family evidence": "### ファミリー判定の根拠",
    "## Cases": "## ケース一覧",
    "## Behavior and C2 assessment": "## 挙動および C2 の評価",
    "## Detection guidance": "## 検知指針",
    "## Detection material": "## 検知資料",
    "## Delivery and behavior": "## 配送経路と挙動",
    "## Reproduction": "## 再現手順",
    "## Rule-building fields": "## ルール作成用フィールド",
    "## Network observables": "## ネットワーク観測情報",
    "## Shodan pivots": "## Shodan ピボット",
    "## C2/config findings": "## C2／設定の確認事項",
    "## Safety and limitations": "## 安全上の注意と制約",
    "## Campaign/delivery shapes": "## キャンペーン／配送形態",
    "## Statically observed behavior features": "## 静的解析で確認した挙動",
    "## Scope and outcome": "## 対象範囲と結果",
    "## Detection and false-positive assessment": "## 検知および誤検知の評価",
    "## C2/config interpretation": "## C2／設定の解釈",
    "## Latest refresh": "## 最新の更新",
    "## C2 and IOC evidence": "## C2 および IOC の根拠",
    "## Detection": "## 検知",
    "## Detection notes": "## 検知上の注意",
    "## Behavioral model": "## 挙動モデル",
    "## Recovered configuration": "## 復元した設定",
    "## Behavior": "## 挙動",
    "## Detection and false positives": "## 検知と誤検知",
    "## Scope and classification outcome": "## 対象範囲と分類結果",
    "## Recovered infection chain": "## 復元した感染チェーン",
    "## Configuration and C2": "## 設定および C2",
    "## Batch outcome": "## バッチ解析結果",
}

TABLE_HEADER_TRANSLATIONS = {
    "| Type | Value | Role | Confidence | Source |":
        "| 種別 (Type) | 値 (Value) | 役割 (Role) | 確度 (Confidence) | 根拠 (Source) |",
    "| Value | Role | Confidence | Source |":
        "| 値 (Value) | 役割 (Role) | 確度 (Confidence) | 情報源 (Source) |",
    "| Depth | Kind | SHA-256 | Size | Format |":
        "| 深さ | 種別 | SHA-256 | サイズ | 形式 |",
    "| Depth | Kind | Format | Size | SHA-256 |":
        "| 深さ | 種別 | 形式 | サイズ | SHA-256 |",
    "| Source | Status |": "| 情報源 (Source) | 状態 (Status) |",
    "| Field | Value |": "| 項目 (Field) | 値 (Value) |",
    "| SHA-256 | Format | Campaign | Packed | Layers | Findings |":
        "| SHA-256 | 形式 (Format) | 配送形態 (Campaign) | パッキング (Packed) | レイヤー数 (Layers) | 確認事項 (Findings) |",
    "| SHA-256 | Type | Unpack | Config | Network candidates |":
        "| SHA-256 | 種別 (Type) | アンパック (Unpack) | 設定 (Config) | ネットワーク候補 (Network candidates) |",
    "| Confidence | Recommended input | False-positive considerations |":
        "| 確度 | 推奨入力 | 誤検知時の考慮事項 |",
}

BULLET_LABEL_TRANSLATIONS = {
    "Original name": "元のファイル名", "Family": "ファミリー", "First seen": "初観測",
    "Submitted name/type/size": "提出時の名前／種別／サイズ",
    "Submitted filename": "提出時のファイル名", "Operator/campaign": "攻撃者／キャンペーン",
    "Execution/network": "実行／ネットワーク", "Campaign shape": "配送／キャンペーン形態",
    "Format": "形式", "Packing suspected": "パッキングの可能性",
    "Packing classification": "パッキング分類", "Unpack status": "アンパック状況",
    "Recovered static layers": "復元した静的レイヤー数", "Sample executed": "検体の実行",
    "Network contacted": "ネットワーク接続", "Category/transport": "種別／通信方式",
    "Category": "種別", "Marker hits": "マーカー一致", "Config keys observed": "確認した設定キー",
    "Static config candidate recovered": "静的設定候補の復元", "Root entropy": "ルートのエントロピー",
    "Root packing assessment": "ルートのパッキング評価",
    "Recursive layers analyzed": "再帰解析したレイヤー数", "7z status": "7z の状態",
    "UPX status": "UPX の状態", "Scope": "対象範囲", "Collected at": "収集日時",
    "Confidence/status": "確度／状態", "Independent agreeing providers": "一致した独立情報源の数",
    "Budget limited": "予算制限", "Status": "状態", "Identified family": "特定したファミリー",
    "Attribution confidence": "帰属の確度", "Combined family": "統合判定したファミリー",
    "Priority": "優先度", "Source": "情報源", "Blockers": "未解決要因",
    "Static state": "静的解析の状態", "Stage URLs": "ステージ URL",
    "Artifact": "アーティファクト", "Artifact type": "アーティファクト種別",
    "Expected payload behavior": "想定されるペイロードの挙動", "Family model": "ファミリーモデル",
    "Liveness": "稼働状況", "Analysis mode": "解析方式", "Confidence": "確度",
    "Endpoint provenance": "エンドポイントの由来", "C2 role assumption": "C2 の役割に関する仮定",
    "Recovered family version": "復元したファミリーのバージョン",
    "Publishable network candidates": "公開可能なネットワーク候補数",
    "Size": "サイズ", "Root": "ルート", "Protection/profile state": "保護／プロファイル状態",
}

SENTENCE_TRANSLATIONS = {
    "An embedded value is not proof that the server is live or exclusively controlled by this family.":
        "埋め込み値だけでは、サーバーの稼働や当該ファミリーによる排他的な管理を証明できない。",
    "The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.":
        "範囲を限定して復号した文字列の根拠を含む、正規化済み抽出結果の全体は `analysis.json` に保持している。",
    "Recovered bytes are deliberately not committed.": "復元したバイト列は意図的にコミットしていない。",
    "No publishable network candidate was recovered statically.":
        "静的解析では公開可能なネットワーク候補を復元できなかった。",
    "Candidates are not labelled as live or confirmed C2. See `c2-observation-plan.json` for passive Shodan pivots and family-specific confirmation requirements.":
        "候補を稼働中または確認済み C2 とは扱わない。受動的な Shodan ピボットとファミリー固有の確認要件は `c2-observation-plan.json` を参照すること。",
    "No bounded inner layer was recovered.": "範囲内では内部レイヤーを復元できなかった。",
    "This is bounded static analysis. Packed or runtime-decrypted configuration may remain unresolved, and source-family attribution does not establish a common operator or campaign.":
        "本結果は範囲を限定した静的解析である。パッキング済みまたは実行時に復号される設定は未解決の可能性があり、取得元のファミリー分類だけでは共通の攻撃者やキャンペーンを確定できない。",
    "- Static extraction only; no payload execution or C2 contact was performed.":
        "- 静的抽出のみを実施し、ペイロードの実行や C2 への接続は行っていない。",
    "- No strict Donut call-over-instance structure was recovered; a family label alone is not confirmation.":
        "- Donut に固有の call-over-instance 構造は復元できておらず、ファミリー名だけでは確認済みとしない。",
    "- Exact hash: high precision and low false-positive risk, but no variant coverage.":
        "- 完全一致ハッシュは高精度で誤検知リスクが低いが、亜種は検知できない。",
    "- Profile marker cluster plus endpoint: medium confidence; forks, leaked builders, and legitimate software strings can overlap.":
        "- プロファイルの複数マーカーとエンドポイントの組み合わせは中程度の確度である。フォーク、流出したビルダー、正規ソフトウェアの文字列と重複し得る。",
    "- Standalone URL/IP literal: low confidence and high false-positive risk; shared hosting, update services, and benign embedded documentation are common causes.":
        "- URL／IP リテラル単独は確度が低く、誤検知リスクが高い。共有ホスティング、更新サービス、無害な埋め込み文書でも一般的に出現する。",
    "- YARA input: profile markers, file size bound, and reviewed family context.":
        "- YARA 入力には、プロファイルマーカー、ファイルサイズ上限、レビュー済みのファミリー文脈を使用する。",
    "- Sigma input: only observed script-delivery behavior should be used; no dynamic process behavior was invented for direct PE cases.":
        "- Sigma 入力には確認済みのスクリプト配送挙動だけを使用する。直接 PE のケースに動的プロセス挙動を推測で追加していない。",
    "- Execution/network: sample not executed; infrastructure not contacted":
        "- 実行／ネットワーク: 検体は実行せず、インフラストラクチャにも接続していない",
    "- Execution/network: not performed": "- 実行／ネットワーク: 実施していない",
    "- Operator/campaign: not attributed": "- 攻撃者／キャンペーン: 未帰属",
    "- Scope: hash metadata only; no sample submission, execution, or infrastructure contact.":
        "- 対象範囲: ハッシュのメタデータのみ。検体の送信・実行やインフラへの接続は行っていない。",
    "- Low confidence / high false-positive risk: filename, generic Electron/NSIS/PyInstaller tags, imphash, or a URL alone.":
        "- 低確度／高い誤検知リスク: ファイル名、一般的な Electron／NSIS／PyInstaller タグ、imphash、または URL 単独。",
    "- Medium confidence / medium false-positive risk: require two independent family-specific static observations or a reviewed structural signature.":
        "- 中確度／中程度の誤検知リスク: ファミリー固有の独立した静的所見を二つ、またはレビュー済みの構造シグネチャを必要とする。",
}

PHRASE_TRANSLATIONS = {
    "MalwareBazaar review": "MalwareBazaar 調査", "analysis results": "解析結果",
    "analysis result": "解析結果", "analysis": "解析", "Overview": "概要",
}
APPROVED_MIXED_LINES = set(TABLE_HEADER_TRANSLATIONS.values())
IOC_TYPES = {
    "sha256", "sha1", "md5", "url", "domain", "hostname", "ipv4", "ipv6",
    "email", "mutex", "filename", "filepath", "registry", "user_agent",
}
EXCLUDED_RESULT_ROOT_DOCS = {
    "analysis-results/README.md",
    "analysis-results/AGENTS.md",
}
UNCLASSIFIED_LOCALIZATION_ROOTS = (
    "analysis-results/malware/unclassified/",
    "analysis-results/collections/malwarebazaar-unknown-20260717/",
)
RESEARCH_LOCALIZATION_ROOT = "analysis-results/research/"
COLLECTION_LOCALIZATION_ROOTS = (
    "analysis-results/collections/refresh-20260715/",
    "analysis-results/collections/malwarebazaar-20260717/",
    "analysis-results/collections/vx-underground-20260716/",
)
LEGACY_LOCALIZATION_ROOTS = tuple(
    f"analysis-results/malware/{family}/"
    for family in (
        "agenttesla",
        "latrodectus",
        "remcosrat",
        "stealc",
        "valleyrat",
        "venomrat",
        "vidar",
    )
)
REMAINING_FAMILY_LOCALIZATION_ROOTS = tuple(
    f"analysis-results/malware/{family}/"
    for family in (
        "quasarrat",
        "hijackloader",
        "redlinestealer",
        "snakekeylogger",
        "njrat",
        "xworm",
        "asyncrat",
        "darkcomet",
        "dcrat",
        "guloader",
        "atlascross",
    )
)
OTHER_FAMILY_LOCALIZATION_ROOTS = tuple(
    f"analysis-results/malware/{family}/"
    for family in (
        "amadey",
        "shadowpad",
        "spyglace",
        "remusstealer",
        "amosstealer",
        "lummastealer",
        "formbook",
        "donutloader",
        "purehvnc",
    )
)
KNOWN_PRODUCT_TITLES = {
    "agenttesla", "agent tesla", "amadey", "amosstealer", "atomic macos stealer",
    "asyncrat", "atlascross", "atlas rat", "darkcomet", "dcrat", "donut", "donutloader",
    "formbook", "xloader", "genesisstealer", "guloader", "hijackloader",
    "latrodectus", "lummastealer", "lumma stealer", "njrat", "originlogger",
    "purehvnc", "purerat", "purehvnc / purerat", "quasarrat", "redlinestealer",
    "redline stealer", "remcosrat", "remusstealer", "shadowpad",
    "snakekeylogger", "snake keylogger", "spyglace", "spyglace / apt-c-60",
    "stealc", "valleyrat", "valleyrat / winos4.0", "venomrat", "vidar", "xworm",
}
SAFE_TECHNICAL_WORDS = {
    "7-zip", "aes", "amos", "agenttesla", "amadey", "aplib", "asar",
    "atlascross", "autoit", "cff", "chrd", "cil", "cpu", "darkcomet",
    "die", "donut", "electron", "enigma", "gzip", "http", "iat", "ioc", "java",
    "ipv6", "jarm", "javascript", "json", "koivm", "latrodectus", "macho",
    "malwarebazaar", "mpress", "n520", "njrat", "nsis", "nspack", "purehvnc", "mach-o",
    "python", "redline", "remcos", "remus", "scc", "shadowpad", "sigma",
    "smartassembly", "spyglace", "stealc", "themida", "upx", "url",
    "utf-16le", "valley", "vidar", "virtualalloc", "readfile",
    "setfilepointer", "getmodulehandlea", "getprocaddress", "winlicense",
    "windows", "xworm", "yaml", "yara", "zip", "amosstealer", "donutloader",
    "formbook", "lummastealer", "purehvnc", "remusstealer", "toolbelt",
    "snake", "venom", "delphi", "cafebabe", "vmprotect",
    "apt-c-60", "jsdelivr", "base64", "downloader", "downloader1",
    "downloader2", "github", "gitlab", "codeberg", "cdn", "proton",
    "drive", "statcounter", "winhttp", "asp", "xor", "com", "clsid",
    "cachedimage", "lnk", "mshta", "certutil", "tar", "git", "tmi",
    "AadDDRTaSPtyAG57er#$ad!lDKTOPLTEL78pE",
    "sha-256", "c2", "id", "jpcert", "866564bb...1d065",
    "K31610KIO9834PG79A471", "K31610KIO9834PG79797",
    "K31610KIO9834PG79787", "false",
    "lumma", "xloader", "microsoft", "eset", "mandiant", "macos", "wps",
    "office", "ref2754", "apt41", "winnti", "cc", "spectralviper",
    "flashpoint", "fishmedley", "thewover", "elastic", "tds", "mitre",
    "att", "ck", "broadcom", "unit", "clearfake", "rat", "stealer",
    "netsarang", "fishmonger", "purecoder", "purerat", "tornet",
    "kaspersky", "securelist", "i-soon", "scatterbee", "semver", "vhdx",
    "go", "atomic", "mach-o", "vba", "vbs", "applescript", "index-xor",
    "pe", "xlsm", "powershell", "cloudflare", "workers", "wav",
    "appdomain", "tripledes-cbc", "pkcs", "pfx", "appv", "excel",
    "protobuf", "tls", "toshiba", "networkagent", "ics", "cyfirma",
    "pwc", "chrd", "asp",
    "apt-c-36", "asyncrat", "gh0st", "vpn", "atlas", "surfshark",
    "signal", "telegram", "zoom", "silverterrier", "apt38", "darkcrystal",
    "nanocore", "guloader", "cloudeye", "png", "idat", "dll",
    "hijackloader", "fakeupdate", "njw0rm", "njq8", "lv", "quasar",
    "downeks", "lapsus", "cisa", "whispergate", "meta", "keylogger",
    "krakenkeylogger", "smtp", "ftp", "turla", "cve", "hta",
    "bladabindi", "version", "maas", "hhs", "acsc", "aa22-216a",
    "hvnc", "formbook",
    "storm-1607", "storm-1113", "storm-1674", "storm-2477",
    "utf-16", "unicode", "x64", ".net", "aes-cbc",
    "starlink", "storm-1919", "proofpoint", "icedid", "ta577", "ta578",
    "webdav", "msi", "clickfix", "sliver", "lapsus$", "ta2722", "covid-19",
    "wininet", "multipart", "default", "zov", "googlemaps", "ta4922",
    "winos4.0", "valleyrat", "ta558", "venomrat", "batloader", "dev-0569",
    "youtube", "royal",
}
SAFE_MIXED_PHRASES = {
    "Blind Eagle",
    "Silver Fox",
    "Transparent Tribe",
    "Dark Comet RAT",
    "Dark Crystal RAT",
    "Visual Basic",
    "Agent Tesla",
    "Dragna Sebastiano Fabio",
    "Heaven's Gate",
    "Process Doppelgänging",
    "Gaza Cybergang",
    "Alloy Taurus",
    "Gorgon Group",
    "Operation Magnus",
    "Maxim Rudometov",
    "SYK Crypter",
    "SecTop RAT",
    "Unit 42",
    "Octo Tempest",
    "Hithink RoyalFlush Information Network Co., Ltd.",
    "Secret Blizzard",
    "Team Cymru",
    "Rust Loader",
    "CISA Cyber Safety Review Board",
    "Balikbayan Foxes",
    "Void Arachne",
    "build ID",
}


class LocalizationError(RuntimeError):
    """ローカライズ処理を安全に完了できない場合の基底例外。"""


class StalePlanError(LocalizationError):
    """計画後に対象 Markdown が変更された場合に発生する。"""


class UnresolvedEnglishError(LocalizationError):
    """未解決の英語説明が残る計画への書き込みを拒否する。"""


class LocalizationApplyError(LocalizationError):
    """書き込みに失敗し、置換済みファイルを元へ戻したことを示す。"""


@dataclass(frozen=True)
class UnresolvedLine:
    """翻訳辞書で安全に解決できなかった英語説明。"""

    line: int
    text: str

    def as_dict(self) -> dict[str, object]:
        return {"line": self.line, "text": self.text}


def _line_ending(line: str) -> tuple[str, str]:
    for ending in ("\r\n", "\n", "\r"):
        if line.endswith(ending):
            return line[: -len(ending)], ending
    return line, ""


def _spans_to_protect(line: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for pattern in (
        INLINE_CODE, BARE_URL, MARKDOWN_DESTINATION, LONG_HASH, TECHNICAL_ENUM,
        TECHNICAL_FILENAME, DOTTED_IDENTIFIER, REPOSITORY_IDENTIFIER,
        ABBREVIATED_HASH,
    ):
        spans.extend(match.span() for match in pattern.finditer(line))
    if "YARA" in line or "Sigma" in line:
        spans.extend(match.span(1) for match in RULE_IDENTIFIER.finditer(line))
    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start < merged[-1][1]:
            old_start, old_end = merged[-1]
            merged[-1] = (old_start, max(old_end, end))
        else:
            merged.append((start, end))
    return merged


def _replace_outside_protected(line: str, replacements: dict[str, str]) -> str:
    """保護区間を一切変更せず、残りの区間だけで既知句を置換する。"""
    spans = _spans_to_protect(line)
    ordered = sorted(replacements.items(), key=lambda item: -len(item[0]))
    pieces: list[str] = []
    cursor = 0
    for start, end in spans:
        plain = line[cursor:start]
        for source, target in ordered:
            plain = plain.replace(source, target)
        pieces.extend((plain, line[start:end]))
        cursor = end
    plain = line[cursor:]
    for source, target in ordered:
        plain = plain.replace(source, target)
    pieces.append(plain)
    return "".join(pieces)


def _residual_english_candidate(line: str) -> bool:
    """英語行または日本語ラベルで隠れた英語説明を監査する。"""
    stripped = line.strip()
    if (
        HARD_CASE_TABLE_ROW.fullmatch(stripped)
        or LOCALIZED_HARD_CASE_LAYER.fullmatch(stripped)
        or SPYGLACE_CONFIG_TABLE_ROW.fullmatch(stripped)
        or TECHNICAL_COMMAND_LIST.fullmatch(stripped)
        or LOCALIZED_RESEARCH_HEADING.fullmatch(stripped)
        or LOCALIZED_CVE_HEADING.fullmatch(stripped)
        or LOCALIZED_SUPPLY_CHAIN_HEADING.fullmatch(stripped)
        or ATLASCROSS_ENDPOINT_IOC_ROW.fullmatch(stripped)
        or NPM_ENDPOINT_IOC_ROW.fullmatch(stripped)
        or REMAINING_FAMILY_ENDPOINT_IOC_ROW.fullmatch(stripped)
        or LOCALIZED_FAMILY_DOC_TITLE.fullmatch(stripped)
    ):
        return False
    generated_heading = re.fullmatch(
        r"#\s+(.+?)(?:\s+解析概要|：(?:公開情報の詳細|版・検体一覧|概要|技術解析))",
        stripped,
    )
    if generated_heading and _is_product_identifier(generated_heading.group(1)):
        return False
    if re.fullmatch(
        r"##\s+v[0-9][A-Za-z0-9._+-]*(?:（[A-Za-z0-9 ._+-]+）)?",
        stripped,
    ):
        return False
    if stripped.startswith("|") and stripped.endswith("|") and TECHNICAL_ENUM.search(stripped):
        technical_projection = TECHNICAL_ENUM.sub(" ", stripped)
        if not _english_prose_candidate(technical_projection):
            return False
    if _english_prose_candidate(line):
        return True
    if not JAPANESE.search(stripped) or stripped in APPROVED_MIXED_LINES:
        return False
    localized_title = re.fullmatch(
        r"#\s+([A-Za-z][A-Za-z0-9 ._+/-]{0,80})\s+(?:解析概要|解析結果|解析)",
        stripped,
    )
    if localized_title and _is_product_identifier(localized_title.group(1)):
        return False
    if re.fullmatch(r"#\s+.+?\s+ケース\s+[0-9A-Fa-f]{32,}", stripped):
        return False
    if stripped.startswith("#") and "MalwareBazaar 調査" in stripped:
        return False
    projected = JAPANESE_TITLE_CITATION.sub(" ", stripped)
    protected_pieces: list[str] = []
    cursor = 0
    for start, end in _spans_to_protect(projected):
        protected_pieces.extend((projected[cursor:start], " "))
        cursor = end
    protected_pieces.append(projected[cursor:])
    projected = JAPANESE.sub(" ", "".join(protected_pieces))
    # snake_case は公開 JSON/表の機械契約値であり、英語の説明文ではない。
    projected = re.sub(
        r"\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b", " ", projected
    )
    projected = TECHNICAL_FILENAME.sub(" ", projected)
    projected = DOTTED_IDENTIFIER.sub(" ", projected)
    projected = REPOSITORY_IDENTIFIER.sub(" ", projected)
    for phrase in sorted(SAFE_MIXED_PHRASES, key=len, reverse=True):
        projected = re.sub(
            rf"(?<![A-Za-z0-9]){re.escape(phrase)}(?![A-Za-z0-9])",
            " ",
            projected,
            flags=re.IGNORECASE,
        )
    for word in sorted(SAFE_TECHNICAL_WORDS, key=len, reverse=True):
        projected = re.sub(
            rf"(?<![A-Za-z0-9]){re.escape(word)}(?![A-Za-z0-9])",
            " ",
            projected,
            flags=re.IGNORECASE,
        )
    return _english_prose_candidate(projected)


def find_unresolved_english(text: str) -> tuple[UnresolvedLine, ...]:
    """コードフェンス外に残る英語説明を行番号と原文のまま返す。"""
    findings: list[UnresolvedLine] = []
    in_fence = False
    fence_character = ""
    fence_length = 0
    for number, raw_line in enumerate(text.splitlines(), 1):
        match = FENCE.match(raw_line)
        if match:
            marker = match.group(1)
            if not in_fence:
                in_fence, fence_character, fence_length = True, marker[0], len(marker)
            elif marker[0] == fence_character and len(marker) >= fence_length:
                in_fence, fence_character, fence_length = False, "", 0
            continue
        stripped = raw_line.strip()
        cells = [cell.strip() for cell in stripped.strip("|").split("|")]
        ioc_data_row = (
            stripped.startswith("|") and stripped.endswith("|")
            and len(cells) == 5 and cells[0].lower() in IOC_TYPES
        )
        if not in_fence and not ioc_data_row and _residual_english_candidate(raw_line):
            findings.append(UnresolvedLine(line=number, text=raw_line))
    return tuple(findings)


def _preserved_values(text: str) -> tuple[str, ...]:
    """保護対象を出現順で返し、別claim間の入れ替えも検出する。"""
    values: list[str] = []
    in_fence = False
    fence_character = ""
    fence_length = 0
    for raw_line in text.splitlines(keepends=True):
        body, _ = _line_ending(raw_line)
        match = FENCE.match(body)
        if match:
            marker = match.group(1)
            values.append("fence:" + raw_line)
            if not in_fence:
                in_fence, fence_character, fence_length = True, marker[0], len(marker)
            elif marker[0] == fence_character and len(marker) >= fence_length:
                in_fence, fence_character, fence_length = False, "", 0
            continue
        if in_fence:
            values.append("fence:" + raw_line)
            continue
        matches: list[tuple[int, str]] = []
        inline_spans: list[tuple[int, int]] = []
        filename_spans = [match.span() for match in TECHNICAL_FILENAME.finditer(body)]
        dotted_spans = [match.span() for match in DOTTED_IDENTIFIER.finditer(body)]
        for match in INLINE_CODE.finditer(body):
            inline_spans.append(match.span())
            inner = match.group(2)
            if TECHNICAL_ENUM.fullmatch(inner):
                value = "enum:" + inner
            elif TECHNICAL_FILENAME.fullmatch(inner):
                value = "filename:" + inner
            elif DOTTED_IDENTIFIER.fullmatch(inner):
                value = "identifier:" + inner
            else:
                value = "code:" + match.group(0)
            matches.append((match.start(), value))
        for prefix, pattern in (
            ("url:", BARE_URL), ("destination:", MARKDOWN_DESTINATION), ("hash:", LONG_HASH),
            ("abbreviated-hash:", ABBREVIATED_HASH),
            ("enum:", TECHNICAL_ENUM),
            ("filename:", TECHNICAL_FILENAME),
            ("identifier:", DOTTED_IDENTIFIER),
            ("repository-id:", REPOSITORY_IDENTIFIER),
        ):
            for match in pattern.finditer(body):
                if any(
                    start <= match.start() and match.end() <= end
                    for start, end in inline_spans
                ):
                    continue
                if pattern is DOTTED_IDENTIFIER and any(
                    start <= match.start() and match.end() <= end
                    for start, end in filename_spans
                ):
                    continue
                if pattern is TECHNICAL_ENUM and any(
                    start <= match.start() and match.end() <= end
                    for start, end in (*filename_spans, *dotted_spans)
                ):
                    continue
                matches.append((match.start(), prefix + match.group(0)))
        if "YARA" in body or "Sigma" in body:
            for match in RULE_IDENTIFIER.finditer(body):
                matches.append((match.start(1), "rule-id:" + match.group(1)))
        values.extend(value for _, value in sorted(matches))
    return tuple(values)


def _translate_bullet(body: str) -> str:
    match = BULLET_FIELD.match(body)
    if not match:
        return body
    marker, label, separator, value = match.groups()
    translated_label = BULLET_LABEL_TRANSLATIONS.get(label.strip())
    if translated_label is None:
        return body
    translated_value = _replace_outside_protected(value, PHRASE_TRANSLATIONS)
    candidate = marker + translated_label + separator + translated_value
    # ラベルだけを日本語にして未知の英語説明を監査から隠さない。
    return body if _residual_english_candidate(candidate) else candidate


def _is_product_identifier(value: str) -> bool:
    """任意の英語見出しを製品名と誤認しない、保守的な識別境界。"""
    normalized = " ".join(value.strip().split())
    if normalized.casefold() in KNOWN_PRODUCT_TITLES:
        return True
    tokens = normalized.split()
    return bool(
        1 <= len(tokens) <= 2
        and all(
            token.isupper()
            or token[:1].isupper() and any(character.isupper() for character in token[1:])
            or any(character.isdigit() for character in token)
            for token in tokens
        )
    )


def _translate_line(body: str) -> str:
    leading = body[: len(body) - len(body.lstrip())]
    trailing = body[len(body.rstrip()):]
    core = body.strip()
    if core in SENTENCE_TRANSLATIONS:
        return leading + SENTENCE_TRANSLATIONS[core] + trailing
    if core in HEADING_TRANSLATIONS:
        return leading + HEADING_TRANSLATIONS[core] + trailing
    if core in TABLE_HEADER_TRANSLATIONS:
        return leading + TABLE_HEADER_TRANSLATIONS[core] + trailing
    case_match = CASE_TITLE.match(body)
    if case_match:
        prefix, family, digest, whitespace = case_match.groups()
        return f"{prefix}{family} ケース {digest}{whitespace}"
    analysis_match = ANALYSIS_TITLE.match(body)
    if analysis_match and _is_product_identifier(analysis_match.group(2)):
        prefix, family, whitespace = analysis_match.groups()
        suffix = "解析結果" if re.search(r"analysis\s+results", body, re.I) else "解析"
        return f"{prefix}{family} {suffix}{whitespace}"
    if "MalwareBazaar review" in body:
        return _replace_outside_protected(body, PHRASE_TRANSLATIONS)
    simple_title = SIMPLE_PRODUCT_TITLE.match(body)
    if simple_title and _is_product_identifier(simple_title.group(2)):
        prefix, product, whitespace = simple_title.groups()
        return f"{prefix}{product} 解析概要{whitespace}"
    translated_bullet = _translate_bullet(body)
    if translated_bullet != body:
        return translated_bullet
    translated_hard_case = _translate_hard_case_line(body)
    if translated_hard_case != body:
        return translated_hard_case
    # 混在行だけを補正し、未知の英語だけの行は原文のまま未解決として残す。
    if JAPANESE.search(body):
        return _replace_outside_protected(body, PHRASE_TRANSLATIONS)
    return body


def _line_translators_for_result_path(
    relative_path: str,
) -> tuple[Callable[[str], str], ...]:
    """成果物の所在に応じて、用途限定の後処理だけを選択する。"""
    normalized = relative_path.replace("\\", "/")
    if normalized.startswith(RESEARCH_LOCALIZATION_ROOT):
        return (_translate_research_line,)
    if normalized.startswith(UNCLASSIFIED_LOCALIZATION_ROOTS):
        return (_translate_unclassified_line,)
    if normalized.startswith(COLLECTION_LOCALIZATION_ROOTS):
        return (_translate_collection_line,)
    if normalized.startswith(OTHER_FAMILY_LOCALIZATION_ROOTS):
        return (_translate_other_family_line,)
    if normalized.startswith(REMAINING_FAMILY_LOCALIZATION_ROOTS):
        return (_translate_remaining_family_line,)
    if normalized.startswith(LEGACY_LOCALIZATION_ROOTS):
        translators: tuple[Callable[[str], str], ...] = (
            _translate_legacy_family_line,
        )
        if normalized.startswith(
            (
                "analysis-results/malware/valleyrat/",
                "analysis-results/malware/venomrat/",
            )
        ):
            translators += (_translate_family_residual_line,)
        return translators
    return ()


def _translate_scoped_line(
    body: str,
    translators: Sequence[Callable[[str], str]],
) -> str:
    """共通辞書優先と原文優先の両経路から、安全に解決できる訳を選ぶ。"""
    # 監査上すでに解決済みの行は固定点とする。後段辞書の訳語に含まれる
    # ASCII 製品名や略語（VB、URL、Run など）を次周で再変換しない。
    if not _residual_english_candidate(body):
        return body

    def apply_all(value: str) -> str:
        for translator in translators:
            value = translator(value)
        return value

    base_only = _translate_line(body)
    base_first = apply_all(base_only)
    if not translators:
        return base_first
    scoped_first = apply_all(_translate_line(apply_all(body)))
    protected = _preserved_values(body)

    def safe_and_resolved(candidate: str) -> bool:
        return (
            _preserved_values(candidate) == protected
            and not _residual_english_candidate(candidate)
        )

    if safe_and_resolved(base_first):
        return base_first
    if safe_and_resolved(base_only):
        return base_only
    if safe_and_resolved(scoped_first):
        return scoped_first
    if _preserved_values(base_first) == protected:
        return base_first
    return scoped_first


def localize_markdown(
    text: str,
    *,
    post_line_translators: Sequence[Callable[[str], str]] = (),
) -> str:
    """Markdown 一件を変換し、全保護対象が維持されたことを検証する。"""
    bom = "\ufeff" if text.startswith("\ufeff") else ""
    content = text[len(bom):]
    output: list[str] = []
    in_fence = False
    fence_character = ""
    fence_length = 0
    for raw_line in content.splitlines(keepends=True):
        body, ending = _line_ending(raw_line)
        match = FENCE.match(body)
        if match:
            marker = match.group(1)
            output.append(raw_line)
            if not in_fence:
                in_fence, fence_character, fence_length = True, marker[0], len(marker)
            elif marker[0] == fence_character and len(marker) >= fence_length:
                in_fence, fence_character, fence_length = False, "", 0
            continue
        if in_fence:
            output.append(raw_line)
            continue
        translated = _translate_scoped_line(body, post_line_translators)
        output.append(translated + ending)
    localized = bom + "".join(output)
    if _preserved_values(text) != _preserved_values(localized):
        raise LocalizationError("protected Markdown values changed during localization")
    return localized


@dataclass(frozen=True)
class PlanEntry:
    """一件の入力、変換後内容、フィンガープリントを保持する。"""

    path: str
    source_sha256: str
    target_sha256: str
    translation_method: str
    unresolved: tuple[UnresolvedLine, ...]
    _path: Path = field(repr=False, compare=False)
    _source_bytes: bytes = field(repr=False, compare=False)
    _target_bytes: bytes = field(repr=False, compare=False)

    @property
    def changed(self) -> bool:
        return self.source_sha256 != self.target_sha256


@dataclass(frozen=True)
class LocalizationPlan:
    """一括適用前に固定した、決定的な Markdown ローカライズ計画。"""

    repository: Path = field(repr=False, compare=False)
    roots: tuple[str, ...]
    entries: tuple[PlanEntry, ...]

    @property
    def unresolved_count(self) -> int:
        return sum(len(entry.unresolved) for entry in self.entries)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _reviewed_translation(repository: Path, source_sha256: str) -> bytes | None:
    """原文ハッシュに結び付いた人手レビュー済み全文訳があれば読み込む。"""
    root = repository / "analysis-framework" / "knowledge" / "result_markdown_ja"
    if not root.exists():
        return None
    root = root.resolve(strict=True)
    _require_within(root, repository, "reviewed translation root escaped repository")
    if _is_reparse_point(root) or not root.is_dir():
        raise LocalizationError("reviewed translation root must be a regular directory")
    candidate = root / f"{source_sha256}.md"
    if not candidate.exists():
        return None
    if _is_reparse_point(candidate) or not candidate.is_file():
        raise LocalizationError("reviewed translation must be a regular Markdown file")
    _require_within(candidate, root, "reviewed translation escaped its knowledge root")
    return candidate.read_bytes()


def _reviewed_translation_output_digests(repository: Path) -> frozenset[str]:
    """レビュー済み全文訳そのものを再変換しないためのハッシュ集合を返す。"""
    root = repository / "analysis-framework" / "knowledge" / "result_markdown_ja"
    if not root.exists():
        return frozenset()
    root = root.resolve(strict=True)
    _require_within(root, repository, "reviewed translation root escaped repository")
    if _is_reparse_point(root) or not root.is_dir():
        raise LocalizationError("reviewed translation root must be a regular directory")

    digests: set[str] = set()
    for candidate in root.glob("*.md"):
        if re.fullmatch(r"[0-9a-f]{64}\.md", candidate.name) is None:
            continue
        if _is_reparse_point(candidate) or not candidate.is_file():
            raise LocalizationError("reviewed translation must be a regular Markdown file")
        _require_within(candidate, root, "reviewed translation escaped its knowledge root")
        try:
            target = candidate.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            raise LocalizationError("reviewed translation is not valid UTF-8") from exc
        normalized = target.replace("\r\n", "\n").replace("\r", "\n")
        # 原文の一様な改行に合わせた出力も、同じレビュー済み訳として扱う。
        for rendered in (target, normalized, normalized.replace("\n", "\r\n")):
            digests.add(_digest(rendered.encode("utf-8")))
    return frozenset(digests)


def _match_source_newlines(source: str, target: str) -> str:
    """一様な原文改行を全文訳へ適用し、フェンスの改行も維持する。"""
    source_without_crlf = source.replace("\r\n", "")
    if "\r" not in source_without_crlf and "\n" not in source_without_crlf:
        newline = "\r\n" if "\r\n" in source else "\n"
        normalized = target.replace("\r\n", "\n").replace("\r", "\n")
        return normalized if newline == "\n" else normalized.replace("\n", "\r\n")
    # 混在改行は位置対応がないため、勝手に正規化しない。
    return target


def _require_within(path: Path, root: Path, message: str) -> None:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError as exc:
        raise LocalizationError(message) from exc


def _requested_path(repository: Path, requested: Path) -> Path:
    return requested if requested.is_absolute() else repository / requested


def discover_result_markdown(
    repository: Path, roots: Iterable[Path] | None = None
) -> tuple[Path, ...]:
    """analysis-results 配下の通常 Markdown だけを重複なく列挙する。"""
    repository = repository.resolve(strict=True)
    if not repository.is_dir():
        raise LocalizationError("repository must be a directory")
    results_root = (repository / "analysis-results").resolve(strict=True)
    if not results_root.is_dir():
        raise LocalizationError("analysis-results directory was not found")
    requested_roots = tuple(roots or (Path("analysis-results"),))
    found: dict[Path, Path] = {}
    for requested in requested_roots:
        lexical = _requested_path(repository, requested)
        try:
            resolved = lexical.resolve(strict=True)
        except OSError as exc:
            raise LocalizationError(f"localization root was not found: {requested}") from exc
        _require_within(
            resolved, results_root, "localization roots must stay within analysis-results"
        )
        if lexical.is_symlink():
            raise LocalizationError("symbolic-link localization roots are not allowed")
        if resolved.is_file():
            candidates: Iterable[Path] = (resolved,)
        elif resolved.is_dir():
            candidates = resolved.rglob("*.md")
        else:
            raise LocalizationError("localization roots must be files or directories")
        for candidate in candidates:
            if candidate.suffix.lower() != ".md" or not candidate.is_file():
                continue
            if candidate.is_symlink():
                raise LocalizationError("symbolic-link Markdown files are not allowed")
            canonical = candidate.resolve(strict=True)
            _require_within(
                canonical, results_root, "Markdown targets must stay within analysis-results"
            )
            if canonical.relative_to(repository).as_posix() in EXCLUDED_RESULT_ROOT_DOCS:
                continue
            found[canonical] = canonical
    return tuple(
        sorted(
            found,
            key=lambda path: path.relative_to(repository).as_posix().casefold(),
        )
    )


def build_plan(
    repository: Path, roots: Iterable[Path] | None = None
) -> LocalizationPlan:
    """現在のバイト列を固定し、書き込みを伴わない変換計画を作る。"""
    repository = repository.resolve(strict=True)
    paths = discover_result_markdown(repository, roots)
    reviewed_output_digests = _reviewed_translation_output_digests(repository)
    entries: list[PlanEntry] = []
    for path in paths:
        source_bytes = path.read_bytes()
        try:
            source_text = source_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            relative = path.relative_to(repository).as_posix()
            raise LocalizationError(f"Markdown is not valid UTF-8: {relative}") from exc
        source_digest = _digest(source_bytes)
        reviewed_bytes = _reviewed_translation(repository, source_digest)
        if source_digest in reviewed_output_digests:
            target_text = source_text
            target_bytes = source_bytes
            method = "reviewed_document"
        elif reviewed_bytes is None:
            relative_path = path.relative_to(repository).as_posix()
            target_text = localize_markdown(
                source_text,
                post_line_translators=_line_translators_for_result_path(relative_path),
            )
            target_bytes = target_text.encode("utf-8")
            method = "template_dictionary"
        else:
            try:
                target_text = reviewed_bytes.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise LocalizationError("reviewed translation is not valid UTF-8") from exc
            target_text = _match_source_newlines(source_text, target_text)
            if _preserved_values(source_text) != _preserved_values(target_text):
                raise LocalizationError(
                    f"reviewed translation changed protected values: {path.relative_to(repository).as_posix()}"
                )
            target_bytes = target_text.encode("utf-8")
            method = "reviewed_document"
        entries.append(
            PlanEntry(
                path=path.relative_to(repository).as_posix(),
                source_sha256=source_digest,
                target_sha256=_digest(target_bytes),
                translation_method=method,
                unresolved=find_unresolved_english(target_text),
                _path=path,
                _source_bytes=source_bytes,
                _target_bytes=target_bytes,
            )
        )
    root_names = tuple(
        sorted(
            (
                _requested_path(repository, root).resolve(strict=True)
                .relative_to(repository)
                .as_posix()
                for root in (roots or (Path("analysis-results"),))
            ),
            key=str.casefold,
        )
    )
    return LocalizationPlan(repository=repository, roots=root_names, entries=tuple(entries))


def plan_report(
    plan: LocalizationPlan, *, mode: str = "dry-run", written_files: int = 0
) -> dict[str, object]:
    """時刻を含めない再現可能な JSON レポートを作る。"""
    files = [
        {
            "path": entry.path,
            "source_sha256": entry.source_sha256,
            "target_sha256": entry.target_sha256,
            "translation_method": entry.translation_method,
            "changed": entry.changed,
            "unresolved_english": [item.as_dict() for item in entry.unresolved],
        }
        for entry in plan.entries
    ]
    changed = sum(entry.changed for entry in plan.entries)
    unresolved_files = sum(bool(entry.unresolved) for entry in plan.entries)
    return {
        "schema_version": 1,
        "scope": "analysis-results/**/*.md",
        "mode": mode,
        "roots": list(plan.roots),
        "counts": {
            "documents": len(plan.entries),
            "changed": changed,
            "unchanged": len(plan.entries) - changed,
            "unresolved_files": unresolved_files,
            "unresolved_lines": plan.unresolved_count,
            "written_files": written_files,
        },
        "files": files,
    }


def _verify_plan_sources(plan: LocalizationPlan) -> None:
    for entry in plan.entries:
        path = entry._path
        _require_within(
            path, plan.repository / "analysis-results",
            "planned Markdown target escaped analysis-results",
        )
        if path.is_symlink() or not path.is_file():
            raise StalePlanError(f"planned Markdown is no longer a regular file: {entry.path}")
        if _digest(path.read_bytes()) != entry.source_sha256:
            raise StalePlanError(f"planned Markdown changed after dry-run: {entry.path}")


def _stage_bytes(path: Path, data: bytes, mode: int) -> Path:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.localize-", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        return temporary
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _replace_path(source: Path, target: Path) -> None:
    """テストで途中失敗を注入できる原子的置換境界。"""
    os.replace(source, target)


def _restore_entry(entry: PlanEntry) -> None:
    mode = stat.S_IMODE(entry._path.stat().st_mode) if entry._path.exists() else 0o644
    temporary = _stage_bytes(entry._path, entry._source_bytes, mode)
    try:
        _replace_path(temporary, entry._path)
    finally:
        temporary.unlink(missing_ok=True)


def apply_plan(plan: LocalizationPlan) -> int:
    """未解決なし・非 stale の計画を一括適用し、失敗時は全件を戻す。"""
    if plan.unresolved_count:
        raise UnresolvedEnglishError(
            f"{plan.unresolved_count} unresolved English prose lines remain"
        )
    _verify_plan_sources(plan)
    changed = [entry for entry in plan.entries if entry.changed]
    staged: dict[str, Path] = {}
    committed: list[PlanEntry] = []
    try:
        for entry in changed:
            mode = stat.S_IMODE(entry._path.stat().st_mode)
            staged[entry.path] = _stage_bytes(entry._path, entry._target_bytes, mode)
        # 一時ファイル作成中の外部変更も、最初の置換前に検出する。
        _verify_plan_sources(plan)
        for entry in changed:
            temporary = staged[entry.path]
            _replace_path(temporary, entry._path)
            committed.append(entry)
            if _digest(entry._path.read_bytes()) != entry.target_sha256:
                raise OSError(f"post-write fingerprint mismatch: {entry.path}")
    except BaseException as exc:
        if isinstance(exc, StalePlanError) and not committed:
            raise
        rollback_failures: list[str] = []
        for entry in reversed(committed):
            try:
                _restore_entry(entry)
            except BaseException as rollback_exc:
                rollback_failures.append(f"{entry.path}: {rollback_exc}")
        detail = ""
        if rollback_failures:
            detail = "; rollback failed for " + ", ".join(rollback_failures)
        raise LocalizationApplyError(
            f"localization write failed; replaced files were rolled back{detail}"
        ) from exc
    finally:
        for temporary in staged.values():
            temporary.unlink(missing_ok=True)
    return len(changed)


def _report_output(repository: Path, requested: Path) -> Path:
    output = _requested_path(repository, requested)
    if output.suffix.lower() != ".json":
        raise LocalizationError("report output must use a .json suffix")
    prospective = output.resolve(strict=False)
    _require_within(
        prospective, repository, "localization reports must stay within the repository"
    )
    lexical = Path(os.path.abspath(output))
    try:
        relative_parent = lexical.parent.relative_to(repository)
    except ValueError as exc:
        raise LocalizationError(
            "localization reports must stay within the repository"
        ) from exc
    cursor = repository
    for part in relative_parent.parts:
        cursor /= part
        if cursor.exists() and _is_reparse_point(cursor):
            raise LocalizationError("reparse-point report parents are not allowed")
    prospective.parent.mkdir(parents=True, exist_ok=True)
    resolved_parent = prospective.parent.resolve(strict=True)
    _require_within(
        resolved_parent, repository, "localization reports must stay within the repository"
    )
    cursor = repository
    for part in resolved_parent.relative_to(repository).parts:
        cursor /= part
        if _is_reparse_point(cursor):
            raise LocalizationError("reparse-point report parents are not allowed")
    final_output = resolved_parent / prospective.name
    if final_output.exists() and _is_reparse_point(final_output):
        raise LocalizationError("reparse-point report outputs are not allowed")
    return final_output


def _is_reparse_point(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and is_junction())


def _write_report_atomic(path: Path, report: dict[str, object]) -> None:
    data = (json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    mode = stat.S_IMODE(path.stat().st_mode) if path.exists() else 0o644
    temporary = _stage_bytes(path, data, mode)
    try:
        _replace_path(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def build_parser() -> argparse.ArgumentParser:
    """dry-run を既定とする CLI の引数を構成する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--repository", type=Path, default=Path(__file__).resolve().parents[2]
    )
    parser.add_argument(
        "--root", type=Path, action="append",
        help="analysis-results 配下の相対パス。複数指定可能。",
    )
    parser.add_argument("--report-json", type=Path)
    parser.add_argument(
        "--write", action="store_true",
        help="未解決行がない計画だけを原子的に適用する。",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """計画を報告し、明示時のみ適用する。未解決・失敗は非ゼロで閉じる。"""
    args = build_parser().parse_args(argv)
    try:
        repository = args.repository.resolve(strict=True)
        plan = build_plan(repository, args.root)
        mode = "write" if args.write else "dry-run"
        written = 0
        if args.write and not plan.unresolved_count:
            written = apply_plan(plan)
        report = plan_report(plan, mode=mode, written_files=written)
        if args.report_json:
            _write_report_atomic(
                _report_output(repository, args.report_json), report
            )
        else:
            print(json.dumps(report, ensure_ascii=False, indent=2))
        if plan.unresolved_count:
            return 2 if args.write else 1
        return 0
    except LocalizationError as exc:
        print(f"ローカライズを中止しました: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
