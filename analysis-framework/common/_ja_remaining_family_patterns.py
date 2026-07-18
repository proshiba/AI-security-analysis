"""残る11ファミリーの引用表記と反復テンプレートを日本語化する。"""

from __future__ import annotations

import re


_REPLACEMENTS = {
    "Palo Alto Networks Unit 42": "パロアルトネットワークス ユニット42",
    "HexaStrike": "ヘキサストライク",
    "Zscaler ThreatLabz": "ジースケーラー脅威研究所",
    "Trellix": "トレリックス",
    "Proofpoint": "プルーフポイント",
    "FortiGuard Threat Actor Encyclopedia": "フォーティガード脅威アクター百科事典",
    "Fortinet": "フォーティネット",
    "Electronic Frontier Foundation": "電子フロンティア財団",
    "NHS England": "NHSイングランド",
    "Check Point Research": "チェック・ポイント・リサーチ",
    "Rapid7": "ラピッドセブン",
    "IBM X-Force": "IBM Xフォース",
    "Microsoft Security Intelligence": "マイクロソフト脅威情報",
    "ESET": "イーセット",
    "MITRE ATT&CK": "マイター攻撃技術知識体系",
    "Dark Reading": "ダーク・リーディング",
    "Mandiant": "マンディアント",
    "Quasar project": "クエーサープロジェクト",
    "CISA Cyber Safety Review Board": "CISAサイバー安全審査委員会",
    "U.S. Department of Justice": "U.S.司法省",
    "Citizen Lab": "シチズンラボ",
    "Broadcom": "ブロードコム",
    "CrowdStrike": "クラウドストライク",
    "Quasar official archived repository": "Quasar公式アーカイブリポジトリ",
    "Downeks and Quasar RAT Used in Recent Targeted Attacks Against Governments":
        "政府機関への最近の標的型攻撃で使われたDowneksとQuasar RAT",
    "Review of the Attacks Associated with Lapsus$ and Related Threat Groups":
        "Lapsus$および関連脅威グループによる攻撃の検証",
    "Persistent Attempts at Cyberespionage Against Southeast Asian Government Target Have Links to Alloy Taurus":
        "東南アジア政府を狙う継続的サイバー諜報とAlloy Taurusの関連",
    "XWorm V6: Exploring Pivotal Plugins": "XWorm V6の主要プラグイン調査",
    "New RedLine Stealer Distributed Using Coronavirus-themed Email Campaign":
        "新型コロナウイルス題材のメール活動によるRedLine Stealer配布",
    "Deep Analysis of Snake Keylogger's New Variant": "Snake Keylogger新版の詳細解析",
    "Deep Dive into a Fresh Variant of Snake Keylogger Malware":
        "Snake Keyloggerマルウェア新版の詳細調査",
    "FortiSandbox 5.0 Detects Evolving Snake Keylogger Variant":
        "FortiSandbox 5.0による進化したSnake Keylogger亜種の検出",
    "U.S. Joins International Action Against RedLine and META Infostealers":
        "U.S.によるRedLineおよびMETA情報窃取型への国際共同対処",
    "Análisis del infame backend de RedLine Stealer":
        "RedLine Stealerの悪名高いバックエンドの分析",
    "Now You See Me - H-worm by Houdini": "HoudiniによるH-wormの分析",
    "The Gorgon Group: Slithering Between Nation State and Cybercrime":
        "国家支援活動とサイバー犯罪の間を行き来するGorgon Group",
    "Attackers Distribute Malware via Freeze.rs And SYK Crypter":
        "Freeze.rsとSYK Crypterを介したマルウェア配布",
    "Deja Vu All Over Again: Tax Scammers at Large":
        "税務詐欺活動の再来",
    "Deep Dive into New XWorm Campaign Utilizing Multiple-Themed Phishing Emails":
        "複数題材のフィッシングメールを使う新たなXWorm活動の詳細調査",
    "Destructive Malware Targeting Organizations in Ukraine, AA22-057A":
        "ウクライナの組織を狙う破壊型マルウェア AA22-057A",
    "Local QuasarRAT analysis results": "ローカルQuasarRAT解析結果",
    "Local RedLine Stealer analysis results": "ローカルRedLine Stealer解析結果",
    "Local Snake Keylogger analysis results": "ローカルSnake Keylogger解析結果",
    "Local njRAT analysis results": "ローカルnjRAT解析結果",
    "Local XWorm analysis results": "ローカルXWorm解析結果",
    "njRAT, Software S0385": "njRATソフトウェア S0385",
}

_EXACT = {
    "## family固有方針": "## ファミリー固有方針",
    "## unknown（不明）": "## 不明版",
    "# Atlas RAT": "# Atlas RAT：概要",
    "# RedLine Stealer": "# RedLine Stealer：技術解析",
    "# Snake Keylogger": "# Snake Keylogger：技術解析",
}

_OSINT_TITLE = re.compile(r"^(#\s+.+?)：OSINT詳細$")
_CASE_FAMILY = re.compile(
    r"^-\s+Family:\s+(\x60[a-z0-9]+\x60)\s+"
    r"\(high confidence from exact MalwareBazaar signature selection "
    r"and verified SHA-256\)$"
)
_COLLECTION_EVIDENCE = re.compile(
    r"^-\s+(\[[^\]]+\]\([^)]+\)):\s+"
    r"10 newest reviewed MalwareBazaar samples, static-only\.$"
)


def translate_line(line: str) -> str:
    """既知の引用・見出し・反復行だけを変換し、未知行は保持する。"""
    leading = line[: len(line) - len(line.lstrip())]
    trailing = line[len(line.rstrip()):]
    core = line.strip()
    exact = _EXACT.get(core)
    if exact is not None:
        return leading + exact + trailing
    match = _OSINT_TITLE.fullmatch(core)
    if match:
        core = match.group(1) + "：公開情報の詳細"
    match = _CASE_FAMILY.fullmatch(core)
    if match:
        return (
            leading
            + f"- ファミリー: {match.group(1)}"
            + "（MalwareBazaarの完全一致シグネチャ選択と"
            + "検証済みSHA-256による高信頼度）"
            + trailing
        )
    match = _COLLECTION_EVIDENCE.fullmatch(core)
    if match:
        return (
            leading
            + f"- {match.group(1)}: MalwareBazaarの最新10検体を"
            + "レビューし、静的解析だけを実施。"
            + trailing
        )
    for source, target in _REPLACEMENTS.items():
        core = core.replace(source, target)
    return leading + core + trailing
