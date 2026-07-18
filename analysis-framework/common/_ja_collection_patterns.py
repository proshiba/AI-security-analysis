"""指定コレクションに残る英語説明を日本語化する補完ルール。"""

from __future__ import annotations

import re

from _ja_legacy_family_patterns import translate_line as _translate_common_line


_LINE_ENDING = re.compile(r"(\r\n|\n|\r)$")


_EXACT_TRANSLATIONS = {
    "# コレクション：refresh-20260715": "# コレクション：20260715更新分",
    "# コレクション：vx-underground-20260716":
        "# コレクション：20260716版ブイエックス・アンダーグラウンド",
    "Ten newest samples selected by exact MalwareBazaar signature were downloaded and analyzed statically. Inner hashes were verified; no sample or recovered payload was executed and no candidate infrastructure was contacted.":
        "MalwareBazaarの完全一致シグネチャで最新10検体を選定し、ダウンロードして静的解析した。内部ハッシュを検証済みであり、検体や回収ペイロードは実行せず、候補インフラにも接続していない。",
    "Family attribution here does not imply one operator or campaign. Builder leakage, forks, repacking, and distinct delivery chains remain separate dimensions.":
        "ここでのファミリー帰属は、単一の運用者やキャンペーンを意味しない。ビルダー流出、フォーク、再パック、異なる配布チェーンは別々の観点として扱う。",
    "Decode the settings object and corroborate host, port, certificate/key material, and AsyncRAT framing. Until that condition is met, report values as candidate delivery/C2/exfiltration infrastructure only. Passive Shodan queries are stored per case; no banner, JARM, certificate, or HTTP title was invented when no live observation occurred.":
        "設定オブジェクトを復号し、ホスト、ポート、証明書／鍵材料、AsyncRATのフレーミングを相互確認する。この条件を満たすまでは、値を配布／C2／持ち出しインフラ候補としてのみ報告する。受動的なShodanクエリはケースごとに保存しており、稼働観測がない場合にバナー、JARM、証明書、HTTPタイトルを推測で作成していない。",
    "| High | Exact reviewed SHA-256 | Very low false positives; misses every rebuild or repack. |":
        "| 高 | 確認済みSHA-256との完全一致 | 誤検知は非常に少ないが、再ビルドや再パックはすべて見逃す。 |",
    "| Medium | Multiple family markers plus decoded/corroborated endpoint structure | Forks, leaked builders, research tools, and shared libraries can match. |":
        "| 中 | 複数のファミリーマーカーと、復号または相互確認したエンドポイント構造 | フォーク、流出ビルダー、調査ツール、共有ライブラリも一致し得る。 |",
    "| Low | One marker, one URL/IP, packer label, or generic script interpreter behavior | Shared hosting, legitimate automation, installers, and documentation strings can over-detect. |":
        "| 低 | 単一マーカー、単一URL／IP、パッカーラベル、または一般的なスクリプト実行動作 | 共有ホスティング、正規の自動化、インストーラー、文書文字列を過剰検知し得る。 |",
    "The generated YARA rule is medium confidence and must be validated against a benign corpus. Sigma should be based on actual endpoint telemetry; this static batch does not fabricate process or registry events.":
        "生成したYARAルールの確度は中であり、良性コーパスに対する検証が必要である。Sigmaは実際のエンドポイントテレメトリーに基づけるべきで、この静的解析バッチではプロセスやレジストリイベントを捏造しない。",
    "Decode the DarkComet configuration block and validate NETDATA plus family command framing. Until that condition is met, report values as candidate delivery/C2/exfiltration infrastructure only. Passive Shodan queries are stored per case; no banner, JARM, certificate, or HTTP title was invented when no live observation occurred.":
        "DarkCometの設定ブロックを復号し、NETDATAとファミリー固有のコマンドフレーミングを検証する。この条件を満たすまでは、値を配布／C2／持ち出しインフラ候補としてのみ報告する。受動的なShodanクエリはケースごとに保存しており、稼働観測がない場合にバナー、JARM、証明書、HTTPタイトルを推測で作成していない。",
    "Decode the embedded settings resource and corroborate host/port with DCRat message serialization. Until that condition is met, report values as candidate delivery/C2/exfiltration infrastructure only. Passive Shodan queries are stored per case; no banner, JARM, certificate, or HTTP title was invented when no live observation occurred.":
        "埋め込み設定リソースを復号し、ホスト／ポートをDCRatのメッセージ直列化方式と相互確認する。この条件を満たすまでは、値を配布／C2／持ち出しインフラ候補としてのみ報告する。受動的なShodanクエリはケースごとに保存しており、稼働観測がない場合にバナー、JARM、証明書、HTTPタイトルを推測で作成していない。",
    "Treat URLs as delivery candidates until the decoded downloader routine and payload transform are recovered. Until that condition is met, report values as candidate delivery/C2/exfiltration infrastructure only. Passive Shodan queries are stored per case; no banner, JARM, certificate, or HTTP title was invented when no live observation occurred.":
        "復号済みダウンローダールーチンとペイロード変換を回収するまでは、URLを配布候補として扱う。この条件を満たすまでは、値を配布／C2／持ち出しインフラ候補としてのみ報告する。受動的なShodanクエリはケースごとに保存しており、稼働観測がない場合にバナー、JARM、証明書、HTTPタイトルを推測で作成していない。",
    "Corroborate a URL with the IDAT/ESAL loader chain and recovered stage metadata; do not equate reachability with C2. Until that condition is met, report values as candidate delivery/C2/exfiltration infrastructure only. Passive Shodan queries are stored per case; no banner, JARM, certificate, or HTTP title was invented when no live observation occurred.":
        "URLをIDAT／ESALローダーチェーンおよび回収済みステージのメタデータと相互確認し、到達可能性をC2と同一視しない。この条件を満たすまでは、値を配布／C2／持ち出しインフラ候補としてのみ報告する。受動的なShodanクエリはケースごとに保存しており、稼働観測がない場合にバナー、JARM、証明書、HTTPタイトルを推測で作成していない。",
    "Recover the H/P/VN configuration tuple and validate the njRAT registration delimiter offline or on loopback. Until that condition is met, report values as candidate delivery/C2/exfiltration infrastructure only. Passive Shodan queries are stored per case; no banner, JARM, certificate, or HTTP title was invented when no live observation occurred.":
        "H／P／VN設定タプルを回収し、njRATの登録区切りをオフラインまたはループバックで検証する。この条件を満たすまでは、値を配布／C2／持ち出しインフラ候補としてのみ報告する。受動的なShodanクエリはケースごとに保存しており、稼働観測がない場合にバナー、JARM、証明書、HTTPタイトルを推測で作成していない。",
    "Corroborate a decoded ClientConfig with Quasar namespaces and certificate-backed packet framing. Until that condition is met, report values as candidate delivery/C2/exfiltration infrastructure only. Passive Shodan queries are stored per case; no banner, JARM, certificate, or HTTP title was invented when no live observation occurred.":
        "復号したClientConfigをQuasarの名前空間および証明書を用いたパケットフレーミングと相互確認する。この条件を満たすまでは、値を配布／C2／持ち出しインフラ候補としてのみ報告する。受動的なShodanクエリはケースごとに保存しており、稼働観測がない場合にバナー、JARM、証明書、HTTPタイトルを推測で作成していない。",
    "Decode the build configuration and corroborate endpoint, build ID, and RedLine collection schema. Until that condition is met, report values as candidate delivery/C2/exfiltration infrastructure only. Passive Shodan queries are stored per case; no banner, JARM, certificate, or HTTP title was invented when no live observation occurred.":
        "ビルド設定を復号し、エンドポイント、ビルドID、RedLineの収集スキーマを相互確認する。この条件を満たすまでは、値を配布／C2／持ち出しインフラ候補としてのみ報告する。受動的なShodanクエリはケースごとに保存しており、稼働観測がない場合にバナー、JARM、証明書、HTTPタイトルを推測で作成していない。",
    "Corroborate an endpoint with the selected exfiltration backend without publishing credentials or tokens. Until that condition is met, report values as candidate delivery/C2/exfiltration infrastructure only. Passive Shodan queries are stored per case; no banner, JARM, certificate, or HTTP title was invented when no live observation occurred.":
        "認証情報やトークンを公開せず、エンドポイントを選択された持ち出しバックエンドと相互確認する。この条件を満たすまでは、値を配布／C2／持ち出しインフラ候補としてのみ報告する。受動的なShodanクエリはケースごとに保存しており、稼働観測がない場合にバナー、JARM、証明書、HTTPタイトルを推測で作成していない。",
    "Recover the configured separator/key and validate XWorm registration framing in an isolated lab. Until that condition is met, report values as candidate delivery/C2/exfiltration infrastructure only. Passive Shodan queries are stored per case; no banner, JARM, certificate, or HTTP title was invented when no live observation occurred.":
        "設定された区切り／鍵を回収し、隔離ラボでXWormの登録フレーミングを検証する。この条件を満たすまでは、値を配布／C2／持ち出しインフラ候補としてのみ報告する。受動的なShodanクエリはケースごとに保存しており、稼働観測がない場合にバナー、JARM、証明書、HTTPタイトルを推測で作成していない。",
    "# MalwareBazaar refresh analysis — 2026-07-15":
        "# マルウェアバザール更新解析 — 2026-07-15",
    "## Summary": "## 概要",
    "> The original heuristic packing counts below are superseded by the":
        "> 以下の元のヒューリスティックなパッキング件数は、次の結果により置き換えられる：",
    "## Notable static findings": "## 注目すべき静的解析結果",
    "- ValleyRAT case [`42420ed30965…`](../../malware/valleyrat/versions/unknown/cases/42420ed30965b2e8cd0abfe59103f9352cf9e8bb9a1c75d340bf13b2660abda5/README.md): `103.43.11.40:1443` was recovered from the reversed vvaS configuration and is therefore a confirmed embedded C2 value. Current liveness and ownership were not tested.":
        "- バレーラットのケース [`42420ed30965…`](../../malware/valleyrat/versions/unknown/cases/42420ed30965b2e8cd0abfe59103f9352cf9e8bb9a1c75d340bf13b2660abda5/README.md)：反転されたvvaS設定から `103.43.11.40:1443` を回収したため、確認済みの埋め込みC2値である。現在の稼働状況と所有者は検証していない。",
    "AgentTesla, RemcosRAT, VenomRAT, Formbook, Vidar, and LummaStealer did not yield a defensible final C2/config value from these submitted layers. This is recorded as a static-analysis limitation rather than interpreted as absence of network behavior.":
        "エージェントテスラ、レムコスRAT、ヴェノムRAT、フォームブック、ヴィダー、ルマスティーラーでは、提出されたレイヤーから根拠の十分な最終C2／設定値を得られなかった。これはネットワーク動作が存在しないという意味ではなく、静的解析の制約として記録する。",
    "## Safety and provenance": "## 安全性と由来",
    "- Recovered layers remain outside the repository in encrypted analysis artifacts.":
        "- 回収したレイヤーは、暗号化した解析アーティファクトとしてリポジトリ外に保持する。",
    "- Certificate/OCSP, vendor documentation, external-IP lookup, and public DNS-over-HTTPS references are suppressed as likely false-positive C2 candidates.":
        "- 証明書／OCSP、ベンダー文書、外部IP検索、公開DNS-over-HTTPSの参照は、誤検知の可能性が高いC2候補として除外する。",
    "10 new MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.":
        "MalwareBazaarの新規提出検体10件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。",
    "35 `vx-underground` submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.":
        "`vx-underground` の提出検体35件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。",
    "## Validated config values": "## 検証済み設定値",
    "2 `vx-underground` submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.":
        "`vx-underground` の提出検体2件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。",
    "54 `vx-underground` submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.":
        "`vx-underground` の提出検体54件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。",
    "25 `vx-underground` submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.":
        "`vx-underground` の提出検体25件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。",
}


_COMMON_TRANSLATIONS = {
    _translate_common_line(source): target
    for source, target in _EXACT_TRANSLATIONS.items()
}
_TRANSLATED_LINES = frozenset(_EXACT_TRANSLATIONS.values())


def _split_line(line: str) -> tuple[str, str, str, str]:
    match = _LINE_ENDING.search(line)
    if match is None:
        body, ending = line, ""
    else:
        body, ending = line[:match.start()], match.group(1)
    leading = body[: len(body) - len(body.lstrip())]
    trailing = body[len(body.rstrip()):]
    return leading, body.strip(), trailing, ending


def _with_line_shape(line: str, translated: str) -> str:
    leading, _, trailing, ending = _split_line(line)
    return leading + translated + trailing + ending


def translate_line(line: str) -> str:
    """コレクション由来の一行を保護値と行形状を保ったまま日本語化する。"""
    _, core, _, _ = _split_line(line)
    if not core or core in _TRANSLATED_LINES:
        return line

    translated = _EXACT_TRANSLATIONS.get(core)
    if translated is not None:
        return _with_line_shape(line, translated)

    translated = _COMMON_TRANSLATIONS.get(core)
    if translated is not None:
        return _with_line_shape(line, translated)

    common = _translate_common_line(line)
    _, common_core, _, _ = _split_line(common)
    translated = _COMMON_TRANSLATIONS.get(common_core)
    if translated is None:
        return common
    return _with_line_shape(line, translated)


__all__ = ["translate_line"]
