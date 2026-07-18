"""旧ファミリー解析文書に残る英語説明を日本語化する内部ルール。

このモジュールは、既存の Markdown ローカライザーを通過した一行を受け取る。
ハッシュ、URL、インラインコード、機械可読 enum、ファイル名、識別子、数値は
プレースホルダーで保護し、人が読む説明部分だけを決定的に置換する。
"""

from __future__ import annotations

import re


_INLINE_CODE = re.compile(r"(`+)([^\r\n]*?)\1")
_BARE_URL = re.compile(r"https?://[^\s<>)]+")
_MARKDOWN_DESTINATION = re.compile(r"(?<=\]\()[^\r\n)]+(?=\))")
_LONG_HASH = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{32,}(?![0-9A-Fa-f])")
_TECHNICAL_ENUM = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b")
_TECHNICAL_FILENAME = re.compile(
    r"\b[A-Za-z0-9_.%*-]+\.(?:json|ya?ml|md|ps1|py|exe|dll|bin|zip|rar|img|iso|js|hta|vbs|png|xlxs)\b",
    re.IGNORECASE,
)
_DOTTED_IDENTIFIER = re.compile(
    r"\b[A-Za-z_$<>][A-Za-z0-9_$<>]*(?:\.[A-Za-z_$<>][A-Za-z0-9_$<>]*)+\b"
)
_REPOSITORY_IDENTIFIER = re.compile(r"\b(?:AI-security-analysis|VX-Underground)\b")
_LEGAL_SIGNER = re.compile(
    re.escape("Hithink RoyalFlush Information Network Co., Ltd.")
)
_NUMBER = re.compile(
    r"(?<![A-Za-z0-9])(?:\d+(?:[.,:/-]\d+)*(?:\.\.\.)?|\d+(?:\.\d+)+)(?![A-Za-z0-9])"
)
_LINE_ENDING = re.compile(r"(\r\n|\n|\r)$")
_PLACEHOLDER = "\ue000P{}\ue001"


_EXACT = {
    "| MSI | `KL-X86Gicasc.msi` | 30,135,808 | `ee1f25b74bc40c30ef3dac839257e6e75c3ef5e84e6c8b464f1984943132f166` | OLE 61 streams、CAB 1、PE streams 2 |":
        "| Windowsインストーラー | `KL-X86Gicasc.msi` | 30,135,808 | `ee1f25b74bc40c30ef3dac839257e6e75c3ef5e84e6c8b464f1984943132f166` | OLEストリーム61件、CAB 1件、PEストリーム2件 |",
    "| Embedded CAB | OLE CAB stream | 28,470,946 | `353a58f77f2b1f85dc5a439708f153f37d94d1cb7c3fc8f830c3e11599e62d4c` | 3 payloads |":
        "| 埋め込みキャビネット書庫 | OLE形式のキャビネット書庫ストリーム | 28,470,946 | `353a58f77f2b1f85dc5a439708f153f37d94d1cb7c3fc8f830c3e11599e62d4c` | ペイロード3件 |",
    "| MSI custom-action PE | OLE PE stream | 736,368 | `066c52ed8ebf63a33ab8290b7c58d0c13f79c14faa8bf12b1b41f643d3ebe281` | installer/custom action exports |":
        "| WindowsインストーラーのカスタムアクションPE | OLE PEストリーム | 736,368 | `066c52ed8ebf63a33ab8290b7c58d0c13f79c14faa8bf12b1b41f643d3ebe281` | インストーラー／カスタムアクションのエクスポート |",
    "| `5cdb8b20bab0ef77f5889729c7c8664326607ecf19ae48d2e1b1398df6b40083` | IMG container and DLL hijacking | `192.252.180.45:4449` (Triage extracted config) |":
        "| `5cdb8b20bab0ef77f5889729c7c8664326607ecf19ae48d2e1b1398df6b40083` | IMGコンテナとDLLハイジャック | `192.252.180.45:4449`（Triageで抽出した設定） |",
    "| none recovered | - | - | static extraction incomplete |":
        "| 回収なし | - | - | 静的抽出が未完了 |",
    "| none recovered | - | - | packed/encrypted or no literal config |":
        "| 回収なし | - | - | パック／暗号化済み、またはリテラル設定なし |",
    "| C2 | Unknown from this static layer |": "| C2 | この静的レイヤーからは不明 |",
    "| Static config | Not recovered |": "| 静的設定 | 未回収 |",
    "- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.":
        "- AES-CTR文字列を使う世代と保護された配布ラッパーでは、回収済みメモリイメージまたは今後のパーサープロファイルが必要になる場合がある。",
    "- Confirmed values require the characteristic decrypted registration format and at least one URL.":
        "- 確認済み値とするには、特徴的な復号済み登録形式と少なくとも1件のURLが必要である。",
    "- No check-in or infrastructure contact was performed.":
        "- チェックインおよびインフラへの接続は実施していない。",
    "- Packed or loader-stage samples require recursive recovery before a final config can be asserted.":
        "- パック済み検体またはローダーステージでは、最終設定を断定する前に再帰的な回収が必要である。",
    "- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.":
        "- Vidarは、直接埋め込まれたC2ではなくデッドドロップ・プロファイルからインフラ情報を取得する場合がある。",
    "- Format: x86 native PE (not .NET)": "- 形式：x86ネイティブPE（.NETではない）",
    "- Source: VX-Underground StealC family directory":
        "- 情報源: VX-UndergroundのStealCファミリーディレクトリ",
    "- Low false-positive risk: exact SHA-256, with low longevity against rebuilding.":
        "- 誤検知リスク低：SHA-256の完全一致。ただし再ビルドへの耐久性は低い。",
    "- Medium false-positive risk: the Sigma delayed `cmd.exe /c timeout /t 5 ... del /f /q` pattern can match installers and cleanup tools.":
        "- 誤検知リスク中：Sigmaの遅延削除パターン `cmd.exe /c timeout /t 5 ... del /f /q` は、インストーラーやクリーンアップツールにも一致し得る。",
    "- Medium false-positive risk: StealC v1 YARA structural rules; dense Base64/resource tables or repeated x86 wrapper calls can overlap with protected legitimate software.":
        "- 誤検知リスク中：StealC v1向けYARA構造ルール。高密度のBase64／リソース表や反復するx86ラッパー呼び出しは、保護された正規ソフトウェアとも重なり得る。",
    "- High false-positive risk: generic browser database, Telegram, Discord, Outlook, or Steam file access also occurs in backup, migration, and endpoint-security products and needs process lineage plus destination context.":
        "- 誤検知リスク高：一般的なブラウザーデータベースやTelegram、Discord、Outlook、Steamファイルへのアクセスは、バックアップ、移行、エンドポイント保護製品でも発生するため、プロセス系譜と通信先の文脈が必要である。",
    "Decoded v1 profiles expose browser credential/cookie/autofill/history/card collection, Firefox and Chromium data access, Telegram/Discord/Outlook/Pidgin/Steam/Tox targets, screenshot and file-grabber support, optional loader behavior, and delayed self-deletion. The reviewed v1 transport constructs WinINet HTTP multipart POST bodies with fields such as `hwid`, `build`, `token`, `file_name`, `file`, and `message`. These are static code/config observations; this case was not allowed to execute.":
        "復号したv1プロファイルから、ブラウザーの認証情報、Cookie、自動入力、履歴、カード情報の収集、Firefox／Chromiumデータへのアクセス、Telegram／Discord／Outlook／Pidgin／Steam／Toxの標的化、スクリーンショットとファイル収集、任意のローダー動作、遅延自己削除が確認できる。確認したv1の通信処理はWinINet HTTPマルチパートPOST本文を構築し、`hwid`、`build`、`token`、`file_name`、`file`、`message` 等のフィールドを使う。これらは静的なコード／設定の観測結果であり、本ケースの実行は許可していない。",
    "No endpoint was contacted, so reachability, HTTP title, response banner, TLS certificate, JARM, and Shodan banner hash are intentionally not asserted. `confirmed_static_config` describes decoded bytes, not current C2 ownership or liveness.":
        "エンドポイントには接続していないため、到達可能性、HTTPタイトル、応答バナー、TLS証明書、JARM、Shodanバナーハッシュは意図的に断定しない。`confirmed_static_config` は復号済みバイト列を表すもので、現在のC2所有者や稼働状況を示すものではない。",
    "The submitted outer layer is retained as a confirmed corpus hash, but no C2 is promoted from unverified strings. Isolated runtime unpacking would be required to obtain a plaintext inner payload.":
        "提出された外層は確認済みコーパスハッシュとして保持するが、未検証文字列からC2へ昇格した値はない。平文の内部ペイロードを得るには、隔離環境での実行時アンパックが必要である。",
    "- Analysis mode: static analysis plus public sandbox evidence; the sample was not executed locally":
        "- 解析方式：静的解析と公開サンドボックスの証拠。検体はローカルで実行していない",
    "- Banner hash, HTTP title, certificate hash and JARM: not available from static/sandbox evidence. Do not invent these values; collect only under an approved live-network procedure.":
        "- バナーハッシュ、HTTPタイトル、証明書ハッシュ、JARM：静的解析／サンドボックスの証拠からは取得できない。値を推測せず、承認済みの実ネットワーク手順でのみ収集する。",
    "- Confidence labels: delivery behavior is `confirmed` from static code/container structure; payload capability is `inferred` from family/config; listed final endpoints are `confirmed` only to the provenance stated above.":
        "- 確度ラベル：配布動作は静的コード／コンテナ構造から `confirmed`、ペイロード機能はファミリー／設定から `inferred`、記載した最終エンドポイントは上記の由来範囲に限り `confirmed` とする。",
    "- Confidence: endpoints labeled confirmed were extracted from malware configuration or process-attributed sandbox evidence. Exact-byte duplicate containers inherit the inner payload result explicitly.":
        "- 確度：確認済みとしたエンドポイントは、マルウェア設定またはプロセスに帰属できるサンドボックス証拠から抽出した。バイト単位で同一の重複コンテナは、内部ペイロードの結果を明示的に継承する。",
    "- Correlate parent/child process, command line, file origin, signer/prevalence and network destination before blocking.":
        "- 遮断前に、親子プロセス、コマンドライン、ファイルの由来、署名者／普及度、通信先を相関する。",
    "- Credential material extracted from configurations is intentionally not published. Preserve it only in access-controlled evidence and rotate/notify an owner when appropriate.":
        "- 設定から抽出した認証情報は意図的に公開しない。アクセス制御された証拠内だけに保持し、必要に応じて所有者への通知とローテーションを行う。",
    "- High confidence / low false-positive risk: exact SHA-256, a reviewed YARA match combining loader structure with family-specific strings, or an endpoint plus matching process ancestry.":
        "- 確度高／誤検知リスク低：SHA-256完全一致、ローダー構造とファミリー固有文字列を組み合わせたレビュー済みYARA一致、またはエンドポイントと整合するプロセス系譜。",
    "- Liveness: no live C2 check was performed for this case; current availability and server ownership remain unknown.":
        "- 稼働状況：本ケースでは実C2確認を行っていないため、現在の利用可能性とサーバー所有者は不明である。",
    "- Low confidence / high false-positive risk: a single domain/IP, FTP/SMTP use, PowerShell, WScript, HTA, or image-named download alone. These are common administrative or application behaviors.":
        "- 確度低／誤検知リスク高：単独のドメイン／IP、FTP／SMTP利用、PowerShell、Windowsスクリプトホスト、HTMLアプリケーション、画像風名称のダウンロード。いずれも一般的な管理・アプリケーション動作である。",
    "- Medium confidence / medium false-positive risk: script host spawning hidden PowerShell together with remote image retrieval, in-memory .NET loading, or a double-extension executable from an ISO.":
        "- 確度中／誤検知リスク中：スクリプトホストによる非表示PowerShell起動とリモート画像取得の組み合わせ、メモリ内.NETロード、またはディスクイメージ内の二重拡張子実行ファイル。",
    "- No live C2 check was performed. Current availability and server identity are therefore unknown.":
        "- 実C2確認は行っていない。そのため現在の利用可能性とサーバーの実体は不明である。",
    "Run the family batch workflow against the original password-protected MalwareBazaar ZIP. Outputs must retain `executed=false` and `network_contacted=false` unless a separately approved dynamic-analysis workflow was used.":
        "元のパスワード保護済みMalwareBazaar ZIPに対してファミリー一括処理を実行する。別途承認された動的解析手順を使用しない限り、出力では `executed=false` と `network_contacted=false` を維持する。",
    "- Endpoint provenance: external sandbox configuration or process-attributed evidence; the submitted loader alone did not establish the final endpoint.":
        "- エンドポイントの由来: 外部サンドボックス設定またはプロセス帰属可能な証拠。提出ローダー単体では最終エンドポイントを確定していない。",
    "- Stage URLs: none recovered": "- ステージURL: 回収なし",
    "- Campaign-specific decoded config should supersede candidates when available.":
        "- キャンペーン固有の復号済み設定を取得できた場合は、候補より優先する。",
    "- Encrypted resource loaders require a recovered final payload before config can be confirmed.":
        "- 暗号化リソースローダーでは、設定を確認済みとする前に最終ペイロードの回収が必要である。",
    "- Literal endpoints require config-reference or process-attributed validation.":
        "- リテラルのエンドポイントには、設定参照またはプロセス帰属による検証が必要である。",
    "- Recovered .NET #US ordering is needed to promote inferred string candidates to confirmed config.":
        "- 推定文字列候補を確認済み設定へ昇格するには、回収した.NET #USの順序情報が必要である。",
    "- Remcos configuration may be encrypted or resource-backed.":
        "- Remcosの設定は暗号化またはリソース格納されている場合がある。",
    "- Static strings alone do not prove an endpoint is C2.":
        "- 静的文字列だけでは、エンドポイントがC2であることを証明できない。",
    "- C2 role assumption: long-lived outbound Remcos command-and-control channel; multiple host/port entries in one recovered configuration are treated as ordered fallback candidates, not separate malware families.":
        "- C2役割の仮定: 長時間維持される外向きRemcos指令・制御チャネル。1件の回収設定にある複数のホスト／ポートは、別々のマルウェアファミリーではなく順序付きフォールバック候補として扱う。",
    "- C2 role assumption: FTP exfiltration/configuration endpoint used to upload stolen information; it is not assumed to be an interactive tasking server.":
        "- C2役割の仮定: 窃取情報のアップロードに使うFTP持ち出し／設定エンドポイント。対話型タスク指示サーバーとは仮定しない。",
    "- C2 role assumption: SMTP exfiltration/configuration endpoint used to upload stolen information; it is not assumed to be an interactive tasking server.":
        "- C2役割の仮定: 窃取情報のアップロードに使うSMTP持ち出し／設定エンドポイント。対話型タスク指示サーバーとは仮定しない。",
    "C2 and dependency paths were recovered from the sample bytes. No liveness check was performed.":
        "C2と依存ファイルのパスは検体バイト列から回収した。稼働確認は実施していない。",
    "Case reports separate observed delivery behavior, inferred family capability, endpoint provenance, and current liveness. No current case was executed locally or live-probed.":
        "ケース報告では、観測した配布動作、推定したファミリー機能、エンドポイントの由来、現在の稼働状況を分離する。現行ケースはいずれもローカル実行または実環境への照会を行っていない。",
    "See `rules/` for family-oriented YARA and Sigma starting points. Rules are hypotheses that require validation against local benign software and telemetry.":
        "ファミリー向けYARA／Sigmaの出発点は `rules/` を参照する。ルールは仮説であり、ローカルの正常ソフトウェアとテレメトリーに対する検証が必要である。",
    "Ten MalwareBazaar submissions were triaged without local sample execution. Delivery patterns are kept separate from payload/config clusters because builders and infrastructure may be reused by different operators.":
        "MalwareBazaar提出検体10件を、ローカル実行せずにトリアージした。ビルダーやインフラは異なる運用者に再利用され得るため、配布パターンとペイロード／設定クラスタは分離している。",
    "The FTP/SMTP endpoints in the current ten-case table came from external sandbox configuration output or, for the RAR wrapper, inheritance from its byte-identical inner sample. They were not recovered from the submitted scripts alone. Offline analysis recovered stage URLs in four cases, but no final .NET payload in the ten original containers because those stages must be separately acquired.":
        "現在の10ケース表にあるFTP／SMTPエンドポイントは、外部サンドボックスの設定出力、または圧縮書庫ラッパーではバイト単位で同一の内部検体からの継承に由来する。提出スクリプトだけから回収したものではない。オフライン解析で4ケースのステージURLを回収したが、それらのステージは別途取得する必要があるため、元の10コンテナから最終マネージドペイロードは回収できていない。",
    "`agenttesla_recover.py` records loader-derived stage URLs, recovers bounded encoded .NET candidates, and extracts redacted CLR configuration. `agenttesla_payload_fetch.py` provides explicit, bounded stage retrieval. New results must label endpoint provenance as `static_recovered_dotnet_payload`, `external_sandbox`, or `inherited_external_sandbox`.":
        "`agenttesla_recover.py` はローダー由来のステージURLを記録し、範囲を限定してエンコード済み.NET候補を回収し、秘匿化したCLR設定を抽出する。`agenttesla_payload_fetch.py` は明示的かつ範囲限定のステージ取得機能を提供する。新規結果では、エンドポイントの由来を `static_recovered_dotnet_payload`、`external_sandbox`、`inherited_external_sandbox` のいずれかで示す。",
    "AgentTesla is primarily an information stealer. In these cases the submitted scripts/HTA/RAR files are delivery layers; after the .NET payload is loaded, recovered FTP or SMTP settings are best understood as stolen-data exfiltration channels rather than interactive operator consoles.":
        "AgentTeslaは主に情報窃取型マルウェアである。これらのケースで提出されたスクリプト／Webアプリケーション／圧縮書庫は配布レイヤーであり、マネージドペイロードのロード後に回収したFTPまたはSMTP設定は、対話型の運用コンソールではなく窃取データの持ち出しチャネルと解釈するのが妥当である。",
    "- DownloadData, IN-/-in1 carving, character reversal, Base64 decode, in-memory .NET load":
        "- データ取得、IN-／-in1の切り出し、文字反転、Base64復号、メモリ内マネージドコードのロード",
    "- Shares SMTP infrastructure and loader pattern with a74a948a":
        "- a74a948aとSMTPインフラおよびローダーパターンを共有する",
    "- Shares SMTP infrastructure and loader pattern with a01716c2":
        "- a01716c2とSMTPインフラおよびローダーパターンを共有する",
    "- Same SMTP host as two peers but different extracted credential material":
        "- 2件の関連検体と同じSMTPホストだが、抽出した認証情報は異なる",
    "- RAR member SHA-256 equals 7f31b2c4...74d8 exactly":
        "- RAR内メンバーのSHA-256は7f31b2c4...74d8と完全一致する",
    "- Shares stage URL with 1fe1d42d but has a different final FTP endpoint":
        "- 1fe1d42dとステージURLを共有するが、最終FTPエンドポイントは異なる",
    "This directory separates family configuration, version/group metadata,":
        "このディレクトリでは、ファミリー設定とバージョン／グループのメタデータを分離し、",
    "delivery shape, and reusable detection hypotheses.":
        "配布形態および再利用可能な検知仮説も分けて管理する。",
    "54 submissions, 33 validated legacy configurations, 27 unique confirmed C2":
        "  提出検体54件、検証済み旧形式設定33件、重複を除いた確認済みC2 27件",
    "URLs, 8 group names, and versions spanning the reviewed 1.1 through 1.3":
        "  URL、グループ名8件、および確認対象の1.1から1.3までのバージョン",
    "The current extractor covers the reviewed legacy PRNG-encrypted string profile.":
        "現在の抽出器は、確認済みの旧式PRNG暗号化文字列プロファイルに対応する。",
    "AES-CTR generations remain a separate parser profile. No sample, loader, or DLL":
        "AES-CTR世代は別のパーサープロファイルとして扱う。検体、ローダー、DLLはいずれも",
    "was executed, and no endpoint was contacted.":
        "実行しておらず、エンドポイントにも接続していない。",
    "1. Decrypt API names, target paths, C2 base URL, PHP gate, dependency directory, and build identifier.":
        "1. API名、対象パス、C2ベースURL、PHPゲート、依存ファイルのディレクトリ、ビルド識別子を復号する。",
    "2. Collect host metadata and application data from browsers, messaging clients, email clients, gaming clients, wallets, and configured file paths.":
        "2. ブラウザー、メッセージング、メール、ゲームの各クライアント、ウォレット、設定済みファイルパスから、ホストのメタデータとアプリケーションデータを収集する。",
    "3. Download required native dependencies from the configured directory where needed.":
        "3. 必要に応じて、設定済みディレクトリから必須のネイティブ依存ファイルをダウンロードする。",
    "4. Submit multipart HTTP POST requests through WinINet. Reviewed strings expose `hwid`, `build`, `token`, `file_name`, `file`, and `message` fields.":
        "4. WinINet経由でマルチパートHTTP POST要求を送信する。確認した文字列には `hwid`、`build`、`token`、`file_name`、`file`、`message` の各フィールドが現れる。",
    "5. Optionally receive a loader task and remove the executable with a delayed `cmd.exe` command.":
        "5. 任意でローダータスクを受信し、遅延実行する `cmd.exe` コマンドで実行ファイルを削除する。",
    "The complete gate is `base_url + gate_path`; the dependency directory is a separate role and must not be normalized into the gate. Build IDs (`default`, `ZOV`, and `GoogleMaps` in this corpus) are grouping pivots but do not prove common operator ownership.":
        "完全なゲートは `base_url + gate_path` である。依存ファイルのディレクトリは別の役割であり、ゲートへ正規化してはならない。このコーパスのビルドID（`default`、`ZOV`、`GoogleMaps`）はグループ化のピボットだが、共通する運用者の所有を証明しない。",
    "Public research describes a version split introduced in March 2025. v2 removes the v1 dependency-DLL request model, uses WinHTTP and JSON, and supports `create`, `upload_file`, `loader`, and `done` operations. Recent variants RC4-encrypt communication. A typical configuration contains a C2 URL, build ID, configuration RC4 key, and communication RC4 key.":
        "公開調査では、2025年3月に導入されたバージョン分岐が説明されている。v2はv1の依存DLL要求モデルを廃止し、WinHTTPとJSONを使用して `create`、`upload_file`、`loader`、`done` の各操作に対応する。最近の亜種は通信をRC4で暗号化する。典型的な設定にはC2 URL、ビルドID、設定用RC4鍵、通信用RC4鍵が含まれる。",
    "The current extractor does not infer a v2 configuration from packer metadata. A complete decoded structure is required before producing a v2 C2 IOC.":
        "現在の抽出器はパッカーのメタデータからv2設定を推定しない。v2のC2 IOCを出力するには、完全な復号済み構造が必要である。",
    "The analysis pipeline is offline by default. Extracted URLs are passed to reporting and detection logic but not fetched. Reachability, banner collection, TLS/JARM, or protocol check-in would be a separate explicitly authorized task; none was performed here.":
        "解析パイプラインは既定でオフライン動作する。抽出URLは報告と検知ロジックへ渡すが、取得はしない。到達可能性、バナー収集、TLS／JARM、プロトコルのチェックインは明示的な許可を要する別タスクであり、ここでは実施していない。",
    "The complete VX-Underground StealC directory was acquired on 2026-07-16: 41 password-protected archives, 41 successful extractions, and 41 x86 native PE files whose extracted SHA-256 matched the archive name. No sample was executed and no recovered endpoint was contacted.":
        "VX-UndergroundのStealCディレクトリ全体を2026-07-16に取得した。内訳はパスワード保護書庫41件、抽出成功41件、抽出したSHA-256が書庫名と一致するx86ネイティブPE 41件である。検体は実行せず、回収したエンドポイントにも接続していない。",
    "Static configuration was fully recovered from 5 files. The remaining 36 outer layers separate into 11 Themida/WinLicense files, 1 Enigma file, 1 NSIS container, 3 identical Delphi resource carriers, and 20 native wrappers/unsupported string generations with high-entropy code or data buffers. These are not reported as “cleanly unpacked”; their C2 remains unknown from the current static layer.":
        "5ファイルから静的設定を完全に回収した。残る36件の外層は、Themida／WinLicense 11件、Enigma 1件、NSISコンテナ1件、同一のDelphiリソースキャリア3件、高エントロピーなコードまたはデータバッファを持つネイティブラッパー／未対応文字列世代20件に分かれる。これらを「完全にアンパック済み」とは報告せず、C2は現在の静的レイヤーからは不明である。",
    "The full per-file inventory is in [inventory.json](inventory.json), and every hash has a case directory under `cases/<sha256>/` with `README.md`, `config.json`, `iocs.json`, and generated `IOC-LIST.md`.":
        "ファイル単位の完全な一覧は [inventory.json](inventory.json) にあり、各ハッシュには `cases/<sha256>/` 配下のケースディレクトリがあり、`README.md`、`config.json`、`iocs.json`、生成済み `IOC-LIST.md` を格納する。",
    "The RC4 variant is a skip-key implementation: when normal RC4 XOR would produce NUL, the ciphertext byte is retained while the RC4 state still advances. This detail repairs otherwise truncated values such as `777palm.com` and `HttpSendRequestA`.":
        "RC4亜種はスキップ鍵方式である。通常のRC4 XORでNULが生じる場合、RC4状態は進めながら暗号文バイトを維持する。この仕様により、`777palm.com` や `HttpSendRequestA` のように本来切り詰められる値を修復できる。",
    "The decoded v1 code targets Chromium and Firefox logins, cookies, autofill, browsing history, and cards; it also contains paths or handlers for Telegram, Discord, Outlook, Pidgin, Steam, Tox, screenshots, a file grabber, optional payload loading, and delayed self-deletion. The transport uses WinINet and multipart HTTP POST fields including `hwid`, `build`, `token`, `file_name`, `file`, and `message`.":
        "復号したv1コードは、Chromium／Firefoxのログイン情報、Cookie、自動入力、閲覧履歴、カード情報を対象とする。また、Telegram、Discord、Outlook、Pidgin、Steam、Tox、スクリーンショット、ファイル収集、任意のペイロードロード、遅延自己削除に関するパスまたは処理を含む。通信にはWinINetとマルチパートHTTP POSTを使用し、`hwid`、`build`、`token`、`file_name`、`file`、`message` の各フィールドを送る。",
    "This is consistent with public StealC v1 research. Public reporting also distinguishes v2: it uses WinHTTP and JSON operations such as `create`, `upload_file`, `loader`, and `done`, while newer v2 builds use standard RC4 for network traffic. Those v2 properties are a family model and are not automatically assigned to an unresolved file in this corpus.":
        "これは公開されているStealC v1調査と整合する。公開報告ではv2も区別され、WinHTTPとJSONを使用して `create`、`upload_file`、`loader`、`done` 等を実行し、新しいv2ビルドはネットワーク通信に標準RC4を使用する。これらv2の特性はファミリーモデルであり、本コーパスの未解決ファイルへ自動的に割り当てない。",
    "References: [SEKOIA v1 configuration extraction](https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-2/), [Zscaler StealC v2 technical analysis](https://www.zscaler.com/fr/blogs/security-research/i-stealc-you-tracking-rapid-changes-stealc), [IBM X-Force configuration model](https://www.ibm.com/think/x-force/stealc-you-later-proofpoint-x-force-support-operation-endgame-disruptions), and [Bitsight detection material](https://github.com/bitsight-research/threat_research/tree/main/stealc).":
        "参考資料: [SEKOIAによるv1設定抽出](https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-2/)、[ZscalerによるStealC v2技術解析](https://www.zscaler.com/fr/blogs/security-research/i-stealc-you-tracking-rapid-changes-stealc)、[IBM X-Forceの設定モデル](https://www.ibm.com/think/x-force/stealc-you-later-proofpoint-x-force-support-operation-endgame-disruptions)、[Bitsightの検知資料](https://github.com/bitsight-research/threat_research/tree/main/stealc)。",
    "- Low false-positive risk: exact file hashes and full decoded PHP gate URLs. Hashes have low durability, and infrastructure may later be reallocated, so neither should be treated as permanent attribution.":
        "- 誤検知リスク低: ファイルハッシュの完全一致と、完全に復号したPHPゲートURL。ハッシュは耐久性が低く、インフラも後に再割り当てされ得るため、どちらも恒久的な帰属根拠として扱わない。",
    "- Medium false-positive risk: the included YARA rules require either at least 40 paired-buffer decoder call sites or a PE with a numeric key plus at least 100 Base64 strings. Large protected applications or embedded resource tables may overlap and should be correlated with family behavior.":
        "- 誤検知リスク中: 同梱YARAルールは、対になるバッファデコーダー呼び出しが40か所以上、または数値鍵とBase64文字列100件以上を持つPEのいずれかを要求する。大規模な保護アプリケーションや埋め込みリソース表と重なる場合があるため、ファミリー動作と相関する。",
    "- Medium false-positive risk: the Sigma rule detects `cmd.exe` with `timeout /t 5` and `del /f /q`; legitimate installers, updaters, and cleanup scripts can produce the same command.":
        "- 誤検知リスク中: Sigmaルールは `cmd.exe` による `timeout /t 5` と `del /f /q` を検知する。正規のインストーラー、更新処理、クリーンアップスクリプトも同じコマンドを生成し得る。",
    "- High false-positive risk: browser database, Telegram, Discord, Outlook, Pidgin, or Steam access alone. Backup, migration, password-manager, and endpoint-security software must be excluded with signer, path, parent process, and outbound destination context.":
        "- 誤検知リスク高: ブラウザーデータベース、Telegram、Discord、Outlook、Pidgin、Steamへの単独アクセス。署名者、パス、親プロセス、外向き通信先の文脈を使い、バックアップ、移行、パスワード管理、エンドポイント保護ソフトウェアを除外する必要がある。",
    "No liveness, banner, HTTP title, certificate hash, JARM, or Shodan banner hash is present because the recovered infrastructure was not contacted. Static configuration evidence is not a current C2 ownership claim.":
        "回収インフラに接続していないため、稼働状況、バナー、HTTPタイトル、証明書ハッシュ、JARM、Shodanバナーハッシュは記載しない。静的設定の証拠は、現在のC2所有者を主張するものではない。",
    "- 10 submissions: 9 PE files and 1 nested ZIP.":
        "- 提出検体10件：PEファイル9件、入れ子ZIP 1件。",
    "- Seven PE files met the static packing heuristic.":
        "- PEファイル7件が静的パッキング判定基準を満たした。",
    "- The nested ZIP contained 1,239 members; bounded selection found encrypted members, so it was not password-guessed or expanded.":
        "- 入れ子ZIPには1,239件のメンバーが含まれ、範囲限定の選択で暗号化メンバーを確認したため、パスワード推測や展開は行っていない。",
    "Unpacked Vidar payloads commonly stage browser credentials, autofill, wallet data, and supporting browser libraries. In this batch, wallet-oriented literals appeared in five cases and browser-oriented literals in one, but most final configuration remained behind loader/packing layers.":
        "アンパック済みVidarペイロードは通常、ブラウザー認証情報、自動入力、ウォレットデータ、補助ブラウザーライブラリをステージングする。本バッチではウォレット関連リテラルが5ケース、ブラウザー関連リテラルが1ケースに現れたが、最終設定の大半はローダー／パッキング層の内側に残った。",
    "No publishable C2 was recovered from the submitted bytes. Apparent OCSP/CA URLs with certificate-byte suffixes were removed as false positives. Vidar may also use external dead-drop content, so absence of a literal endpoint is not evidence of no C2 behavior.":
        "提出バイト列から公開可能なC2は回収できなかった。証明書バイトの接尾辞を持つ見かけ上のOCSP／CA URLは誤検知として除外した。Vidarは外部デッドドロップ内容も利用し得るため、リテラルエンドポイントがないことはC2動作がない証拠にはならない。",
    "- High FP: browser database filenames or wallet filenames alone.":
        "- 誤検知リスク高：ブラウザーデータベースまたはウォレットのファイル名だけの一致。",
    "- Medium FP: non-browser process accessing several credential stores and staging archives.":
        "- 誤検知リスク中：ブラウザー以外のプロセスによる複数の認証情報ストアへのアクセスと書庫のステージング。",
    "- Lower FP: combine unpacked Vidar artifact strings, dependency downloads, credential staging, and process-attributed outbound HTTP.":
        "- 誤検知リスク低め：アンパック済みVidarの文字列、依存ファイルのダウンロード、認証情報のステージング、プロセス帰属可能な外向きHTTPを組み合わせる。",
    "Ten recent MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.":
        "最近のMalwareBazaar提出検体10件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離している。",
    "No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.":
        "能動的なC2チェックインは行っていない。オフライン評価と受動照会の生成には `analysis-framework/common/c2_candidate_detector.py` を使用する。",
    "- **High false-positive risk:** generic access to browser databases, wallets, `osascript`, Go runtime strings, or high-entropy PE sections. Backup, migration, enterprise inventory, installers, and legitimate Go applications can match.":
        "- **誤検知リスク高：** ブラウザーデータベース、ウォレット、`osascript`、Goランタイム文字列、高エントロピーPEセクションへの一般的なアクセス。バックアップ、移行、企業資産管理、インストーラー、正規Goアプリケーションも一致し得る。",
    "- **Medium false-positive risk:** script interpreter plus network download plus execution, or an unsigned process reading multiple browser/wallet stores. Administrative automation and software deployment can overlap.":
        "- **誤検知リスク中：** スクリプトインタープリター、ネットワークダウンロード、実行の組み合わせ、または未署名プロセスによる複数のブラウザー／ウォレットストアの読み取り。管理自動化やソフトウェア配布と重なる場合がある。",
    "- **Low false-positive risk:** combine family-specific strings, reviewed config path/host, credential-store collection, and unusual parent/child or network context. Builder/version changes can still cause false negatives.":
        "- **誤検知リスク低：** ファミリー固有文字列、確認済み設定パス／ホスト、認証情報ストアの収集、異常な親子プロセスまたはネットワーク文脈を組み合わせる。ビルダー／バージョン変更による見逃しは残り得る。",
    "- Unknown packers and password-protected nested archives remain unresolved.":
        "- 不明なパッカーとパスワード保護された入れ子書庫は未解決である。",
    "- MalwareBazaar signature attribution is a lead and was retained separately from static evidence.":
        "- MalwareBazaarのシグネチャ帰属は手掛かりであり、静的証拠とは分離して保持した。",
    "The [25-sample static batch](../../collections/vx-underground-20260716/sources/vidar/README.md) includes":
        "[25検体の静的解析バッチ](../../collections/vx-underground-20260716/sources/vidar/README.md) には、",
    "recursive container recovery, bounded handling of very large PE files, and":
        "コンテナの再帰回収、非常に大きいPEファイルの範囲限定処理、",
    "validated repeated-XOR configurations where present.":
        "および存在する場合に検証した反復XOR設定が含まれる。",
}


_HEADINGS = {
    "Behavior model": "動作モデル",
    "v1 reviewed model": "v1確認済みモデル",
    "v2 family model": "v2ファミリーモデル",
    "Behavioral findings": "動作上の確認事項",
    "Bounded recovery result": "範囲限定の回収結果",
    "C2 assessment": "C2評価",
    "Campaign behavior model": "キャンペーン動作モデル",
    "Case matrix": "ケース一覧表",
    "Confidence model": "確度モデル",
    "Constraints": "制約",
    "Detection assessment": "検知評価",
    "Detection confidence and false positives": "検知確度と誤検知",
    "Detection implications": "検知への示唆",
    "Evidence provenance": "証拠の由来",
    "Family behavior and C2 model": "ファミリーの動作およびC2モデル",
    "File evidence": "ファイルの証拠",
    "Infection chain": "感染チェーン",
    "Infrastructure": "インフラ",
    "Japan-observed cluster": "日本観測クラスタ",
    "Japan-observed delivery chain": "日本観測の配布チェーン",
    "Judgment": "評価",
    "MalwareBazaar static set": "MalwareBazaar静的解析セット",
    "N520 protocol confirmed scope": "N520プロトコル確認範囲",
    "Network evidence": "ネットワークの証拠",
    "Observed behavior": "観測した動作",
    "Recovered configurations": "回収した設定",
    "Reviewed batches": "確認したバッチ",
    "Reviewed set": "確認対象セット",
    "Safe validation boundary": "安全な検証範囲",
    "Static behavior": "静的に確認した動作",
    "Static behavior and configuration": "静的に確認した動作と設定",
    "Static MalwareBazaar configuration": "MalwareBazaar検体の静的設定",
    "VX-Underground batch, 2026-07-16": "VX-Undergroundバッチ（2026-07-16）",
    "2026-07-15 unpacking reassessment": "2026-07-15 アンパック再評価",
    "Agent Tesla：OSINT詳細": "AgentTesla 解析概要",
    "Shodan ピボット": "インターネット公開情報の探索用ピボット",
    "family固有方針": "ファミリー固有方針",
    "unknown（不明）": "不明",
    "Sigma/YARA/Shodan材料": "Sigma／YARA／Shodan用材料",
    "sideload host条件案": "サイドロードホスト条件案",
    "復号shellcode条件案": "復号シェルコード条件案",
    "推奨rule分割": "推奨ルール分割",
}


_PHRASES = {
    "Program Files": "プログラムファイル",
    "Silver Fox": "シルバーフォックス",
    "SilverFox": "シルバーフォックス",
    "Void Arachne": "ボイド・アラクネ",
    "Bright Food": "ブライトフード",
    "False positives": "誤検知",
    "Bonifico": "ボニフィコ",
    "RemcosRAT": "Remcos",
    "Top Malware Strains": "年の主要マルウェア株",
    "-pro": "-プロ",
    "WScript": "Windowsスクリプトホスト",
    "WMI": "Windows管理インターフェース",
    "VBS": "VBスクリプト",
    "Launches through ": "次の識別子経由で起動する：",
    "Contained PE": "格納PE",
    "Large UTF-": "大規模UTF-",
    " JavaScript padded with plausible library comments":
        " JavaScriptをもっともらしいライブラリコメントで水増ししたもの",
    "Breaking Security": "ブレイキング・セキュリティ",
    "Balikbayan Foxes": "バリクバヤン・フォクシーズ",
    "Remcos RAT": "Remcos遠隔操作ツール",
    "2021 Top Malware Strains, AA22-216A": "2021年の主要マルウェア株（AA22-216A）",
    "New Threat Actor Spoofs Philippine Government and COVID-":
        "フィリピン政府と新型コロナ",
    " Health Data": "保健情報を装う攻撃者",
    "Arkei Variants: From Vidar to Mars Stealer": "Arkei亜種：VidarからMars情報窃取型まで",
    "DEV-0569 finds new ways to deliver Royal ransomware, various payloads":
        "DEV-0569によるRoyalランサムウェア等の新しい配布手法",
    " finds new ways to deliver Royal ransomware, various payloads":
        "によるRoyalランサムウェア等の新しい配布手法",
    "Threat Actors Deliver Malware via YouTube Video Game Cracks":
        "YouTubeのゲームクラックを悪用したマルウェア配布",
    "Vidar Stealer Unmasked: Code Signing Abuse, Go Loaders and File Inflation":
        "Vidarの実態：コード署名悪用、Goローダー、ファイル水増し",
    "Kaspersky": "カスペルスキー",
    "SANS ISC": "SANSインターネットストームセンター",
    "Arkei": "アーケイ",
    "Stealer": "情報窃取型",
    "stealer": "情報窃取型",
    "Builder": "ビルダー",
    "BATLOADER": "バットローダー",
    " Pro": " プロ",
    "unpacking reassessment": "アンパック再評価",
    "RemcosRAT is an interactive remote-administration implant. Its configured host/port values are expected to carry outbound tasking and result traffic; multiple ports in one configuration are treated as fallback candidates. Delivery URLs remain separate from final C2.":
        "RemcosRATは対話型の遠隔管理インプラントである。設定済みホスト／ポートは外向きのタスク指示と結果通信を担うと見込まれ、1件の設定にある複数ポートはフォールバック候補として扱う。配布URLは最終C2と分離する。",
    "Obfuscated VBS with WScript/WMI-oriented execution path":
        "WScript／WMIを指向する実行経路を持つ難読化VBS",
    "External sandbox observed WScript and PowerShell before Remcos configuration extraction":
        "外部サンドボックスではRemcos設定抽出前にWScriptとPowerShellを観測した",
    "NSIS word-XOR key": "NSISのワードXOR鍵",
    "recovered a": "から回収した値:",
    "System-plugin command stream": "Systemプラグインのコマンドストリーム",
    "Static x64 constant propagation identified source offset":
        "静的なx64定数伝播でソースオフセットを特定した:",
    "dword XOR key": "dword XOR鍵",
    "length": "長さ",
    "and step": "ステップ",
    "Intermediate loader SHA-256": "中間ローダーのSHA-256",
    "was recovered": "を回収した",
    "The intermediate begins with native code rather than a PE header and remains control-flow obfuscated. Final payload recovery is incomplete.":
        "中間データはPEヘッダーではなくネイティブコードで始まり、制御フロー難読化が残る。最終ペイロードの回収は未完了である。",
    "no loader execution or emulation was performed": "ローダーの実行またはエミュレーションは行っていない",
    "Native x86 Remcos with browser theft, keylogging, mutex and IP-geolocation strings":
        "ブラウザー情報窃取、キーロギング、ミューテックス、IP位置情報文字列を持つネイティブx86 Remcos",
    "MalwareBazaar tag mentions": "MalwareBazaarタグに記載された値:",
    "but no port/config was independently recovered": "ただしポート／設定は独立して回収していない",
    "do not promote the tag pivot to confirmed C2": "タグのピボットを確認済みC2へ昇格しない",
    "interactive C2 is expected for Remcos, but no defensible host/port was recovered for this case":
        "Remcosでは対話型C2を想定するが、本ケースで根拠を示せるホスト／ポートは回収していない",
    "family tags or infrastructure pivots were not promoted to confirmed C2":
        "ファミリータグやインフラ探索用ピボットを確認済みC2へ昇格していない",
    "No independently confirmed final C2 endpoint was recovered":
        "独立して確認できる最終C2エンドポイントは回収していない",
    "Confirmed host/port was not recovered, so no defensible Shodan query is emitted":
        "確認済みホスト／ポートを回収していないため、根拠を示せるShodan照会は出力しない",
    "HTA retrieves an image-named stage": "HTAが画像風名称のステージを取得する",
    "One configuration contains multiple fallback ports": "1件の設定に複数のフォールバックポートが含まれる",
    "The stage host is preserved as an observed literal and was not validated as routable":
        "ステージホストは観測リテラルとして保持するが、ルーティング可能性は検証していない",
    "Final configuration contains four fallback ports": "最終設定に4件のフォールバックポートが含まれる",
    "Reads bytes from a benign Windows binary and reconstructs a PowerShell command":
        "正常なWindowsバイナリからバイト列を読み、PowerShellコマンドを再構成する",
    "Launches through Shell.Application.ShellExecute": "Shell.Application.ShellExecute経由で起動する",
    "Remote stage is transformed and loaded in memory": "リモートステージを変換してメモリ内へロードする",
    "Also delivered inside the": "次の検体内でも配布された:",
    "ISO sample": "ディスクイメージ検体",
    "64-bit native/AOT-like executable": "64ビットのネイティブ／AOT風実行ファイル",
    "Remote stage and final C2 are distinct observables": "リモートステージと最終C2は別の観測値である",
    "ISO contains": "ディスクイメージに含まれるファイル:",
    "Contained PE SHA-256 equals": "格納PEのSHA-256は",
    "configuration is inherited from that identical payload": "設定は同一ペイロードから継承する",
    "Large UTF-16 JavaScript padded with plausible library comments":
        "もっともらしいライブラリコメントで水増しした大規模UTF-16 JavaScript",
    "Instantiates ActiveXObject, writes/launches a secondary JavaScript path, and leads to PowerShell in sandbox telemetry":
        "ActiveXObjectを生成し、二次JavaScriptパスへ書き込んで起動し、サンドボックスのテレメトリーではPowerShellへ至る",
    "<br>": "／",
    "Bitsight": "ビットサイト",
    "Sekoia": "セコイア",
    "SEKOIA": "セコイア",
    "Zscaler": "ゼットスケーラー",
    "ESET": "イーセット",
    "IBM X-Force": "IBMエックスフォース",
    "Stealc: a copycat of Vidar and Raccoon infostealers gaining in popularity - Part ":
        "StealC：Vidar／Raccoonに似た情報窃取型マルウェアの台頭（第",
    "I StealC You: Tracking the Rapid Changes To StealC": "StealCの急速な変化を追跡",
    "I StealC You：Tracking the Rapid Changes To StealC": "StealCの急速な変化を追跡",
    "Bitsight Aids Disruption Efforts on Amadey Malware and StealC Malware":
        "Amadey／StealC妨害活動へのBitsightの協力",
    "ESET takes part in global Operation Endgame to disrupt Amadey botnet and Stealc infostealer":
        "AmadeyボットネットとStealCを妨害する国際作戦へのESET参加",
    "Operation Endgame": "エンドゲーム作戦",
    "Raccoon": "ラクーン",
    "Mars": "マーズ",
    "Firefox": "ファイアフォックス",
    "Chromium": "クロミウム",
    "Telegram": "テレグラム",
    "Discord": "ディスコード",
    "Outlook": "アウトルック",
    "Pidgin": "ピジン",
    "Steam": "スチーム",
    "Tox": "トックス",
    "WinINet": "ウィンアイネット",
    "WinHTTP": "ウィンHTTP",
    "multipart": "マルチパート",
    "build ID": "ビルド識別子",
    "Build ID": "ビルド識別子",
    "RC": "アールシー",
    "XOR": "排他的論理和",
    "NUL": "ヌル",
    "Proofpoint": "プルーフポイント",
    "Team Cymru": "チーム・カムリ",
    "TeamCymru": "チーム・カムリ",
    "MaaS": "サービス型マルウェア",
    "Microsoft": "マイクロソフト",
    "IcedID": "アイスドアイディー",
    "Brute Ratel": "ブルートラーテル",
    "ClickFix": "クリックフィックス",
    "Palo Alto Networks Unit 42": "ユニット42",
    "Palo Alto Networks Unit ": "ユニット",
    "Unit 42": "ユニット42",
    "Unit ": "ユニット",
    "CISA and ACSC": "米豪当局",
    "CISA・ACSC": "米豪当局",
    "HHS Health Sector Cybersecurity Coordination Center": "米国保健当局",
    "Microsoft Security Intelligence": "Microsoft",
    "SANS Internet Storm Center": "SANS ISC",
    "Kaspersky Resource Center": "Kaspersky",
    "Agent Tesla": "AgentTesla",
    "Local AgentTesla": "ローカルAgentTesla",
    "Local RemcosRAT": "ローカルRemcosRAT",
    "Local StealC": "ローカルStealC",
    "Local ValleyRAT": "ローカルValleyRAT",
    "Local VenomRAT": "ローカルVenomRAT",
    "Local Vidar": "ローカルVidar",
    "unknown": "不明",
    "Confirmed configuration/sandbox endpoint": "確認済み設定／サンドボックスエンドポイント",
    "infrastructure pivot; not a protocol fingerprint": "インフラ探索用ピボット。プロトコル指紋ではない",
    "Distribution separation": "配布系統の分離",
    "are loader/stage locations and are not final C2 unless separately correlated":
        "はローダー／ステージの場所であり、別途相関できない限り最終C2ではない",
    "Endpoint provenance": "エンドポイントの由来",
    "inherited from a byte-identical inner payload": "バイト単位で同一の内部ペイロードから継承",
    "no independent endpoint extraction was claimed for the wrapper":
        "ラッパーから独立してエンドポイントを抽出したとは主張しない",
    "Campaign pattern": "キャンペーンパターン",
    "Campaign type": "キャンペーン種別",
    "Analysis date": "解析日",
    "Provenance": "由来",
    "user-provided Japan-observed submission": "利用者提供の日本観測提出検体",
    "Family evidence": "ファミリー判定の証拠",
    "public report labels": "公開報告のラベル",
    "Recovered family version": "回収したファミリーバージョン",
    "not recovered": "未回収",
    "Static config": "静的設定",
    "static extraction incomplete": "静的抽出が未完了",
    "none recovered": "回収なし",
    "Unknown from this static layer": "この静的レイヤーからは不明",
    "Observed in this case": "本ケースでの観測",
    "COVID-": "新型コロナ",
    "PowerShell": "パワーシェル",
    "Unicode": "ユニコード",
    "Base": "ベース",
    "Image-like remote stage": "画像風のリモートステージ",
    "fromCharCode/eval-style JavaScript loader": "fromCharCode／eval形式のJavaScriptローダー",
    "DownloadData, IN-/-in1 carving, character reversal, Base64 decode, in-memory .NET load":
        "データ取得、IN-／-in1の切り出し、文字反転、Base64復号、メモリ内マネージドコードのロード",
    "Shares SMTP infrastructure and loader pattern with": "SMTPインフラおよびローダーパターンを共有する相手：",
    "Same SMTP host as two peers but different extracted credential material":
        "2件の関連検体と同じSMTPホストだが、抽出した認証情報は異なる",
    "RAR member SHA-256 equals": "RAR内メンバーのSHA-256は",
    "RAR member": "圧縮書庫内メンバー",
    "equals": "一致する",
    "exactly": "と完全一致する",
    "Shares stage URL with": "ステージURLを共有する相手：",
    "but has a different final FTP endpoint": "ただし最終FTPエンドポイントは異なる",
    "Source": "情報源",
    "Submitted artifact": "提出アーティファクト",
    "Large one-line obfuscated JavaScript": "1行の大規模な難読化JavaScript",
    "Decoded stage is loaded in memory": "復号したステージをメモリ内へロードする",
    "Remote PNG container used as a stage": "リモートPNGコンテナをステージとして使用する",
    "Unicode junk marker removal reconstructs PowerShell":
        "Unicodeジャンクマーカーを除去してPowerShellを再構成する",
    "Unicode junk marker reconstruction": "Unicodeジャンクマーカーの再構成",
    "PowerShell/AES and in-memory .NET loading behavior":
        "PowerShell／AESとメモリ内.NETロード動作",
    "Do not equate shared infrastructure with identical operator":
        "共有インフラを同一運用者と同一視しない",
    "Illustrates why delivery and payload/config clustering must remain separate":
        "配布とペイロード／設定のクラスタリングを分離すべき理由を示す",
    "C2 is inherited from the byte-identical inner payload":
        "C2はバイト単位で同一の内部ペイロードから継承する",
    "configuration extracted by external sandbox": "外部サンドボックスが抽出した設定",
    "exfiltration configuration": "持ち出し設定",
    "Stage URLs": "ステージURL",
    "Expected payload behavior": "想定されるペイロード動作",
    "After the .NET payload is loaded": ".NETペイロードのロード後",
    "After the payload is loaded": "ペイロードのロード後",
    "is expected to collect credentials and host/application data and exfiltrate them through its configured channel":
        "認証情報とホスト／アプリケーション情報を収集し、設定済みチャネルから持ち出すと見込まれる",
    "is expected to provide interactive remote administration such as command execution, file/process control, surveillance and persistence":
        "コマンド実行、ファイル／プロセス制御、監視、永続化等の対話型遠隔管理機能を提供すると見込まれる",
    "This is family/config-derived capability unless process-attributed evidence says otherwise":
        "プロセス帰属可能な反証がない限り、これはファミリー／設定から導いた機能である",
    "These are family capabilities; the case report lists only behavior actually observed in its delivery/sandbox evidence":
        "これらはファミリー機能であり、ケース報告には配布／サンドボックス証拠で実際に観測した動作だけを記載する",
    "delivery behavior": "配布動作",
    "payload capability": "ペイロード機能",
    "endpoint provenance": "エンドポイントの由来",
    "current liveness": "現在の稼働状況",
    "No local execution and no live C2 contact were performed":
        "ローカル実行および実C2への接続は行っていない",
    "No sample was executed and no extracted infrastructure was contacted":
        "検体は実行せず、抽出したインフラにも接続していない",
    "No active C2 check-in was performed": "能動的なC2チェックインは行っていない",
    "External infrastructure was not contacted": "外部インフラには接続していない",
    "Samples were never executed and recovered layers are not committed":
        "検体は実行しておらず、回収レイヤーもコミットしていない",
    "Detection rules under": "次の場所にある検知ルール",
    "are starting points and require environment tuning": "は出発点であり、環境に応じた調整が必要である",
    "Literal C2s should be short-lived IOC matches rather than durable family signatures":
        "リテラルC2は永続的なファミリー署名ではなく、短命なIOC一致として扱うべきである",
    "High false-positive risk": "誤検知リスク高",
    "Medium false-positive risk": "誤検知リスク中",
    "Low false-positive risk": "誤検知リスク低",
    "High FP": "誤検知リスク高",
    "Medium FP": "誤検知リスク中",
    "Lower FP": "誤検知リスク低め",
    "exact SHA-256": "SHA-256完全一致",
    "Hash rules are brittle against repacking": "ハッシュルールは再パックに弱い",
    "false positives": "誤検知",
    "false negatives": "見逃し",
    "process lineage": "プロセス系譜",
    "destination context": "通信先の文脈",
    "command line": "コマンドライン",
    "file origin": "ファイルの由来",
    "network destination": "通信先",
    "confirmed C2/config endpoint": "確認済みC2／設定エンドポイント",
    "Confirmed C2/config endpoint": "確認済みC2／設定エンドポイント",
    "Configuration status": "設定状況",
    "Static pattern": "静的パターン",
    "Delivery pattern": "配布パターン",
    "Final C2 evidence": "最終C2の証拠",
    "Observed infection behavior": "観測した感染動作",
    "Expected C2 role": "想定C2役割",
    "Observed behavior": "観測した動作",
    "C2 or infrastructure role": "C2またはインフラの役割",
    "C2 or infrastructure": "C2またはインフラ",
    "Confidence / caution": "確度／注意点",
    "Confidence": "確度",
    "Artifact": "アーティファクト",
    "Pattern": "パターン",
    "Method": "方式",
    "Build": "ビルド",
    "C2 gate": "C2判定条件",
    "Dependency directory": "依存ファイルのディレクトリ",
    "Role": "役割",
    "File/object": "ファイル／オブジェクト",
    "File": "ファイル",
    "Size": "サイズ",
    "Protocol confirmation": "プロトコル確認",
    "Response banner": "応答バナー",
    "Value": "値",
    "recorded": "記録済み",
    "analysis_history": "analysis_history",
    "endpoint": "エンドポイント",
    "new MalwareBazaar samples": "MalwareBazaar新規検体",
    "VX-Underground batch": "VX-Undergroundバッチ",
    "Reviewed batches": "確認したバッチ",
    "Reviewed set": "確認対象セット",
    "behavior and C2 assessment": "動作およびC2評価",
    "behavior and C2 model": "動作およびC2モデル",
    "case": "ケース",
    "Case": "ケース",
    "analysis results": "解析結果",
    "Static endpoint candidates": "静的エンドポイント候補",
    "Malware type": "マルウェア種別",
    "No liveness check was performed": "稼働確認は実施していない",
    "not live-confirmed C2": "稼働確認済みC2ではない",
    "not final C2": "最終C2ではない",
    "final payload": "最終ペイロード",
    "final configuration": "最終設定",
    "final config": "最終設定",
    "static configuration candidates": "静的設定候補",
    "static configuration": "静的設定",
    "static evidence": "静的証拠",
    "public sandbox evidence": "公開サンドボックスの証拠",
    "process-attributed evidence": "プロセス帰属可能な証拠",
    "delivery infrastructure": "配布インフラ",
    "network evidence": "ネットワーク証拠",
    "configuration output": "設定出力",
    "recovered configurations": "回収した設定",
    "recovered configuration": "回収した設定",
    "recovered memory image": "回収済みメモリイメージ",
    "recovered layers": "回収レイヤー",
    "recovered final payload": "回収済み最終ペイロード",
    "was not executed locally": "ローカルで実行していない",
    "was not executed": "実行していない",
    "were not executed": "実行していない",
    "was not contacted": "接続していない",
    "were not contacted": "接続していない",
    "not independently validated": "独立した検証は行っていない",
    "not independently recovered": "独立して回収していない",
    "not recovered": "未回収",
    "not available": "取得不能",
    "remain unknown": "不明のままである",
    "remains unknown": "不明のままである",
    "remain unresolved": "未解決のままである",
    "remains unresolved": "未解決のままである",
    "requires validation": "検証が必要である",
    "require validation": "検証が必要である",
    "requires recursive recovery": "再帰的な回収が必要である",
    "require recursive recovery": "再帰的な回収が必要である",
    "requires format-specific recovery": "形式固有の回収が必要である",
    "require format-specific recovery": "形式固有の回収が必要である",
    "must remain separate": "分離を維持する必要がある",
    "must be separately acquired": "別途取得する必要がある",
    "must not be interpreted as proof": "証明と解釈してはならない",
    "is not evidence": "証拠ではない",
    "does not establish": "確定するものではない",
    "does not prove": "証明しない",
    "Do not invent": "推測で作成しない",
    "Do not detect only": "単独では検知しない",
    "Do not equate": "同一視しない",
    "Do not promote": "昇格しない",
}


_REGEX_REPLACEMENTS = (
    (re.compile(r"^(#\s+)(.+?)：OSINT詳細$"), r"\1\2 解析概要"),
    (re.compile(r"^(#\s+.+?)\s+case\s+(.+)$", re.IGNORECASE), r"\1 ケース \2"),
    (re.compile(r"^(#\s+)(.+?)\s+behavior and C2 (?:assessment|model)$", re.IGNORECASE), r"\1\2 動作およびC2評価"),
    (re.compile(r"^(#\s+)(.+?)\s+analysis results$", re.IGNORECASE), r"\1\2 解析結果"),
    (re.compile(r"^(#\s+)(.+?)\s+analysis$", re.IGNORECASE), r"\1\2 解析"),
)


_WORD_TRANSLATIONS = {
    "valleyrat": "バレーラット", "venomrat": "Venom", "rat": "遠隔操作型",
    "false-positive": "誤検知", "confidence": "確度", "fortinet": "フォーティネット",
    "alone": "単独", "bitsadmin": "バックグラウンド転送管理ツール", "quasar": "クエーサー",
    "scrubcrypt": "スクラブクリプト", "winos": "ウィノス", "plus": "加えて",
    "check-in": "チェックイン", "check": "確認", "msi": "Windowsインストーラー",
    "hvnc": "非表示VNC", "grabber": "収集機能", "trojan": "トロイの木馬",
    "attributed": "帰属済み", "cbc": "CBC方式", "server-first": "サーバー先行",
    "linked": "関連", "ghidra": "ギドラ", "endpoint": "エンドポイント",
    "ancestry": "系譜", "urls": "URL", "related": "関連", "memory": "メモリ",
    "asyncrat": "アシンクラット", "dll-hijack": "DLLハイジャック",
    "each": "各", "associated": "関連付け済み", "sni": "SNI",
    "common": "共通", "session": "セッション", "client": "クライアント",
    "station": "ステーション", "upload": "アップロード", "server": "サーバー",
    "unexpected": "想定外", "data": "データ", "multiple": "複数",
    "deep": "詳細", "dive": "調査", "targeting": "標的化", "speakers": "話者",
    "all": "すべて", "separates": "分離する", "system": "システム",
    "create": "作成", "actions": "操作", "stages": "ステージ", "pair": "組",
    "any": "いずれか", "side-loading": "サイドロード", "kernel": "カーネル",
    "imported": "インポート済み", "normal": "通常", "sections": "セクション",
    "confirms": "確認する", "overlapping": "重複する", "instructions": "命令",
    "predicates": "述語", "thunks": "サンク", "manipulation": "操作",
    "blocker": "阻害要因", "marked": "指定済み", "fully": "完全に",
    "unpacked": "アンパック済み", "emulated": "エミュレーション済み",
    "primary": "主要", "temporary": "一時", "paths": "パス", "live": "稼働中",
    "so": "そのため", "legitimate": "正規", "below": "配下", "runonce": "RunOnce",
    "fields": "フィールド", "transforms": "変換", "zlib": "zlib",
    "independently": "独立して", "chunks": "チャンク", "runtimebroker": "RuntimeBroker",
    "control": "制御", "analyzed": "解析済み", "using": "使用して",
    "external": "外部", "supports": "対応する", "unresolved": "未解決",
    "unavailable": "取得不能", "inferred": "推定", "derived": "派生",
    "roles": "役割", "statically": "静的に", "registration": "登録",
    "names": "名前", "desktop": "デスクトップ", "empty": "空", "received": "受信済み",
    "guessed": "推測済み", "operator": "運用者", "brute": "総当たり",
    "force": "強制", "arbitrary": "任意", "do": "実施する", "proof": "証明",
    "relationships": "関係", "ports": "ポート", "here": "ここ",
    "combined": "組み合わせ済み", "highest": "最高", "exclusion": "除外",
    "execute": "実行する", "relationship": "関係", "decoding": "復号",
    "recovers": "回収する", "large": "大規模", "obfuscated": "難読化済み",
    "exposed": "露出", "complete": "完全", "combination": "組み合わせ",
    "module": "モジュール", "traffic": "通信", "initial": "初期",
    "component": "コンポーネント", "layout": "レイアウト", "call": "呼び出し",
    "sibling": "同階層", "raw": "生", "banner": "バナー", "retrieval": "取得",
    "useful": "有用", "scheduled": "スケジュール済み", "container": "コンテナ",
    "creation": "作成", "handling": "処理", "labels": "ラベル", "valid": "有効",
    "unusual": "異常", "strings": "文字列", "locally": "ローカルで",
    "subject": "対象", "exhibits": "示す", "context": "文脈", "japanese": "日本語",
    "label": "ラベル", "loading": "ロード", "returned": "返却済み",
    "submissions": "提出検体", "hijacking": "ハイジャック", "download": "ダウンロード",
    "four": "四件", "namespaces": "名前空間", "sql": "SQL", "same": "同じ",
    "they": "これら", "trace": "トレース", "itself": "それ自体", "native": "ネイティブ",
    "largest": "最大", "namespace": "名前空間", "literals": "リテラル",
    "forks": "フォーク", "research": "調査", "commercial": "商用",
    "protectors": "保護製品", "explicit": "明示的", "did": "実施した",
    "locale": "ロケール", "material": "材料", "reverse": "反転",
    "a": "", "an": "", "the": "", "and": "および", "or": "または",
    "is": "", "are": "", "was": "", "were": "", "be": "", "been": "",
    "has": "を含む", "have": "を含む", "had": "を含んだ", "with": "を伴う",
    "without": "を伴わない", "from": "から", "to": "へ", "for": "向け",
    "in": "内", "on": "上", "of": "の", "by": "により", "as": "として",
    "this": "この", "that": "その", "these": "これら", "those": "それら",
    "its": "その", "it": "それ", "not": "ない", "no": "なし", "only": "のみ",
    "may": "場合がある", "can": "可能", "could": "可能", "must": "必要",
    "should": "べき", "would": "想定", "will": "予定", "also": "また",
    "but": "ただし", "when": "場合", "where": "場所", "while": "一方",
    "before": "前", "after": "後", "because": "ため", "if": "場合",
    "than": "より", "into": "へ", "through": "経由", "under": "配下",
    "process": "プロセス", "host": "ホスト", "recovered": "回収済み",
    "recover": "回収する", "hash": "ハッシュ", "hashes": "ハッシュ",
    "configuration": "設定", "configurations": "設定", "config": "設定",
    "final": "最終", "port": "ポート", "chain": "チェーン",
    "protocol": "プロトコル", "task": "タスク", "evidence": "証拠",
    "behavior": "動作", "bytes": "バイト", "byte": "バイト",
    "execution": "実行", "campaign": "キャンペーン", "domain": "ドメイン",
    "high": "高", "medium": "中", "low": "低", "sandbox": "サンドボックス",
    "bounded": "範囲限定", "security": "セキュリティ", "suspected": "疑い",
    "crime": "犯罪", "group": "グループ", "global": "世界規模",
    "persistence": "永続化", "correlate": "相関する", "correlated": "相関済み",
    "confirmed": "確認済み", "bundle": "バンドル", "defender": "防御側",
    "command": "コマンド", "detection": "検知", "resource": "リソース",
    "resources": "リソース", "path": "パス", "public": "公開",
    "signed": "署名済み", "expected": "想定", "infrastructure": "インフラ",
    "payload": "ペイロード", "certificate": "証明書", "plugin": "プラグイン",
    "plugins": "プラグイン", "observed": "観測済み", "analysis": "解析",
    "installer": "インストーラー", "installers": "インストーラー", "size": "サイズ",
    "implant": "インプラント", "custom": "独自", "file": "ファイル",
    "files": "ファイル", "stage": "ステージ", "role": "役割",
    "network": "ネットワーク", "risk": "リスク", "static": "静的",
    "rule": "ルール", "rules": "ルール", "embedded": "埋め込み",
    "terminal": "終端", "loader": "ローダー", "loaders": "ローダー",
    "use": "使用", "uses": "使用する", "used": "使用済み", "entropy": "エントロピー",
    "artifact": "アーティファクト", "response": "応答", "encrypted": "暗号化済み",
    "malware": "マルウェア", "correlation": "相関", "protected": "保護済み",
    "telemetry": "テレメトリー", "managed": "マネージド", "family": "ファミリー",
    "delivery": "配布", "distribution": "配布", "unverified": "未検証",
    "sample": "検体", "samples": "検体", "child": "子", "key": "鍵",
    "result": "結果", "results": "結果", "reports": "報告", "staged": "ステージ済み",
    "remote": "リモート", "tasking": "タスク指示", "matching": "一致する",
    "contains": "を含む", "contain": "を含む", "section": "セクション",
    "type": "種別", "event": "イベント", "exact": "完全一致", "service": "サービス",
    "filename": "ファイル名", "filenames": "ファイル名", "lure": "誘導名",
    "excluded": "除外済み", "hooks": "フック", "single": "単独",
    "enumeration": "列挙", "provenance": "由来", "token": "トークン",
    "communication": "通信", "second": "二番目", "name": "名前",
    "handshake": "ハンドシェイク", "identifier": "識別子", "appears": "現れる",
    "across": "全体", "threat": "脅威", "landscape": "情勢", "run": "実行",
    "load": "ロード", "marker": "マーカー", "consistent": "整合する",
    "extraction": "抽出", "entry": "エントリ", "malicious": "悪性",
    "resolvers": "リゾルバー", "addresses": "アドレス", "address": "アドレス",
    "write": "書き込み", "servers": "サーバー", "packed": "パック済み",
    "potential": "可能性", "shared": "共有", "interactive": "対話型",
    "value": "値", "values": "値", "validation": "検証", "content": "内容",
    "registry": "レジストリ", "one": "一件", "three": "三件",
    "fallback": "フォールバック", "modification": "変更", "resolution": "解決",
    "new": "新規", "string": "文字列", "structure": "構造", "changes": "変更",
    "routine": "ルーチン", "level": "レベル", "injection": "インジェクション",
    "both": "両方", "recovery": "回収", "image": "イメージ", "opaque": "不透明",
    "internal": "内部", "header": "ヘッダー", "structural": "構造的",
    "overlay": "オーバーレイ", "activity": "活動", "import": "インポート",
    "export": "エクスポート", "support": "対応", "outer": "外層",
    "executable": "実行ファイル", "literal": "リテラル", "adjustment": "調整",
    "outbound": "外向き", "findings": "確認事項", "stated": "記載済み",
    "capability": "機能", "chinese": "中国語圏", "going": "進出",
    "brief": "概説", "defanged": "無力化", "cybercrime": "サイバー犯罪",
    "deploys": "配布する", "arsenal": "多数", "taken": "停止", "down": "済み",
    "end": "終了", "game": "作戦", "apis": "API", "api": "API",
    "locations": "場所", "location": "場所", "remain": "維持される",
    "remained": "維持された", "remaining": "残り", "ordered": "順序通り",
    "remains": "維持される", "batch": "バッチ", "document": "文書",
    "consolidates": "統合する", "assessment": "評価", "distinguishes": "区別する",
    "what": "内容", "directly": "直接", "broader": "広範な",
    "inference": "推論", "some": "一部", "cases": "ケース",
    "represent": "表す", "different": "異なる", "operators": "運用者",
    "leaked": "流出した", "builders": "ビルダー", "ioc": "侵害指標",
    "protection": "保護", "truncated": "切り詰めた", "commands": "コマンド",
    "provide": "提供する", "indicate": "示す", "capabilities": "機能",
    "sent": "送信した", "during": "期間中", "collection": "収集",
    "bound": "上限", "executables": "実行ファイル", "pcaps": "通信記録",
    "credentials": "認証情報", "projects": "プロジェクト", "stored": "保存済み",
    "launch": "起動する", "retrieve": "取得する", "object": "オブジェクト",
    "storage": "ストレージ", "privilege": "権限", "weaken": "弱体化する",
    "dns": "DNS", "pivot": "探索軸", "application": "アプリケーション",
    "applications": "アプリケーション", "networking": "ネットワーク通信",
    "surface": "機能面", "review": "確認", "retrieves": "取得する",
    "decodes": "復号する", "sysceo": "SysCEO", "winget-style": "winget形式",
    "compression": "圧縮", "transformation": "変換", "tencent-related": "Tencent関連",
    "decoy": "おとり", "bright": "Bright", "food": "Food", "co-location": "同一配置",
    "reuse": "再利用", "zero-raw": "生データなし", "random-name": "ランダム名",
    "rx": "読み取り実行", "loads": "ロードする", "stager": "ステージャー",
    "large-overlay": "大規模オーバーレイ", "localappdata": "ローカルアプリデータ",
    "launches": "起動する", "candidate": "候補", "launched": "起動した",
    "backdoor": "バックドア", "identified": "特定した", "authenticated": "認証済み",
    "frames": "フレーム", "acquisition": "取得", "modules": "モジュール",
    "mismatch": "不一致", "derivation": "導出", "making": "確立する",
    "connections": "接続", "reduces": "低減する", "inno-style": "Inno形式",
    "pattern": "パターン", "created": "作成された", "quarantined": "隔離された",
    "creates": "作成する", "logon": "ログオン", "bonus-notice": "賞与通知",
    "malspam": "迷惑メール", "validly": "有効に", "treating": "扱うこと",
    "serious": "重大な", "imphash": "インポートハッシュ",
    "authentihash": "Authentihash", "describe": "表す", "nonstandard": "標準外の",
    "user-writable": "ユーザー書き込み可能な", "directory": "ディレクトリ",
    "mail": "メール", "cef": "Chromium埋め込みフレームワーク",
    "commonly": "一般に", "metadata": "メタデータ", "report": "報告",
    "downloading": "ダウンロードする", "executing": "実行する",
    "authorized": "許可された", "performed": "実施された", "reviewed": "確認した",
    "july": "7月", "tax-notice-themed": "税務通知を装う", "include": "含む",
    "launcher": "ランチャー", "disk-image": "ディスクイメージ", "variant": "亜種",
    "copied": "コピーした", "richest": "最も詳細な", "which": "その動作は",
    "paired": "組み合わせた", "script": "スクリプト", "identify": "特定する",
    "converge": "一致する", "promoted": "昇格した", "endpoints": "エンドポイント",
    "unrelated": "無関係な", "reconnect": "再接続", "install": "インストール",
    "password": "パスワード", "mutex": "ミューテックス", "setting": "設定",
    "settings": "設定", "browser-login": "ブラウザーログイン", "keylogging": "キー入力記録",
    "ui": "ユーザーインターフェース", "oriented": "指向", "occur": "存在する",
    "call-site": "呼び出し箇所", "primitives": "基本処理", "layer": "レイヤー",
    "does": "実施する", "reveal": "明らかにする", "followed": "後続する",
    "connection": "接続", "unlikely": "可能性が低い", "signals": "兆候",
    "weak": "弱い", "venom-like": "Venom類似", "builds": "ビルド",
    "match": "一致する", "code-signing": "コード署名", "administrative": "管理用の",
    "software": "ソフトウェア", "behaviors": "動作", "non-executing": "非実行型の",
    "reversal": "反転", "keys": "鍵", "ivs": "初期化ベクトル", "carving": "切り出し",
    "either": "いずれの", "narrows": "絞り込む", "next": "次の", "step": "手順",
    "specific": "固有の", "algorithm": "アルゴリズム", "reconstruction": "再構成",
    "blind": "無差別な", "dataset": "データセット", "user-provided": "利用者提供の",
    "japan-observed": "日本で観測された", "selected": "選定した", "first": "最初の",
    "fourth": "4番目", "called": "呼称する", "supplied": "提供された",
    "requester": "依頼者", "geolocation": "位置情報", "analytic": "分析ロジック",
    "combines": "組み合わせる", "extension": "拡張子", "masquerading": "偽装",
    "very": "非常に", "feature": "特徴", "prone": "生じやすい", "submitted": "提出された",
    "produced": "生成した", "reassembled": "再構成した", "environment": "環境",
    "char-minus": "文字値減算", "transform": "変換", "style": "形式",
    "socket": "ソケット", "keyboard": "キーボード", "hook": "フック",
    "functionality": "機能", "feature-rich": "多機能な", "direct": "直接の",
    "classified": "分類された", "contact": "接続する", "hosts": "ホスト",
    "settings-field": "設定フィールド", "combinations": "組み合わせ",
    "plausible": "可能性のある", "analytics": "分析ロジック", "hunt": "探索する",
    "rare": "希少な", "domains": "ドメイン", "time-sensitive": "時間依存の",
    "repurposed": "転用された", "imports": "インポートする", "main": "主要な",
    "target": "対象", "revocation": "失効確認", "signatures": "署名",
    "there": "そこには", "current": "現在の", "treat": "扱う",
    "named": "名前付きの", "surrounding": "周辺の", "generic": "一般的な",
    "scanning": "走査", "rejected": "除外された", "grouped": "グループ化した",
    "more": "超", "echo": "echo", "redirection": "リダイレクト",
    "decoded": "復号した", "completed": "完成した", "stream": "ストリーム",
    "once": "一度", "previous": "以前の", "entries": "エントリ",
    "fragment": "断片", "noise": "ノイズ", "gating": "判定条件",
    "now": "現在は", "suppresses": "抑制する", "fragments": "断片",
    "two": "二件", "retained": "保持した", "neither": "どちらも",
    "additional": "追加の", "then": "その後", "reproduced": "再現した",
    "recipe": "手順", "zip-delivered": "ZIP配布の", "tax-notice": "税務通知",
    "copies": "コピーする", "user": "ユーザー", "roaming": "ローミング",
    "profile": "プロファイル", "referencing": "参照する", "7z-delivered": "7z配布の",
    "exposes": "展開する", "scheduler": "スケジューラー", "run-key": "Runキー",
    "reported": "報告された", "japan": "日本", "observation": "観測",
    "requester-supplied": "依頼者提供の", "delay": "遅延", "uac-policy": "ユーザーアカウント制御ポリシー",
    "tools": "ツール", "separate": "別の", "sni": "サーバー名表示",
    "qt": "キュートフレームワーク", "inno": "イノセットアップ",
    "modified": "変更済み", "tencent": "テンセント", "runtimebroker": "ランタイムブローカー",
    "runonce": "一度限り実行キー", "appdata": "アプリデータ", "crypto": "暗号",
    "zip": "圧縮書庫", "exe": "実行ファイル", "ping": "疎通確認",
    "bits": "バックグラウンド転送", "vbs": "VBスクリプト", "vb": "ビジュアルベーシック",
    "url": "ウェブアドレス",
}

_WORD_TRANSLATIONS_CASEFOLD = {
    source.casefold(): target for source, target in _WORD_TRANSLATIONS.items()
}
_WORD_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:"
    + "|".join(
        re.escape(source)
        for source in sorted(_WORD_TRANSLATIONS, key=len, reverse=True)
    )
    + r")(?![A-Za-z0-9])",
    re.IGNORECASE,
)


def _line_ending(line: str) -> tuple[str, str]:
    match = _LINE_ENDING.search(line)
    if match is None:
        return line, ""
    return line[: match.start()], match.group(1)


def _protected_spans(line: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for pattern in (
        _INLINE_CODE,
        _BARE_URL,
        _MARKDOWN_DESTINATION,
        _LONG_HASH,
        _TECHNICAL_ENUM,
        _TECHNICAL_FILENAME,
        _DOTTED_IDENTIFIER,
        _REPOSITORY_IDENTIFIER,
        _LEGAL_SIGNER,
        _NUMBER,
    ):
        spans.extend(match.span() for match in pattern.finditer(line))
    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start < merged[-1][1]:
            old_start, old_end = merged[-1]
            merged[-1] = old_start, max(old_end, end)
        else:
            merged.append((start, end))
    return merged


def _protect(line: str) -> tuple[str, tuple[str, ...]]:
    values: list[str] = []
    pieces: list[str] = []
    cursor = 0
    for start, end in _protected_spans(line):
        pieces.append(line[cursor:start])
        pieces.append(_PLACEHOLDER.format(len(values)))
        values.append(line[start:end])
        cursor = end
    pieces.append(line[cursor:])
    return "".join(pieces), tuple(values)


def _restore(line: str, values: tuple[str, ...]) -> str:
    for index, value in enumerate(values):
        line = line.replace(_PLACEHOLDER.format(index), value)
    return line


def _translate_heading(line: str) -> str:
    match = re.fullmatch(r"(\s*#{1,6}\s+)(.*?)(\s*)", line)
    if match is None:
        return line
    prefix, title, trailing = match.groups()
    translated = _HEADINGS.get(title)
    return line if translated is None else prefix + translated + trailing


def _replace_phrases(line: str) -> str:
    for source, target in sorted(_PHRASES.items(), key=lambda item: -len(item[0])):
        line = line.replace(source, target)
    return line


def _replace_words(line: str) -> str:
    """保護区間外に残った説明語だけを、単語境界付きで補完翻訳する。"""
    line = _WORD_PATTERN.sub(
        lambda match: _WORD_TRANSLATIONS_CASEFOLD[match.group(0).casefold()], line
    )
    return re.sub(r" {2,}", " ", line)


def translate_line(line: str) -> str:
    """既存ローカライザー通過後の一行を、安全に日本語化して返す。"""
    body, ending = _line_ending(line)
    leading = body[: len(body) - len(body.lstrip())]
    trailing = body[len(body.rstrip()):]
    core = body.strip()
    if not core:
        return line

    exact = _EXACT.get(core)
    if exact is not None:
        core = exact

    protected, values = _protect(core)
    translated = _translate_heading(protected)
    for pattern, replacement in _REGEX_REPLACEMENTS:
        translated = pattern.sub(replacement, translated)
    translated = _replace_phrases(translated)
    translated = _replace_words(translated)
    translated = translated.replace(": ", "：")
    restored = _restore(translated, values)
    restored = re.sub(r"(?<![A-Za-z0-9])TA(?=\d)", "ティーエー", restored)
    restored = re.sub(r"(?<![A-Za-z0-9])Storm-(?=\d)", "ストーム-", restored)
    restored = re.sub(r"(?<![A-Za-z0-9])DEV-(?=\d)", "ディーイーブイ-", restored)
    restored = re.sub(r"(?<![A-Za-z0-9])Winos(?=\d)", "ウィノス", restored)
    restored = re.sub(
        r"(?<![A-Za-z0-9])(VX-Underground|AI-security-analysis)(?=[ぁ-んァ-ヶ一-龯々〆ヵヶー])",
        r"\1 ",
        restored,
    )
    restored = re.sub(r"（第(\d+)」", r"（第\1部）」", restored)
    return leading + restored + trailing + ending


__all__ = ["translate_line"]
