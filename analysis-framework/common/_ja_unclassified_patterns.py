"""未分類 case と対応 collection に固有の Markdown 1 行翻訳。

公開成果物や共通 localizer から独立させ、機械可読な値、hash、URL、
Markdown link destination、enum を変更せず、人が読む説明だけを日本語化する。
"""

from __future__ import annotations

import re


_EXACT = {
    "## ハッシュ OSINT 情報の補強": "## ハッシュを用いた公開情報の補強",
    "- None recovered from static evidence.": "- 静的根拠から復元できた項目はありません。",
    "- No defensible family-specific evidence; retained as unknown.":
        "- family 固有と判断できる十分な根拠がないため、`unknown` のまま保持します。",
    "- No family-specific public label was recovered.":
        "- family 固有の公開 label は得られませんでした。",
    "- 低確度／高い誤検知リスク: ファイル名、一般的な Electron／NSIS／PyInstaller タグ、imphash、または URL 単独。":
        "- 低確度／高い誤検知リスク: ファイル名、一般的な `Electron`／`NSIS`／`PyInstaller` tag、`imphash`、または `URL` 単独。",
    "- Sigma should combine process ancestry, extraction path, and script/runtime behavior; no process behavior was asserted from static data alone.":
        "- Sigma ではプロセスの親子関係、抽出パス、スクリプト／ランタイムの挙動を組み合わせます。静的データだけからプロセス挙動を断定していません。",
    "- Static-only attribution; low-confidence labels remain provisional.":
        "- 帰属判断は静的解析だけに基づき、低信頼度の label は暫定扱いです。",
    "- General string URLs are candidates, not confirmed C2 endpoints.":
        "- 一般 string から得た URL は候補であり、確認済み C2 endpoint ではありません。",
    "- Oversized Electron runtime binaries are inventoried but not recursively parsed.":
        "- 大容量の Electron ランタイム binary は棚卸しだけを行い、再帰 parse していません。",
    "# Hash OSINT enrichment": "# ハッシュを用いた公開情報の補強",
    "Low-confidence and unidentified cases were correlated using hash-only public intelligence. Family attribution is promoted to medium only when at least two independent providers agree. Aggregator transports do not count as an extra vote.":
        "低信頼度または未識別の case を、hash だけを使う公開情報で関連付けました。family 帰属を中信頼度へ昇格するには、独立した provider が 2 つ以上一致する必要があります。aggregator の転送経路は追加の 1 票として数えません。",
    "## Outcome": "## 結果",
    "- Targeted cases: 93": "- 対象 case 数: 93",
    "- Family lead recovered: 69": "- family 候補を得た case 数: 69",
    "- Supported at medium/high confidence: 6": "- 中／高信頼度の裏付けがある case 数: 6",
    "## Family distribution": "## Family 別分布",
    "| Family | Confidence | Count |": "| Family | 信頼度 | 件数 |",
    "## Source coverage": "## 情報源 coverage",
    "| Source | Status | Count |": "| 情報源 | 状態 | 件数 |",
    "| SHA-256 | Family | Confidence | Providers |":
        "| SHA-256 | Family | 信頼度 | Provider |",
    "## Interpretation": "## 解釈",
    "A missing public label does not make a file benign. CIRCL known-file context is recorded separately and never supplies a malware-family vote. OTX pulse names remain community evidence. A keyed service is marked unavailable when its required credential is absent; no file is uploaded as a fallback.":
        "公開 label がないことは file が benign である根拠になりません。CIRCL の既知 file 文脈は別に記録し、malware family の票には使いません。OTX pulse 名は community 根拠として保持します。key が必要な service は credential がなければ利用不能とし、fallback として file を upload しません。",
    "# MalwareBazaar unknown/stealer static classification":
        "# MalwareBazaar の `unknown`／stealer 静的分類",
    "This batch contains the newest 100 MalwareBazaar entries whose family signature was empty and whose tags included `unknown`, `stealer`, or `infostealer`. Samples were parsed statically; no sample or recovered payload was executed, and no extracted infrastructure was contacted.":
        "この batch は、family signature が空で、tag に `unknown`、`stealer`、`infostealer` のいずれかを含む MalwareBazaar の最新 100 entry を対象とします。検体は静的に parse し、検体や復元 payload を実行せず、抽出したインフラへも接続していません。",
    "## Collection": "## 収集情報",
    "- First-seen range: `2026-07-16 02:23:46` to `2026-05-24 10:52:59`":
        "- 初回観測範囲: `2026-07-16 02:23:46` から `2026-05-24 10:52:59`",
    "- Analysis errors: 0": "- 解析 error: 0",
    "- Identified (including provisional low confidence): 70":
        "- 識別済み（暫定の低信頼度を含む）: 70",
    "- Supported at medium/high confidence: 7":
        "- 中／高信頼度の裏付けあり: 7",
    "- Provisional external-only/low-confidence leads: 63":
        "- 外部情報だけに基づく暫定／低信頼度候補: 63",
    "- Remaining unknown: 30": "- 未識別のまま: 30",
    "## Attribution distribution": "## 帰属の分布",
    "## Supported family attributions": "## 裏付けのある family 帰属",
    "| SHA-256 | Family | Confidence | Internal support |":
        "| SHA-256 | Family | 信頼度 | 内部根拠 |",
    "## Detection rules": "## 検知 rule",
    "- [IRAHook Fabric mod structure](rules/yara/irahook_fabric_mod_2026.yar): medium confidence, low expected false-positive risk after the full package-path conjunction.":
        "- [IRAHook Fabric mod 構造](rules/yara/irahook_fabric_mod_2026.yar): 中信頼度です。package path の全条件を組み合わせた場合、想定誤検知リスクは低くなります。",
    "- [Electron credential-loader ASAR structure](rules/yara/electron_credential_loader_asar_2026.yar): medium confidence, medium expected false-positive risk; apply to a recovered ASAR or loader script.":
        "- [Electron credential loader の ASAR 構造](rules/yara/electron_credential_loader_asar_2026.yar): 中信頼度で、想定誤検知リスクも中程度です。復元済み ASAR または loader script に適用します。",
    "- No Sigma rule is asserted from this static-only batch because no process or event telemetry was collected.":
        "- process または event telemetry を収集していないため、この静的解析専用 batch から Sigma rule は提示しません。",
    "## Static network candidates": "## 静的 network 候補",
    "These values were recovered from static strings or configuration-like data. They were not contacted and are not confirmed C2 endpoints.":
        "これらの値は静的 string または config に似た data から復元しました。接続は行っておらず、確認済み C2 endpoint ではありません。",
    "## Case index": "## Case 索引",
    "| First seen | SHA-256 | Family | Confidence |":
        "| 初回観測 | SHA-256 | Family | 信頼度 |",
    "Family names based only on a source tag or external public rule remain provisional. A medium/high result requires internal detector/YARA/structure evidence. `unknown` or `conflicting` cases are intentionally not force-labeled. Network values are static candidates, not confirmed C2 infrastructure.":
        "source tag または外部公開 rule だけに基づく family 名は暫定扱いです。中／高信頼度には内部 detector、YARA、構造のいずれかの根拠が必要です。`unknown` または `conflicting` の case へ意図的に label を強制しません。network 値は静的候補であり、確認済み C2 インフラではありません。",
    "- Details: [OSINT.md](OSINT.md)": "- 詳細: [OSINT.md](OSINT.md)",
    "# MX-Go provisional cluster": "# MX-Go　解析概要",
    "`MX-Go` is an unclassified, Japan-targeted, remotely controlled bulk-email spam bot cluster. It is not registered as a confirmed malware family because only one payload is currently available.":
        "`MX-Go` は、日本を標的とする遠隔制御型の大量メール送信 bot の未分類クラスターです。現在利用できる payload が 1 つだけのため、確認済み malware family としては登録していません。",
    "- Payload SHA-256: `e25053585ac5e4f411f954fe7bedc8cb62672a3f9ae96b6022a7b7116700228e`":
        "- Payload SHA-256: `e25053585ac5e4f411f954fe7bedc8cb62672a3f9ae96b6022a7b7116700228e`",
    "- Embedded control server: `43.165.179.173:5000` (TCP open and four matching API routes live-confirmed 2026-07-15; no check-in)":
        "- 埋め込み control server: `43.165.179.173:5000`（2026-07-15 に TCP open と一致する 4 つの API route の稼働を確認。check-in は未実施）",
    "- Observed content/config host: `www.iainglespa.com` (TLS alive; known paths currently appear gated/disabled)":
        "- 観測した content/config host: `www.iainglespa.com`（TLS の稼働を確認。既知 path は現在 gate または無効化されている可能性あり）",
    "- Local protocol lab: `emulators/unclassified/mx_go/`":
        "- ローカル protocol lab: `emulators/unclassified/mx_go/`",
    "The sample, Triage JSONL, and FLOSS raw output are intentionally excluded. Only normalized evidence and detection material are stored.":
        "検体、Triage JSONL、FLOSS の raw 出力は意図的に除外し、正規化した根拠と検知資料だけを保存します。",
    "# 未分類：OSINT詳細": "# 未分類：公開情報の詳細",
    "# Unclassified malware clusters": "# 未分類 malware クラスター",
    "Provisional clusters remain here until multiple samples and stable code/config traits justify family registration.":
        "複数の検体と安定した code/config 特徴により family 登録を正当化できるまで、暫定クラスターをここに保持します。",
    "- [MX-Go](groups/mx-go/README.md): Japan-targeted remotely controlled bulk-email spam bot.":
        "- [MX-Go](groups/mx-go/README.md): 日本を標的とする遠隔制御型の大量メール送信 bot。",
    "- [MalwareBazaar unknown/stealer newest-100 (2026-07-17)](../../collections/malwarebazaar-unknown-20260717/sources/unclassified/README.md): calibrated static family attribution, per-case IOC lists, and reusable detection material.":
        "- [MalwareBazaar `unknown`／stealer 最新 100 件（2026-07-17）](../../collections/malwarebazaar-unknown-20260717/sources/unclassified/README.md): 調整済みの静的 family 帰属、case 別 IOC list、再利用可能な検知資料。",
    "## unknown（不明）": "## `unknown`（不明）",
    "# 260713-kdg5eafz7v / MX-Go cluster":
        "# MX-Go　解析結果",
    "- 分類: unclassified / MX-Go cluster":
        "- 分類: `unclassified` / MX-Go クラスター",
    "- 種別: remotely controlled bulk-email spam bot":
        "- 種別: `remotely controlled bulk-email spam bot`（遠隔制御型の大量メール送信 bot）",
    "- RAT判定: 汎用RATを支持する証拠なし":
        "- RAT 判定: 汎用 RAT を支持する根拠なし",
    "`mx-go.exe`は署名なしのnative x64 PE（GUI subsystem）で、Go build infoは `go1.26.1`、module pathは `mx-go`。PE timestampは0。Go関数名と型情報が残っているため、機能を高い確度で復元できた。":
        "`mx-go.exe` は署名なしの native x64 PE（GUI subsystem）です。Go build 情報は `go1.26.1`、module path は `mx-go`、PE timestamp は 0 です。Go の関数名と型情報が残っているため、機能を高い確度で復元できました。",
    "- `mx-go/internal/mail`: MIME/日本語携帯向け本文、ISO-2022-JP、送信者生成、SMTP/MX直送、DKIM署名":
        "- `mx-go/internal/mail`: MIME／日本語携帯向け本文、ISO-2022-JP、送信者生成、SMTP/MX 直接送信、DKIM 署名。",
    "- `mx-go/internal/dnsmx`: 宛先domainのMX解決とSQLite/memory cache":
        "- `mx-go/internal/dnsmx`: 宛先メール交換先の解決と SQLite／メモリキャッシュ。",
    "- `mx-go/internal/remote`: 受信者、HTML本文、送信domain、DKIM関連設定の取得":
        "- `mx-go/internal/remote`: 受信者、HTML 本文、送信 domain、DKIM 関連設定の取得。",
    "- `mx-go/internal/control`: heartbeat、command polling、activate/shutdown/restart等":
        "- `mx-go/internal/control`: heartbeat、command polling、activate／shutdown／restart など。",
    "- `mx-go/internal/dnshealth`: DKIM公開鍵、SPF、MX健全性確認":
        "- `mx-go/internal/dnshealth`: ドメイン鍵の公開鍵、送信元認証、メール交換設定の健全性確認。",
    "- 宛先domainごとのMX direct delivery":
        "- 宛先 domain ごとの MX 直接送信。",
    "- randomized sender、Message-ID、EHLO、送信domain":
        "- 送信者のランダム生成、Message-ID、EHLO、送信 domain。",
    "- DKIM key生成/署名、SPF/DKIM TXTのAliyun DNS自動設定":
        "- DKIM key の生成／署名と、SPF/DKIM TXT の Aliyun DNS 自動設定。",
    "- Spamhaus ZENチェック、public IPv4確認":
        "- Spamhaus ZEN の確認と public IPv4 の確認。",
    "汎用RATに一般的な画面取得、keylogging、任意shell、file manager、資格情報窃取の実装は静的symbolから確認できない。Triageの`WriteProcessMemory`シグネチャは観測事実だが、これだけでprocess injectionやRAT機能とは断定しない。":
        "汎用 RAT に一般的な画面取得、keylogging、任意 shell、file manager、資格情報窃取の実装は静的 symbol から確認できません。Triage の `WriteProcessMemory` signature は観測事実ですが、これだけで process injection や RAT 機能とは断定しません。",
    "| Key | Value / meaning |": "| 項目 | 値／意味 |",
    "control APIの静的文字列には `/api/heartbeat`, `/api/v1/heartbeat_direct`, `/api/client_command/`, `/api/v1/activate`, `/api/v1/shutdown`, `/api/v1/selftest_result` がある。command構造にはpause/activate、restart、exit/shutdown、UI表示制御に対応するfieldが見える。任意OS command実行を示すcontrol actionは確認していない。":
        "control API の静的 string には `/api/heartbeat`、`/api/v1/heartbeat_direct`、`/api/client_command/`、`/api/v1/activate`、`/api/v1/shutdown`、`/api/v1/selftest_result` があります。command 構造には pause／activate、restart、exit／shutdown、UI 表示制御に対応する field が見えます。任意 OS command 実行を示す control action は確認していません。",
    "## 動的挙動（Triage公開テレメトリ）":
        "## 公開サンドボックス解析結果",
    "Cloudflare IPは共有edgeであり、専用C2 IPとしてblockしない。`ctldl.windowsupdate.com`も同process telemetryに出るが、証明書/Windows関連の補助通信としてC2候補から除外した。":
        "Cloudflare IP は共有 edge のため、専用 C2 IP として block しません。`ctldl.windowsupdate.com` も同じ process telemetry に現れますが、certificate／Windows 関連の補助通信として C2 候補から除外しました。",
    "| Indicator | Role | Evidence | Confidence |":
        "| Indicator | 役割 | 根拠 | 信頼度 |",
    "| `www.iainglespa.com` | content/config distribution、control補助の可能性 | 5つのURL + 2 sandboxでTLS接続 | 高 |":
        "| `www.iainglespa.com` | `content/config distribution`（control 補助の可能性） | 5 つの URL と 2 sandbox で TLS 接続 | 高 |",
    "| `104.21.4.118`, `172.67.132.11` | Cloudflare edge | DNS/TLS telemetry | 高、block IOCとしては低品質 |":
        "| `104.21.4.118`, `172.67.132.11` | `Cloudflare edge` | `DNS/TLS telemetry` | 高。ただし block IOC としては低品質 |",
    "| `https://alidns.aliyuncs.com` | legitimate Aliyun DNS API | static function/string | 高、悪性IOCではない |":
        "| `https://alidns.aliyuncs.com` | `legitimate Aliyun DNS API` | `static function/string` | 高。ただし悪性 IOC ではない |",
    "- Sliver / Merlin / Mythic / SparkRAT / ChaosRAT: GoとHTTP(S) controlという表面的共通点のみ。各framework固有protocol/config、remote shell、post-exploitation機能がない。":
        "- Sliver / Merlin / Mythic / SparkRAT / ChaosRAT: Go と HTTP(S) control という表面的共通点だけです。各 framework 固有の protocol/config、remote shell、post-exploitation 機能はありません。",
    "- VenomRAT / Quasar / Remcos: .NET/native RATのconfig/namespace/protocolと一致しない。":
        "- VenomRAT / Quasar / Remcos: .NET/native RAT の config/namespace/protocol と一致しません。",
    "- AgentTesla: メール関連機能は共通するが、AgentTeslaはcredential stealerのexfiltrationであり、本検体はSMTP配送エンジン自体を実装する。":
        "- AgentTesla: メール関連機能は共通しますが、AgentTesla は credential stealer の exfiltration に使う一方、本検体は SMTP 配送 engine 自体を実装します。",
    "- spam bot / bulk mailer: recipient/template配布、MX直送、sender randomization、DKIM/SPF自動化、blocklist確認、remote campaign controlが強く一致する。":
        "- spam bot / bulk mailer: recipient/template 配布、MX 直接送信、sender randomization、DKIM/SPF 自動化、blocklist 確認、remote campaign control が強く一致します。",
    "公開検索ではhash、mutex、C2文字列、cluster固有APIの既知報告を確認できなかった。したがって「既知RATの亜種」より「独自または非公開のspam bot」が妥当。ただし、新ファミリー確定には追加検体とcode/config clusteringが必要。":
        "公開検索では hash、mutex、C2 string、クラスター固有 API の既知 report を確認できませんでした。そのため「既知 RAT の亜種」より「独自または非公開の spam bot」が妥当です。ただし、新 family の確定には追加検体と code/config clustering が必要です。",
    "- 高: payload SHA-256、mutex + `mx-go/internal/*` + control API/固有URLを組み合わせたYARA。誤検知は同一toolの正規研究copy程度。":
        "- 高: payload SHA-256、mutex、`mx-go/internal/*`、control API／固有 URL を組み合わせた YARA。誤検知は同一 tool の正規研究 copy 程度です。",
    "- 中: `43.165.179.173:5000`。control backendとの関連性は高いが、IP再割当や別service併設で誤検知し得る。":
        "- 中: `43.165.179.173:5000`。control backend との関連性は高いものの、IP 再割当や別 service の併設で誤検知する可能性があります。",
    "- 低: JA3単独。Go標準TLS clientと共有される可能性が高く、domain/process条件との併用が必須。":
        "- 低: JA3 単独。Go 標準 TLS client と共有される可能性が高く、domain/process 条件との併用が必須です。",
    "- 検知に不適: Cloudflare edge IP、Aliyun/API IP確認/Spamhaus URL。正常利用が非常に多い。":
        "- 検知に不適: Cloudflare edge IP、Aliyun/API、IP 確認／Spamhaus URL。正常利用が非常に多いためです。",
    "状態変更を伴わないTCP、HTTP root、既知routeへのOPTIONS、TLS、content pathへのHEADだけを実施した。":
        "状態変更を伴わない TCP、HTTP root、既知 route への OPTIONS、TLS、content path への HEAD だけを実施しました。",
    "- root banner SHA-256: `b31ad76cca159ac5782beb3c33799c28eae70e191f1d853c329e9bfb7960c6cc`":
        "- root banner の SHA-256: `b31ad76cca159ac5782beb3c33799c28eae70e191f1d853c329e9bfb7960c6cc`",
    "- Shodan mmh3: `-1999552396`": "- Shodan mmh3: `-1999552396`",
    "- `/api/heartbeat`と`/api/client_command/`は404。legacy route、別path parameter、またはserver/client version差の可能性がある。":
        "- `/api/heartbeat` と `/api/client_command/` は 404 でした。legacy route、別 path parameter、server/client version 差の可能性があります。",
    "単なるopen portより強く、**MX-Goに関連するcontrol backendが現在稼働している可能性は高い**。ただしPOST/check-inは送っていないため、client認証、task format、campaign状態は未確認。":
        "単なる open port より強い根拠であり、**MX-Go に関連する control backend が現在稼働している可能性は高い**と判断します。ただし POST/check-in を送っていないため、client 認証、task format、campaign 状態は未確認です。",
    "- Issuer: Google Trust Services WE1":
        "- 発行者: `Google Trust Services WE1`",
    "- 5つの既知`.txt` pathはHEAD 200。ただし不存在pathも同じstatus、Content-Type、Last-Modifiedを返す。":
        "- 5 つの既知 `.txt` path は HEAD 200 でした。ただし、存在しない path も同じ status、Content-Type、Last-Modified を返します。",
    "したがってhost/TLSは生きているが、既知pathは現在、Cloudflare配下の共通403/placeholderへ置き換えられたか、条件付きでgateされている可能性が高い。受信者リストやtemplate本文は取得していない。":
        "したがって host/TLS は稼働していますが、既知 path は現在 Cloudflare 配下の共通 403／placeholder へ置換されたか、条件付きで gate されている可能性が高いと判断します。受信者 list や template 本文は取得していません。",
    "## ローカルprotocol lab": "## ローカル protocol lab",
    "再現可能なlocalhost限定C2/content server、合成check-in client、合成受信者fixtureを`emulators/unclassified/mx_go/`に追加した。`c2_detector.py --protocol mxgo`はoffline previewが既定で、active modeはloopbackに強制される。実C2への登録や実受信者データの取得には使用できない。 CLI往復試験では合成check-in成功、合成受信者2件の件数・SHA-256取得、値のredactionを確認した。":
        "再現可能な localhost 限定 C2/content server、合成 check-in client、合成受信者 fixture を `emulators/unclassified/mx_go/` に追加しました。`c2_detector.py --protocol mxgo` は offline preview が既定で、active mode は loopback に強制されます。実 C2 への登録や実受信者 data の取得には使えません。CLI 往復 test では合成 check-in の成功、合成受信者 2 件の件数と SHA-256 の取得、値の redaction を確認しました。",
    "実検体は静的にのみ解析した。限定ライブ確認ではTCP/TLS/HTTP root/OPTIONS/HEADだけを実施した。malware check-in、POST、command取得、recipient/template本文取得、メール送信、sample実行は行っていない。":
        "実検体は静的にだけ解析しました。限定 live 確認では TCP/TLS/HTTP root/OPTIONS/HEAD だけを実施しました。malware check-in、POST、command 取得、recipient/template 本文取得、メール送信、sample 実行は行っていません。",
    "- Conflicting family leads retained: `tinba`":
        "- 競合する family 候補を保持: `tinba`",
    "## 限定ライブ確認（2026-07-15 JST）":
        "## 限定ライブ確認（2026-07-15 `JST`）",
}


_EVIDENCE_DESCRIPTIONS = {
    "GenesisStealer_Installer_NSIS_MaaS_Template":
        "GenesisStealer_Installer_NSIS_MaaS_Template",
    "RemusStealer_GoPayload": "RemusStealer_GoPayload",
    "NSIS/Electron ASAR loader markers":
        "NSIS/Electron ASAR loader のマーカー",
    "IRAHook Fabric mod package and EasySleep class markers":
        "IRAHook Fabric mod package と EasySleep class のマーカー",
    "registered detector matched": "登録済み detector が一致",
    "wasp stealer": "`wasp stealer`",
    "StealC_V1_Paired_Buffer_XOR": "StealC_V1_Paired_Buffer_XOR",
    "StealC_V1_Base64_RC4_SkipKey_Layout":
        "StealC_V1_Base64_RC4_SkipKey_Layout",
}

_FIRST_SEEN = re.compile(r"^- MalwareBazaar first seen: (\x60[^\x60]+\x60)$")
_FORMAT_SIZE = re.compile(
    r"^- Format / size: (\x60[^\x60]+\x60) / (\x60[^\x60]+\x60) bytes$"
)
_HIGH_HASH = re.compile(
    r"^- High confidence / low false-positive risk: "
    r"exact submitted SHA-256 (\x60[0-9a-fA-F]{64}\x60)\.$"
)
_DEPTH = re.compile(
    r"^- Depth ([0-9]+): (\x60[^\x60]+\x60) "
    r"(\x60[0-9a-fA-F]{64}\x60) "
    r"\(([0-9]+) bytes, ([A-Za-z][A-Za-z0-9_+-]*)\)$"
)
_EVIDENCE = re.compile(
    r"^- (\x60[^\x60]+\x60): (\x60[^\x60]+\x60) - (.+)$"
)
_ENDPOINT_ROW = re.compile(
    r"^\| endpoint \| ([^|]+?) \| ([^|]+?) \| "
    r"([^|]+?) \| ([^|]+?) \|$"
)
_COLLECTION_TITLE = re.compile(r"^# コレクション：(.+)$")

# 既存のインラインコード、URL、Markdown リンク先は機械値として保護する。
_PROTECTED_MARKDOWN = re.compile(
    r"(`[^`\r\n]*`|\]\([^\)\r\n]*\)|https?://[^\s|)>]+)"
)
_LATIN_RUN = re.compile(
    r"[A-Za-z][A-Za-z0-9_.+/#()*-]*(?: [A-Za-z][A-Za-z0-9_.+/#()*-]*)*"
)
_JAPANESE_GAP = re.compile(
    r"(?<=[\u3000-\u30ff\u3400-\u9fff\uff10-\uff5a0-9]) +"
    r"(?=[\u3000-\u30ff\u3400-\u9fff\uff10-\uff5a0-9])"
)
_JAPANESE_BEFORE_CODE = re.compile(
    r"(?<=[\u3000-\u30ff\u3400-\u9fff\uff10-\uff5a0-9]) +(?=`)"
)
_CODE_BEFORE_JAPANESE = re.compile(
    r"(?<=`) +(?=[\u3000-\u30ff\u3400-\u9fff\uff10-\uff5a0-9])"
)

# 通常文として残っていた語だけを日本語にする。製品名、規格名、API 動作名など、
# 翻訳すると同一性が失われる語は下の処理でインラインコードとして明示する。
_PROSE_TERMS = (
    ("remotely controlled bulk-email spam bot", "遠隔制御型の大量メール送信ボット"),
    ("malwarebazaar-unknown-20260717", "MalwareBazaar未分類コレクション（2026年7月17日）"),
    ("IRAHook Fabric mod package", "IRAHook拡張パッケージ"),
    ("IRAHook Fabric mod", "IRAHook拡張モジュール"),
    ("EasySleep class", "スリープ処理クラス"),
    ("Google Trust Services WE1", "グーグル・トラスト・サービスWE1"),
    ("legitimate Aliyun DNS API", "正規のクラウド名前解決API"),
    ("DNS/TLS telemetry", "名前解決／暗号化通信のテレメトリ"),
    ("static function/string", "静的な関数／文字列"),
    ("Cloudflare edge", "共有配信網のエッジ"),
    ("TCP open", "TCP接続の開放"),
    ("task format", "タスク形式"),
    ("post-exploitation", "侵害後活動"),
    ("POST", "HTTP送信"),
    ("offline preview", "オフライン事前確認"),
    ("active mode", "能動モード"),
    ("SMTP/MX 直接送信", "メール交換サーバーへの直接送信"),
    ("DKIM 公開鍵", "ドメイン鍵の公開鍵"),
    ("DKIM 署名", "ドメイン鍵署名"),
    ("Go 標準 TLS client", "標準の暗号化通信クライアント"),
    ("Go標準TLS client", "標準の暗号化通信クライアント"),
    ("check-in", "定期接続"),
    ("heartbeat", "生存通知"),
    ("activate", "有効化"),
    ("shutdown", "停止"),
    ("restart", "再起動"),
    ("pause", "一時停止"),
    ("exit", "終了"),
    ("credential stealer", "認証情報窃取型マルウェア"),
    ("wasp stealer", "WaspStealer"),
    ("unclassified", "未分類"),
    ("unknown", "未識別"),
    ("infostealer", "情報窃取型"),
    ("stealer", "情報窃取型"),
    ("imphash", "インポートハッシュ"),
    ("MIME", "多目的メール形式"),
    ("ISO-2022-JP", "日本語文字コード"),
    ("RAT", "遠隔操作型マルウェア"),
    (".NET", "ドットネット"),
    ("Sliver", "スリバー"),
    ("Merlin", "マーリン"),
    ("Mythic", "ミシック"),
    ("SparkRAT", "スパーク遠隔操作型"),
    ("ChaosRAT", "カオス遠隔操作型"),
    ("VenomRAT", "ヴェノム遠隔操作型"),
    ("Quasar", "クエーサー"),
    ("Remcos", "レムコス"),
    ("Cloudflare", "クラウドフレア"),
    ("Aliyun", "アリクラウド"),
    ("Spamhaus", "スパムハウス"),
    ("Shodan", "ショーダン"),
    ("localhost", "ローカルホスト"),
    ("loopback", "ループバック"),
    ("CLI", "コマンドライン"),
    ("JST", "日本標準時"),
    ("inferred", "推定"),
    ("recorded", "記録済み"),
    ("endpoint", "エンドポイント"),
    ("OS", "オペレーティングシステム"),
    ("sender randomization", "送信者のランダム化"),
    ("remote campaign control", "遠隔キャンペーン制御"),
    ("event telemetry", "イベントテレメトリ"),
    ("process telemetry", "プロセステレメトリ"),
    ("process injection", "プロセス注入"),
    ("file manager", "ファイル管理"),
    ("remote shell", "遠隔シェル"),
    ("package path", "パッケージパス"),
    ("loader script", "ローダースクリプト"),
    ("control backend", "制御バックエンド"),
    ("control server", "制御サーバー"),
    ("content/config host", "コンテンツ／設定ホスト"),
    ("protocol lab", "プロトコル検証環境"),
    ("raw output", "未加工出力"),
    ("memory cache", "メモリキャッシュ"),
    ("command polling", "コマンドの定期取得"),
    ("root banner", "ルート応答バナー"),
    ("open port", "開放ポート"),
    ("public label", "公開ラベル"),
    ("known-file", "既知ファイル"),
    ("server/client version", "サーバー／クライアントのバージョン"),
    ("protocol/config", "プロトコル／設定"),
    ("code/config", "コード／設定"),
    ("content/config", "コンテンツ／設定"),
    ("recipient/template", "受信者／テンプレート"),
    ("domain/process", "ドメイン／プロセス"),
    (".NET/native", ".NET／ネイティブ"),
    ("spam bot", "迷惑メール送信ボット"),
    ("bulk mailer", "大量メール送信プログラム"),
    ("distribution", "分布"),
    ("confidence", "信頼度"),
    ("indicator", "指標"),
    ("evidence", "根拠"),
    ("meaning", "意味"),
    ("hash", "ハッシュ"),
    ("mutex", "ミューテックス"),
    ("parse", "解析"),
    ("binary", "バイナリ"),
    ("malware", "マルウェア"),
    ("loader", "ローダー"),
    ("telemetry", "テレメトリ"),
    ("sandbox", "サンドボックス"),
    ("certificate", "証明書"),
    ("placeholder", "代替応答"),
    ("parameter", "パラメータ"),
    ("campaign", "キャンペーン"),
    ("legacy", "旧式"),
    ("error", "エラー"),
    ("shell", "シェル"),
    ("edge", "エッジ"),
    ("block", "遮断"),
    ("content", "コンテンツ"),
    ("raw", "未加工"),
    ("info", "情報"),
    ("byte", "バイト"),
    ("family", "ファミリ"),
    ("cases", "ケース"),
    ("case", "ケース"),
    ("providers", "情報提供元"),
    ("provider", "情報提供元"),
    ("aggregator", "集約サービス"),
    ("coverage", "網羅状況"),
    ("source", "情報源"),
    ("label", "ラベル"),
    ("benign", "良性"),
    ("community", "コミュニティ"),
    ("credential", "認証情報"),
    ("fallback", "代替手段"),
    ("upload", "アップロード"),
    ("file", "ファイル"),
    ("batch", "一括解析"),
    ("entries", "登録"),
    ("entry", "登録"),
    ("tags", "タグ"),
    ("tag", "タグ"),
    ("samples", "検体"),
    ("sample", "検体"),
    ("payload", "ペイロード"),
    ("rules", "ルール"),
    ("rule", "ルール"),
    ("process", "プロセス"),
    ("network", "ネットワーク"),
    ("strings", "文字列"),
    ("string", "文字列"),
    ("configuration", "設定"),
    ("config", "設定"),
    ("data", "データ"),
    ("detector", "検出器"),
    ("endpoints", "エンドポイント"),
    ("endpoint", "エンドポイント"),
    ("cluster", "クラスター"),
    ("bot", "ボット"),
    ("list", "一覧"),
    ("template", "テンプレート"),
    ("recipient", "受信者"),
    ("domain", "ドメイン"),
    ("keylogging", "キー入力記録"),
    ("signature", "シグネチャ"),
    ("symbol", "シンボル"),
    ("framework", "フレームワーク"),
    ("protocol", "プロトコル"),
    ("namespace", "名前空間"),
    ("exfiltration", "持ち出し"),
    ("engine", "エンジン"),
    ("blocklist", "拒否リスト"),
    ("report", "報告"),
    ("clustering", "クラスタリング"),
    ("tool", "ツール"),
    ("copy", "複製"),
    ("service", "サービス"),
    ("host", "ホスト"),
    ("route", "経路"),
    ("status", "状態"),
    ("field", "フィールド"),
    ("command", "コマンド"),
    ("action", "操作"),
    ("client", "クライアント"),
    ("server", "サーバー"),
    ("path", "パス"),
    ("gate", "アクセス制限"),
    ("fixture", "テストデータ"),
    ("redaction", "秘匿化"),
    ("test", "テスト"),
    ("live", "実環境"),
    ("static", "静的"),
    ("native", "ネイティブ"),
    ("build", "ビルド"),
    ("module", "モジュール"),
    ("timestamp", "タイムスタンプ"),
    ("subsystem", "サブシステム"),
    ("key", "鍵"),
    ("public", "公開"),
    ("control", "制御"),
)


def _localize_prose_segment(segment: str) -> str:
    """保護対象外の説明語を訳し、契約復元用に識別子を一時区切りする。"""

    for source, target in _PROSE_TERMS:
        segment = re.sub(
            rf"(?<![A-Za-z0-9_]){re.escape(source)}(?![A-Za-z0-9_])",
            target,
            segment,
            flags=re.IGNORECASE,
        )
    segment = _JAPANESE_GAP.sub("", segment)
    return _LATIN_RUN.sub(lambda match: f"`{match.group(0)}`", segment)


def _finish_translation(text: str) -> str:
    """既存の機械値区間を保持したまま、説明語を日本語化する。"""

    parts = _PROTECTED_MARKDOWN.split(text)
    translated = "".join(
        part if index % 2 else _localize_prose_segment(part)
        for index, part in enumerate(parts)
    )
    translated = _JAPANESE_BEFORE_CODE.sub("", translated)
    return _CODE_BEFORE_JAPANESE.sub("", translated)


def _restore_inline_contract(source: str, translated: str) -> str:
    """原文にないインラインコード記法を最終出力から除く。"""

    remaining = [
        match.group(0) for match in re.finditer(r"(`+)([^\r\n]*?)\1", source)
    ]

    def restore(match: re.Match[str]) -> str:
        token = match.group(0)
        if token in remaining:
            remaining.remove(token)
            return token
        return match.group(2)

    return re.sub(r"(`+)([^\r\n]*?)\1", restore, translated)


def _render(
    leading: str,
    source: str,
    translated: str,
    trailing: str,
) -> str:
    """追加コード記法を除いて訳し、原文の保護契約を再確認して返す。"""

    translated = _restore_inline_contract(source, translated)
    translated = _finish_translation(translated)
    translated = _restore_inline_contract(source, translated)
    return leading + translated + trailing


def _margins(line: str) -> tuple[str, str, str]:
    """前後の空白と改行を保持して本文を分離する。"""

    leading = line[: len(line) - len(line.lstrip())]
    body_with_end = line[len(leading):]
    trailing = body_with_end[len(body_with_end.rstrip()):]
    body = (
        body_with_end[: len(body_with_end) - len(trailing)]
        if trailing
        else body_with_end
    )
    return leading, body, trailing


def translate_line(line: str) -> str:
    """既存 localizer 適用後の未分類固有説明を、安全に日本語化する。"""

    leading, body, trailing = _margins(line)
    translated = _EXACT.get(body)
    if translated is not None:
        return _render(leading, body, translated, trailing)

    match = _COLLECTION_TITLE.fullmatch(body)
    if match:
        return _render(
            leading,
            body,
            f"# コレクション：`{match.group(1)}`",
            trailing,
        )

    match = _FIRST_SEEN.fullmatch(body)
    if match:
        return _render(
            leading,
            body,
            f"- MalwareBazaar 初回観測: {match.group(1)}",
            trailing,
        )

    match = _FORMAT_SIZE.fullmatch(body)
    if match:
        return _render(
            leading,
            body,
            f"- 形式 / サイズ: {match.group(1)} / {match.group(2)} byte",
            trailing,
        )

    match = _HIGH_HASH.fullmatch(body)
    if match:
        return _render(
            leading,
            body,
            "- 高信頼度／低い誤検知リスク: "
            f"提出検体と完全一致する SHA-256 {match.group(1)}。",
            trailing,
        )

    match = _DEPTH.fullmatch(body)
    if match:
        depth, kind, digest, size, status = match.groups()
        return _render(
            leading,
            body,
            f"- 深度 {depth}: {kind} {digest}"
            f" （{size} byte、`{status}`）",
            trailing,
        )

    match = _EVIDENCE.fullmatch(body)
    if match:
        source, family, description = match.groups()
        description = _EVIDENCE_DESCRIPTIONS.get(description, description)
        translated = f"- 帰属根拠 {source}: {family} - {description}"
        return _render(leading, body, translated, trailing)

    match = _ENDPOINT_ROW.fullmatch(body)
    if match:
        value, role, confidence, source = (
            part.strip() for part in match.groups()
        )
        return _render(
            leading,
            body,
            f"| `endpoint` | `{value}` | `{role}` | "
            f"`{confidence}` | `{source}` |",
            trailing,
        )

    return line
