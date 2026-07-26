# マルウェア通信解析・ネットワークシグネチャ開発計画

## 目的

既存の静的解析が完了した後、公開PCAPを独自に解析し、検体、設定、通信、campaignの関係を補強します。最終目的は、単一のIPアドレスやdomainに依存せず、通信の構造や状態遷移からマルウェア通信を発見できるSnort 3シグネチャと検証可能な根拠を作ることです。

外部記事の説明やIOCは答えとして先に採用しません。PCAPから得た観測を正本とし、独立した解析が終わった後に外部情報と照合します。

## 初期データ源

- [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/)
- [Traffic Analysis Exercises](https://www.malware-traffic-analysis.net/training-exercises.html)
- [Snort 3 Rule Writing Guide](https://docs.snort.org/rules/)

同サイトはWindowsマルウェアを中心とするPCAPと検体を公開しています。PCAP内にマルウェア本体が含まれる可能性があり、endpoint security製品が悪性として検出する場合があるため、すべて危険な入力として扱います。

## 初期優先対象

保有検体との対応可能性と比較材料の多さから、最初のpilotは次の順序とします。

| 優先度 | 公開事例 | 主な比較対象 | 検討する通信 |
|---:|---|---|---|
| 1 | 2026-04-16 Lumma Stealer＋Sectop RAT | Lumma、後続RAT | 初期感染、情報窃取、後続payload |
| 2 | 2026-04-13 XLoader／Formbook | Formbook、XLoader | 多数domainへの通信、request構造、fallback |
| 3 | 2026-03-12 SmartApeSG＋Remcos RAT | RemcosRAT、ClickFix系campaign | 配布段階と最終RAT通信の分離 |
| 4 | 2026-02-03 GuLoader＋AgentTesla系 | GuLoader、AgentTesla | cloud配布、IP確認、FTP exfiltration |

ページタイトルや外部のfamily名だけでは、手元の検体とPCAPを同一variantとして扱いません。完全一致SHA-256、PCAPから回収したartifact hash、復号済み設定、希少なprotocol特徴などで対応を評価します。

## 安全な取得と保管

1. ZIPとPCAPはリポジトリ外のアクセス制限領域に保存する。
2. source URL、公開日、取得日時、ZIP SHA-256、PCAP SHA-256、byte数を取得manifestへ記録する。
3. passwordや資格情報はmanifest、Markdown、Git履歴へ保存しない。
4. PCAPからexportしたHTTP、SMB、SMTP等のobjectも検体として扱い、非公開領域に隔離する。
5. export objectはhashと形式だけを公開し、実体をリポジトリへ入れない。
6. 検体、export object、script、document macroを実行しない。
7. PCAPはオフライン入力として読み、traffic replayや外部hostへの再送を行わない。
8. live C2、配布先、DNS resolver、外部解析serviceへ接続しない。

## 独自PCAP解析の順序

### 1. PCAP同一性と健全性

- capture形式、時間範囲、packet数、欠落・切断、interface、snap length
- capture全体と分割PCAPのSHA-256
- 内部host、gateway、DNS、外部host候補
- retransmission、欠落segment、重複packetが解析へ与える制約

### 2. protocol inventory

- IPv4／IPv6、TCP／UDP、DNS、HTTP、TLS、SMTP、FTP、SMB等の件数
- conversation、byte数、packet数、接続間隔、方向、継続時間
- DNS query／answer、CNAME、TTL、NXDOMAIN、再照会
- TLS SNI、ALPN、version、cipher、証明書属性、fingerprint
- HTTP method、host、URI、header順序、content type、body長、response code
- FTP command順序、authentication、upload path、転送方向
- 未知TCP／UDPの先頭byte、message長、delimiter、反復、request-response関係

### 3. 感染chainの再構成

- 配布、payload取得、check-in、tasking、追加payload、exfiltrationを別phaseとして記録する。
- 1つのIPやdomainに複数の役割を付けず、観測したflowごとに役割を評価する。
- HTTP object等を回収した場合はSHA-256を計算し、既存caseと完全一致するか確認する。
- 静的設定のhost、port、URI、user-agent、暗号鍵、campaign IDとPCAP観測を比較する。
- PCAP内の時間順序と静的に推定した全体ロジックが矛盾する場合は、矛盾を残す。

### 4. 外部情報との照合

独自解析を固定した後に、公開ページの説明、IOC一覧、他の一次情報と比較します。外部情報だけで得た値には`osint_reported`、PCAPで直接確認した値には`pcap_observed`、静的設定とも一致した値には`pcap_and_static_confirmed`を付けます。

## Snort 3シグネチャの設計

### ルールの種類

1. `behavioral`: protocol構造や複数fieldの組合せを検出する長寿命候補
2. `campaign`: 配布chainやcampaign固有のURI・header・証明書・状態遷移を検出する中期候補
3. `ioc`: domain、IP、完全URI等を検出する短期ルール
4. `flow-state`: `flowbits`等で複数packet・複数phaseを関連付ける補助ルール

IOCルールとbehavioralルールを同じ確度で扱いません。共有hosting、CDN、cloud storage、正規IP確認serviceは単独条件にしません。

### 必須設計項目

- `flow`で方向と確立済みsessionを指定する。
- HTTPは`http_uri`、`http_header`、`http_client_body`等の適切なsticky bufferを使用する。
- 最も希少で安定した`content`を`fast_pattern`候補とする。
- 必要に応じて`distance`、`within`、`offset`、`depth`で相対位置を制約する。
- 単一packetで不足する場合は`flowbits`で状態を関連付ける。
- beacon頻度やscan様動作を扱う場合だけ`detection_filter`を使用する。
- `sid`、`rev`、family、campaign、source、観測日、確度、対象Snort versionを管理する。
- 暗号化通信は平文payloadを仮定せず、SNI、証明書、TLS fingerprint、接続形状の限界を明記する。

### 採用しない設計

- IP、port、user-agent、一般的なHTTP methodのどれか1つだけで悪性判定する。
- 公開ページのIOCをPCAPで確認せず、そのままruleへ変換する。
- 1つの正例PCAPにだけ一致する過学習した長いbyte列を、variant共通ruleとして公開する。
- packet lossやTCP再構成の影響を無視してoffsetを固定する。
- alert件数だけを見て検知精度を判断する。

## オフライン検証

各ルールは次の順序で検証します。

1. Snort 3の設定・rule構文検証を通す。
2. 対象PCAPを`-r`で読み、想定flow・packetだけにalertするか確認する。
3. 同一campaignの別PCAPがあれば再現率を確認する。
4. 無害なHTTP、TLS、FTP等のbaseline PCAPで誤検知を確認する。
5. familyが異なる悪性PCAPで、共通service利用による交差検知を確認する。
6. rule条件を1つずつ除くablationで、各条件が必要な理由を記録する。
7. alertのpacket番号、stream、根拠field、期待件数をtest fixtureへ固定する。

PCAPをnetwork interfaceへreplayせず、ファイル入力だけで試験します。

## 成果物

```text
analysis-results/network-traffic/<family>/<campaign-or-unknown>/<capture-date>/
  README.md
  capture-metadata.json
  flows.json
  protocol-observations.json
  sample-links.json
  signature-evidence.json

analysis-framework/malware/<family>/rules/snort3/
  <family-or-campaign>.rules
```

生PCAP、ZIP、export object、復号payload、資格情報は成果物へ含めません。公開するIP、domain、URIは既存IOC方針に従って役割・確度・sourceを付けます。

## 自動化候補

- source pageからPCAP候補とmetadataを収集するinventory処理
- 既存caseのSHA-256／family／期間と公開事例を対応付ける候補生成
- `tshark`または同等parserによるprotocol observationの正規化
- 静的設定とPCAP観測の差分・一致判定
- Snort 3 rule雛形の生成
- Snort構文検証、正例・負例PCAP、期待alertを実行するtest harness
- rule coverage、誤検知、最終観測日、失効候補の週次集計

自動処理は候補作成までとし、通信の意味、family帰属、rule公開は人手レビューを必須にします。

## 完了条件

- PCAPのsource、hash、取得日時、解析制約が記録されている。
- 感染chainと各flowの役割が、packetまたはstreamの根拠へ追跡できる。
- 外部記載と独自観測が分離されている。
- 検体との紐付けが完全一致または複数の独立証拠で説明されている。
- Snortルールが構文検証、正例PCAP、負例PCAPを通過している。
- 各alertの根拠と想定誤検知条件が日本語で記録されている。
- 生PCAPや回収artifactがGit管理対象へ入っていない。
