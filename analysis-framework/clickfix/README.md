# ClickFix独立一括取り込み

ClickFix Hunter、ClickFix Campaign Monitor、ThreatFoxの`clickfix`／`clearfake` tagから
重複のない50件を固定し、domain単位のHTTP／実ブラウザ観測、インフラ調査、Triage既存解析照合、
公開成果物を生成します。

## 安全上の前提

- landing pageと静的に復元したstage URLへの上限付きGETに加え、実ブラウザでJavaScript実行後のDOMとclipboard書き込みを観測します。
- clipboard APIとlegacy copy eventはページ初期化時からinterceptし、値を記録してOS clipboardへの書き込みを可能な限り抑止します。
- copy／verify等の表示操作は再現しますが、取得したPowerShell／Windows commandやpayloadは実行しません。
- provider生応答、取得本文、Triageのraw reportは`--private-output`へ保存し、Gitへ追加しません。
- private／loopback／link-localへ解決されたhostには接続しません。
- C2 protocol、認証情報、form入力、POST、WebDAV変更系methodは送信しません。
- DNS、IP、TLS、open port、sandbox通信だけでC2またはactorを確定しません。
- Triageへ新規sampleを提出せず、sample、dumped file、memory、PCAPを自動downloadしません。

実ブラウザ観測の詳細とprivate JSON形式は[BROWSER-OBSERVATION.md](BROWSER-OBSERVATION.md)を参照してください。

## 感染チェーンの記録

ペイロードだけでなく、landing／injectから終端までを共通phaseへ分解して記録します。

- landing／inject、lure表示、clipboard設定、利用者操作、shell／LOLBIN、resolver／次段、終端payloadを分離します。
- 各phaseに観測、情報源報告、静的復元、推定、未観測、未取得の状態と根拠を付けます。
- 実ブラウザ、HTTP本文、provider command、Triage process／network、取得payloadの証跡を混同しません。
- 利用者による貼り付け・実行は、sandbox等で確認できない限り`inferred`または`not_observed`とします。
- `INFECTION-CHAIN.md`へMermaid図、段階表、停止位置、未解決edge、次の取得手順を保存します。
- `analysis.json`の`infection_chain`へ同じ情報を機械可読形式で保存します。


## 実行順

### 1. 情報源取り込みと限定ライブ観測

```powershell
py -3.13 .\analysis-framework\clickfix\clickfix_daily_intake.py `
  --repository . `
  --analysis-date 2026-07-30 `
  --private-output .\.work\clickfix `
  --collect-sources `
  --allow-live-probes `
  --limit 50 `
  --write
```

この初回実行では50件を固定する。ブラウザ観測後、同じ`--private-output`と`--source-dir`を使い、`--require-browser-observations --write`付きで再実行する。

`--collect-sources`は環境変数`MALWAREBAZAAR_AUTH_KEY`をabuse.chのAuth-Keyとして
値を表示せず使用します。既存provider応答を再利用するときは`--source-dir`を指定します。
HTTPS観測では既存接続のleaf証明書SHA-256、issuer、SAN、有効期間も保存します。
ブラウザ観測後、各caseの
`<private-output>/<analysis-date>/cases/<case-id>/browser-observation.json`を読み込み、
HTTP観測と統合します。`--require-browser-observations`は選定した全caseに観測記録があることを検証します。

標準ブラウザ制御カーネルを利用できないWindows環境では、Chrome DevTools Protocolを使う
`clickfix_browser_observer.py`で同じprivate JSONを生成できます。初回取り込み後に次を実行し、
その後`--require-browser-observations`付きで取り込みを再実行します。

```powershell
py -3.13 .\analysis-framework\clickfix\clickfix_browser_observer.py `
  --selection C:\private\clickfix\2026-08-03\selection.json `
  --private-output C:\private\clickfix\2026-08-03 `
  --limit 50
```

この代替経路もclipboard書き込みを初期化scriptで横取りし、POST等の変更系request、private IP、
downloadを遮断します。取得commandを貼り付けたり実行したりしません。

### 2. インフラ調査

```powershell
py -3.13 .\analysis-framework\clickfix\clickfix_infrastructure_enrichment.py `
  --repository . `
  --analysis-date 2026-07-30 `
  --private-output .\.work\clickfix\infrastructure `
  --write
```

current DNS（A／AAAA／CNAME／NS／MX）、domain／IP RDAP、証明書透明性、netblock、ASN、
Shodan InternetDBを取得します。履歴passive DNS providerは未設定のため、取得できないことを
明記し、情報源観測日時、現行DNS、RDAP event、CT期間を別レイヤーで扱います。

### 3. Hatching Triage照合

```powershell
py -3.13 .\analysis-framework\clickfix\clickfix_triage_enrichment.py `
  --repository . `
  --analysis-date 2026-07-30 `
  --private-output .\.work\clickfix\triage `
  --write
```

環境変数`TRIAGE_API_KEY`を値を表示せず使用します。`domain:`を必須とし、取得済み完全URLは`url:`、取得済みhashは`sha256:`で既存解析を検索し、
公開sampleだけのoverviewと最大2件のbehavioral reportを要約します。process名、raw commandを
公開しないcommand SHA-256、通信候補、dumped file、memory resource、PCAP候補を残します。
hashを取得したcaseは`sha256:`照合を追加します。

Triage APIは公開解析の検索、overview、task report、元sample、dumped file、memory、PCAPの
取得endpointを提供しますが、この処理は検索とJSON report取得だけを行います。
[Triage Search API](https://tria.ge/docs/cloud-api/search/)、
[Triage Samples API](https://tria.ge/docs/cloud-api/samples/)、
[Triage解析種別](https://tria.ge/docs/analysis/)を参照してください。

## 公開レイアウト

```text
analysis-results/clickfix/
  <domain>/
    cases/
      <case-id>/
        README.md
        FEATURES.md
        OVERALL-LOGIC.md
        INFECTION-CHAIN.md
        INFRASTRUCTURE.md
        TRIAGE.md
        analysis.json
        infrastructure.json
        triage-evidence.json
        iocs.json
        IOC-LIST.md
        live-observation.json
        rules/sigma.yml
  collections/
    clickfix-daily-<YYYYMMDD>/
      README.md
      INFRASTRUCTURE-SUMMARY.md
      TRIAGE-SUMMARY.md
      manifest.json
```

配布binaryの完全hashを取得できた場合は、この階層だけで完了扱いにせず、
`analysis-results/malware/<family>/versions/<version>/cases/<sha256>/`へ別caseとして
静的解析結果を登録します。