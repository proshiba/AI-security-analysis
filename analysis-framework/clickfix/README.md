# ClickFix日次取り込み

ClickFix Hunter、ClickFix Campaign Monitor、ThreatFoxの`clickfix`／`clearfake` tagから
重複のない50件を固定し、domain単位の限定ライブ観測、インフラ調査、Triage既存解析照合、
公開成果物を生成します。

## 安全上の前提

- landing pageと静的に復元したstage URLへ、上限付きGETだけを送信します。
- JavaScript、clipboard操作、PowerShell、Windows command、取得payloadは実行しません。
- provider生応答、取得本文、Triageのraw reportは`--private-output`へ保存し、Gitへ追加しません。
- private／loopback／link-localへ解決されたhostには接続しません。
- C2 protocol、認証情報、form入力、POST、WebDAV変更系methodは送信しません。
- DNS、IP、TLS、open port、sandbox通信だけでC2またはactorを確定しません。
- Triageへ新規sampleを提出せず、sample、dumped file、memory、PCAPを自動downloadしません。

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

`--collect-sources`は環境変数`MALWAREBAZAAR_AUTH_KEY`をabuse.chのAuth-Keyとして
値を表示せず使用します。既存provider応答を再利用するときは`--source-dir`を指定します。
HTTPS観測では既存接続のleaf証明書SHA-256、issuer、SAN、有効期間も保存します。

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