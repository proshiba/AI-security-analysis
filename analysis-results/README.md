# Analysis results

静的解析・設定抽出・IOC評価の公開用結果です。検体本体、復元バイナリ、資格情報、ローカル解析パスは含めません。

標準配置は次のとおりです。

```text
analysis-results/<malware-family>/cases/<sample-sha256>/
analysis-results/<malware-family>/refresh-YYYYMMDD/cases/<sample-sha256>/
```

個別case、campaign、incidentには `README.md` に加えてIOCだけを抜き出した `IOC-LIST.md` を置きます。全件の索引は [IOC-INDEX.md](IOC-INDEX.md) です。一覧は次のgeneratorで再生成・検証します。

```powershell
python .\analysis-framework\common\generate_ioc_lists.py --repository .
python .\analysis-framework\common\generate_ioc_lists.py --repository . --check
```

`IOC-LIST.md` は生成物です。手編集せず、元のREADME、`iocs.json`、`config.json`、`analysis_history.yaml` を修正して再生成してください。

## Families

- [ValleyRAT](valleyrat/README.md) / [behavior and C2 model](valleyrat/BEHAVIOR-C2.md)
- [AgentTesla](agenttesla/README.md)
- [ShadowPad](shadowpad/README.md)
- [StealC](stealc/README.md) / [behavior and C2 model](stealc/BEHAVIOR-C2.md)
- [RemcosRAT](remcosrat/README.md)
- [VenomRAT](venomrat/README.md) / [behavior and C2 model](venomrat/BEHAVIOR-C2.md)
- [Formbook](formbook/README.md) / [behavior and C2 model](formbook/BEHAVIOR-C2.md)
- [Vidar](vidar/README.md) / [behavior and C2 model](vidar/BEHAVIOR-C2.md)
- [Amadey](amadey/README.md)
- [Latrodectus](latrodectus/README.md)
- [LummaStealer](lummastealer/README.md) / [behavior and C2 model](lummastealer/BEHAVIOR-C2.md)
- [RemusStealer](remusstealer/README.md) / [behavior and C2 model](remusstealer/BEHAVIOR-C2.md)
- [Atomic macOS Stealer (AMOS)](amosstealer/README.md) / [behavior and C2 model](amosstealer/BEHAVIOR-C2.md)
- [Unclassified malware](unclassified/README.md)
- [AsyncRAT](asyncrat/README.md)
- [XWorm](xworm/README.md)
- [QuasarRAT](quasarrat/README.md)
- [njRAT](njrat/README.md)
- [DarkComet](darkcomet/README.md)
- [DCRat](dcrat/README.md)
- [RedLine Stealer](redlinestealer/README.md)
- [Snake Keylogger](snakekeylogger/README.md)
- [GuLoader](guloader/README.md)
- [HijackLoader](hijackloader/README.md)
- [npm supply-chain: axios/plain-crypto-js](npm-supply-chain/cases/e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09/README.md)
- [AtlasCross / Atlas RAT](atlascross/campaigns/silver-fox-vpn-2026/README.md)
- [Trivy / TeamPCP supply-chain incident](supply-chain/trivy-teampcp-2026/README.md)
- [2026-04-01 security news analysis](news/20260401/README.md)

## Latest refresh

- [2026-07-15: 9 families / 90 new samples](REFRESH-2026-07-15.md)
- [2026-07-15: unpacking reassessment and remaining blockers](UNPACKING-REASSESSMENT-2026-07-15.md)

## Cross-family deep static analysis, 2026-07-17

- [80 difficult cases / 142 statically analyzed layers](static-hard-cases/README.md)
- Static-only: no sample execution, CPU emulation, network/C2 contact, or recovered-binary publication.

## VX-Underground family batches, 2026-07-16

- [DonutLoader: 2 submissions](donutloader/vx-underground-20260716/README.md)
- [Atomic macOS Stealer: 2 submissions](amosstealer/vx-underground-20260716/README.md)
- [Vidar: 25 submissions](vidar/vx-underground-20260716/README.md)
- [Amadey: 35 submissions](amadey/vx-underground-20260716/README.md)
- [Latrodectus: 54 submissions](latrodectus/vx-underground-20260716/README.md)

各レポートでは、MalwareBazaarの署名ラベル、静的に確認したファミリーマーカー、配布・ローダー形態、復号済み設定、候補IOCを区別します。埋め込みURLやIPは、それだけでは稼働中C2や当該ファミリー専用インフラを意味しません。

すべてのrefresh解析は検体をローカル実行せず、実インフラへの接続も行いません。Sigma/YARAは検知仮説であり、正規ソフトウェアとの重複、署名・普及度、親子プロセス、通信先を組み合わせて環境別に検証してください。

## PureHVNC and DonutLoader cases


- [SpyGlace / APT-C-60 2026](spyglace/README.md) / [campaign analysis and IOC set](spyglace/campaigns/apt-c60-2026/README.md)
- [PureHVNC / PureRAT](purehvnc/README.md)
- [DonutLoader](donutloader/README.md)

The DonutLoader result preserves both delivery classification and terminal PureRAT identity; configured C2 is not attributed to the delivery host or intermediate loader.

## Unclassified newest-first batch, 2026-07-17

- [100 MalwareBazaar unsigned/unknown-stealer cases](unclassified/malwarebazaar-unknown-20260717/README.md)
- Medium-confidence internal support: 7; provisional low-confidence leads: 63; unresolved: 30.
- Static IOC candidates are unconfirmed and were not contacted.

## Profile-defined ten-family batch, 2026-07-17

- [Architecture, execution order, retry handling, relationship diagram, and batch summary](../analysis-framework/docs/PROFILED-FAMILY-EXPANSION.md)
- 10 families / 100 newest exact-signature samples; 100/100 passed hash, routing, public-output, and offline-safety validation.
- One candidate C2-role literal was recovered: `80.234.41.242:7895` in a RedLine Stealer case. It was not contacted and is not labelled live or confirmed.
- Five stage URL candidates were retained as delivery IOCs. Four public-IP discovery services were retained only as behavior context and excluded from IOC/C2 plans.
- No encrypted family configuration was fully recovered in this batch; packed or runtime-only configurations remain explicitly unresolved.
- Per-family medium-confidence YARA is stored under each batch. The shared low-confidence Sigma correlation template is under [_shared/rules/sigma](./_shared/rules/sigma/profiled_family_script_delivery.yml).
