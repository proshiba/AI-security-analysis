# 解析成果物

静的解析、設定抽出、IOC評価、OSINT調査の公開用成果物です。検体本体、復元バイナリ、資格情報、ローカル解析パス、プロバイダーの生応答は含めません。検体の実行とCPU／CILエミュレーションは行いません。batch-0001以降のC2接続検証は、静的に復元した正確な候補だけにアプリケーション有効データなし・短時間・応答上限付きで行い、TCP到達やUDP無応答だけではC2確定としません。

## フォルダ構成

マルウェアの個別検体は、収集回や日付に左右されない固定深度で管理します。

```text
analysis-results/
├─ malware/<family>/
│  ├─ README.md
│  ├─ OSINT.md
│  ├─ VERSIONS.md
│  ├─ TECHNICAL-ANALYSIS.md
│  └─ versions/<version-key>/cases/<sha256>/
├─ collections/<collection-id>/
├─ catalog/cases.json
├─ research/{campaigns,supply-chain,vulnerabilities,news,audits}/
└─ _shared/
```

`refresh-*`、`vx-underground-*`、`malwarebazaar-*` は検体の親フォルダには置きません。収集元、収集日、収集単位は [`collections/`](collections/) のmanifestでSHA-256に関連付け、同じ検体を複製しません。設計、版判定、移行時の検証条件は[成果物レイアウト仕様](../analysis-framework/docs/RESULT-LAYOUT.md)を参照してください。

## 現在の収録状況

| 区分 | 件数 |
|---|---:|
| SHA-256で一意な全case | 633 |
| 既知・暫定マルウェアファミリ | 518 |
| 未分類 | 114 |
| サプライチェーンpayload | 1 |
| 版を静的根拠で確認済み | 69 |
| exact sampleの外部報告で版を特定 | 4 |
| 構成世代を静的・OSINT相関で推定 | 4 |
| 版不明（既知・暫定ファミリ） | 441 |
| 版不明（未分類） | 114 |

版名は、静的に回収したsample-specificな設定、またはexact SHA-256に結び付く外部報告がある場合だけ使用します。runtime、依存package、packer、first-seen日、一般的なファミリ記事だけでは版を決めず、根拠がない場合は `versions/unknown/` に置きます。各ファミリの判定根拠と対象検体は `VERSIONS.md` にまとめています。

未分類114件は既知ファミリへ無理に帰属させていません。84件は低信頼の暫定cluster、30件は未解決として区別し、いずれも版は不明です。

## マルウェアファミリ

各 `README.md` から、概要、開発・販売主体、利用アクター、コモディティ／MaaS性、過去の攻撃事例、技術解析、版情報へ移動できます。詳細なOSINTと出典は各 `OSINT.md` にあります。

- [Agent Tesla](malware/agenttesla/README.md)
- [Amadey](malware/amadey/README.md)
- [Atomic macOS Stealer（AMOS、アトミックmacOSスティーラー）](malware/amosstealer/README.md)
- [AsyncRAT](malware/asyncrat/README.md)
- [AtlasCross／Atlas RAT](malware/atlascross/README.md)
- [CHUD Bot（暫定）](malware/chud-bot/README.md)
- [Condi](malware/condi/README.md)
- [DarkComet](malware/darkcomet/README.md)
- [DCRat](malware/dcrat/README.md)
- [DonutLoader](malware/donutloader/README.md)
- [Efimer](malware/efimer/README.md)
- [Formbook](malware/formbook/README.md)
- [GuLoader](malware/guloader/README.md)
- [HijackLoader](malware/hijackloader/README.md)
- [JiProxy UDP relay（暫定）](malware/jiproxy-relay/README.md)
- [Latrodectus](malware/latrodectus/README.md)
- [JOMANGY](malware/jomangy/README.md)
- [JackSkid](malware/jackskid/README.md)
- [Lumma Stealer](malware/lummastealer/README.md)
- [njRAT](malware/njrat/README.md)
- [Mirai派生ENS/DoH Bot](malware/mirai-derived-ens-doh-bot/README.md)
- [ProtectionAgent保護.NETローダー](malware/protection-agent-loader/README.md)
- [Proxyrack PoPクライアント不正デプロイヤー](malware/proxyrack-pop-deployer/README.md)
- [PureHVNC／PureRAT](malware/purehvnc/README.md)
- [QuasarRAT](malware/quasarrat/README.md)
- [RedLine Stealer](malware/redlinestealer/README.md)
- [Remcos RAT](malware/remcosrat/README.md)
- [Remus Stealer](malware/remusstealer/README.md)
- [ShadowPad](malware/shadowpad/README.md)
- [Snake Keylogger](malware/snakekeylogger/README.md)
- [SoftBot（Mirai派生）](malware/softbot/README.md)
- [SpyGlace](malware/spyglace/README.md)
- [StealC](malware/stealc/README.md)
- [TraffMonetizer不正デプロイヤー](malware/traffmonetizer-deployer/README.md)
- [ValleyRAT](malware/valleyrat/README.md)
- [VenomRAT](malware/venomrat/README.md)
- [Vidar](malware/vidar/README.md)
- [WannaCry](malware/wannacry/README.md)
- [XWorm](malware/xworm/README.md)
- [未分類検体](malware/unclassified/README.md)
- [XMRig](malware/xmrig/README.md)

## 収集単位

collectionは検体の別コピーではなく、収集時点のmembershipとファミリ別集約成果物を保持します。

- [2026-07-15 refresh：9ファミリ／90件](collections/refresh-20260715/README.md)
- [2026-07-16 VX-Underground：118件](collections/vx-underground-20260716/README.md)
- [2026-07-17 MalwareBazaar 10ファミリ：100件](collections/malwarebazaar-20260717/README.md)
- [2026-07-17 MalwareBazaar未分類：100件](collections/malwarebazaar-unknown-20260717/README.md)
- [MalwareBazaar 1000検体解析（進行中、batch-0001～0009：89件解析済み／1件取得待ち）](research/malwarebazaar/batches/README.md)

## 横断調査

- [未完了・未スクリプト化項目の追加解析と全体監査](research/audits/static-analysis-audit-20260717/README.md)
- [難解析80件／静的解析155 layer](research/audits/static-hard-cases/README.md)
- [unpacking再評価](research/audits/unpacking-reassessment-20260715.md)
- [SpyGlace／APT-C-60攻撃キャンペーン](research/campaigns/spyglace/apt-c60-2026/README.md)
- [AtlasCross／Silver Fox偽VPNキャンペーン](research/campaigns/atlascross/silver-fox-vpn-2026/README.md)
- [npm axios／plain-crypto-jsサプライチェーン侵害](research/supply-chain/npm/axios-plain-crypto-js-2026/cases/e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09/README.md)
- [Trivy／TeamPCPサプライチェーン事案](research/supply-chain/trivy-teampcp-2026/README.md)
- [CVE-2026-3055](research/vulnerabilities/cve-2026-3055/README.md)
- [2026-04-01セキュリティニュース調査](research/news/20260401/README.md)

## IOCの再生成と検証

個別case、campaign、incidentには、人間向け `README.md` とIOC専用 `IOC-LIST.md` を置きます。全件索引は [`IOC-INDEX.md`](IOC-INDEX.md) です。`IOC-LIST.md` は生成物なので直接編集せず、元の `README.md`、`iocs.json`、`config.json`、`analysis_history.yaml` を修正してから再生成します。

```powershell
python .\analysis-framework\common\generate_ioc_lists.py --repository .
python .\analysis-framework\common\generate_ioc_lists.py --repository . --check
```

埋め込みURLやIPは、それだけでは稼働中C2やファミリ専用インフラを意味しません。配布先、stage取得先、C2候補、公開IP確認サービスなどの役割を分離し、確度と根拠を併記しています。Sigma／YARAは検知仮説であり、環境別の検証が必要です。

## 公開JSONの境界

プロバイダーの生応答は、git管理外の `.work/` にだけ保存します。公開前にMalwareBazaarの応答を許可項目だけの要約へ変換し、メールアドレス様の値を除去したうえで、書込みなしの監査を通します。

```powershell
python .\analysis-framework\common\sanitize_public_results.py --root .\analysis-results --write
python .\analysis-framework\common\sanitize_public_results.py --root .\analysis-results
```

公開要約に残すのは、exact sample hash、初回／最終観測時刻、size、file type／MIME、signature、tagだけです。資格情報、token、query、fragment、復元secret、安全検査ログは公開しません。
