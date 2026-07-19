# AIセキュリティ解析

AIを補助的に使い、マルウェア検体の静的解析、キャンペーン分類、C2／IOC整理、検知ルール作成材料の管理を行うためのリポジトリです。現在は39の既知・暫定マルウェアファミリ、未分類検体、サプライチェーン調査を含む603件のSHA-256 caseを扱い、解析コードは `analysis-framework/`、公開可能な解析結果は `analysis-results/`、過去解析の索引は `analysis_history.yaml` に分離しています。ファミリ別のOSINT、版根拠、全case一覧は [解析成果物](analysis-results/README.md) を参照してください。

> **安全上の前提**: このリポジトリには検体本体、抽出した実行可能ファイル、復号バイナリ、PCAP、Ghidra project、資格情報を保存しません。保存対象はレポート、メタデータ、IOC、テキスト化した逆アセンブル、検知ルール候補など公開可能な成果物に限定します。

## リポジトリ構成

```text
analysis-framework/              # 解析・分類を実行するコード
  Invoke-Analysis.ps1            # 自動解析のエントリポイント
  common/                        # ZIP/MSI/CAB/PE調査、C2確認、Ghidra連携などの共通処理
  classifiers/                   # 検体から malware_type / campaign_type を選ぶ分類器
  registry/                      # malware_type と detector の登録
  malware/<malware-type>/        # 種別固有の detector / campaign handler / config / docs / tests
emulators/                      # 防御目的のプロトコルエミュレータ
  <malware-type>/               # マルウェア種別ごとの安全な通信再現ツール
analysis-results/                # 検体を含まない公開可能な解析結果
  malware/<family>/              # マルウェアファミリー別の概要
    versions/<version-key>/cases/<sha256>/ # 版・検体SHA-256ごとのレポートと成果物
  collections/<collection-id>/   # 収集元・収集日別の検体集合と集約成果物
  research/<topic>/              # キャンペーン、脆弱性、ニュース、横断調査
  IOC-INDEX.md                    # 全解析のIOC-only一覧への索引
analysis_history.yaml            # 過去解析の一覧とREADME用サマリの元データ
README.md                        # このファイル
```

新しいマルウェア種を追加するときは、独立したトップレベルディレクトリを増やさず、解析コードを `analysis-framework/malware/<type>/`、結果を `analysis-results/malware/<family>/versions/<version-key>/`、防御目的の通信再現ツールを `emulators/<type>/` に追加します。共通化できる処理や識別器は `analysis-framework/common/` または `analysis-framework/classifiers/` へ昇格します。

## インストール方法

### 1. 前提ツール

- Windows PowerShell 5.1 以降、または PowerShell 7 以降
- Python 3.11 以降
- 解析用の隔離環境（VM/サンドボックス推奨）
- 任意: Ghidra、FLOSS、YARA、Sigma変換/検証ツール、Shodan CLI/API

### 2. Python仮想環境の作成

```powershell
cd <repo-root>\analysis-framework
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Linux/macOS上で静的メタデータ確認だけを行う場合は以下でも構いません。

```bash
cd <repo-root>/analysis-framework
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. 動作確認

```powershell
python .\classifiers\classify_sample.py --help
python .\common\analyze_submission.py --help
python .\common\c2_detector.py --help
```

`Invoke-Analysis.ps1` の既定Pythonパスはローカル環境向けに固定されているため、通常は `-Python` で作成した仮想環境の `python.exe` を明示してください。

## 利用方法

### 基本フロー

1. 検体を隔離環境に置き、検体のSHA-256を控えます。
2. `classify_sample.py` が `analysis-framework/registry/malware_types.json` に登録された detector を読み込み、`malware_type` と `campaign_type` を選びます。
3. `Invoke-Analysis.ps1` が campaign handler を呼び出し、復号、MSI/CAB解析、C2抽出などを行います。
4. 結果を `analysis-results/malware/<family>/versions/<version-key>/cases/<sample-sha256>/` に整理し、検体・復号バイナリなど保存禁止物が含まれないことを確認します。
5. `analysis_history.yaml` に解析履歴を1件追加し、READMEの履歴サマリも更新します。
6. IOC-only一覧を再生成し、`--check` で全解析との同期を確認します。

### 分類のみ実行

```powershell
python .\analysis-framework\classifiers\classify_sample.py `
  --sample C:\malware-lab\samples\sample.zip `
  --registry .\analysis-framework\registry\malware_types.json `
  --output C:\malware-lab\out\classification.json
```

分類結果には以下が含まれます。

- `malware_type`: 登録済み種別。現在は主に `valleyrat`。
- `campaign_type`: campaign handler を選ぶための分類。例: `dll_sideload_vvas_bundle`, `msi_embedded_cab_custom_actions`。
- `*_confidence`: hash一致、構造一致などに基づく信頼度。
- `candidates`: detector が見つけた候補と理由。
- `observations`: SHA-256、サイズ、ZIP member、MSI/OLE構造など。

### 自動解析の実行

DLL side-loading + vvaS bundle のように reviewed profile が必要なケース:

```powershell
.\analysis-framework\Invoke-Analysis.ps1 `
  -Sample C:\malware-lab\samples\sample.zip `
  -OutputDirectory C:\malware-lab\out\<sha256> `
  -ProfilePath .\analysis-framework\malware\valleyrat\config\profiles\<sha256>.json `
  -Python .\analysis-framework\.venv\Scripts\python.exe
```

MSI/CAB custom action 系のケース:

```powershell
.\analysis-framework\Invoke-Analysis.ps1 `
  -Sample C:\malware-lab\samples\sample.zip `
  -OutputDirectory C:\malware-lab\out\<sha256> `
  -Python .\analysis-framework\.venv\Scripts\python.exe
```

ライブC2確認は、review済み profile に `live_c2_targets` がある場合に限り、明示的に有効化します。

```powershell
.\analysis-framework\Invoke-Analysis.ps1 `
  -Sample C:\malware-lab\samples\sample.zip `
  -OutputDirectory C:\malware-lab\out\<sha256> `
  -ProfilePath .\analysis-framework\malware\valleyrat\config\profiles\<sha256>.json `
  -AllowLiveC2Check `
  -CollectJarm `
  -Python .\analysis-framework\.venv\Scripts\python.exe
```

ライブC2確認は外部ホストへの通信を伴います。隔離環境、許可された調査範囲、送信データの最小化、ログ保存方針を確認したうえで実行してください。

## 解析結果の見方

### 結果ディレクトリ

`analysis-results/malware/<family>/versions/<version-key>/cases/<sha256>/` 配下の `README.md` が人間向けの入口です。各ケースのREADMEでは、少なくとも以下を確認します。

- **判定とチェーン**: malware type、campaign type、感染/実行チェーン、信頼度。
- **ファイルIOC**: submitted sample、embedded object、loader、payload、decoyなどのSHA-256。
- **C2/通信IOC**: domain/IP/port、process帰属、信頼度、配布先とC2の分離。
- **Sigma/YARA材料**: 使える条件、避けるべき単独条件、誤検知の注意点。
- **制約**: ローカル実行やライブ接続の有無、未取得stage、未検証事項。

各個別解析には、説明を除いたIOC専用の `IOC-LIST.md` も置きます。横断索引は [analysis-results/IOC-INDEX.md](analysis-results/IOC-INDEX.md) です。README、構造化IOC、config、解析履歴を更新した後は次を実行してください。

```powershell
python .\analysis-framework\common\generate_ioc_lists.py --repository .
python .\analysis-framework\common\generate_ioc_lists.py --repository . --check
```

生成一覧は `種別 / 値 / 役割 / 確度 / 根拠` の5列だけを持ち、URLの資格情報・クエリ・フラグメント、正規署名付きホスト、文脈専用値、Shodan/Sigma/YARAクエリを除外します。公開可能なIOCがない解析にも空の標準表を生成します。

### 自動解析出力の代表例

- `classification.json`: detector による `malware_type` / `campaign_type` 選択結果。
- `run-summary.json`: 実行した handler、ローカル実行有無、ライブC2確認有無。
- `submission-analysis.json`: ZIP/MSI/CAB/PEを再帰的に調べたメタデータ。
- `extraction-result.json`: 安全展開の結果。
- `file-inventory.csv`: bundle内ファイルの一覧、hash、サイズなど。
- `decoded-analysis/vvas-static-summary.json`: vvaS shellcode の marker、C2、port、API hash など。
- `msi-analysis.json`, `msi-chain-c2-analysis.json`: MSI/OLE/CAB/custom action とC2抽出結果。
- `c2-live/*.json`: 明示的に許可した限定C2 probeの結果。

### 判定ラベルの読み方

- **confirmed / 高信頼**: 復号config、process帰属付き通信、限定protocol応答など、複数根拠で確認。
- **inferred / 中信頼**: 構造や周辺証跡から強く示唆されるが、通信やpayloadまでは直接確認していない。
- **unverified / 未検証**: 参考情報。検知条件に使う場合は追加検証が必要。

## 解析履歴サマリ

履歴の正本はプロジェクト直下の `analysis_history.yaml` です。READMEでは、マルウェア種、解析回数、最後の解析日を以下に要約します。

| マルウェア種 | 解析回数 | 最後の解析日 | 主な解析パターン |
|---|---:|---|---|
| ValleyRAT | 12 | 2026-07-16 | 従来パターンと `cefclient_libcef_sideload_malspam` |
| AgentTesla | 10 | 2026-07-13 | `unicode_marker_powershell_png_stage`, `javascript_aes_inmemory_dotnet`, `fromcharcode_eval_loader`, `rar_wrapped_javascript` |
| RemcosRAT | 10 | 2026-07-13 | VBS/JS/HTAローダー、直接PE、ISO二重拡張子による配布 |
| MX-Go（未分類） | 1 | 2026-07-15 | Go製一括メール送信エンジン、遠隔コンテンツ／設定、HTTPキャンペーン制御、日本環境ゲート |
| npmサプライチェーン | 1 | 2026-07-16 | `axios_plain_crypto_js` のpostinstall静的復号 |
| AtlasCross / Atlas RAT | 1 | 2026-07-16 | `silver_fox_vpn_2026` の設定アルゴリズムとプロトコル証拠 |
| ShadowPad | 8 | 2026-07-16 | ScatterBee OLEVIEWチェーン、x86/x64 Casper設定、nsPack完全一致ハッシュ相関 |
| StealC | 41 | 2026-07-16 | v1設定を5件復号、保護／ラップ済み外層36件を静的解析の未解決ケースとして保持 |
| Condi | 5 | 2026-07-18 | XOR設定、攻撃・スキャナー・killer、UPX系譜、配布ローダー |
| Linux ENS/SNS Bot（暫定） | 1 | 2026-07-18 | ENSによる動的IP解決、暗号化記述子、静的ポート表 |
| CHUD Bot（暫定） | 4 | 2026-07-19 | PowerPC/ARM、UPX系譜、複数init永続化、ループバックchallenge/tagプロトコル |
| Efimer | 4 | 2026-07-19 | PyInstaller/PyArmor、検体別XOR鍵、JavaScript配列回転、Tor v3 C2 |
| PUTA v3（Putita） | 4 | 2026-07-19 | x86/ARMv5、UPX系譜、認証付き設定復号、暗号化C2、13攻撃ID |
| GendDDoS（Ohshitクラスタ） | 2 | 2026-07-19 | ARMv6/ARMv7、XORテーブル、DNS fallback、14攻撃ハンドラ |
| Eclipse DDoS Bot（暫定） | 6 | 2026-07-19 | x86-64/i586/ARM/M68K/MIPS LE、平文命令、永続化、競合排除 |
| JackSkid | 1 | 2026-07-19 | 独自テーブル暗号、ENS/SNS名前解決、Telnet走査、anti-VM |
| FreePBX K.php侵害スクリプト | 1 | 2026-07-19 | 再帰Base64、WebShell、管理者追加、cron再感染、設定窃取 |
| MIG Logcleaner | 1 | 2026-07-19 | v2.0、wtmp/utmp/lastlog改変、ネットワーク機能なし |
| HTML認証情報フィッシング | 1 | 2026-07-19 | form送信先抽出、秘密値非保持、共有サービスとC2の分離 |
| カスタム保護PEローダー（暫定） | 1 | 2026-07-19 | 保護外層、次段・設定・C2未解決 |
| Sobfox Launcher（暫定） | 1 | 2026-07-19 | ランチャー外層、次段・設定・C2未解決 |
| インフラ用デコイHTA（暫定） | 1 | 2026-07-19 | 能動コード・次段・C2を確認できないnegative capability評価 |
| WannaCry | 3 | 2026-07-19 | PlayGame外層、内包PE・暗号化XIA、キルスイッチ、Tor v2 C2 |
| JOMANGY | 4 | 2026-07-19 | 多層Base64/ROT13、FreePBX webshell、UID 0/cron永続化、設定窃取相と配布相の分離 |
| Linux複数ペイロードBotローダー（暫定） | 3 | 2026-07-19 | `/proc`競合排除、5次段配布、`pdvr`/`lilin`引数、配布先と最終C2の分離 |
| Electronペイロードローダー（暫定） | 1 | 2026-07-19 | NSIS/Electron難読化、Defender除外、子Go合成ワークロード |
| Mirai派生ENS/DoH Bot | 3 | 2026-07-19 | PowerPC/MIPS/ARM、ChaCha20設定、TCP C2、DoH/ENS補助解決、Telnet走査 |

### ValleyRAT 解析履歴

| 解析日 | SHA-256 prefix | Campaign / chain | 解析レベル | 主なC2 |
|---|---|---|---|---|
| 2026-07-12 | `8bf54a76` | `dll_sideload_vvas_bundle` | 静的深掘り＋限定的なライブC2確認 | `202.95.8.27:6666`, `202.95.8.27:8888` |
| 2026-07-10 | `b433ecdf` | `msi_embedded_cab_custom_actions` | 静的深掘り＋サンドボックス証拠 | `www.tq8j.com:443`, `103.45.64.246:443` |
| 2026-07-12 | `942be7e0` | `installer_overlay_dropper` | 静的解析＋サンドボックス証拠 | `150.158.50.175:443` |
| 2026-07-12 | `eab4918e` | `single_pe_direct` | 静的解析＋サンドボックス証拠 | `154.81.37.130:4444`, `154.81.37.130:5555` |
| 2026-07-12 | `15015ac7` | `dll_sideload_vvas_bundle` | static decode | `134.122.128.66:6666`, `134.122.128.66:8888` |
| 2026-07-11 | `5bdcf2d4` | `installer_overlay_dropper` | 静的解析＋サンドボックス証拠 | `27.124.18.166:63016`, `27.124.18.166:63026` |
| 2026-07-11 | `0e4931df` | `msi_embedded_pe_staged_download` | 静的解析＋サンドボックス証拠 | `8.210.15.149:28300` |
| 2026-07-15 | `d11e7931` | `single_pe_n520_managed` | 静的深掘り＋範囲限定プロトコル検証 | 設定 `118.107.21.88:9000`、C2 `118.107.21.88:9999` |
| 2026-07-15 | `df603ed5` | `inno_installer_silverfox_unresolved` | 静的解析＋公開証拠の相関 | 推定 `oidng2.duoshit.com:443` / `51.79.18.52:443` |
| 2026-07-15 | `6546aad6` | `upx_nrv2e_silverfox_http_bundle` | 静的深掘りによる復元 | 配布 `43.198.235.91:80`、最終C2は未解決 |
| 2026-07-15 | `32146526` | `qt_static_obfuscated_silverfox` | 静的解析＋DNS相関 | `cqbxbkj.cn` / `18.167.91.239`、ポート `8880` は未検証 |
| 2026-07-16 | `f543dcf4` | `cefclient_libcef_sideload_malspam` | 情報源／公開成果物の相関 | `ljowqjd.cn`、最終設定は取得不能 |

### AgentTesla / RemcosRAT 解析履歴

- AgentTesla: 10検体。FTP/SMTP設定、Unicodeマーカー/画像ステージ、AES/PowerShellメモリ内.NET、RARラッパーを整理しました。
- RemcosRAT: 10検体。VBS/JS/HTA、直接PE、ISO二重拡張子を整理し、設定またはプロセス帰属付き証跡からC2を記録しました。
- 20検体すべてでAES認証、内側SHA-256、family/campaign分類の回帰テストに合格しています。
- 検体本体、復号payload、FTP/SMTP認証情報は公開成果物に含めていません。

`analysis_history.yaml` の各要素には、解析日、検体SHA-256、解析レベル、campaign type、マッチした解析パターン、主要C2、結果ディレクトリ、補足メモを入れます。READMEの表を更新する際は、このYAMLを先に更新してください。

## ルール・IOC運用時の注意

- IPアドレス単独、ファイル名単独、`rundll32.exe` 単独などの条件は短寿命または誤検知が多いため、hash、署名状態、親子関係、image load、process帰属付き通信と組み合わせます。
- 正規署名付きhostやdecoy installerは、bundle内での同居関係や悪性DLL loadがない限り、単体で悪性判定しません。
- OSS/Tencent COSなどの配布先と、最終C2は分離して記録します。
- ライブC2確認結果は時点依存です。READMEやYAMLには確認日と手法を残し、検知ルールでは構造条件を優先します。

## 参考ドキュメント

- [analysis-framework/README.md](analysis-framework/README.md): 解析フレームワーク概要
- [analysis-framework/malware/valleyrat/README.md](analysis-framework/malware/valleyrat/README.md): ValleyRAT固有解析
- [analysis-framework/malware/valleyrat/docs/VALLEYRAT-WORKFLOW.md](analysis-framework/malware/valleyrat/docs/VALLEYRAT-WORKFLOW.md): ValleyRAT解析ワークフロー
- [analysis-results/README.md](analysis-results/README.md): 公開可能な結果の保存方針
- [analysis-results/malware/valleyrat/README.md](analysis-results/malware/valleyrat/README.md): ValleyRAT結果一覧
- [analysis-results/malware/valleyrat/BEHAVIOR-C2.md](analysis-results/malware/valleyrat/BEHAVIOR-C2.md): 感染チェーン別の挙動、C2役割、確度、N520プロトコル

### 新規開発メモ: マルウェア種指定とSandbox evidence

- `analysis-framework/classifiers/classify_sample.py` は `--malware-type <registered-type>` を受け付け、登録済み detector のうち指定種別だけを実行できます。種別指定は handler 選択の補助であり、campaign type は引き続き構造証跡に基づいて選びます。
- `analysis-framework/Invoke-Analysis.ps1` では `-MalwareType` で同じ指定ができます。
- `analysis-framework/common/vt_sandbox.py` は VirusTotal の file behaviours relationship から sandbox verdict、process、domain/IP を正規化し、`virustotal-sandbox.json` として保存します。VirusTotal 情報は相関用 evidence であり、IP/domain 単独では C2 確定に使いません。
- [analysis-results/malware/agenttesla/README.md](analysis-results/malware/agenttesla/README.md): AgentTesla結果一覧
- [analysis-results/malware/remcosrat/README.md](analysis-results/malware/remcosrat/README.md): RemcosRAT結果一覧

## VenomRATの解析（2026-07-15）

レビュー済み7ケースを `analysis-results/malware/venomrat/` 配下に記録しています。内訳は、ユーザー提供の日本国内観測Triage提出物4件と、MalwareBazaarから取得して静的解析した検体3件です。再利用可能な検出器とリソース／設定トリアージツールは `analysis-framework/malware/venomrat/` 配下にあります。

## MX-Go未分類クラスタ（2026-07-15）

Triage提出物1件を復元して静的解析しました。ペイロードはGo 1.26.1製の遠隔制御型一括メール送信スパムボットであり、汎用RATではありません。解析ツールは `analysis-framework/malware/unclassified/mx_go/`、正規化済み結果、C2／コンテンツ基盤、Sigma／YARA材料は `analysis-results/malware/unclassified/groups/mx-go/` 配下にあります。ループバック限定のC2／コンテンツサーバーとクライアントエミュレーターは `emulators/unclassified/mx_go/` 配下にあり、`c2_detector.py` の能動MX-Goモードもループバックだけを許可します。

## 宣言型解析の設計

- [次期宣言型解析基盤の設計・スキーマ・移行計画](analysis-framework/docs/README.md)

## 宣言型エンジンと設定抽出器

- `analysis-framework/src/asa/`: 厳格なYAML検証、条件DSL、ファミリー／キャンペーン採点、DAGコンパイル、オフラインポリシー適用
- `analysis-framework/definitions/`: 29件のマルウェア定義、31件のワークフロー、既定のオフラインポリシー。現在は21ファミリーを `analysis-framework/registry/malware_types.json` に登録済み
- `extractors/`: SpyGlace／APT-C-60、ValleyRAT、AgentTesla、RemcosRAT、VenomRAT、MX-Go、Formbook、Vidar、LummaStealer、RemusStealer、AMOS、PureHVNC、DonutLoaderなど、共通契約に従う設定抽出器
- `docs/pydoc/`: 自動生成したPython API文書

現行エンジンは計画を検証・コンパイルした後、許可リストにあるオフライン静的解析手順を実行します。検体の起動や外部インフラへの接続は行わず、FLOSSとGhidra MCPの連携も事前確認だけです。

## スティーラー一括解析（2026-07-15）

MalwareBazaarの最近の提出物50件を静的解析しました。内訳はFormbook、Vidar、LummaStealer、RemusStealer、Atomic macOS Stealer（AMOS）が各10件です。結果は `analysis-results/malware/<family>/`、共有静的アンパック処理は `unpackers/`、オフラインC2評価は `analysis-framework/common/c2_candidate_detector.py`、合成プロトコル検証環境はループバック限定で `emulators/stealers/` 配下にあります。

## MalwareBazaar再収集（2026-07-15）

未収集だったMalwareBazaar提出物90件を静的解析しました。内訳はValleyRAT、AgentTesla、RemcosRAT、VenomRAT、Formbook、Vidar、LummaStealer、RemusStealer、AMOSが各10件です。宣言型実行90件はすべて `ready` で完了し、検体や抽出インフラには接続していません。[ファミリー横断の再収集レポート](analysis-results/collections/refresh-20260715/REPORT.md)と、同コレクションの `sources/<family>/` を参照してください。ケース本体は各ファミリーの固定階層へ保存します。

取得ツールは既存結果ツリーのハッシュを除外し、共通パイプラインは上記9ファミリーすべてに対応します。公開マニフェストからはローカル検体パスを除外します。

## PureHVNCとDonutLoaderへの対応

ネイティブPureHVNCと、CHRD／WAVを用いるDonutLoaderからPureRATへ至るチェーンについて、宣言型ファミリー／ワークフロー定義、静的アンパッカー、設定抽出器、受動的C2検索計画生成器、ループバック限定プロトコル検証環境、Python API文書、テスト、ケースレポートを追加しました。生の実行可能ファイルや復元済み実行可能ファイルはリポジトリに保存していません。

## APT-C-60／SpyGlaceの2026年解析

JPCERT/CCが報告した2026年の配布チェーンについて、リポジトリ履歴インベントリ、安全なLNK／Base64／TAR再構築、反復XORによるPE復元、v3.1.15設定抽出器、受動的C2ピボット、ループバック限定プロトコル検証環境、宣言型YAML、テスト、Python API文書、Sigma／YARA、公開可能な結果までを一貫して扱います。[キャンペーンレポート](analysis-results/research/campaigns/spyglace/apt-c60-2026/README.md)と[オフラインワークフロー](docs/APT-C60-2026-WORKFLOW.md)を参照してください。v3.1.15成果物4件から設定を抽出済みで、マルウェアやC2の実行・接続は行っていません。

## VX-Undergroundファミリー解析（2026-07-16）

共有オフラインパイプラインを提出物118件へ適用しました。内訳はDonutLoader 2件、AMOS 2件、Vidar 25件、Amadey 35件、Latrodectus 54件です。現行形式のDonutとXORラッパーを静的に復元し、連結されたXZ／AppleディスクイメージとユニバーサルMach-Oの各レイヤーを再構築しました。取得できたAmadey、Latrodectus、Vidarの設定は検証後に抽出しました。

ケースは各ファミリーの `analysis-results/malware/<family>/versions/<version-key>/cases/`、収集元との対応と集約成果物は `analysis-results/collections/vx-underground-20260716/` 配下にあります。生バイナリと復元バイナリは除外しています。検体を実行せず、抽出したインフラにも接続していません。

## MalwareBazaar未分類最新100件（2026-07-17）

ファミリーシグネチャが空で、発見タグが `unknown`、`stealer`、`infostealer` のいずれかである未解析のMalwareBazaar最新100件を、`first_seen` の降順で静的解析しました。7件には中確度の内部根拠があり、63件には低確度の暫定ファミリー候補が残り、30件は未分類のままです。結果、静的IOC候補、YARA材料は[MalwareBazaar未分類コレクション](analysis-results/collections/malwarebazaar-unknown-20260717/sources/unclassified/README.md)にあります。検体や復元ペイロードを実行せず、抽出したインフラにも接続していません。

## プロファイル定義によるファミリー拡張（2026-07-17）

AsyncRAT、XWorm、QuasarRAT、njRAT、DarkComet、DCRat、RedLine Stealer、Snake Keylogger、GuLoader、HijackLoaderは現在、プロファイル駆動の検出、設定抽出、受動的C2計画、宣言型YAML、合成データ用ループバック限定エミュレーターを共有しています。各ファミリーについてMalwareBazaarの最新10検体を静的解析し、計100件が最終的な完全性／安全性検証に合格しました。取得処理は再試行キューを永続化するため、時間制限または回数制限に達したハッシュをほかの解析後に再開できます。[関係とワークフロー文書](analysis-framework/docs/PROFILED-FAMILY-EXPANSION.md)を参照してください。

## MalwareBazaar 1000検体解析（batch-0001～0003、2026-07-18～19）

新着順から既処理SHA-256を除外し、選定を各バッチの初回取得時に固定して解析しています。[batch-0001](analysis-results/research/malwarebazaar/batches/batch-0001/README.md)と[batch-0002](analysis-results/research/malwarebazaar/batches/batch-0002/README.md)は各10件完了しました。[batch-0003](analysis-results/research/malwarebazaar/batches/batch-0003/README.md)は9件を解析済みで、選定後にMalwareBazaar APIから消えた1件を取得待ちとして保持しています。後着検体へ通知なく置換しません。

復元できた正確な候補だけに、TCP connectまたはTor SOCKS CONNECTまでの限定検証を行いました。アプリケーションデータ、認証情報、マルウェア登録値は送信せず、TCP到達をC2確定に使いません。配布先、共有サービス、ローカル制御先、キルスイッチをC2と分離し、検体自体は一切実行していません。現在は29件解析済み、1件取得待ちです。
