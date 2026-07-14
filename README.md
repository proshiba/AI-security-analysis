# AI Security Analysis

AIを補助的に使い、マルウェア検体の静的解析、キャンペーン分類、C2/IOC整理、検知ルール作成材料の管理を行うためのリポジトリです。現時点の主な対象は **ValleyRAT** で、解析コードは `analysis-framework/`、公開可能な解析結果は `analysis-results/`、過去解析の索引は `analysis_history.yaml` に分離しています。

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
  <malware-type>/cases/<sha256>/ # 検体SHA-256ごとのレポートと成果物
analysis_history.yaml            # 過去解析の一覧とREADME用サマリの元データ
README.md                        # このファイル
```

新しいマルウェア種を追加するときは、独立したトップレベルディレクトリを増やさず、解析コードを `analysis-framework/malware/<type>/`、結果を `analysis-results/<type>/`、防御目的の通信再現ツールを `emulators/<type>/` に追加します。共通化できる処理や識別器は `analysis-framework/common/` または `analysis-framework/classifiers/` へ昇格します。

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
4. 結果を `analysis-results/<malware-type>/cases/<sample-sha256>/` に整理し、検体・復号バイナリなど保存禁止物が含まれないことを確認します。
5. `analysis_history.yaml` に解析履歴を1件追加し、READMEの履歴サマリも更新します。

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

`analysis-results/<malware-type>/cases/<sha256>/` 配下の `README.md` が人間向けの入口です。各case READMEでは、少なくとも以下を確認します。

- **判定とチェーン**: malware type、campaign type、感染/実行チェーン、信頼度。
- **ファイルIOC**: submitted sample、embedded object、loader、payload、decoyなどのSHA-256。
- **C2/通信IOC**: domain/IP/port、process帰属、信頼度、配布先とC2の分離。
- **Sigma/YARA材料**: 使える条件、避けるべき単独条件、誤検知の注意点。
- **制約**: ローカル実行やライブ接続の有無、未取得stage、未検証事項。

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
| ValleyRAT | 11 | 2026-07-15 | `dll_sideload_vvas_bundle`, `msi_embedded_cab_custom_actions`, `installer_overlay_dropper`, `single_pe_direct`, `msi_embedded_pe_staged_download`, `single_pe_n520_managed`, `inno_installer_silverfox_unresolved`, `upx_nrv2e_silverfox_http_bundle`, `qt_static_obfuscated_silverfox` |
| AgentTesla | 10 | 2026-07-13 | `unicode_marker_powershell_png_stage`, `javascript_aes_inmemory_dotnet`, `fromcharcode_eval_loader`, `rar_wrapped_javascript` |
| RemcosRAT | 10 | 2026-07-13 | VBS/JS/HTA loaders, direct PE, ISO double-extension delivery |
| MX-Go (unclassified) | 1 | 2026-07-15 | Go bulk-mail engine, remote content/config, HTTP campaign control, Japan environment gate |

### ValleyRAT 解析履歴

| 解析日 | SHA-256 prefix | Campaign / chain | 解析レベル | 主なC2 |
|---|---|---|---|---|
| 2026-07-12 | `8bf54a76` | `dll_sideload_vvas_bundle` | deep static + limited live C2 | `202.95.8.27:6666`, `202.95.8.27:8888` |
| 2026-07-10 | `b433ecdf` | `msi_embedded_cab_custom_actions` | deep static + sandbox evidence | `www.tq8j.com:443`, `103.45.64.246:443` |
| 2026-07-12 | `942be7e0` | `installer_overlay_dropper` | static + sandbox evidence | `150.158.50.175:443` |
| 2026-07-12 | `eab4918e` | `single_pe_direct` | static + sandbox evidence | `154.81.37.130:4444`, `154.81.37.130:5555` |
| 2026-07-12 | `15015ac7` | `dll_sideload_vvas_bundle` | static decode | `134.122.128.66:6666`, `134.122.128.66:8888` |
| 2026-07-11 | `5bdcf2d4` | `installer_overlay_dropper` | static + sandbox evidence | `27.124.18.166:63016`, `27.124.18.166:63026` |
| 2026-07-11 | `0e4931df` | `msi_embedded_pe_staged_download` | static + sandbox evidence | `8.210.15.149:28300` |
| 2026-07-15 | `d11e7931` | `single_pe_n520_managed` | deep static + bounded protocol validation | config `118.107.21.88:9000`; C2 `118.107.21.88:9999` |
| 2026-07-15 | `df603ed5` | `inno_installer_silverfox_unresolved` | static + public evidence correlation | inferred `oidng2.duoshit.com:443` / `51.79.18.52:443` |
| 2026-07-15 | `6546aad6` | `upx_nrv2e_silverfox_http_bundle` | deep static recovery | distribution `43.198.235.91:80`; final C2 unresolved |
| 2026-07-15 | `32146526` | `qt_static_obfuscated_silverfox` | static + DNS correlation | `cqbxbkj.cn` / `18.167.91.239`; port `8880` unverified |

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
- [analysis-results/valleyrat/README.md](analysis-results/valleyrat/README.md): ValleyRAT結果一覧
- [analysis-results/valleyrat/BEHAVIOR-C2.md](analysis-results/valleyrat/BEHAVIOR-C2.md): 感染チェーン別の挙動、C2役割、確度、N520 protocol

### 新規開発メモ: マルウェア種指定とSandbox evidence

- `analysis-framework/classifiers/classify_sample.py` は `--malware-type <registered-type>` を受け付け、登録済み detector のうち指定種別だけを実行できます。種別指定は handler 選択の補助であり、campaign type は引き続き構造証跡に基づいて選びます。
- `analysis-framework/Invoke-Analysis.ps1` では `-MalwareType` で同じ指定ができます。
- `analysis-framework/common/vt_sandbox.py` は VirusTotal の file behaviours relationship から sandbox verdict、process、domain/IP を正規化し、`virustotal-sandbox.json` として保存します。VirusTotal 情報は相関用 evidence であり、IP/domain 単独では C2 確定に使いません。
- [analysis-results/agenttesla/README.md](analysis-results/agenttesla/README.md): AgentTesla結果一覧
- [analysis-results/remcosrat/README.md](analysis-results/remcosrat/README.md): RemcosRAT結果一覧

## VenomRAT (2026-07-15)

Seven reviewed cases are documented under `analysis-results/venomrat`: four user-provided Japan-observed Triage submissions and three MalwareBazaar static-analysis samples. The reusable detector and resource/configuration triage tool are under `analysis-framework/malware/venomrat`.

## MX-Go unclassified cluster (2026-07-15)

One Triage submission was recovered and statically analyzed. The payload is a Go 1.26.1 remotely controlled bulk-email spam bot, not a general-purpose RAT. Analysis tools are under `analysis-framework/malware/unclassified/mx_go`; normalized results, C2/content infrastructure, and Sigma/YARA material are under `analysis-results/unclassified/mx-go`. A loopback-only C2/content server and client emulator are under `emulators/unclassified/mx_go`; active MX-Go modes in `c2_detector.py` are also loopback-only.
