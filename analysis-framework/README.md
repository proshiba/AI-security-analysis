# 解析フレームワーク

複数のマルウェア種と配布キャンペーンを、検体をローカル実行せずに整理するための解析基盤です。成果物は `analysis-results/malware/<family>/versions/<version-key>/cases/` に分離し、収集単位の集約物は `analysis-results/collections/<collection-id>/` に置きます。

## 推奨する一括静的解析

現在の標準入口は `common/analyze_sample.py` です。ファイルまたはディレクトリを渡すと、上限付きのメモリ内静的アンパック、ルートと復元層に対する全登録検出器の評価、既存解析関数の棚卸し、汎用トリアージ、適用可能な設定抽出器の全層試行、特徴的な関数／スクリプトのロジック記録、全体フロー文書、fingerprint生成、挙動・検体特徴profile、campaign自動label、SHA-256単位の統合レポート作成までを一括で行います。

```powershell
python .\common\analyze_sample.py `
  --input C:\malware-lab\incoming `
  --output C:\malware-lab\analysis-output
```

検体実行、ライブC2接続、外部サービスへの提出は行いません。判定だけを確認する場合は `--assessment-only` を指定します。出力、適用状態、安全境界、旧CLIとの関係は[一括静的解析と解析器適用可否判定](docs/ONE-SHOT-ANALYSIS.md)、関数ロジックと類似性判定は[静的ロジック記録とコード類似性](docs/STATIC-LOGIC-AND-CODE-SIMILARITY.md)、特徴profileとcampaign相関は[検体特徴と攻撃キャンペーン相関](docs/CASE-KNOWLEDGE-CAMPAIGNS.md)を参照してください。

## 従来のファミリー別実行順

1. MalwareBazaarのパスワード付きZIPを `MalwareSamples/<Family>/<SHA256>/<SHA256>.zip` に置く。
2. `Invoke-FamilyBatch.ps1` でAES認証、内側SHA-256、形式、スクリプト層、PEメタデータを抽出する。
3. `classifiers/classify_sample.py` がマルウェア種を決め、その種の `detect.py` が配布/ローダーパターンを選ぶ。
4. 公開サンドボックス証跡がある場合は `parse_triage_report.py` と `extract_triage_config.py` で補完する。ローカル実行結果と混同しない。
5. レビュー済み `config/known-cases.json` から `generate_family_reports.py` で公開用レポートを生成する。
6. `tests/Test-KnownFamilies.ps1` で既知検体を回帰テストする。

```powershell
.\Invoke-FamilyBatch.ps1 `
  -Family agenttesla `
  -SampleRoot C:\Users\Administrator\MalwareSamples\AgentTesla `
  -Python C:\Users\Administrator\Tools\GhidraMCP\.venv\Scripts\python.exe
```

## 主な出力

- `family-triage.json`: 内側メンバーのSHA-256、形式、エントロピー、静的IOC
- `classification.json`: family、campaign pattern、判定理由、信頼度
- `script-layers.json`: 文字コード、難読化候補、反復行、Base64候補
- `triage-evidence.json`: 外部サンドボックス由来のC2、URL、プロセス（ローカル実行ではない）
- `analysis-results/malware/<family>/versions/<version-key>/cases/<sha256>/README.md`: 公開用の検体別結果


ACRStealerタグ集合の巨大化PE、SFX／AutoIt、MSI、ネイティブローダーを安全に分離する手順は[ACRStealer静的解析基盤](malware/acrstealer/README.md)を参照してください。

## 失敗時の確認点

- `encrypted/password`: ZIPパスワードが `infected` か、`pyzipper` が導入済みか確認する。
- `inner hash mismatch`: 処理を停止し、URL、外側ZIP、メンバー名、期待SHA-256を再確認する。
- `unknown`: familyを決め打ちせず、形式・文字列・サンドボックス設定をレビューして新しいhandlerを追加する。
- 大型一行JSで時間がかかる: 汎用正規表現を増やさず、サイズ上限付き抽出とfamily固有handlerを使う。
- Defenderが復号PEを隔離: 保護を無効化せず、メモリ内解析、パスワードZIP、公開サンドボックス証跡を使う。
- C2未抽出: MalwareBazaarタグだけを確定C2に昇格しない。設定抽出またはプロセス帰属付き通信を根拠にする。

## 安全境界

### C2生存確認
C2生存確認は `common/c2_detector.py` に統合されている。profileにレビュー済み`live_c2_targets`があり、実行時に`-AllowLiveC2Check`を指定した場合だけ自動解析の末尾で実行する。TLS対象のJARMは追加で`-CollectJarm`を指定する。詳細は [C2-LIVENESS.md](common/C2-LIVENESS.md) を参照。

## マルウェア種の選択、検出器のルーティング、VirusTotalサンドボックス証拠

`classifiers/classify_sample.py` は次の2つのモードに対応します。

- 既定モードでは、`registry/malware_types.json` に登録されたすべての検出器を実行し、観測した構造または既知のSHA-256からマルウェア種を選択します。
- `--malware-type <registered-type>` は検出対象を登録済みの1種に限定します。解析者が既知の文脈を持って新規解析を始める場合に有用ですが、キャンペーン選択には引き続き検出器の観測が必要です。構造が一致しない場合、明示したファミリー値だけでは `campaign_type: unknown` になります。

実行例:

```bash
python analysis-framework/classifiers/classify_sample.py \
  --sample /path/to/sample.zip \
  --registry analysis-framework/registry/malware_types.json \
  --malware-type valleyrat \
  --output /tmp/classification.json
```

`Invoke-Analysis.ps1` は同じ選択値を `-MalwareType` で渡します。`-VirusTotalApiKey`（または `VT_API_KEY`）を指定すると、VirusTotalサンドボックスの挙動要約も収集できます。取得する `virustotal-sandbox.json` は相関用証拠に限定します。エンドポイントを確認済みC2へ昇格する前に、プロセスへ帰属したサンドボックス通信を、復号済み設定、ローダーチェーン、またはほかの静的証拠と相関しなければなりません。

VirusTotalサンドボックスだけを取得する例:

```bash
python analysis-framework/common/vt_sandbox.py \
  --sha256 <sample-sha256> \
  --api-key "$VT_API_KEY" \
  --output /tmp/virustotal-sandbox.json
```

## 生成物
検体の実行、ライブC2接続、認証情報の公開は既定で行いません。`c2_detector.py` のライブ確認は別途承認された場合だけ利用します。Ghidra MCPはlocalhost限定とし、任意スクリプト実行は無効のままにします。

## リファクタ後の共通I/O

AES-ZIP認証、パス検証、文字コード判定、一括処理の段階、失敗時の確認点は [安全な提出物I/Oと一括処理ワークフロー](docs/SAFE-SUBMISSION-IO.md) を参照してください。
## 次期宣言型解析基盤の設計

ファミリー識別、campaign識別、必要ツール、解析DAGをYAMLで定義し、解析実装を共通step catalogへ
集約した構成は [解析フレームワーク文書](docs/README.md) を参照してください。


## 宣言型オフラインエンジン

`src/asa` パッケージは `definitions/` を検証し、ファミリー／キャンペーン規則を評価し、許可リスト方式のステップカタログと `offline-default` ポリシーを適用して、決定的なDAGをコンパイルします。そのうえで、検体を起動せず外部インフラにも接続せずに、対応する静的解析ステップを実行します。`python -m asa.runtime_cli` を使用し、[実装上の注意](docs/DECLARATIVE-ENGINE-IMPLEMENTATION.md)も参照してください。


## 再現可能なMalwareBazaarファミリー再収集

`common/malwarebazaar_batch.py` は、件数を制限してパスワード保護アーカイブをダウンロードし、一時的なAPI障害を再試行します。また、`analysis-results/` 配下にすでに存在するすべてのSHA-256を除外できます。`common/analyze_stealer_set.py` は、同じ宣言型／静的アンパック／設定／C2パイプラインで、ValleyRAT、AgentTesla、RemcosRAT、VenomRAT、Formbook、Vidar、LummaStealer、RemusStealer、AMOSに対応します。`common/generate_stealer_reports.py` は公開用の取得マニフェストを書き出す際に、ローカルアーカイブのパスを除去します。

```powershell
python common/malwarebazaar_batch.py `
  --signature ValleyRAT `
  --signature AgentTesla `
  --limit 10 `
  --query-limit 100 `
  --exclude-path ..\analysis-results `
  --root C:\Users\Administrator\MalwareSamples\refresh-YYYYMMDD
```

1ファミリーのマニフェストをオフラインパイプラインへ渡し、公開可能な再収集ツリーを生成する例:

```powershell
python common/analyze_stealer_set.py `
  --manifest C:\Users\Administrator\MalwareSamples\refresh-YYYYMMDD\ValleyRAT\manifest.json `
  --output C:\Users\Administrator\malware-lab\refresh-YYYYMMDD\ValleyRAT `
  --definitions definitions

python common/generate_stealer_reports.py `
  --summary C:\Users\Administrator\malware-lab\refresh-YYYYMMDD\ValleyRAT\summary.json `
  --pipeline-root C:\Users\Administrator\malware-lab\refresh-YYYYMMDD\ValleyRAT `
  --destination ..\analysis-results\collections\refresh-YYYYMMDD\sources\valleyrat `
  --acquisition-manifest C:\Users\Administrator\MalwareSamples\refresh-YYYYMMDD\ValleyRAT\manifest.json
```

このワークフローは検体を実行せず、抽出したインフラにも接続しません。復元したレイヤーはリポジトリ外のパスワード保護済み解析アーカイブに保持します。

## ファミリーディレクトリにある生ファイルの解析

`common/analyze_stealer_set.py --input-root` は、検体ごとのZIPが単一メンバーの受け入れ用アーカイブであると仮定せず、ローカルのファミリーディレクトリにある生ファイルを解析します。ディレクトリパスは公開しません。重複ファイルはSHA-256で排除し、復元レイヤーの再帰処理には上限を設け、非常に大きいPEには範囲限定のエントロピー計算とマーカー抽出を使います。

```powershell
python common/analyze_stealer_set.py `
  --input-root C:\malware-lab\vx-underground\Latrodectus `
  --family latrodectus `
  --signature Latrodectus `
  --output C:\malware-lab\out\latrodectus `
  --definitions definitions `
  --sevenzip 'C:\Program Files\7-Zip\7z.exe'
```

現在の共有パイプラインはAmadey、Latrodectus、DonutLoader、Vidar、AMOSに対応します。ファミリーとキャンペーンの選択は宣言型のままとし、静的アンパック、設定抽出、レポート生成、IOC生成は共有モジュールに維持します。

## 新しい検体を優先するMalwareBazaar未分類ワークフロー

`common/malwarebazaar_unknown_batch.py` は `unknown`、`stealer`、`infostealer` タグを照会し、MalwareBazaarのファミリーシグネチャが空の項目だけを残します。結果ツリーに存在するハッシュを除外し、タグ間の重複を排除して、`first_seen` の降順で最大100件を選択します。ダウンロードは暗号化されたまま再開可能であり、認証キーは `MALWAREBAZAAR_AUTH_KEY` からだけ読み取ります。

```powershell
python common/malwarebazaar_unknown_batch.py `
  --root C:\malware-lab\unknown-YYYYMMDD `
  --limit 100 `
  --exclude-path ..\analysis-results

python common/analyze_unknown_set.py `
  --manifest C:\malware-lab\unknown-YYYYMMDD\manifest.json `
  --output C:\malware-lab\unknown-analysis-YYYYMMDD `
  --registry registry\malware_types.json `
  --sevenzip 'C:\Program Files\7-Zip\7z.exe'
```

解析器は、登録済み検出器、リポジトリ内YARA、レビュー済み構造シグネチャ、上限付き再帰アンパック、ASAR解析、静的IOC無害化を使用します。外部タグ、サンドボックスラベル、公開YARA名は手掛かりとして保持しますが、それだけでは根拠のあるファミリー帰属にしません。`--force-hash <sha256>` はパーサー変更後に選択したキャッシュ済みケースを再実行し、`--force` はすべてのキャッシュ済みケースを無視します。抽出したネットワーク値は未確認の静的候補のままとし、このワークフローから接続することはありません。

## ハッシュ限定OSINT補強

`common/osint_hash_enricher.py` は、検体を提出せず抽出インフラにも接続せずに、低確度ケースと未識別ケースを完全一致ハッシュのメタデータと相関します。情報源レジストリは `osint/hash_sources.yaml` です。生レスポンスは無視対象のキャッシュへ保持し、正規化した証拠だけを公開ケースツリーへ書き込みます。ネットワーク収集は既定で無効です。

```powershell
python common/osint_hash_enricher.py `
  --summary ..\analysis-results\collections\<batch>\sources\unclassified\summary.json `
  --output ..\analysis-results\collections\<batch>\sources\unclassified `
  --registry osint\hash_sources.yaml `
  --cache ..\.work\<batch>\osint-cache `
  --history ..\analysis_history.yaml `
  --curated-evidence ..\analysis-results\collections\<batch>\sources\unclassified\research-evidence.yaml
```

決定的なキャッシュ再生を行う場合は `--allow-network` を省略します。プロバイダー照会または範囲を限定した `--source <name> --refresh` には、明示的な `--allow-network` が必要です。単一ファミリープロバイダーの結果は低確度の手掛かりに留めます。中確度には相互に独立し一致するプロバイダー2件が必要で、競合も保持します。

情報源の意味、精選証拠スキーマ、実行順、出力、失敗時確認は [ハッシュ限定OSINTワークフロー](docs/HASH-OSINT-WORKFLOW.md) を参照してください。

## プロファイル定義による10ファミリーワークフロー

2026-07-17の拡張では、抽出器や検出器のロジックを10組複製せずに、AsyncRAT、XWorm、QuasarRAT、njRAT、DarkComet、DCRat、RedLine Stealer、Snake Keylogger、GuLoader、HijackLoaderを追加しました。ファミリー差分は `extractors/profiles/windows_family_profiles.json` に定義し、共有実装は `common/profiled_family_detector.py`、`extractors/profiled_family.py`、`common/c2_candidate_detector.py`、`emulators/families/lab.py` です。

`malwarebazaar_batch.py` は、再試行回数を使い切った一時的なダウンロード失敗を `retry_queue` に記録します。同じコマンドを再実行すると、有効な暗号化ZIPを再利用し、不足ハッシュを再試行します。レポート生成後に `validate_family_expansion.py` を使い、内側ハッシュ、検出器／抽出器のルーティング、必要な公開ファイル、禁止バイナリ成果物、非実行／非接続フラグを検証します。関係、コマンド、失敗時確認、100ケースの結果は [プロファイル定義によるファミリー拡張](docs/PROFILED-FAMILY-EXPANSION.md) に記載しています。

## 静的深掘りが必要な難解析ケースのワークフロー

`inventories/static-hard-cases.yaml` は、過去に解析が難航したケース、阻害要因、認証済み子ハッシュを記録します。`common/deep_static_triage.py` は上限付きのメモリ内再帰静的解析を実行し、無害化したJSONとMarkdownだけを公開します。ネイティブエントリのCFG観測は `unpackers/static_control_flow.py`、マネージドPEのメタデータ、CIL、リソースのトリアージは `unpackers/managed_il_triage.py` から得ます。

このワークフローは、検体を実行またはCPUエミュレーションせず、抽出したインフラにも接続せず、復元バイナリレイヤーも書き出しません。`suspected` の制御フロー技法は優先順位付けの手掛かりであり、確認済み帰属ではありません。証拠基準、手法対応表、コマンド、出力、失敗時確認は [静的深掘り解析](docs/DEEP-STATIC-ANALYSIS.md) を参照してください。
