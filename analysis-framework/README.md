# 解析フレームワーク

複数のマルウェア種と配布キャンペーンを、検体をローカル実行せずに整理するための解析基盤です。成果物は `analysis-results/malware/<family>/versions/<version-key>/cases/` に分離し、収集単位の集約物は `analysis-results/collections/<collection-id>/` に置きます。

## 推奨する一括静的解析

解析engineの正本は`common/analyze_sample.py`です。WebUI、ローカルAPI、batch serviceから検体を受け付けるproduction入口は`common/analysis_job_runner.py`とし、family別scriptやengineを直接起動しません。runnerは固定request schema、job専用入力snapshot、runtime preflight、process封じ込め、成果物の独立再検証、atomicなstatus／resultを追加します。信頼済みの解析者がengineだけを直接試す場合を除き、runner経路を使用してください。

engineは、ファイルまたはディレクトリを渡すと、上限付きのメモリ内静的アンパック、ルートと復元層に対する全登録検出器の評価、入力形式契約付きの既存解析関数棚卸し、全復元層の汎用トリアージ、選択層とその外装祖先だけを対象にした設定抽出、証拠階層による結果選択、特徴的な関数／スクリプトのロジック記録、全体フロー文書、指紋生成、挙動・検体特徴プロファイル、キャンペーン自動ラベル、SHA-256単位の統合レポート作成までを一括で行います。信頼済みhandlerの設定実値から通信候補を自動正規化し、`communication-patterns.json`と10 phaseの`c2-analysis.json`も生成します。無関係な兄弟層や形式不一致層へファミリー固有解析器を総当たりせず、候補、静的設定endpoint、protocol確認、稼働確認を別の状態として保持します。

```powershell
python .\common\analyze_sample.py `
  --input C:\malware-lab\incoming `
  --output C:\malware-lab\analysis-output
```

WebUI adapterからは、`analysis_job_runner.py schema`をrequest formの正本として使い、request JSONを有界stdinへ渡します。pollと結果表示では`schema --artifact status|progress|result|snapshot`を正本とし、状態別field、件数上限、安全field、成果物pathをUI側へ複製しません。`status`コマンドは`status.json`、`progress.json`、存在する場合は`result.json`を1つのsnapshotとして返し、返却前に同じ契約を依存なしvalidatorで適用して、cross-job混入とstate／phase／result不一致を`job_state_invalid`で拒否します。引数なしの`schema`は後方互換のrequest schemaです。本リポジトリが提供するのはこのscript-only CLI／Python API契約までであり、HTTPを待ち受けるWebUI backendは別途実装します。

```powershell
Get-Content -Raw -Encoding UTF8 .\job.json | python `
  .\common\analysis_job_runner.py run --request - `
  --input-root C:\malware-job-input --jobs-root C:\malware-job-state
```

標準ZIPとAES ZIPを含む復元層は、残り層数・個別サイズ・総復元量・圧縮率の上限を引き継いで最大4層まで処理します。必要に応じて `--sevenzip`、`--upx`、`--diec` で外部実行ファイルを明示し、PEコンテナー候補の追加検査に限って `--force-container-probe` を使います。`--password` は受け入れ用外装と内側アーカイブの両方へ適用します。

上記の外部実行file引数は、信頼済み解析者が`analyze_sample.py`を直接検証する場合のinterfaceです。WebUI／ローカルAPIのproduction runnerではrequest JSONから`upx`、`sevenzip`、`diec`を指定できません。UPXまたはself-containedな7zzを有効にする場合は、service operatorが管理するstrict manifestとraw SHA-256 pinをrunner CLIへ固定し、job-private snapshotだけを実行します。DIECはこのproduction契約では無効です。tool processは有界出力・時間・process・memory・一時tree quotaの内側で動作し、provenanceを解析契約と`result.json`へ残します。設定例は[ローカル静的解析ジョブ契約](docs/LOCAL-ANALYSIS-JOB-CONTRACT.md)を参照してください。

検体実行、ライブC2接続、外部サービスへの提出は行いません。判定だけを確認する場合は `--assessment-only` を指定します。`--resume` は解析コード・設定の契約指紋、ケース完了状態、入力由来情報、全必須成果物のSHA-256を検証できたケースだけを再利用します。AIを使わない正本フローと品質ゲートは[AI非依存の一括静的解析オーケストレーション](docs/AI-FREE-STATIC-ANALYSIS-ORCHESTRATION.md)、出力、入力契約、証拠階層、完了状態、安全境界、旧CLIとの関係は[一括静的解析と解析器適用可否判定](docs/ONE-SHOT-ANALYSIS.md)、WebUI／ローカルAPIからAIなしで起動・監視する境界は[ローカル静的解析ジョブ契約](docs/LOCAL-ANALYSIS-JOB-CONTRACT.md)、関数ロジックと類似性判定は[静的ロジック記録とコード類似性](docs/STATIC-LOGIC-AND-CODE-SIMILARITY.md)、特徴プロファイルとキャンペーン相関は[検体特徴と攻撃キャンペーン相関](docs/CASE-KNOWLEDGE-CAMPAIGNS.md)を参照してください。

識別から静的解析、正規case公開、代表関数の完了確認、catalog／UI更新、非公開dataのS3保管までを単一の再開可能な固定stageへ接続する場合は、[解析lifecycleの自動化](docs/ANALYSIS-LIFECYCLE-AUTOMATION.md)を使用します。複数のlifecycleを1つのmanifestから順番に計画、実行、検証、再開する場合は、[解析全体オーケストレータ](docs/ANALYSIS-ORCHESTRATOR.md)を使用します。どちらも任意commandやlive C2を許可せず、未解決部分は機械可読blockerとして残します。

production jobの一時fileは`analysis/.private-temp/`へ隔離し、子processの`TEMP`、`TMP`、`TMPDIR`を同じjob内へ固定します。終了時に内容が空であることとdirectory identityを検証して削除し、残存file、hardlink、reparse、quota超過があれば成功として公開しません。

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
C2生存確認は`nmap/nmap_c2_detector.py`を標準入口とし、対象への接触はNmap NSEだけで実行する。profileにレビュー済み`live_c2_targets`があり、実行時に`-AllowLiveC2Check`と`-Nmap`を指定した場合だけ自動解析の末尾で実行する。JARMとPython direct probeは使用しない。詳細は[C2-LIVENESS.md](common/C2-LIVENESS.md)を参照。

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
検体の実行、ライブC2接続、認証情報の公開は既定で行いません。承認されたactive C2観測は`nmap/nmap_c2_detector.py`からallowlist済みNmap NSEだけを起動し、旧`common/c2_detector.py`はoffline planに限定します。Ghidra MCPはlocalhost限定とし、任意スクリプト実行は無効のままにします。

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

### 終端ペイロード未取得台帳

`common/build_terminal_payload_gap_inventory.py`は、精査済み`inventories/static-hard-cases.yaml`、case `report.json`、人が読めるcase文書を統合し、終端payloadまたは終端familyへ到達していないケースを`intelligence/terminal-payload-recovery/`へ生成します。単なる`partial`や最終C2だけの未回収は自動対象にしません。

```powershell
py -3.13 .\common\build_terminal_payload_gap_inventory.py --repository .. --write
py -3.13 .\common\build_terminal_payload_gap_inventory.py --repository .. --check
```

最新版は取得時点で再照会し、P0 family、既存hash除外、完全配布chain、公開sandboxのexact artifact／memoryの順で選びます。構造化reportが終端family確認済みかつcase完了を示すまで、古い未取得根拠を自動的に閉じません。

RemusStealerのfull process dumpからmapped PE、暗号化設定、静的C2 endpoint、fail-closedのC2判定profileを一括復元する場合は、[RemusStealer process dump静的一括解析](docs/REMUS-PROCESS-DUMP-STATIC-RECOVERY.md)を参照してください。

## 新規caseの全体反映


case追加・更新後は、`common/refresh_case_inventory.py`を使ってmetadata identity、全case catalog、README件数、IOC索引、コード類似性、checksum、UI、portal indexを依存順に更新します。`partial`や`triaged_unknown`もcatalogへ登録し、解析完了状態は`report.json`とcollection manifestに分離して保持します。

```powershell
py -3.13 .\common\refresh_case_inventory.py --repository .. --write
py -3.13 .\common\refresh_case_inventory.py --repository .. --check
```

対象ファイル、collection membership、解析履歴、family文書、campaign相関を含む完了条件は[新規解析の公開・全体反映チェックリスト](docs/CASE-PUBLICATION-CHECKLIST.md)を参照してください。

## 宣言型の静的変換・PE構造・レイヤー再帰

新しいsidecar変換は `unpackers/profiles/byte_transforms.json`、PEローダー構造は `registry/pe_structural_profiles.json` へ宣言します。許可リスト外のbyte操作やvalidatorは拒否され、復元byteはDonut、magic、PE、ZIPの構造検証後だけ子レイヤーになります。PEの構造一致は最大 `medium` とし、完全一致ハッシュだけを `high` にします。

`common/static_layer_pipeline.py` はone-shot CLIからレイヤー再帰を分離した共通実装です。任意の共通契約unpackerを注入でき、深さ、件数、単体サイズ、総量、圧縮率を `StaticLayerPolicy` で一括管理します。追加方法と証拠基準は[拡張可能な静的解析プロファイル](docs/EXTENSIBLE-STATIC-PROFILES.md)を参照してください。
