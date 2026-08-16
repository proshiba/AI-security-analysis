# 一括静的解析と解析器適用可否判定

`common/analyze_sample.py` は、検体または検体ディレクトリを渡すと、入力認証、SHA-256重複排除、全登録検出器の評価、既存解析器の適用可否判定、汎用静的トリアージ、ファミリー固有設定抽出、統合レポート生成を1回で行います。検体を実行せず、外部ホストにも接続しません。

## 推奨コマンド

```powershell
python .\analysis-framework\common\analyze_sample.py `
  --input C:\malware-lab\incoming `
  --output C:\malware-lab\analysis-output
```

UPX、7-Zip、Detect It Easy CLIは自動探索せず、必要な場合だけ実行ファイルを明示します。

```powershell
python .\analysis-framework\common\analyze_sample.py `
  --input C:\malware-lab\incoming `
  --output C:\malware-lab\analysis-output `
  --sevenzip 'C:\Program Files\7-Zip\7z.exe' `
  --upx C:\malware-lab\tools\upx.exe `
  --diec C:\malware-lab\tools\diec.exe
```

`--sevenzip` は7z、RAR、CAB、DMGおよびコンテナー候補のPE、`--upx` はUPX圧縮層、`--diec` はPE／Mach-Oの識別補助に使用します。レビュー済みの手掛かりがあるPEを7-Zipで追加検査するときだけ `--force-container-probe` も指定します。指定した実行ファイルの同一性は解析契約へ含めます。

既存のPowerShell入口も、追加オプションがない場合は同じ処理へ委譲します。

```powershell
.\analysis-framework\Invoke-Analysis.ps1 `
  -Sample C:\malware-lab\incoming\sample.zip `
  -OutputDirectory C:\malware-lab\analysis-output `
  -Python .\analysis-framework\.venv\Scripts\python.exe
```

複数のファイルまたはディレクトリは `--input` を繰り返して指定します。同一SHA-256は1回だけ解析し、1検体のエラーで残りを停止しません。

WebUI／ローカルAPIからは`analysis_job_runner.py`を正本入口として使います。ここで提供するのはscript-onlyのCLI／Python API契約であり、HTTPを待ち受けるWebUI backendではありません。serviceを起動するinterpreterのsystem siteまたは専用venvへ`analysis-framework/requirements.txt`を導入してください。runner、analyzer、隔離handler、follow-on workerは同じinterpreterのisolated modeを使用し、user-siteを無効化したruntime preflightに失敗した場合は解析を開始しません。catalog全体は開始前に構築し、個別handlerの再帰依存監査とimportは実行直前に行います。Windows固有のPython pathへは固定していないため、同じ依存契約を満たせばREMnuxでも利用できます。

## 処理順

1. symlinkと出力ディレクトリを除外し、ファイル数・ファイルサイズ上限を確認する。
2. `auto`モードでは、暗号化された単一メンバーZIPだけをMalwareBazaar受け入れ用外装として認証し、内包物をメモリ内で読む。通常のZIP bundleは構造検出のため外装のまま扱う。
3. 既存の静的アンパッカーでPE埋め込み物、ZIPメンバー、スクリプトの静的復号結果などをメモリ内で最大4層まで再帰復元する。層数、個別サイズ、総復元量に上限を適用し、復元本文は保存しない。
4. ルート検体と各復元層に対して `registry/malware_types.json` の全検出器を評価し、既知SHA-256、構造一致、曖昧性、検出器エラーを分離する。
5. `malware/**` と `extractors/**` にある既存の `extract_config`、`extract`、`analyze`、`extract_directory` 関数をASTで棚卸しし、共通バイト列APIと入力形式契約へ適合するか判定する。モジュールの `HANDLER_CONTRACT`、先頭マジック値の厳格な検査、呼び出しアダプターの順で受け入れ形式を決定する。
6. ルート検体を含む全復元層へ汎用トリアージを個別に実行し、各層の `complete`、`partial`、`failed` と全体の `analysis_coverage` を記録する。1層の構文解析失敗や上限到達を、ルート層の成功で隠さない。
7. いずれかの層で一意に選択されたファミリーの標準解析器だけをインポート前検証し、選択層を先に、その外装祖先をフォールバックとして試行する。無関係な兄弟層は実行せず、入力形式が契約外の層もスキップする。十分な証拠を選択層から得た場合は祖先フォールバックを省略する。
8. 解析器の戻り値を証拠階層へ正規化し、空結果を成功扱いしない。最も強い証拠を採用し、十分な最上位結果が複数層で同点なら `ambiguous_evidence` として自動確定を止める。
9. 結果から資格情報、メールアドレス、Bearer資格情報、URLのuserinfo・query・fragment・資格情報path、JSON文字列内の秘密値、復元バイナリ本文を除去してJSONへ保存する。unknown、同確度競合、キャンペーン不一致では特殊解析器を強制しない。
10. 静的結果から関数／スクリプト単位のロジックを構造化し、正規化ハッシュとSimHashを付ける。バイナリで関数解析が未実施の場合は要追加解析として明示する。
11. 挙動・検体特徴プロファイルを作り、登録済みの強いキャンペーン指紋と一致する場合だけ自動ラベルを付ける。

この処理順には、全レイヤーのdetector証拠をまとめる`family-routing.json`、exact root SHA-256に束縛した外部hintを安全handlerで補強する`candidate-handler-assessment.json`、family・config・network・終端payload・関数ロジックを判定する`orchestration.json`の品質ゲートが含まれます。さらに、十分な静的証拠を持つhandlerだけから設定回収状態と通信候補を`communication-patterns.json`へ正規化し、同じ証拠を10 phaseの`c2-analysis.json`へ反映します。外部label単独、空のhandler成功、別familyの結果だけでfamilyや完了状態を昇格しません。

通信候補は候補のまま保持し、静的設定endpointと分離します。静的設定endpointが得られても稼働確認にはせず、family固有frame、serializer、通信関数などの証拠がない限りprotocol確認にも昇格しません。未完phaseにはblockerと次の最小手順を残すため、自動処理後も追加解析が必要な位置を機械的に判断できます。

handlerがraw payloadを復元した場合は、isolated workerの一時成果物を親processが再hashしてcaseへ保持します。保持監査が完全なpayloadだけを、最大64件・128 edge・深さ4・合計256 MiB・300秒の有界fixed-point queueで同じ解析へ再投入します。子caseにはrootとは別の解析契約を使い、timeout途中、seal不一致、成果物hash不一致、cycle、共有payload、上限到達を`partial`として残します。別rootと同じSHA-256はroot nodeを共有しますが、root契約caseをchild契約の親昇格proofには使いません。

保持metadataは`edge`、先頭4,096件までの理由付き`omitted_metadata`、それを超える親別の件数・canonical多重集合SHA-256である`omitted_metadata_commitments`へ完全分割します。runnerは親wrapperからこの分割を独立再計算します。omissionまたはcommitmentが1件でもあればjobは`partial`であり、commitmentがある場合は親caseを`complete`へ昇格しません。詳細は[AI非依存の一括静的解析オーケストレーション](AI-FREE-STATIC-ANALYSIS-ORCHESTRATION.md)を参照してください。

## process封じ込めと配備境界

runner経由のfull analyzerとdirect CLIのisolated full analyzerはactive process 32件・job全体4 GiB、runtime preflightと入力manifest workerは各4件・1 GiB、follow-on workerは8件・2 GiBへ制限します。direct CLIは最大24時間、runtime preflightは各30秒、follow-on workerは子解析timeout以下です。従来入口の`invoke_analysis.py`が起動する各stageも32件・4 GiB、`import_ghidra_project.py`が起動するGhidra headless importも64件・8 GiBの共通境界を使います。Windowsは`KILL_ON_JOB_CLOSE`付きJob Object、POSIXは独立process groupと`RLIMIT_AS`／`RLIMIT_NPROC`を使い、割当失敗時は無制限実行へfallbackしません。

ただし、Windowsにはprocess生成からJob Object割当までの短いraceがあり、POSIXでは`setsid`等によるprocess group離脱の余地があります。これらは外向き通信、filesystem権限、敵対的コードを完全に隔離するsandboxではありません。また、runnerの解析出力100,000 entry・合計1 GiB・空き256 MiB監視はjob単位であり、全同時jobのglobal quotaではありません。本番では低権限service account、必要最小ACL、outbound deny、同時実行数とglobal filesystem quota、Windowsのより強い起動brokerまたはcontainer／VM、POSIXのcontainer／cgroupを併用します。

## 適用状態

各caseの `applicability.json` は、過去に作成した解析関数を次の状態で列挙します。

| 状態 | 意味 |
|---|---|
| `applicable` | 検出器が一意に選択したファミリーの標準解析器。自動実行対象 |
| `applicable_forced` | `--family` で解析者が明示したファミリーの標準解析器。構造一致の代替証拠ではない |
| `not_applicable` | 別ファミリー用のため実行しない |
| `manual_review` | 未登録ファミリー、キャンペーン専用、派生版専用などのため自動流用しない |
| `unsupported_interface` | Path入力、追加の必須引数など、インメモリ共通APIへ未移行 |

対応件数は `summary.json` と `applicability.json` の `catalog` に記録します。件数はリポジトリ内スクリプトの追加・移行に応じて自動更新されるため、固定値を文書へ転記しません。

`applicability.json` の `family_coverage` は、登録済み検出器と既存解析器の対応をファミリー単位でも示します。`automatic_handler_available`、`manual_or_unsupported_only`、`no_handler_implemented`、`handler_without_registered_detector` を区別するため、解析関数が未実装のファミリーや検出器未登録の過去スクリプトも見落としません。

## ハンドラーの入力契約と証拠階層

ファミリー固有ハンドラーは、モジュール直下にリテラルだけで構成した `HANDLER_CONTRACT` を宣言できます。カタログはモジュールをインポートせずASTで読み取ります。

```python
HANDLER_CONTRACT = {
    "input_formats": ["pe"],
    "minimum_evidence_score": 1,
}
```

`input_formats` は `pe`、`elf`、`script`、`zip`、`rar`、`ole` など、静的形式検出器が返す形式名を指定します。複数指定も可能です。宣言がない場合は、関数先頭の厳格なマジック値検査を優先し、共通 `extract` または `extract_config` の既知アダプターには上限付きの `pe`／`elf`／`macho`／`script`／`data` 契約を適用します。どちらにも該当しない旧実装だけを `any` として棚卸しします。宣言値が不正なハンドラーは自動実行しません。`applicability.json` では `input_formats`、`input_contract_source`、`minimum_evidence_score` を確認できます。

戻り値の証拠品質は次の階層で比較します。単なるファミリー名、空のオブジェクトや配列、一般的な成功メッセージだけでは証拠になりません。設定回収済みや一致済みを示す真偽値は、別キーや配列へ置いても証拠として数えません。許可したネットワーク／構造キー配下の文字列・数値・構造化オブジェクトなどの型付き実値、または設定オブジェクトとの相関を要求し、ハンドラーが自己申告したconfidenceやstatusなどのメタデータはスコアに使いません。

| 階層 | 名前 | 主な意味 |
|---:|---|---|
| 4 | `decoded_configuration` | 復号済み設定の制御値と、相関する型付き設定実値を回収した |
| 3 | `validated_static_configuration` | 静的検証済み設定の制御値と、相関する型付き設定実値を回収した |
| 2 | `structural_corroboration` | 許可した構造キー配下に、マーカー、コマンド、亜種などの型付き実値がある |
| 1 | `literal_candidate` | 許可したネットワークキー配下に、URLや接続先などの型付き候補がある |
| 0 | `no_evidence` | 有効な静的証拠がない |

結果ファイルを生成した試行は `handlers/*.json` の `attempts` に残り、結果ファイルを生成できなかった失敗や形式不一致の試行は `report.json` の `handler_executions` に残ります。主なスキップ状態は `skipped_unrelated_layer`、`skipped_incompatible_format`、`skipped_fallback_not_needed` です。ハンドラー全体の状態は、有効証拠なしを `no_evidence`、複数層の最上位証拠が同点で一意に選べない場合を `ambiguous_evidence`、契約を満たす対象層がない場合を `incompatible_input_format` とします。これらは正常完了へ昇格せず、追加確認が必要なケースとして扱います。

## 主な出力

```text
<output>/
  summary.json
  follow-on-analysis.json
  cases/<sha256>/
    report.json
    static-layers.json
    classification.json
    family-routing.json
    candidate-handler-assessment.json
    orchestration.json
    communication-patterns.json
    c2-analysis.json
    applicability.json
    generic-triage.json
    features.json
    FEATURES.md
    static-logic.json
    STATIC-LOGIC.md
    campaign-labels.json
    handlers/<family>-<handler-id-hash>.json
    p/<sha256>.<kind別拡張子>
```

- `summary.json`: root入力の件数・状態、後段payloadの`derived_cases`／`derived_counts`、解析器の証拠状態、汎用解析の網羅状態、再開件数、解析契約
- `follow-on-analysis.json`: rootから保持payloadを辿ったnode／edge、深さ、除外理由、上限、子解析契約SHA-256
- `static-layers.json`: 静的復元の親子関係、方法、上限適用状況。復元本文は含まない
- `classification.json`: ルートと全復元層の検出器評価、選択ファミリー、キャンペーン、曖昧性、判定根拠
- `family-routing.json`: 全レイヤーの候補、証拠tier、一意性、候補handler実行可否
- `candidate-handler-assessment.json`: external hint候補の隔離検証結果。候補観測とfamily確定を分離する
- `orchestration.json`: family、config、network、終端payload、関数ロジックの品質gateとblocker
- `communication-patterns.json`: 信頼済みhandlerから得た静的設定endpoint、未確定候補、protocol hintを分離した公開可能な通信パターン
- `c2-analysis.json`: root解析からprotocol確認までの10 phase、blocker、次の最小手順を記録するfail-closedのC2解析契約
- `applicability.json`: 全既存解析器の対応状況とインポート前検証結果
- `generic-triage.json`: ルートと全復元層の形式、ハッシュ、エントロピー、PE／ELF／スクリプト構造、未確認の静的IOC候補、層別状態、集約した `analysis_coverage`
- `features.json`／`FEATURES.md`: IOC値や検知ルールを除いた、機械可読／人向けの挙動・検体特徴
- `static-logic.json`／`STATIC-LOGIC.md`: 関数／スクリプト単位の役割、処理手順、呼出関係、API、制御フロー、正規化指紋、根拠
- `campaign-labels.json`: 登録済みの強い共有証拠との一致結果。一致なしも明示する
- `handlers/*.json`: 適用可能なファミリー固有解析器の無害化済み結果、入力形式、経路上の役割、試行層、採用層、証拠階層／スコア、曖昧な最上位層

`report.json` の `case_state` は、再開や公開前レビューに使うケース単位の完了判定です。

| 状態 | 意味 | `--resume`で再利用 |
|---|---|---|
| `complete` | ファミリーを一意に選択し、有効な固有解析証拠を得て、阻害要因がない | 可 |
| `triaged_unknown` | 汎用トリアージ処理は成功したが、ファミリーと必要な解析証拠を確定できていない | 不可 |
| `assessment_only_complete` | 適用可否判定モードを阻害要因なしで完了 | 可 |
| `partial` | 上限到達、層の部分解析、検出器エラー、証拠不足、曖昧性、形式不一致、代表関数解析未完了などがある | 不可 |
| `failed` | 汎用トリアージが全体として失敗し、有効な固有解析結果もない | 不可 |

`triaged_unknown` は実行処理の成功を表す状態名として保持しますが、解析完了ではありません。`complete=false`、`resumable=false` とし、CLIでは部分成功の終了コード `20`、job runnerでは `completed_partial`／`analysis_state=partial` へ写像します。

`case_state.blockers` には完了を妨げた理由を列挙します。`report.json` の `analysis_contract` は、パイプライン契約バージョン、解析コード、`requirements.txt`、Python実装、主要依存パッケージ版、レジストリ、検出器、抽出器、アンパッカー、ルール、ハンドラーカタログ、結果へ影響する設定から作ったSHA-256指紋です。`artifact_sha256` はケース内の必須成果物ごとの内容ハッシュ、`report_semantic_sha256` はseal field自身を除くreport全体の決定的な内容ハッシュです。

`orchestration.json` のconfig gateは、受理済みfamily handler内で `decoded_config_recovered` または `static_config_recovered` と同じobjectに復元実値が存在し、handler ID・family・証拠pathのprovenanceを記録できた場合だけ満たします。boolean自己申告、capability名、`configuration_recovered`だけでは満たしません。network gateは候補表示用の `network_endpoints` ではなく `qualified_network_endpoints` を使います。C2／control／exfiltrationの役割があり、同じhandlerの静的config実値と相関するか、由来付きのreview済みprotocol証拠があるendpointだけが品質gateを満たします。配布URL、更新先、decoy、legitimate host、未検証candidateは候補として残しても完了へ昇格させません。

`analyze_sample.py`の完了は、入力とローカルで保持できた後段payloadに対するオフライン静的解析の完了です。全edgeを親のseal済みwrapper metadataと保持file本体の再SHA-256へ結び付け、子caseの解析契約、report seal、成果物hash、親子edgeをproofとして親wrapperへ結び付けます。品質gateと親reportを再sealできた場合は、深いstageから親caseを順に`complete`へ昇格します。他のblockerまたはproof不一致があれば`partial`のままです。包括解析ではこれに加えて、公開sandboxの完全一致hash照会、memory image・外部drop物の取得可否確認、設定から得たC2候補を含む全履歴ライブ確認を別の安全境界で実施します。具体的な一括手順は[MALWAREBAZAAR-WINDOWS-BATCH.md](MALWAREBAZAAR-WINDOWS-BATCH.md)を参照してください。

正規化したスクリプト本文は既定で保存しません。出力は公開前提の最終成果物ではなく、解析者がレビューする中間成果物です。IOCの役割、確度、配布先とC2の分離は別途確認してください。関数ロジックのレビューと類似性判定は[静的ロジック記録とコード類似性](STATIC-LOGIC-AND-CODE-SIMILARITY.md)、特徴プロファイルとキャンペーン相関は[検体特徴と攻撃キャンペーン相関](CASE-KNOWLEDGE-CAMPAIGNS.md)を参照してください。

## 判定だけを行う

```powershell
python .\analysis-framework\common\analyze_sample.py `
  --input C:\malware-lab\incoming\sample.bin `
  --output C:\malware-lab\assessment `
  --assessment-only
```

このモードではルート検体の検出器評価と解析器カタログの適用判定だけを行い、静的アンパック、汎用トリアージ、ファミリー固有解析器は実行しません。

## 完了ケースを安全に再利用する

```powershell
python .\analysis-framework\common\analyze_sample.py `
  --input C:\malware-lab\incoming `
  --output C:\malware-lab\analysis-output `
  --resume
```

`--resume` は、単に `report.json` が存在するだけでは再利用しません。次をすべて満たすケースだけを再利用します。

- `case_state.resumable` が `true` で、`complete`または`assessment_only_complete`である。
- `status`、`complete`、`resumable`、`blockers`、実行モード、選択family、handler成功状態が相互に矛盾しない。
- 内包検体SHA-256に加え、入力名、入力種別、外装SHA-256、メンバー名が現在の入力と一致する。
- `analysis_contract` が現在の解析コード、依存版、レジストリ、ルール、カタログ、外部ツールの同一性、パスワードのSHA-256指紋を含むCLI設定から計算した指紋と完全一致する。パスワード平文は保存しない。
- `report_semantic_sha256` がreport全体と一致する。
- 必須成果物、knowledge成果物、handler結果の集合が `artifact_sha256` と完全一致し、各内容ハッシュが一致する。
- handler／knowledge pathが正規化済み相対pathで、case境界内の通常ファイルだけを指す。symbolic link、Windows junction、その他のreparse pointは途中componentを含めて拒否する。
- `classification.json` と `applicability.json` のfamily、campaign、confidence、選択根拠、handler適用性がreportと一致する。
- 検体未実行・ネットワーク未接続の安全フラグと `--assessment-only` の実行モードが一致する。

解析コードや設定の変更、成果物の欠落・改変、古い契約、`partial`／`failed` ケースを検出した場合は、キャッシュとして採用せず再解析します。

正規collectionへの公開では `assessment_only_complete` を受理しません。通常解析で完了した100件をすべて副作用なしで事前検証してから書き込みを始めるため、後続caseの不整合による部分公開を避けます。

## ファミリーを明示する

```powershell
python .\analysis-framework\common\analyze_sample.py `
  --input C:\malware-lab\incoming\sample.bin `
  --output C:\malware-lab\analysis-output `
  --family nanocore
```

`--family` は解析者が外部根拠を持つ場合のルーティング補助です。検出器が一致しない場合も `explicit_user_type_unmatched` または明示選択として記録し、ファミリー帰属の確認済み証拠には昇格しません。派生版専用解析器は自動実行しません。

## アーカイブモード

- `auto`: 既定。暗号化単一メンバーZIPだけをメモリ内展開し、通常ZIPはbundleのまま解析する。
- `raw`: ZIPを含むすべての入力をそのまま解析する。
- `malwarebazaar`: 各入力を単一メンバーZIPとして認証する。生ファイルを混在させない。

アーカイブmember名、member数、個別サイズ、総展開量、圧縮率を検証し、path traversalとzip bomb候補を拒否します。一括解析の残り層数・個別サイズ・総復元量の上限は、内側ZIPと7-Zip展開にも伝播します。

`--password` はMalwareBazaar受け入れ用外装だけでなく、再帰処理中に見つかった標準ZIPとAES ZIPにも使用します。AES ZIPの復号には `pyzipper` が必要です。復号失敗、暗号方式未対応、上限到達はその層を `partial` とし、別層の成功で隠しません。

## 旧ValleyRATワークフロー

`ProfilePath`、`NetworkEvidence`、`AllowLiveC2Check`、`Nmap`、または`LegacyValleyWorkflow`を指定した`Invoke-Analysis.ps1`は、従来のValleyRATキャンペーン専用処理を使用します。ライブC2観測は一括静的解析には含まれず、現在のタスクで明示的に許可された場合だけNmap NSE経由で実行してください。廃止済みの`CollectJarm`を指定すると接触前に拒否します。

## 終了コード

- `0`: 入力エラーがなく、全caseが `complete`または`assessment_only_complete`
- `20`: 1件以上の入力エラー、`triaged_unknown`、`partial`、`failed`、または未完了の後段解析あり。成功した処理と成功した段階の結果は保持する

CLI引数自体が不正な場合は、Pythonの引数parserが終了コード `2` を返します。
