# 分割production jobのcase別datastore保管

`coordinate_partitioned_analysis_datastore.py`は、固定200件を最大4つの
production jobへ分割した解析結果を、取得検体ごとのS3 archiveへ安全に
引き渡すためのコーディネータです。コーディネータ自身はarchive作成や
uploadを行いません。全体preflightを通過した場合だけ、指定した1 caseの
stagingと`archive_analysis_datastore.py`向け引数を返します。

## 全体preflight

次の条件を全件について先に検証します。1件でも不一致ならstaging前に
全体をfail-closedで停止します。

- `source-root/manifest.json`が固定200件を完全取得済みである
- selection commitment、`batch-manifest.json`、4 requestを決定的に再構築できる
- `items[].metadata`の公開可能な安全投影が、commit済み`selected_metadata`と
  SHA-256順序込みで完全一致する
- 指定したjob directory集合がpartitionのjob ID集合と完全一致する
- 各jobを`analysis_job_runner.revalidate_completed_job()`で再検証できる。明示した途中stagingでは
  `revalidate_valid_partial_job()`の厳格な失敗時契約に完全一致する
- 既定では全jobが`complete`で、error、duplicate、partial、failed、`triaged_unknown`を含まない
- job間のanalysis contractが一致する
- job-private入力snapshotの外側ZIP SHA-256とsource manifestのZIPが一致する
- analysis contractの入力manifestとroot reportから、固定選定hashを実case SHA-256へ一意に結合できる
- 4 jobの要求hash列が固定選定200件を元の順序で過不足なく被覆する
- 異なる取得検体が同じ解析rootへ結合されていない
- 各jobのfollow-on root、node、edge、payloadがjob内case treeと一致する
- job analysis treeのexact content manifest SHA-256がpreflight後も変化していない

derived caseは200件の母数へ加えません。rootから安全に到達できる厳格な
`complete` derived caseだけが、そのrootのarchiveへ含まれます。

### 検証済み途中caseのcase単位保管

代表関数解析待ちなどの既知blockerを持つ途中caseを先にdatastoreへ保管する場合だけ、
`--allow-partial-staging`を明示します。publisherと同じく、terminal failed、exit code 2、
`invalid_analysis_state`、`partial-summary.json`、固定root集合・順序、外側ZIPから内側memberの
結合、全report seal・analysis contract・安全フラグ、blocker allowlistを全件再検証します。
未知blocker、`failed`／missing case、scan membership不一致は全体preflightで拒否します。

完了caseと検証済み途中caseは混在できます。preflight結果は
`publication_stage=partial_followup_required`、`all_jobs_complete=false`となり、
`case_state_counts.partial`は`case_state_counts.complete`へ加算されません。case処理結果にも
対象の`case_state`と`publication_stage`を残します。job analysis treeの内容commitmentを
case staging前後で再確認するため、S3へ渡せるのは同じ条件で承認したreportだけです。
現在sourceからjob-time component集合を完全再現できない場合は
`source_replay_verified=false`をpreflightとcase結果へ残します。この状態は過去sourceを
現在sourceとして扱わないことを示すlimitationであり、partialのcase単位保管だけに使用し、
解析完了やcomplete公開の根拠には使用しません。

## preflightだけを実行する

`--temporary-root`はrepository、source、jobとは分離した既存directoryを指定します。
Ghidra成果物を含めないことを明示するため、`--ghidra-not-requested`は省略できません。

```powershell
py -3.13 .\analysis-framework\common\coordinate_partitioned_analysis_datastore.py `
  --repository C:\work\AI-security-analysis `
  --selection-manifest C:\private\latest200\source\manifest.json `
  --batch-manifest C:\private\latest200\requests\batch-manifest.json `
  --source-root C:\private\latest200\source `
  --job-root C:\private\latest200\jobs\latest200-001 `
  --job-root C:\private\latest200\jobs\latest200-002 `
  --job-root C:\private\latest200\jobs\latest200-003 `
  --job-root C:\private\latest200\jobs\latest200-004 `
  --collection-id malwarebazaar-windows-20261102-0200 `
  --temporary-root C:\private\latest200\revalidation-temp `
  --ghidra-not-requested `
  --preflight-only
```

`case_count=200`、`job_count=4`、`all_jobs_complete=true`、
`case_job_binding_unique=true`を確認してからcase処理へ進みます。

途中caseを含む場合は同じcommandへ`--allow-partial-staging`を追加し、
`case_count=200`、`case_state_counts.complete + case_state_counts.partial = 200`、
`publication_stage=partial_followup_required`を確認します。途中caseを完了として扱っては
いけません。

> **標準出力の保管禁止境界**: preflight結果には警告だけが入り、case処理結果には
> repository外のprivate絶対pathと`archive_analysis_datastore.py`向け引数も入ります。
> `coordinate_partitioned_analysis_datastore.py`の標準出力を解析repository内のfileへ
> redirect、`tee`、copy、commitしてはいけません。必要な実行記録はrepository外の
> receipt rootへ保存し、Gitへ追加しません。

## 1 caseをstageする

`--case-sha256`には固定選定側のSHA-256を指定します。provider要求hashと
実際に解析したmember SHA-256が異なる場合も、外側ZIP、入力snapshot、
解析契約、root reportを照合して実caseへ結合します。

```powershell
py -3.13 .\analysis-framework\common\coordinate_partitioned_analysis_datastore.py `
  <preflightと同じselection、batch、source、job、collection、temporary引数> `
  --ghidra-not-requested `
  --case-sha256 <固定選定側SHA-256> `
  --output-root C:\private\latest200\datastore\staging `
  --receipt-root C:\private\latest200\datastore\receipts
```

`status=staging_ready`では、標準出力の`archive_arguments`を順序どおり
`archive_analysis_datastore.py`へ渡します。引数にはtarget、単一case source、
source-tree SHA-256、file件数、合計size、固定S3 bucket、region、private receipt
pathが含まれます。異なるcaseのsourceを同じarchiveへ追加してはいけません。
出力schemaの`output_handling_warning_ja`は、このprivate pathをGitへ保存しない境界を
機械可読結果にも明示します。

```powershell
py -3.13 .\analysis-framework\common\archive_analysis_datastore.py `
  <coordinate結果のarchive_argumentsをそのまま指定>
```

1 caseについてarchive、upload、HeadObject検証、receipt保存を完了してから、
次のcaseへ進みます。並列uploadは行いません。source ZIP、job成果物、元解析treeは
自動削除しません。

## receipt再利用

private receiptは次の固定layoutで保存します。

- `receipts/archive-reports/<target>.json`
- `receipts/archive-bindings/<target>.json`

同じcaseを再実行すると、まず既存stagingを全file再hashします。receiptがある場合は
target、source-tree SHA-256、file件数、合計size、report SHA-256を照合し、さらに
S3 `HeadObject`でContentLength、SSE-S3、archive SHA-256、manifest SHA-256、
target、source-tree SHA-256 metadataを再検証します。すべて一致した場合だけ
`status=verified_reused`を返し、remote検証済みarchiveと完全一致するowned
staging copyだけを削除します。元sourceとjob成果物は削除しません。

初回archive helperはupload reportだけを作るため、bindingが未作成の場合は、
コーディネータがremote再検証に成功した後でprivate bindingをatomicに作成します。
reportとbindingの片方だけが不正に残る状態、source-tree変更、remote検証失敗は
再利用しません。receiptとbindingはGitへ追加しません。

## 実行しない処理

- 検体の実行
- 検体内URL、C2、dead-dropへの接続
- Ghidra解析
- コーディネータ自身によるS3 upload
- source、job、元解析成果物の削除

既存receiptの確認時に限り、host IAM roleとAWS CLIで指定datastore objectへ
`HeadObject`を行います。
