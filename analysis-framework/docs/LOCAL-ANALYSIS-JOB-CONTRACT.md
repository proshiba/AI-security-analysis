# ローカル静的解析ジョブ契約

## 目的

`analysis_job_runner.py`は、WebUIまたはローカルAPIから`analyze_sample.py`を呼び出すための、AIを必要としないmachine-readableな境界です。検体の分類・復元・既知handler適用は既存の`analyze_sample.py`へ委譲し、runnerは次を担当します。

- JSON要求の厳格検証
- JSONを単一handleから`上限+1 byte`だけ読み、hardlink、reparse、読取中の置換・変更を拒否
- 入力rootとjob出力rootの分離
- path traversal、symbolic link、junction、reparse pointの拒否
- 入力件数・個別size・合計size・静的layer数の上限
- 固定allowlistからのsubprocess引数配列生成
- `shell=False`での封じ込め済みprocess tree起動
- stdout／stderrをEOFまで並行drainし、各先頭1 MiBだけを保持
- timeout、quota超過、例外時の子孫process tree終了
- 解析出力treeの実行中監視と完了後の件数・合計size再検証
- API keyとPython注入環境変数を除いた子process環境
- runnerと同じinterpreter、isolated mode、user-site無効、固定依存import、full analyzerと自動handler catalog構築によるruntime preflight
- `status.json`、`progress.json`、`result.json`のatomic更新
- `analyze_sample.py`の終了codeと安全summaryの検証
- root／child解析契約を現在の要求、固定manifest、現在コードから独立再計算
- follow-on graphのSHA-256、hard counter、DAG深さ、親子edge、子report seal、成果物hash、lineage、derived集計の再検証
- 全follow-on edgeを親のseal済みwrapper metadataと保持file本体の再SHA-256へ結合し、保持metadataを`edge + omitted_metadata + omitted_metadata_commitments`へ多重度込みで完全分割
- seal検証済みroot caseから全集計値を再計算し、summaryの自己申告値と照合
- `assessment_only`契約とfollow-on無効状態を結合し、通常解析での無効化を成功扱いしない
- 親昇格proofの完全一致集合、親子caseの厳格complete、品質gate、report semantic hashの再検証
- `executed_sample=false`、`network_contacted=false`、`ai_used=false`の明示確認

このrunnerは検体を実行せず、外部hostへ接続しません。要求JSONからnetwork、live C2、認証、JARM、任意実行file、任意registry、任意Python、任意outputを有効にすることもできません。本リポジトリが提供するのはこのscript-only CLI／Python API契約であり、HTTP server、認証、queue、同時実行制御を備えたWebUI backend実装ではありません。

## 配置境界

入力とjob出力には専用directoryを用意します。両rootが同一、または一方が他方の配下にある構成は拒否されます。`jobs-root`は解析repository自身またはその親・子directoryにも置けません。

```text
C:\malware-job-input\          # 検体専用。Git管理しない
  intake-20260810\sample.zip
  hints\analysis-20260810-0001.json # family hint専用。通常inputsと分離
C:\malware-job-state\          # status、log、静的解析出力。Git管理しない
  analysis-20260810-0001\
    contract-inputs\family-hint-manifest.json # 検証時bytesの固定copy
    contract-inputs\input-snapshot-manifest.json # 検体snapshotの全file identity
    contract-inputs\samples\<index>\...          # analyzerが読むjob専用copy
```

要求内の`inputs`は`input-root`からのPOSIX形式相対pathです。drive letter、先頭`/`、backslash、`.`、`..`、空component、Windows予約device名を使用できません。

## CLIシグネチャ

### request／成果物schemaを取得する

```powershell
# 後方互換: --artifact request と同じ
py -3.13 .\analysis-framework\common\analysis_job_runner.py schema

py -3.13 .\analysis-framework\common\analysis_job_runner.py schema --artifact request
py -3.13 .\analysis-framework\common\analysis_job_runner.py schema --artifact status
py -3.13 .\analysis-framework\common\analysis_job_runner.py schema --artifact progress
py -3.13 .\analysis-framework\common\analysis_job_runner.py schema --artifact result
py -3.13 .\analysis-framework\common\analysis_job_runner.py schema --artifact snapshot
```

WebUIとAPI adapterは、`request`をrequest form、client-side検証、family選択肢の正本として使用し、`status`、`progress`、`result`、`snapshot`をpoll応答と成果物のdecode／表示契約として使用します。option名、既定値、上限、family一覧、状態別fieldをUI側へ手書きで複製しません。各成果物schemaは状態またはphase別のfield集合を厳密に分け、未知fieldを拒否します。`snapshot`はatomic fileの取得結果であり、`result.json`から`progress.json`、`status.json`の順に終端更新する短い間、非終端statusとresultが同居する形も許可します。JSON Schemaで表現しきれない大文字小文字を無視したpath重複、Windows予約名、`retry_max_static_layers > max_static_layers`、registry整合性、入れ子のjob ID一致はrunnerまたはadapterが最終検証します。

### 受付前検証を行う

```powershell
py -3.13 .\analysis-framework\common\analysis_job_runner.py validate `
  --request C:\malware-job-requests\analysis-20260810-0001.json `
  --input-root C:\malware-job-input `
  --jobs-root C:\malware-job-state
```

検体解析、job directory作成、状態file作成は行いません。要求と入力境界を検証し、同じinterpreterのisolated／sanitized環境で固定依存importと`analyze_sample.py --runtime-preflight`による自動handler catalog構築を確認し、正規化済み計画を標準出力へJSONで返します。個別handlerの再帰依存監査とimportは、入力形式が一致して実行対象になった直前にも毎回fail-closedで行います。検体を読み込む解析処理、handler実行、外部通信は行いません。

### ジョブを実行する

```powershell
py -3.13 .\analysis-framework\common\analysis_job_runner.py run `
  --request C:\malware-job-requests\analysis-20260810-0001.json `
  --input-root C:\malware-job-input `
  --jobs-root C:\malware-job-state `
  --timeout-seconds 21600
```

`run`は同期実行です。Web APIはこのrunner自体を専用service processとして起動し、応答待ちとは別に`status`をpollします。runnerをshell command文字列へ連結せず、API側も必ず引数配列で起動します。

`--timeout-seconds`はfull analyzer processへ適用する実行上限であり、入力列挙、snapshot作成、hash計算、前後処理、結果tree検証までを含むrunner全体のdeadlineではありません。Web serviceから実行するbrokerはrunnerを専用processへ委譲し、これより長いwall-clock deadlineを別途設定してください。storage I/Oが停止した場合も、brokerはdeadline到達時にrunnerと配下のprocess treeを確実に回収する必要があります。

WebUI adapterはrequest用一時fileを作らず、`--request -`を指定してUTF-8 JSONをstdinへ渡せます。stdinは64 KiBを1 byteでも超えると拒否し、重複key、非有限数、未知fieldもfile入力と同じstrict schemaで拒否します。

```powershell
$OutputEncoding = [System.Text.UTF8Encoding]::new($false)
Get-Content -Raw -Encoding UTF8 .\job.json | py -3.13 `
  .\analysis-framework\common\analysis_job_runner.py run `
  --request - --input-root C:\malware-job-input --jobs-root C:\malware-job-state
```

`$OutputEncoding`の指定はWindows PowerShellがnative processへのpipeをUTF-8以外へ再encodeすることを防ぎます。WebUI／service adapterでは、文字列pipeではなく検証前のrequest bytesをsubprocessのstdinへ直接渡します。

### 状態を取得する

```powershell
py -3.13 .\analysis-framework\common\analysis_job_runner.py status `
  --jobs-root C:\malware-job-state `
  --job-id analysis-20260810-0001
```

`status.json`、`progress.json`、存在する場合は`result.json`を1つのsnapshotとして標準出力へ返します。各fileは単一handleのstrict JSON readerで読み、成果物Schemaのexact key、型、固定値、上限、job IDと相互状態を第三者依存なしで検証します。重複key、未知field、別jobの混入、terminal state／progress／result不一致は`job_state_invalid`で拒否します。

snapshotは3 fileを`status`、`progress`、`result`の順で読むため、先に読んだ非終端statusより後のphaseまたはresultが同じ応答へ入る場合があります。許可する遷移は次のとおりです。

| 読み取ったstatus | 許可するprogress phase |
|---|---|
| `queued` | 全phase。極短時間で完了したjobでは`queued`とresultが同居し得る |
| `validating` | `queued`以降の全phase |
| `running` | `validating_inputs`以降の全phase |
| terminal | 同名のterminal phaseだけ |

terminal progressまたはterminal statusにはresultが必須で、`completed`→`complete`、`completed_partial`→`partial`、`failed`→`failed`、`timed_out`→`timed_out`を完全一致させます。statusとprogressが非終端の間にresultが見える形は、resultを最後に読み取る際のatomic遷移として許可しますが、内包Schemaと全job IDは常に検証します。

### 終了code

| code | 意味 |
|---:|---|
| `0` | `analyze_sample.py`が完全成功し、安全summaryを検証済み |
| `20` | `triaged_unknown`や追加解析待ちを含む部分成功。job自体は受理済み |
| `1` | analyzerの受理対象外終了code、またはrunner内部error |
| `2` | JSON、path、上限、runtime依存、summary等の契約違反 |
| `124` | 時間上限へ到達 |

## Python APIシグネチャ

Web API adapterまたはローカルserviceから直接importする場合の入口は次です。

```python
load_job_request(path: Path) -> JobRequest

load_job_request_from_stdin(stream: BinaryIO | None = None) -> JobRequest

validate_job(
    request: JobRequest,
    *,
    input_root: Path,
    jobs_root: Path,
) -> dict[str, Any]

run_job(
    request: JobRequest,
    *,
    input_root: Path,
    jobs_root: Path,
    timeout_seconds: int = 21600,
) -> int

read_job_snapshot(
    jobs_root: Path,
    job_id: str,
) -> dict[str, Any]

job_artifact_schemas.validate_job_artifact_document(
    kind: str,
    value: Any,
    *,
    expected_job_id: str | None = None,
) -> None
```

通常のAPI統合ではCLIをprocess境界として使う方が、Web serviceと解析依存関係を分離できます。Python APIは同一host上の信頼済みadapterに限定します。

## requestスキーマ

```json
{
  "schema_version": 1,
  "job_id": "analysis-20260810-0001",
  "inputs": [
    "intake-20260810/sample.zip"
  ],
  "family_hint_manifest": "hints/analysis-20260810-0001.json",
  "trusted_static_tools": {
    "profile_id": "windows-amd64-20260810",
    "operator_manifest_sha256": "64文字のSHA-256",
    "snapshot_manifest_sha256": "64文字のSHA-256",
    "tools": {
      "upx": {
        "name": "upx.exe",
        "size": 1234567,
        "sha256": "64文字のSHA-256"
      },
      "sevenzip": {
        "name": "sevenzip.exe",
        "size": 2345678,
        "sha256": "64文字のSHA-256"
      },
      "diec": null
    }
  },
  "options": {
    "archive_mode": "auto",
    "family": "valleyrat",
    "minimum_confidence": "medium",
    "assessment_only": false,
    "force_container_probe": false,
    "max_files": 100,
    "max_file_size": 536870912,
    "string_scan_limit": 1000000,
    "max_static_layers": 64,
    "retry_max_static_layers": 128
  }
}
```

### top-level keyの契約

| key | 必須 | 契約 |
|---|---|---|
| `schema_version` | 必須 | 現在は整数`1`のみ |
| `job_id` | 必須 | 1～64文字の小文字英数字、`.`、`_`、`-`。既存IDの再利用禁止 |
| `inputs` | 必須 | 1～64件のroot相対path。大文字小文字だけが異なる重複も拒否 |
| `family_hint_manifest` | 任意 | `input-root`相対のstrict JSON。4 MiB以下。通常`inputs`と重複禁止 |
| `options` | 任意 | 次表のkeyだけを許可 |

未知key、重複JSON key、`NaN`／`Infinity`、UTF-8以外、64 KiBを超える要求fileは拒否されます。要求、registry、manifest、summary、状態JSONは、単一file handleの`fstat`と`上限+1 byte`読取で検証します。hardlink、reparse point、読取中にidentity・size・更新時刻が変わったfileはfail-closedです。

### 許可option

| key | 既定 | 上限／候補 |
|---|---:|---|
| `archive_mode` | `auto` | `auto`、`raw`、`malwarebazaar` |
| `family` | `null` | `malware_types.json`の完全一致IDだけ |
| `minimum_confidence` | `medium` | `low`、`medium`、`high` |
| `assessment_only` | `false` | boolean |
| `force_container_probe` | `false` | boolean |
| `max_files` | `1000` | 1～1000 |
| `max_file_size` | `536870912` | 1～512 MiB |
| `string_scan_limit` | `1000000` | 1～1,000,000 |
| `max_static_layers` | `64` | 1～64 |
| `retry_max_static_layers` | `null` | 初回上限より大きく、最大256 |

入力全体の合計は2 GiB、tree entryは10,000件までです。要求上限を大きくしてもrunnerのhard limitを超えることはできません。受付時に全入力fileを`lstat` identityへ固定し、単一handleからjob専用`contract-inputs/samples/<index>/`へcopyします。copy前後でdirectory identity、通常file、hardlink、reparse point、size、mtime、ctime、SHA-256を検証し、worker／analyzerの前後でもmanifestとtreeを再検証します。以後の解析へ渡すのはjob専用snapshotだけで、元の入力pathは渡しません。

`family_hint_manifest`は解析対象file数へ含めず、UTF-8、重複keyなし、非有限数なし、JSON object root、通常file、4 MiB以下をrunnerで検証します。検証した同じbytesをjob-localの`contract-inputs/family-hint-manifest.json`へatomicに固定し、子processには元fileではなくこのcopyだけを渡します。manifest内のexact root SHA-256とfamily候補のschemaは`analyze_sample.py`側でも再検証し、metadata hint単独でfamilyを確定しません。

Triageのmemory dumpや静的に復元したpayloadを別入力として再解析する場合は、そのartifact自身のexact SHA-256を`samples`のkeyにします。hintへ`root_sha256`、`parent_sha256`、`artifact_sha256`、`artifact_kind`、`source`、`source_id`、`depth`、`inherited_family`、`family_hint_source`を全て付けると、親候補familyの既存handlerを子artifactへ再適用できます。一部だけのlineage、manifest keyと異なる`artifact_sha256`、depth 1で一致しないroot／parentは拒否します。継承hintはcandidate verification専用で帰属根拠にはならず、子artifact自身のdetector／handler証拠と異なる場合は`classification_conflict`を記録して独立証拠を優先します。follow-onで保持したpayloadには元artifactのlineage深さへ加算して同じrootを自動継承し、元manifestのidentityをroot／follow-on双方の解析契約へ結合します。

同一artifact SHA-256でも、`root_sha256`、`parent_sha256`、`depth`、family候補、`source`／`source_id`、provenanceが異なれば解析文脈は同一ではありません。将来follow-onをresumeまたはcacheする場合は、artifact SHA-256だけを再利用keyにせず、このcanonical lineage tuple、正規化済みhint、handler契約SHA-256を全てidentityへ結合します。現在のrunnerはjob IDを再利用しません。親providerの元`source`／`provenance`は親manifest／reportに保持し、子hintでは復元sourceと親SHA-256へ正規化します。同じfamily、confidence、lineage、正規化済みsource／provenance等が全て一致する子hintだけをcanonical fingerprintで重複排除します。同じrootに対する`depth`は既存lineageへ加算し、異なるroot／depth候補が残る場合は任意選択せず拒否します。

解析出力はroot case、後段case、機械可読成果物を合わせてjob単位で100,000 entry、合計1 GiBまでです。既定runnerは0.5秒間隔で出力treeとjob filesystemの空きを監視し、上限超過または空きが256 MiB以下になった時点でprocess treeを終了します。process終了後も同じquotaを再検証します。この監視は単一jobの第2境界であり、同時に動く全jobを合算した`jobs-root`のglobal quotaではありません。

runnerは`analysis/.private-temp/`を所有者限定で排他的に作成し、full analyzer、input manifest worker、handler、follow-on workerの`TEMP`、`TMP`、`TMPDIR`をjob内へ固定します。hostの一時pathは継承しません。内側workerはこのdirectory配下へさらに専用一時directoryを作ります。process終了後は解析出力と同じ100,000 entry／1 GiB上限、通常file、hardlink、reparse pointを再検証し、directory identityが作成時と一致し、内容が空である場合だけ非再帰削除します。残存file、差替え、link、quota超過はjob失敗です。Windowsの`chmod`はACLそのものではないため、本番serviceはjob rootを専用accountだけが変更できるACLでも保護します。

productionの解析processは、Windowsでは`KILL_ON_JOB_CLOSE`付きJob Objectへ割り当てます。runner経由のfull analyzerとdirect CLIのisolated full analyzerはactive process 32件・job全体4 GiB、2段のruntime preflightと入力manifest workerは各4件・1 GiB、follow-on workerはhandler子processを許容する8件・2 GiBへ制限します。direct CLIは24時間、runtime preflightは各30秒の明示timeout、follow-on workerは固定点queueが渡す既存の子timeoutを使います。従来入口の`invoke_analysis.py`が起動する各stageは32件・4 GiB、`import_ghidra_project.py`が起動するGhidra headless importは64件・8 GiBへ制限します。割当失敗は解析を開始済みとして継続せず、直ちにprocess treeを終了してfail-closedにします。POSIXでは独立process groupに加えて`RLIMIT_AS`と`RLIMIT_NPROC`を設定し、親から継承したより厳しい上限を緩めません。正常終了時も境界を閉じ、残存子孫を終了します。

ただし、Windowsにはprocess生成からJob Object割当までの短いraceがあり、POSIXでは子processが`setsid`等で別sessionへ移るとprocess group終了から逃れる余地があります。`RLIMIT_NPROC`もOS仕様上UID単位です。したがって、この境界を敵対的コードの完全なsandboxまたは厳密なtree単位quotaとは扱いません。より強い保証が必要な本番配備では、低権限accountとACL、outbound denyに加えて、Windowsのより強い起動brokerまたはcontainer／VM、POSIXのcontainer／cgroupを併用します。

### 明示的に禁止するoption

`allow_network`、`allow_live_c2_check`、`allow_live_c2_emulation`、`allow_authentication`、`allow_malware_registration_tasking`、`collect_jarm`、`password`、`profile_path`、`registry`、`python`、`output`、`upx`、`sevenzip`、`diec`等は使用できません。未知optionもfail-closedです。

### operator管理の信頼済み静的ツール

request JSONから外部実行fileを指定することは禁止したままです。production serviceでUPXまたは7zzを有効にする場合だけ、service operatorが固定したCLI引数`--trusted-tools-manifest`と`--trusted-tools-manifest-sha256`をpairで使います。片方だけの指定、client値の転送、起動ごとの自動探索、`PATH`検索は禁止です。

manifestはBOMなしUTF-8、重複keyなし、1 MiB以下のstrict JSONで、top-levelとtool entryの未知fieldを拒否します。`platform`は現在hostと大文字小文字を無視して完全一致し、`tools`は`upx`と`sevenzip`の2 keyだけを持ち、少なくとも1件を有効にします。DIECはproduction契約では意図的に無効です。

```json
{
  "schema_version": 1,
  "profile_id": "windows-amd64-20260810",
  "platform": {
    "sys_platform": "win32",
    "machine": "amd64"
  },
  "tools": {
    "upx": {
      "path": "C:\\malware-lab\\operator-tools\\upx.exe",
      "size": 1234567,
      "sha256": "64文字の小文字SHA-256"
    },
    "sevenzip": {
      "path": "C:\\malware-lab\\operator-tools\\7zz.exe",
      "size": 2345678,
      "sha256": "64文字の小文字SHA-256"
    }
  }
}
```

```powershell
py -3.13 .\analysis-framework\common\analysis_job_runner.py validate `
  --request C:\malware-lab\requests\job.json `
  --input-root C:\malware-lab\intake `
  --jobs-root C:\malware-lab\jobs `
  --trusted-tools-manifest C:\malware-lab\operator-policy\trusted-static-tools.json `
  --trusted-tools-manifest-sha256 <manifest-raw-sha256>

py -3.13 .\analysis-framework\common\analysis_job_runner.py run `
  --request C:\malware-lab\requests\job.json `
  --input-root C:\malware-lab\intake `
  --jobs-root C:\malware-lab\jobs `
  --trusted-tools-manifest C:\malware-lab\operator-policy\trusted-static-tools.json `
  --trusted-tools-manifest-sha256 <manifest-raw-sha256>
```

各binaryは絶対path、1～128 MiB、単一link、非reparseの通常fileで、`input-root`、`jobs-root`、repositoryのすべてから分離します。UPXと7zzは追加DLLを同伴しないself-containedな配布物を使います。runnerはmanifest raw SHA-256とbinary size／SHA-256を単一handleで照合し、検証済みsourceをjob-private `contract-inputs/static-tools/<tool-id>/`へ単一handleからcopyします。実行権限を設定したsnapshotだけをanalyzerへ渡し、元pathはargv、解析契約、公開resultへ渡しません。worker前後にmanifest、snapshot tree、binary SHA-256を再検証します。

UPX／7zz processは`analysis/.private-temp/`内を作業directoryとし、credentialやPython注入環境を継承しません。process treeはactive process 8件・memory 1 GiB、stdout／stderrは各1 MiB、一時treeは10,000 entry・合計1 GiB以下です。UPXは120秒、7zz inventoryは60秒、extractは180秒を上限とし、50 ms間隔と終了後にtreeを検証します。抽出fileはsize上限付き単一handleで再読込し、reparse、hardlink、特殊file、path escape、読込中差替えを拒否します。これはparser脆弱性に対するkernel sandboxではないため、低権限account、outbound deny、ACL、container／VMも併用します。

## job directoryスキーマ

```text
<jobs-root>/<job-id>/
  request.json       # 正規化済み要求
  status.json        # lifecycleとterminal状態
  progress.json      # phase単位の進捗
  result.json        # terminal結果
  stdout.log         # 最大1 MiB
  stderr.log         # 最大1 MiB
  contract-inputs/   # runnerが検証時bytesから作った変更不能扱いの入力copy
    analysis-contract-bundle.json # 入力SHA-256、root契約、子契約
    input-snapshot-manifest.json   # 元identity、snapshot path、size、SHA-256
    trusted-static-tools.json      # operator tool有効時のsnapshot provenance
    static-tools/<tool-id>/...     # job-private UPX／7zz launcher snapshot
    samples/<index>/...            # 名前衝突を避けた検体snapshot
    family-hint-manifest.json      # 指定時だけ
  analysis/          # analyze_sample.pyのroot・derived成果物
    .private-temp/   # 空なら終了時に非再帰削除。残存物・差替え時は調査用に保持
    summary.json
    follow-on-analysis.json
    cases/<sha256>/
```

`job-id`directoryは排他的に新規作成します。既存directoryを再利用、上書き、resumeしません。再実行には新しい`job_id`を発行します。

### statusスキーマ

```json
{
  "schema_version": 1,
  "job_id": "analysis-20260810-0001",
  "state": "running",
  "terminal": false,
  "created_at_utc": "2026-08-10T01:00:00Z",
  "started_at_utc": "2026-08-10T01:00:01Z",
  "finished_at_utc": null,
  "progress_path": "progress.json",
  "result_path": null,
  "error": null
}
```

`state`は`queued`、`validating`、`running`、`completed`、`completed_partial`、`failed`、`timed_out`のいずれかです。

### progressスキーマ

```json
{
  "schema_version": 1,
  "job_id": "analysis-20260810-0001",
  "phase": "static_analysis",
  "percent": 30,
  "message": "オフライン静的解析を実行しています",
  "total_files": 1,
  "total_bytes": 123456,
  "updated_at_utc": "2026-08-10T01:00:01Z"
}
```

現行の`analyze_sample.py`はcaseごとのprogress eventを公開しないため、`percent`はphase進捗です。検体単位の厳密な完了率として表示しません。

### resultスキーマ

```json
{
  "schema_version": 1,
  "job_id": "analysis-20260810-0001",
  "request_sha256": "64文字のSHA-256",
  "accepted": true,
  "analysis_state": "complete",
  "inputs": [
    {
      "relative_path": "intake-20260810/sample.zip",
      "kind": "file",
      "file_count": 1,
      "total_bytes": 123456
    }
  ],
  "family_hint_manifest": "hints/analysis-20260810-0001.json",
  "counts": {
    "input_files": 1,
    "analyzed": 1,
    "complete": 1,
    "partial": 0,
    "failed": 0
  },
  "derived_counts": {
    "analyzed": 1,
    "complete": 1,
    "partial": 0,
    "failed": 0
  },
  "follow_on_analysis": {
    "artifact": "follow-on-analysis.json",
    "sha256": "64文字のSHA-256",
    "status": "complete",
    "node_count": 2,
    "edge_count": 1,
    "error_count": 0
  },
  "artifacts": {
    "analysis_summary": "analysis/summary.json",
    "follow_on_analysis": "analysis/follow-on-analysis.json",
    "family_hint_manifest": "contract-inputs/family-hint-manifest.json",
    "family_hint_manifest_sha256": "64文字のSHA-256",
    "analysis_contract_bundle": "contract-inputs/analysis-contract-bundle.json",
    "analysis_contract_bundle_sha256": "64文字のSHA-256",
    "input_snapshot_manifest": "contract-inputs/input-snapshot-manifest.json",
    "input_snapshot_manifest_sha256": "64文字のSHA-256",
    "trusted_static_tools_manifest": "contract-inputs/trusted-static-tools.json",
    "trusted_static_tools_manifest_sha256": "64文字のSHA-256",
    "stdout": "stdout.log",
    "stderr": "stderr.log",
    "stdout_truncated": false,
    "stderr_truncated": false,
    "analysis_output": {
      "entries": 100,
      "files": 80,
      "directories": 20,
      "total_bytes": 12345678
    }
  },
  "process": {
    "exit_code": 0,
    "shell": false,
    "script": "analysis-framework/common/analyze_sample.py",
    "timeout_seconds": 21600
  },
  "safety": {
    "network_or_live_options_allowed": false,
    "sample_execution_allowed": false,
    "summary_safety_contract_verified": true,
    "executed_sample": false,
    "network_contacted": false,
    "ai_used": false
  },
  "finished_at_utc": "2026-08-10T01:03:00Z"
}
```

`counts`は入力root検体だけ、`derived_counts`は保持payloadを固定点解析してterminal stateまで到達した子caseだけを数えます。runnerはrootのseal済みreport、orchestration、candidate assessmentとcase recordを照合した後、family、automation、handler、解析stage、terminal state、resumeの全件数をcase recordから再計算します。`triaged_unknown`はprocess成功として受理しますが解析完了には数えず、rootまたはderived caseに1件でもあれば`completed_partial`、`analysis_state=partial`、終了code `20`へ写像します。timeout途中、seal不一致、成果物hash不一致、解析契約不一致の子caseは`derived_counts`へ入らず、follow-on状態とjob終了codeを`partial`／`20`にします。runnerはgraph上の`analyzed`／`resumed_complete` node集合と`derived_cases`を完全一致で照合します。

`input-snapshot-manifest.json`は元入力identityとsnapshotの相対path、size、SHA-256を固定します。`analysis-contract-bundle.json`は、production実行直前にisolated `-I -B` workerがsnapshotから読み取ったanalyzer単位の入力名、読取成否、SHA-256と、現在コード・registry・固定optionから計算したroot／child解析契約を保存します。runnerは両manifestをatomic保存後に再読込し、`result.json`へfile bytesのSHA-256を記録します。これによりUIの受付件数、snapshot、analyzerの`cases`／`duplicates`／`errors`、実際に解析した入力を完全照合できます。

`trusted-static-tools.json`はoperator manifestのraw SHA-256、host platform、job-private launcherの相対path、名前、size、SHA-256を固定します。root／child解析契約の`settings.static_tools`、summary、`result.trusted_static_tools`、artifact manifest SHA-256を独立照合します。toolを無効にしたjobでは`trusted_static_tools`と対応artifact 2 fieldはすべて`null`であり、provenanceとmanifest参照の片方だけを持つresultはschema違反です。公開値へoperatorの絶対pathは含めません。

親caseを`complete`へ昇格した場合、`follow-on-analysis.json`の`promoted_parent_sha256`と、全検証済みreport内の`follow_on_promotion`保持case集合は完全一致しなければなりません。昇格に使えるのは当該親から通常またはshared edgeで到達したchild-contract caseだけで、`depth_limit`、cycle、size／件数上限、別root再利用を別経路の成功で流用しません。runnerはresolved familyの品質gateへ寄与したwrapper群から保持payload集合とoutcomeを再計算し、wrapper内部proof、親proof、子解析契約SHA-256、子report semantic hash、親子edgeを完全一致で再結合します。

別のroot入力と同じSHA-256の保持payloadは、depth 0のroot nodeを重複作成せずshared edgeで参照します。`shared_sha256_reused_complete`は参照先rootのseal済みcaseとorchestrationが厳格な`complete`の場合だけ受理します。root契約で解析したcaseをchild契約の親昇格proofへ流用しません。

保持metadataをedgeへ変換できなかった場合は、黙って切り捨てません。先頭4,096件までは`omitted_metadata`へ親・子SHA-256、size、path、role、kindと、edge上限、再読込byte上限、wall-clock、成果物検証失敗の理由を記録します。この上限を超える残余は、親ごとに多重度を保つcanonical SHA-256と件数を`omitted_metadata_commitments`へ記録します。canonical hashはunique metadataと多重度を辞書順で逐次hashし、多重度分の巨大なlistを生成しません。runnerはseal済みwrapperから残余`Counter`を独立再計算し、`edge + omitted_metadata + omitted_metadata_commitments`が全保持metadataを過不足なく表すことを照合します。個別omissionまたはcommitmentが1件でもあれば必ず`partial`です。commitmentがあるjobでは親昇格を無効化し、昇格済み親一覧も空でなければなりません。親昇格はproof、品質gate、artifact manifest、全JSON serializationを先に検証し、その後に各fileをatomic replaceして`report.json`を最後に保存します。これは論理的な二段階commitであり、複数fileを単一filesystem transactionにするものではありません。I/O失敗時はcompleteとして公開しません。

失敗時も`result.json`を生成し、`accepted=false`、安定した`error.code`、日本語の`error.message`、`safety.ai_used=false`を記録します。subprocessのraw stderrをJSONへ埋め込まず、privateなjob rootの`stderr.log`だけへ保存します。stdout／stderrは専用threadでEOFまで消費し続けるため、子processをpipe詰まりさせず、memoryには各1 MiBを超えて保持しません。

## WebUI／API統合

`ui/`は静的閲覧UIであり、ブラウザJavaScriptからローカルprocessを直接起動してはいけません。現在の実装範囲はrunnerのCLI／Python APIと成果物schemaまでで、次のHTTP backendは提供していません。統合時は次の薄いローカルserviceを別processで用意します。

1. `POST /api/analysis-jobs`でrequest JSONを受け取り、runnerの`--request -`へbodyをそのまま有界stdinとして渡す。
2. service側の固定`input-root`と`jobs-root`を使用し、clientからroot pathを受け取らない。
3. `validate`で要求、入力、同一interpreterのisolated／sanitized runtime preflightを行う。serviceのvenvまたはsystem siteへ`analysis-framework/requirements.txt`を導入し、user-siteだけの依存へfallbackしない。
4. `run`を引数配列、`shell=False`、低権限service accountで起動する。runnerはOS別に分離したprocess groupを所有し、Windows Job ObjectまたはPOSIX process groupを正常終了時にも閉じる。timeout・例外・quota超過時はJob close／`taskkill /T /F`またはprocess groupへの`SIGKILL`で子孫を終了する。
5. `GET /api/analysis-jobs/<job-id>`はrunnerの`status`コマンドを呼び、`status.json`、`progress.json`、存在する場合は`result.json`を検証済みの1つのsnapshotとして返す。`status.json`単体だけを返さない。
6. terminal後、公開可能な解析成果物だけを既存のpublication pipelineへ渡す。

Web serviceには同時実行数、`jobs-root`全体のglobal filesystem quota、rate limit、認証、CSRF対策を別途実装します。runnerの0.5秒監視にはsampling間隔があり、瞬間的な大量書込みをOS filesystem quotaのように事前阻止できるわけではありません。runnerの時間・件数・size上限は、それらが破られた場合の第2境界です。

現在のrunnerは同期実行・排他的job IDを採用し、process crash後のlease／heartbeat、stale jobの自動回収、同一requestのidempotent retryは実装していません。Web serviceは同じjob IDを無条件に再利用せず、非終端jobと所有processを別のbroker境界で照合し、回収を明示的な運用または将来のlease機構へ委ねます。再試行時は新しいjob IDを発行し、`request_sha256`で元要求との対応を記録します。

各JSONは同一directory内の一時fileを`fsync`してからatomic replaceしますが、親directoryのdurability同期はplatform間で保証していません。通常のprocess crashでは旧版または新版の完全なfileを読みますが、OS crash／電源断に対する永続化保証ではありません。耐電源断要件はservice側のtransactional storeまたはfilesystem機能で補います。

runner自身はOS firewallやfilesystem ACLを設定しません。`network_contacted=false`は解析コードと成果物の契約であり、kernel levelの通信遮断証明ではありません。production serviceは低権限account、検体snapshotとjob root以外を読めないACL、outbound deny firewall、必要に応じてcontainer／VMを併用します。

## `analyze_sample.py`との配線

runnerは固定pathの`analyze_sample.py`を次の固定関係で起動します。family別scriptや後段payload解析器をWebUI adapterから直接起動しません。

```text
request JSON
  -> analysis_job_runner.py
     -> input／option検証
     -> 元入力をcontract-inputs/samplesへ単一handle snapshot化
     -> input-snapshot-manifest.jsonを固定し、各consumer前後で再検証
     -> family hint manifestの分離検証とjob-local固定copy（指定時だけ）
     -> 同一interpreter・user-site無効のruntime preflight
     -> isolated workerで入力SHA-256とroot／child解析契約を一括固定
     -> contract-inputs/analysis-contract-bundle.jsonをatomic保存・再hash
     -> [sys.executable, analyze_sample.py, --input, ..., --output, ...,
         --family-hint-manifest, ...]
        shell=False
     -> analysis/summary.json
     -> analysis/follow-on-analysis.json
     -> output quotaとroot／derived件数整合性を検証
     -> follow-on graph SHA-256、hard counter、DAG、子report seal、成果物hash、lineageを検証
     -> edge／omission／commitmentを親wrapper metadataと保持fileの再SHA-256へ結合
     -> 親昇格proof、親子strict complete、品質gateを検証
     -> executed_sample／network_contacted／ai_used=falseを検証
     -> status／progress／result JSON
```

`family_hint_manifest`を指定した場合、`analyze_sample.py`は`--family-hint-manifest`を受け取り、exact root SHA-256に対応する候補だけをassessment対象へ追加します。manifestが未指定なら通常の自動routingです。保持payloadは`analyze_sample.py`自身が専用の子解析契約と有界fixed-point queueで処理し、runnerは完成済み成果物だけを検証・公開します。case単位progressを将来配線する場合はstdoutへ混在させず、job runnerが専用file descriptorまたはJSON Lines event fileで受け取れる任意interfaceを追加します。現在の統合に必須ではありません。

family handlerは公開resultへraw bytesを入れません。検証済みbytesはworker内部の明示的な`terminal_payload` recordだけで返し、親processが一時fileを単一handleで再読込してsizeとSHA-256を再計算します。保持に成功したroot reportは`retained_artifact_paths`をsorted uniqueで持ち、許可される形は`p/<64桁の小文字SHA-256>.<archive|bin|elf|exe|macho|txt>`だけです。path中のdigestと`artifact_sha256`が一致しない、重複、未知path、path traversalはcase integrity違反です。follow-on child nodeの`family_hint_count`は0から16、lineageを持つ場合のroot SHA-256とdepth 1から64もrunnerが再検証します。

## 検証

```powershell
py -3.13 -m pytest .\analysis-framework\tests\test_analysis_job_runner.py -q
py -3.13 -m ruff check .\analysis-framework\common\analysis_job_runner.py `
  .\analysis-framework\tests\test_analysis_job_runner.py
```

テストはstrict JSON、stdin size上限、machine-readable schemaと実装定数の一致、snapshotの重複／未知field、cross-job混入、terminal整合性、許可されたatomic遷移、hardlink、network／live option拒否、path traversal、重複入力、root重複、reparse、件数上限、元file差替え・grow・同名file・snapshot改ざん、canonical manifest copy、isolated runtime依存、同一interpreter、private stdinの契約worker、入力manifest／重複／errorの完全照合、`shell=False`、有界stdout／stderr drain、process tree終了、実行中・完了後output quota、seal済みrootからの全件数再計算、root／child契約アンカー、assessment-only状態結合、follow-on graph改ざん、hard counter、edge／omission／commitment完全分割、commitment時の親昇格禁止、node状態、親wrapper metadataとedgeの完全一致、payload再hash、別root同一SHA再利用、子report seal・成果物hash・lineage、親別昇格proof、wrapper内部proof、途中case除外、終了codeとsummaryの一致、global wall-clock、`ai_used=false`、完全成功、部分成功、安全summary違反、異常終了、timeout、atomic JSON、job ID再利用拒否を確認します。

## 防御上の補足

runnerはnetwork optionを公開せず、信頼済みのオフライン静的解析scriptだけを起動します。ただしPython process自体へOSレベルの通信遮断を付与するものではありません。本番serviceでは専用低権限accountとoutbound denyを併用してください。`summary.network_contacted=false`は解析契約の事後確認であり、OSのegress policyを置き換えません。同様に、runnerが固定する`ai_used=false`はこのscript-only経路の契約値であり、serviceが別processや別APIでAIを呼び出さないことはservice側の監査対象です。runtime preflightは同じ`sys.executable`のisolated modeと最小環境を使い、user-site依存を許可しません。全handlerを毎jobで一括importして起動を遅延させず、catalog全体を短時間で構築したうえで、選択されたhandlerの再帰依存監査とimportを実行直前に行います。handler本体とrepository-local Python依存は、監査時に単一handleから取得したSHA-256付きbytes snapshotだけを専用loaderで実行します。監査後のpath再import、manifest外local import、差し替え、hardlink、reparseはfail-closedです。data fileは別の成果物・path契約で検証します。Windows、REMnux、containerのいずれでも、serviceを起動するsystem siteまたは専用venvへrequirementsを導入してください。

producerが`terminal_payload_acquisition`参照を持つ場合、runnerは`terminal-payload-acquisition.json`を単一handleで読み、SHA-256と件数を確認した後、検証済みfollow-on graphから終端frontierを再計算します。`selected_sha256`は厳格completeの最深leafだけ、timeout・上限・cycle・omissionは`pending_sha256`とblockerへ写像され、外部取得・検体実行・通信の安全フラグは常にfalseでなければなりません。graphと一致しない取得済み主張はjob結果へ公開しません。
