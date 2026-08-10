# ローカル静的解析ジョブ契約

## 目的

`analysis_job_runner.py`は、WebUIまたはローカルAPIから`analyze_sample.py`を呼び出すための、AIを必要としないmachine-readableな境界です。検体の分類・復元・既知handler適用は既存の`analyze_sample.py`へ委譲し、runnerは次を担当します。

- JSON要求の厳格検証
- 入力rootとjob出力rootの分離
- path traversal、symbolic link、junction、reparse pointの拒否
- 入力件数・個別size・合計size・静的layer数の上限
- 固定allowlistからのsubprocess引数配列生成
- `shell=False`での単一process起動
- API keyとPython注入環境変数を除いた子process環境
- `status.json`、`progress.json`、`result.json`のatomic更新
- `analyze_sample.py`の終了codeと安全summaryの検証

このrunnerは検体を実行せず、外部hostへ接続しません。要求JSONからnetwork、live C2、認証、JARM、任意実行file、任意registry、任意Python、任意outputを有効にすることもできません。

## 配置境界

入力とjob出力には専用directoryを用意します。両rootが同一、または一方が他方の配下にある構成は拒否されます。

```text
C:\malware-job-input\          # 検体専用。Git管理しない
  intake-20260810\sample.zip
  hints\analysis-20260810-0001.json # family hint専用。通常inputsと分離
C:\malware-job-state\          # status、log、静的解析出力。Git管理しない
  analysis-20260810-0001\
```

要求内の`inputs`は`input-root`からのPOSIX形式相対pathです。drive letter、先頭`/`、backslash、`.`、`..`、空component、Windows予約device名を使用できません。

## CLIシグネチャ

### 検証だけを行う

```powershell
py -3.13 .\analysis-framework\common\analysis_job_runner.py validate `
  --request C:\malware-job-requests\analysis-20260810-0001.json `
  --input-root C:\malware-job-input `
  --jobs-root C:\malware-job-state
```

検体解析、job directory作成、状態file作成は行いません。要求と入力境界を検証し、正規化済み計画を標準出力へJSONで返します。

### ジョブを実行する

```powershell
py -3.13 .\analysis-framework\common\analysis_job_runner.py run `
  --request C:\malware-job-requests\analysis-20260810-0001.json `
  --input-root C:\malware-job-input `
  --jobs-root C:\malware-job-state `
  --timeout-seconds 21600
```

`run`は同期実行です。Web APIはこのrunner自体を専用service processとして起動し、応答待ちとは別に`status`をpollします。runnerをshell command文字列へ連結せず、API側も必ず引数配列で起動します。

### 状態を取得する

```powershell
py -3.13 .\analysis-framework\common\analysis_job_runner.py status `
  --jobs-root C:\malware-job-state `
  --job-id analysis-20260810-0001
```

`status.json`、`progress.json`、存在する場合は`result.json`を1つのsnapshotとして標準出力へ返します。

### 終了code

| code | 意味 |
|---:|---|
| `0` | `analyze_sample.py`が完全成功し、安全summaryを検証済み |
| `20` | 追加解析待ちを含む部分成功。job自体は受理済み |
| `1` | analyzerの受理対象外終了code、またはrunner内部error |
| `2` | JSON、path、上限、summary等の契約違反 |
| `124` | 時間上限へ到達 |

## Python APIシグネチャ

Web API adapterまたはローカルserviceから直接importする場合の入口は次です。

```python
load_job_request(path: Path) -> JobRequest

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

未知key、重複JSON key、`NaN`／`Infinity`、UTF-8以外、64 KiBを超える要求fileは拒否されます。

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

入力全体の合計は2 GiB、tree entryは10,000件までです。要求上限を大きくしてもrunnerのhard limitを超えることはできません。`family_hint_manifest`は解析対象file数へ含めず、UTF-8、重複keyなし、非有限数なし、JSON object root、通常file、4 MiB以下をrunnerで検証します。manifest内のexact root SHA-256とfamily候補のschemaは`analyze_sample.py`側でも再検証し、metadata hint単独でfamilyを確定しません。

### 明示的に禁止するoption

`allow_network`、`allow_live_c2_check`、`allow_live_c2_emulation`、`allow_authentication`、`allow_malware_registration_tasking`、`collect_jarm`、`password`、`profile_path`、`registry`、`python`、`output`、`upx`、`sevenzip`、`diec`等は使用できません。未知optionもfail-closedです。

## job directoryスキーマ

```text
<jobs-root>/<job-id>/
  request.json       # 正規化済み要求
  status.json        # lifecycleとterminal状態
  progress.json      # phase単位の進捗
  result.json        # terminal結果
  stdout.log         # 最大1 MiB
  stderr.log         # 最大1 MiB
  analysis/          # analyze_sample.pyの成果物
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
  "artifacts": {
    "analysis_summary": "analysis/summary.json",
    "stdout": "stdout.log",
    "stderr": "stderr.log",
    "stdout_truncated": false,
    "stderr_truncated": false
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
    "network_contacted": false
  },
  "finished_at_utc": "2026-08-10T01:03:00Z"
}
```

失敗時も`result.json`を生成し、`accepted=false`、安定した`error.code`、日本語の`error.message`を記録します。subprocessのraw stderrをJSONへ埋め込まず、privateなjob rootの`stderr.log`だけへ保存します。

## WebUI／API統合

`ui/`は静的閲覧UIであり、ブラウザJavaScriptからローカルprocessを直接起動してはいけません。統合時は次の薄いローカルserviceを別processで用意します。

1. `POST /api/analysis-jobs`でrequest JSONを受け取る。
2. service側の固定`input-root`と`jobs-root`を使用し、clientからroot pathを受け取らない。
3. `validate`または`load_job_request`で受理前検証する。
4. `run`を引数配列、`shell=False`、低権限service accountで起動する。
5. `GET /api/analysis-jobs/<job-id>`は`status`のJSONだけを返す。
6. terminal後、公開可能な解析成果物だけを既存のpublication pipelineへ渡す。

Web serviceには同時実行数、disk quota、rate limit、認証、CSRF対策を別途実装します。runnerの時間・件数・size上限は、それらが破られた場合の第2境界です。

## `analyze_sample.py`との配線

既存`analyze_sample.py`の変更は不要です。runnerは固定pathの同scriptを、次の固定関係で起動します。

```text
request JSON
  -> analysis_job_runner.py
     -> input／option検証
     -> family hint manifestの分離検証（指定時だけ）
     -> [sys.executable, analyze_sample.py, --input, ..., --output, ...,
         --family-hint-manifest, ...]
        shell=False
     -> analysis/summary.json
     -> safety contract検証
     -> status／progress／result JSON
```

`family_hint_manifest`を指定した場合、`analyze_sample.py`は`--family-hint-manifest`を受け取り、exact root SHA-256に対応する候補だけをassessment対象へ追加する必要があります。manifestが未指定なら既存CLIと同じargvです。case単位progressを将来配線する場合はstdoutへ混在させず、job runnerが専用file descriptorまたはJSON Lines event fileで受け取れる任意interfaceを追加します。現在の統合に必須ではありません。

## 検証

```powershell
py -3.13 -m pytest .\analysis-framework\tests\test_analysis_job_runner.py -q
py -3.13 -m ruff check .\analysis-framework\common\analysis_job_runner.py `
  .\analysis-framework\tests\test_analysis_job_runner.py
```

テストはstrict JSON、network／live option拒否、path traversal、重複入力、root重複、reparse、件数上限、sanitized環境、`shell=False`、完全成功、部分成功、安全summary違反、異常終了、timeout、atomic JSON、job ID再利用拒否を確認します。

## 防御上の補足

runnerはnetwork optionを公開せず、信頼済みのオフライン静的解析scriptだけを起動します。ただしPython process自体へOSレベルの通信遮断を付与するものではありません。本番serviceでは専用低権限accountとoutbound denyを併用してください。`summary.network_contacted=false`は解析契約の事後確認であり、OSのegress policyを置き換えません。
