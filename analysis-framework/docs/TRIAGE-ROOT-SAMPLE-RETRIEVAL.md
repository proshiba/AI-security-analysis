# Triage root sampleの安全な取得

`triage_artifact_retrieval.py`は、公開Triage解析に付随するmemory imageやdrop fileに加え、明示的に許可した場合だけroot sampleを取得できます。root sample取得は既定で無効です。

## 実行例

```powershell
$triageOutputRoot = Join-Path $env:MALWARE_ANALYSIS_PRIVATE_ROOT "triage"
py -3.13 analysis-framework/common/triage_artifact_retrieval.py `
  --hash e66bbb6c651b5ab839434b8e62f502169f35894e28dbe9f3275911582eccd250 `
  --output-root $triageOutputRoot `
  --allow-network `
  --download `
  --include-root-sample `
  --max-artifacts 20 `
  --max-root-samples 1 `
  --max-root-sample-bytes 536870912 `
  --max-root-total-bytes 536870912 `
  --password infected
```

`MALWARE_ANALYSIS_PRIVATE_ROOT`には、事前にリポジトリ外の隔離領域を設定してください。

`--include-root-sample`と`--download`の両方がある場合だけroot sampleを取得します。`--include-root-sample`を省略した既存の候補列挙・成果物取得フローは変わりません。保存先はリポジトリ外を指定します。

`--max-root-samples`はroot sample専用の件数上限で、既定は1件、最大は100件です。`--max-artifacts`と`--max-total-bytes`は通常のdrop file／memory artifactだけへ適用され、root sampleには流用しません。root sampleには`--max-root-sample-bytes`の応答・archive単位上限と、`--max-root-total-bytes`の暗号化archive合計上限を別に適用します。既定はいずれも512 MiBで、単体上限の最大は512 MiB、合計上限の最大は1 GiBです。

## 検証と保存

root sample候補は、要求した完全SHA-256とTriage metadataのSHA-256が一致し、公開解析と確認できたsample IDからだけ作成します。同じSHA-256に複数の公開解析がある場合は、最初に検証できた1件だけを取得します。

取得には`external_api_helpers.TriageClient.fetch_sample`を使い、常に`expected_sha256`を渡します。

- raw応答は保存前に完全SHA-256を照合します。
- raw応答は平文をdiskへ書かず、memory内でWinZip AES-256 ZIPに変換します。
- HTTP応答またはAES変換後archiveが単体上限を超えた場合は保存前に拒否します。raw sourceが上限内でも、archive化による増加を例外にしません。
- serverが暗号化ZIPを返した場合はbyte列をそのまま保存します。この場合、`source_sha256`はserver応答archiveのhashであり、root sample本体のhashではありません。
- 保存は新規file作成に限定し、既存destinationを上書きしません。
- 検体の展開、実行、sandboxへの新規submitは行いません。
- API clientは候補照会と同じ`NoRedirectHandler`を使い、same-host／cross-hostの30xをどちらも追跡しません。明示注入transportは`redirects_denied is True`を公開できない限り拒否します。

## manifestへの記録

`manifest.json`には通常成果物と分離して次を記録します。

- `root_sample_opt_in`: 明示optionの有無
- `root_sample_limit`: CLIで固定したroot sample件数上限
- `root_sample_candidates`: 完全hash一致で確認した候補
- `root_sample_download_attempted`: 実際に取得処理へ進んだか
- `root_sample_downloads`: source、sample ID、expected SHA-256、応答SHA-256／size、archive SHA-256／size／暗号方式、平文保存有無
- `root_sample_download_status`: `complete`、`partial`、`not_started`、`not_requested`の処理状態
- `root_sample_budget`: 単体・合計上限、試行数、保存済みarchive合計、残量、上限枯渇理由
- `root_sample_errors`: root sample単位の安全な失敗分類。上限超過は固定reason codeで記録
- `root_sample_archive_total_bytes`: 保存した暗号化archiveの合計size

raw応答を完全照合できた場合だけ`payload_sha256_verified`を`true`にします。server提供の暗号化ZIPは内部を展開しないため、この値は`false`とし、Triage metadataでの一致を`metadata_sha256_verified`へ別記します。

root sampleの取得失敗は`root_sample_errors`へ記録し、他のroot sampleや通常成果物の取得を中断しません。合計残量まで縮めた2件目以降がsize上限を超えた場合は`root_sample_aggregate_byte_budget_exhausted`を記録し、statusを`partial`としてroot sample取得を停止します。例外message、API key、応答本文はmanifestへ保存しません。

## 回帰test

```powershell
py -3.13 -m pytest -q `
  analysis-framework/tests/test_triage_artifact_retrieval.py `
  analysis-framework/tests/test_triage_root_sample_cli.py `
  analysis-framework/tests/test_triage_root_sample_security.py `
  analysis-framework/tests/test_external_api_helpers.py
```

testはmock応答だけを使い、外部通信と検体実行を行いません。
