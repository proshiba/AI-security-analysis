# 外部API連携helper

`analysis-framework/common/external_api_helpers.py` は、検体取得とIOC補強に必要な
外部serviceを、Python 3.11以上と標準library中心で利用するためのclientです。
moduleのimportとclient生成だけでは通信せず、資格情報は各API操作の実行時に環境変数
からだけ読みます。keyを引数、設定file、logへ渡さないでください。

## helperと資格情報

| client | 主な操作 | 操作時に必要な環境変数 |
|---|---|---|
| `MalwareBazaarClient` | SHA-256／tag／signature／family照会、暗号化ZIP取得 | `MALWAREBAZAAR_AUTH_KEY` |
| `MaxMindClient` | local GeoLite2 City／ASN照合、任意のGeoIP2 web service照合 | local照合は不要。web serviceは`MAXMIND_ACCOUNT_ID`と`MAXMIND_LICENSE_KEY` |
| `VirusTotalClient` | file hash／IP／domain補強、既存sandbox behavior要約 | `VT_API_KEY` |
| `TriageClient` | 検体取得・submit、status poll、behavior report・memory artifact取得 | `TRIAGE_API_KEY` |

検体download先は`output_path`または`downloads_dir`で明示できます。省略時は
`MALWARE_LAB_DOWNLOADS_DIR`、それもなければ現在directory配下のgit管理外
`downloads/`を使います。既存fileは上書きしません。

## 公開API

```python
MalwareBazaarClient(*, http=None)
query_by_hash(sha256: str) -> dict | None
query_by_tag(tag: str, *, limit: int = 100) -> list[dict]
query_by_signature(signature: str, *, limit: int = 100) -> list[dict]
query_by_family(family: str, *, limit: int = 100) -> list[dict]
download_sample(sha256: str, output_path: Path | None = None, *, downloads_dir: Path | None = None) -> dict

MaxMindClient(city_db_path: Path | None = None, asn_db_path: Path | None = None, *, http=None)
enrich_ip(ip_address: str, *, use_web_service: bool = False) -> dict

VirusTotalClient(*, http=None, limiter: RateLimiter | None = None)
enrich_file_hash(file_hash: str) -> dict
enrich_ip(ip_address: str) -> dict
enrich_domain(domain: str) -> dict
fetch_behavior_reports(file_hash: str) -> dict

TriageClient(*, http=None, sleeper=time.sleep, clock=time.monotonic)
fetch_sample(sample_id: str, output_path: Path | None = None, *, downloads_dir: Path | None = None, expected_sha256: str | None = None, password: str = "infected", member_name: str | None = None, max_bytes: int = 536870912) -> dict
submit_sample(sample_path: Path, *, profiles: Sequence[str] = (), tags: Sequence[str] = (), timeout_seconds: int | None = None) -> dict
get_analysis_status(sample_id: str) -> dict
poll_analysis_status(sample_id: str, *, interval_seconds: float = 15.0, timeout_seconds: float = 900.0) -> dict
retrieve_behavioral_report(sample_id: str, task_id: str | None = None) -> dict
list_memory_dump_artifacts(sample_id: str) -> list[dict]
retrieve_memory_dump(sample_id: str, task_id: str, artifact_name: str, output_path: Path, *, max_bytes: int = 67108864) -> dict
```

`HttpClient`はtimeout、応答byte上限、429／一時的5xxの上限付き再試行を共有します。
header、URL、応答本文をlogや例外へ出さないため、tokenをdebug出力へ含めません。
Triageの既定transportは`NoRedirectHandler`を使い、same-host／cross-hostの30xを拒否します。
`TriageClient(http=...)`へ明示transportを注入する場合は、`redirects_denied is True`を
公開する必要があります。拒否能力を確認できないtransportはfail closedで受け付けません。

## GeoLite2の準備

MaxMindはlocal MMDBを優先します。MaxMind accountでGeoLite2を有効化し、公式
`geoipupdate`を導入して、repository外のprivate directoryへ次のeditionを更新します。

```text
EditionIDs GeoLite2-City GeoLite2-ASN
```

WindowsではMaxMind配布の`geoipupdate.exe`、Linuxではpackageまたは公式binaryを使い、
定期実行でDBを更新します。`geoipupdate`の設定fileにaccount IDとlicense keyを置く場合は、
OSのaccess controlで保護し、repositoryへ追加しないでください。Pythonからlocal照合する
場合だけ、既存の任意依存を導入します。

```bash
python3 -m pip install -r analysis-framework/requirements-maxmind.txt
```

`MaxMindClient(Path("GeoLite2-City.mmdb"), Path("GeoLite2-ASN.mmdb"))`へ両pathを
渡すと、`MAXMIND_LICENSE_KEY`なしでcountry、city、ASN、organizationを正規化します。
web serviceは`use_web_service=True`を明示した場合だけ使用します。GeoLite2の位置情報は
概略であり、個人、住所、攻撃者所在地、C2稼働を確定する根拠にしません。

## rate limitと再試行

- VirusTotal clientの既定`RateLimiter`はpublic API想定の4 request/分、500 request/日です。
- batch処理では同じ`VirusTotalClient` instanceを再利用してください。別process間の枠は共有しません。
- 429では`Retry-After`を優先し、なければ上限付き指数backoffを使います。
- 日次上限へ達した場合は`RateLimitError`で停止します。keyを切り替えて迂回しません。
- MalwareBazaarとTriageも429および一時的5xxだけを上限付きで再試行します。

## 検体取扱い

取得対象はLIVE MALWAREです。MalwareBazaarの検体downloadと、Triageが暗号化ZIPを
返す既存経路では、server応答が暗号化ZIPであることを確認し、そのbyteを変更せず保存します。
Triageがraw sampleを返した場合は`expected_sha256`との完全一致を必須とし、平文をdiskへ
書かずmemory上でpassword `infected`のWinZip AES-256へ包んでから保存します。保存先は
atomicな新規fileとして作成し、既存fileを上書きしません。結果metadataにはserver応答が
暗号化ZIPだったか、sourceのSHA-256とsize、平文を保存していないことを記録します。
`max_bytes`はHTTP応答だけでなく保存する暗号化archiveにも適用します。raw sampleが上限内でも、
AES-256 ZIP化による増加後に上限を超えた場合はdiskへ書く前に拒否し、
`archive_size_limit_exceeded`として分類します。自動展開、password解除、import、実行は行いません。

Triageへのsubmitは、承認済みのdynamic-analysis workflowで対象と保存先を明示した場合だけ
使用してください。helperはorchestrator上で検体を実行しません。memory dumpも不透明な
artifactとしてrepository外へ保存し、別の承認済み静的解析工程へ渡します。検体、memory
dump、API生応答、資格情報はcommitしないでください。

## テスト

全network I/Oは`unittest.mock`で置き換え、実serviceや実検体へ接続しません。

```bash
python3 -m pytest -q analysis-framework/tests/test_external_api_helpers.py
```
