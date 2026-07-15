# Analysis framework

複数のマルウェア種と配布キャンペーンを、検体をローカル実行せずに整理するための解析基盤です。成果物は `analysis-results/<family>/` に分離します。

## 実行順

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
- `analysis-results/<family>/cases/<sha256>/README.md`: 公開用の検体別結果

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

## Malware type selection, detector routing, and VirusTotal sandbox evidence

`classifiers/classify_sample.py` supports two modes:

- Default mode runs every detector registered in `registry/malware_types.json` and selects the malware type from observed structure or known SHA-256.
- `--malware-type <registered-type>` restricts detection to one registered type. This is useful when starting a new analysis with analyst context, but campaign selection still requires detector observations; an explicit family value alone produces `campaign_type: unknown` when structure does not match.

Example:

```bash
python analysis-framework/classifiers/classify_sample.py \
  --sample /path/to/sample.zip \
  --registry analysis-framework/registry/malware_types.json \
  --malware-type valleyrat \
  --output /tmp/classification.json
```

`Invoke-Analysis.ps1` forwards the same selection through `-MalwareType`. It can also collect VirusTotal sandbox behaviour summaries with `-VirusTotalApiKey` (or `VT_API_KEY`). The fetched `virustotal-sandbox.json` is intended as correlation evidence only: process-attributed sandbox network activity must still be correlated with decoded configuration, loader chains, or other static evidence before promoting an endpoint to confirmed C2.

Standalone VirusTotal sandbox fetch:

```bash
python analysis-framework/common/vt_sandbox.py \
  --sha256 <sample-sha256> \
  --api-key "$VT_API_KEY" \
  --output /tmp/virustotal-sandbox.json
```

## 生成物
検体の実行、ライブC2接続、認証情報の公開は既定で行いません。`c2_detector.py` のライブ確認は別途承認された場合だけ利用します。Ghidra MCPはlocalhost限定とし、任意スクリプト実行は無効のままにします。

## リファクタ後の共通I/O

AES-ZIP認証、パス検証、文字コード判定、batch stage、失敗時の確認点は [Safe submission I/O and batch workflow](docs/SAFE-SUBMISSION-IO.md) を参照してください。
## 次期宣言型解析基盤の設計

ファミリー識別、campaign識別、必要ツール、解析DAGをYAMLで定義し、解析実装を共通step catalogへ
集約した構成は [analysis framework documentation](docs/README.md) を参照してください。


## Declarative offline engine

The `src/asa` package validates `definitions/`, evaluates family/campaign rules, enforces the allowlisted step catalog and `offline-default` policy, compiles a deterministic DAG, and executes supported static steps without launching samples or contacting external infrastructure. Use `python -m asa.runtime_cli`; see [implementation notes](docs/DECLARATIVE-ENGINE-IMPLEMENTATION.md).


## Repeatable MalwareBazaar family refresh

`common/malwarebazaar_batch.py` downloads a bounded number of password-protected archives, retries transient API failures, and can exclude every SHA-256 already present below `analysis-results/`. `common/analyze_stealer_set.py` supports ValleyRAT, AgentTesla, RemcosRAT, VenomRAT, Formbook, Vidar, LummaStealer, RemusStealer, and AMOS through the same declarative/static-unpack/config/C2 pipeline. `common/generate_stealer_reports.py` removes local archive paths when it writes public acquisition manifests.

```powershell
python common/malwarebazaar_batch.py `
  --signature ValleyRAT `
  --signature AgentTesla `
  --limit 10 `
  --query-limit 100 `
  --exclude-path ..\analysis-results `
  --root C:\Users\Administrator\MalwareSamples\refresh-YYYYMMDD
```

Run one family manifest through the offline pipeline, then generate its publish-safe refresh tree:

```powershell
python common/analyze_stealer_set.py `
  --manifest C:\Users\Administrator\MalwareSamples\refresh-YYYYMMDD\ValleyRAT\manifest.json `
  --output C:\Users\Administrator\malware-lab\refresh-YYYYMMDD\ValleyRAT `
  --definitions definitions

python common/generate_stealer_reports.py `
  --summary C:\Users\Administrator\malware-lab\refresh-YYYYMMDD\ValleyRAT\summary.json `
  --pipeline-root C:\Users\Administrator\malware-lab\refresh-YYYYMMDD\ValleyRAT `
  --destination ..\analysis-results\valleyrat\refresh-YYYYMMDD `
  --acquisition-manifest C:\Users\Administrator\MalwareSamples\refresh-YYYYMMDD\ValleyRAT\manifest.json
```

The workflow never executes a sample or contacts extracted infrastructure. Recovered layers stay outside the repository in password-protected analysis archives.
