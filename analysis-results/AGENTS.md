# Analysis-results instructions

このファイルは `analysis-results/` 配下の全成果物に適用します。ルート `AGENTS.md` の安全・分類・検証ルールも併せて遵守してください。

## 個別解析の必須成果物

- 個別のcase、campaign、incident解析ディレクトリには、人間向けの `README.md` とIOC専用の `IOC-LIST.md` を置くこと。
- `IOC-LIST.md` は `analysis-framework/common/generate_ioc_lists.py` から生成すること。生成物を直接編集しないこと。
- 解析に公開可能なIOCがない場合も、空の標準表を持つ `IOC-LIST.md` を残すこと。
- リポジトリ横断索引 `analysis-results/IOC-INDEX.md` も同じgeneratorで更新すること。

## IOC専用一覧の内容

- 表の列は `Type`、`Value`、`Role`、`Confidence`、`Source` に固定すること。
- 検体・payload hash、domain、IP、endpoint、URL、証明書hash、特徴的なfile path/nameのうち、解析証拠に紐づく値だけを載せること。
- 配布先、stage取得先、C2、証明書、submitted sample、embedded payloadなどの役割を区別すること。
- 挙動説明、推測、検知考察、Shodan/Sigma/YARAクエリ、汎用的なコマンド・プロセス名を一覧へ書かないこと。これらはREADMEまたはrulesへ残すこと。
- URLからuserinfo、query、fragmentを除去すること。token、password、メールアドレス、API keyその他の資格情報を掲載しないこと。

## Hash OSINT result rules

- Case OSINT output contains normalized evidence only. Raw provider responses
  belong under ignored `.work/` storage and must not be committed.
- Curated research must be keyed by exact SHA-256, marked analyst-reviewed, and
  retain sanitized provenance. General family articles are context only unless
  they identify or structurally correlate the exact case.
- One provider is low confidence; medium requires two independent agreeing
  providers. Retain disagreements and unresolved status explicitly.
- Never publish API keys, environment-variable names, credentials, URL query or
  fragment data, email addresses, recovered secrets, or safety-check output.
- `context_only`、`not_ioc`、`not_c2`、`dual-use` の値を除外すること。
- 正規署名付きhost、decoy、共有サービスは、悪性を示す相関があっても単体hash/domainをIOC専用一覧へ載せる必要性を再評価し、単独悪性判定につながる値は除外すること。
- TCP open、通常HTTP応答、証明書、banner、JARMだけでC2を `confirmed` としないこと。

## 更新と検証

元のREADME、`iocs.json`、`config.json`、`analysis_history.yaml` を更新してから、リポジトリルートで次を実行してください。

```powershell
python .\analysis-framework\common\generate_ioc_lists.py --repository .
python .\analysis-framework\common\generate_ioc_lists.py --repository . --check
```

generatorを変更した場合は `analysis-framework/tests/test_generate_ioc_lists.py` を実行し、pydocを再生成してください。Markdown変更後は `git diff --check` も実行してください。
