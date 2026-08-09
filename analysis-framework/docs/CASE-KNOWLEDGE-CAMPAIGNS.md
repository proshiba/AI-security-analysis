# 検体特徴と攻撃キャンペーン相関

この仕組みは、YARA／Sigmaとは別に、過去解析から「検体そのものの特徴」と
「静的に確認した挙動」だけを標準化し、強い共有証拠を持つcaseへ攻撃キャンペーン候補の
ラベルを付けます。検体の実行、復元バイナリの公開、外部インフラへの接続は行いません。

## caseごとの成果物

各 `versions/<version-key>/cases/<sha256>/` に次を置きます。

- `FEATURES.md`: 人が読む日本語の挙動・検体特徴一覧。IOC値、YARA、Sigma、C2値は含めない。
- `features.json`: 同じ内容の機械可読profileと解析充足度。
- `campaign-labels.json`: 既知fingerprintとの一致結果。一致なしも `no_strong_match` として記録する。

`features.json` の `analysis_assessment.status` は次の意味です。

- `complete`: 挙動と検体特徴を含む主要な直接根拠が揃う。
- `partial`: 解析根拠はあるが、挙動の明文化、終端payload、設定などに追加作業がある。
- `insufficient`: 公開済み成果物だけでは主要項目を説明できない。

監査は不足を推測で補いません。特に、ファミリー一般情報から検体固有configやC2を
補完せず、外層packerの所見と終端payloadの所見を分離します。

## 全caseの再生成と監査

```powershell
python .\analysis-framework\common\generate_case_features.py --repository . --write
python .\analysis-framework\common\generate_case_features.py --repository . --check
python .\analysis-framework\common\audit_case_knowledge.py --repository . --write
```

### 指定したcaseだけの再生成と監査

全caseを更新せず、追加解析したcaseだけを正規生成するときは、repository相対の
caseディレクトリを `--case-dir` で指定します。

```powershell
python .\analysis-framework\common\generate_case_features.py --repository . `
  --case-dir analysis-results/malware/<family>/versions/<version>/cases/<sha256> --write
python .\analysis-framework\common\generate_case_features.py --repository . `
  --case-dir analysis-results/malware/<family>/versions/<version>/cases/<sha256> --check
```

`--case-dir` は複数回指定できます。省略時は従来どおり全caseを処理します。
指定先はrepository内の `analysis-results` 配下にあるSHA-256名のcaseディレクトリに
限定されます。repository外のパス、`..`、symbolic link／junction等のreparse point、
重複指定は安全のため拒否します。サブセット処理でも `analysis_history.yaml` との相関は
維持されます。

監査結果は `analysis-results/research/audits/case-knowledge-<date>/` に保存します。
全件の不足理由と次の作業は `audit.json`、人向け集計は `README.md` にあります。

## campaign相関の考え方

相関は `analysis-framework/registry/campaign_correlation_rules.json` の閾値と重みに従います。
共有URL、endpoint、非ルートの共有子要素hashなどを使い、同一ファミリー内と
ファミリー横断で別の閾値を適用します。次は単独のcampaign証拠にしません。

- ファミリー名、collection、収集日、ファイル名
- IPアドレス1個だけの一致
- 汎用的な実行方式やpackerだけの一致
- Microsoftの仕様URL、署名検証先、BitTorrentの正規bootstrap
- localhost、private／予約address、ファイル名を誤認したドメイン

`IOC-LIST.md` が存在するcaseでは、この一覧を公開IOCの信頼境界として使います。
提出検体hashしか掲載されていない場合は「相関可能なnetwork IOCなし」と解釈し、
汎用JSON文字列走査へfallbackしません。これにより、`.pdb`、`.drv`、短い疑似TLD、
文書参照URLをcampaign証拠へ昇格させる誤相関を防ぎます。

campaign候補は同一アクターへの帰属を意味しません。共有サーバー、builder、販売基盤、
ホスティングの再利用でも同じ結果になり得るため、各候補に制約を明記します。

## campaign成果物と自動ラベル

```powershell
python .\analysis-framework\common\correlate_campaigns.py --repository . `
  --output-root .\analysis-results\research\campaigns\correlated-20260724 `
  --fingerprints .\analysis-framework\registry\campaign_fingerprints.json `
  --case-labels --write
python .\analysis-framework\common\correlate_campaigns.py --repository . `
  --output-root .\analysis-results\research\campaigns\correlated-20260724 `
  --fingerprints .\analysis-framework\registry\campaign_fingerprints.json `
  --case-labels --check
```

出力は `analysis-results/research/campaigns/correlated-<date>/` に置きます。各候補には
`README.md`、`campaign.json`、`iocs.json`、`IOC-LIST.md`、`rules/correlation-rule.json` があり、
再利用用fingerprintは `analysis-framework/registry/campaign_fingerprints.json` に集約します。

`common/analyze_sample.py` は新しいcaseの解析後に `features.json`、`FEATURES.md`、
`campaign-labels.json` を生成します。自動ラベルは、fingerprintに登録した強い指標が
必要数一致し、かつ既知の対象ファミリーに含まれる場合だけ付与します。挙動特徴だけの
一致や、未知ファミリーへの横断的な類推ではラベルを付けません。
追跡済みcaseの `campaign-labels.json` を更新するときは、他の追跡成果物hashを先に検証し、
`campaign-labels.json` のhashと `report.json` のsemantic sealを同期します。

`--case-labels` を省略した場合、campaign snapshotとfingerprintだけを操作し、既存caseの
`campaign-labels.json` は変更も検査もしません。`--write` と `--check` の両方を省略した
場合はdry-runです。

## 派生成果物の一括更新

campaign snapshotの追加後にIOC一覧を作り、その後にコード類似性索引を更新する必要があります。
順序の抜けと書込み後の検証漏れを避けるには、次の共通入口を使います。

```powershell
python .\analysis-framework\common\refresh_derived_artifacts.py --repository . `
  --campaign-output-root .\analysis-results\research\campaigns\correlated-20260724 `
  --case-labels --write
python .\analysis-framework\common\refresh_derived_artifacts.py --repository . `
  --campaign-output-root .\analysis-results\research\campaigns\correlated-20260724 `
  --case-labels --check
```

処理順はcampaign、IOC一覧、コード類似性索引です。`--write` ではこの順に更新した後、
同じ範囲を再度checkします。既定はread-onlyのdry-runで、検体の読込み・実行や外部通信は
行いません。

## 旧analysis.jsonの版移行

既知の旧形式だけにトップレベル `schema_version` を補う場合は次を使います。
未知形式は変更せず監査対象として残します。

```powershell
python .\analysis-framework\common\normalize_analysis_schema.py --repository . --write
python .\analysis-framework\common\normalize_analysis_schema.py --repository . --check
```
