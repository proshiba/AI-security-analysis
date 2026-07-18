# `analysis-results` の作業規則

このファイルは `analysis-results/` 配下の全成果物に適用します。ルート [`AGENTS.md`](../AGENTS.md) の安全、分類、検証規則も併せて遵守してください。

## 正規レイアウト

- 既知マルウェアと未分類検体のcaseは `malware/<family>/versions/<version-key>/cases/<sha256>/` に置きます。
- 収集回は `collections/<collection-id>/manifest.json` からSHA-256に関連付け、caseを複製しません。
- campaign、サプライチェーン、脆弱性、ニュース、横断監査は `research/` の該当namespaceへ置きます。
- `refresh-*` や収集元を示すフォルダを `malware/<family>/` の下に新設しません。
- 版はsample-specificな根拠がある場合だけ付与し、根拠がなければ `versions/unknown/` を使用します。
- caseを追加・移動したときは `catalog/cases.json`、collection manifest、case `metadata.json`、参照link、checksum manifestを同時に整合させます。

詳細は[成果物レイアウト仕様](../analysis-framework/docs/RESULT-LAYOUT.md)を参照してください。

## 個別解析の必須成果物

- 個別のcase、campaign、incident解析ディレクトリには、人間向けの `README.md` とIOC専用の `IOC-LIST.md` を置きます。
- `IOC-LIST.md` は `analysis-framework/common/generate_ioc_lists.py` から生成し、生成物を直接編集しません。
- 公開可能なIOCがない場合も、空の標準表を持つ `IOC-LIST.md` を残します。
- リポジトリ横断索引 `analysis-results/IOC-INDEX.md` も同じgeneratorで更新します。
- 文書の見出し、本文、表の人間向けlabel、図の説明、制約、根拠、確度、誤検知評価は日本語で記述します。マルウェア名、アクター名、API名、path、JSON key、schema enum、command、hash、domain、URL、IOCなどの技術識別子は原表記を維持できます。
- OSINTの原題や引用を原文で残す場合は、日本語題または日本語要約を併記します。英語の原文だけで概要や根拠を記述しません。
- generatorが作るREADME、IOC表、索引、監査文書も日本語にします。生成結果だけを翻訳せず、template／knowledge data／rendererを修正し、再生成しても英語へ戻らないようにします。

## IOC専用一覧

- 表の列は `種別 (Type)`、`値 (Value)`、`役割 (Role)`、`確度 (Confidence)`、`根拠 (Source)` の5列に固定します。
- 検体／payload hash、domain、IP、endpoint、URL、証明書hash、特徴的なfile path／nameのうち、解析証拠に結び付く値だけを載せます。
- 配布先、stage取得先、C2、証明書、submitted sample、embedded payloadなどの役割を区別します。
- 挙動説明、推測、検知考察、Shodan／Sigma／YARA query、汎用的なcommand／process名は一覧へ書かず、`README.md` またはrulesへ残します。
- URLからuserinfo、query、fragmentを除去します。token、password、メールアドレス、API keyなどの資格情報は掲載しません。
- `context_only`、`not_ioc`、`not_c2`、`dual-use` の値は除外します。
- 正規署名付きhost、decoy、共有serviceは、単独悪性判定につながる値を除外します。
- TCP open、通常HTTP応答、証明書、banner、JARMだけでC2を `confirmed` としません。

## SHA-256単位のOSINT

- caseのOSINT出力には正規化した根拠だけを保存し、生応答はgit管理外の `.work/` に置きます。
- 精査済み調査はexact SHA-256をkeyとし、analyst-reviewedであることと、機微情報を除いた出典を残します。
- 一般的なファミリ記事は、そのcase自体を特定するか構造的相関がある場合を除き、背景情報として扱います。
- 単一providerだけなら確度は低です。中確度には、独立した2つ以上の一致するproviderが必要です。不一致と未解決状態も明記します。
- API key、環境変数名、資格情報、URL query／fragment、メールアドレス、復元secret、安全検査ログを公開しません。

## マルウェアファミリのOSINT文書

- 各ファミリの `README.md` で概要を把握できるようにし、詳細は `OSINT.md`、版根拠は `VERSIONS.md`、既存技術解析は `TECHNICAL-ANALYSIS.md` へ分離します。
- `OSINT.md` には、開発・販売主体、利用アクター、コモディティ／MaaS性、過去の攻撃・標的、主要機能、出典と調査日を含めます。
- 帰属は公開資料の表現を超えて断定せず、不明・諸説あり・犯罪市場で広く利用、などの不確実性を明示します。
- OSINT sourceを更新した場合は、knowledge JSONのschema、URL重複、必須項目、rendererの再現性をテストします。

## 更新と検証

元の `README.md`、`iocs.json`、`config.json`、`analysis_history.yaml` を更新してから、リポジトリルートで次を実行します。

```powershell
python .\analysis-framework\common\generate_ioc_lists.py --repository .
python .\analysis-framework\common\generate_ioc_lists.py --repository . --check
```

generatorを変更した場合は対応するunit testとpydocを更新します。Markdown変更後は日本語監査、local link監査、`git diff --check` も実行します。

日本語監査は、少なくとも次のコマンドをfail-closedで実行します。

```powershell
python .\analysis-framework\common\localize_result_markdown.py --repository .
python .\analysis-framework\common\audit_japanese_docs.py --repository . --root analysis-results --fail-on-findings
```
