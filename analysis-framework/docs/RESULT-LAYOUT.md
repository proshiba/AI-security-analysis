# 解析成果物の固定レイアウト

## 目的

解析 case の親に `refresh-*`、`vx-underground-*`、`malwarebazaar-*` を置かず、マルウェア case の深さを次に固定します。

```text
analysis-results/malware/<family>/versions/<version-key>/cases/<sha256>/
```

収集元と収集日は `analysis-results/collections/<collection-id>/manifest.json` に SHA-256 の membership として保存します。case 本体は collection に複製しません。campaign、incident、脆弱性、ニュース、横断監査は `analysis-results/research/` に分離します。

collection manifest の `cases` は `{"case_id": "sha256:<sha256>"}` だけを保持します。family ごとの集約 artifact は `family_sources` から `sources/<family>` へ対応付けます。

```text
analysis-results/collections/<collection-id>/
├─ manifest.json
└─ sources/<family>/
   ├─ README.md
   ├─ IOC-LIST.md
   ├─ manifest.json
   └─ rules/
```

`unclassified` 配下にあった 101 case は、既知 family と同一視しません。path の固定深さと catalog 互換のため `family=unclassified` は維持しつつ、`case_kind=unclassified`、`attribution_status=unresolved|provisional` を metadata/catalog に保存します。71 case は低信頼の暫定 cluster（MX-Go 1 case を含む）として、安全な family ID に正規化した `provisional_cluster_id` を保持します。残る 30 case は `unresolved` です。cluster 名は既知 family への確定帰属や version 根拠には使わず、version は全 101 case で `unknown` のままです。

npm の axios/plain-crypto-js 侵害で回収した `setup.js` はマルウェア family の release ではありません。この case は次の research path に置き、`case_kind=supply_chain_payload`、`malware_version.status=not_applicable` とします。

```text
analysis-results/research/supply-chain/npm/axios-plain-crypto-js-2026/cases/<sha256>/
```

## caseの標準成果物

新規作成または解析内容を更新するcaseでは、固定階層のcaseディレクトリ直下に次を置きます。

```text
README.md
IOC-LIST.md
features.json
FEATURES.md
static-logic.json
STATIC-LOGIC.md
campaign-labels.json
```

`static-logic.json`／`STATIC-LOGIC.md` は、関数またはスクリプト単位の役割、処理手順、呼出関係、API、主要制御フロー、正規化fingerprint、解析ツール、明示的なprogram selector、根拠と確度を保持します。バイナリ検体で関数解析が未実施の場合は `function_analysis_required` を記録し、解析済みとして扱いません。全caseの横断類似性索引は `analysis-results/catalog/code-similarity.json`／`CODE-SIMILARITY.md` に生成します。

## version の判定

folder に版を使用できるのは、sample-specific な根拠を family ごとに許可した場合だけです。

- Amadey、Latrodectus: 静的に回収した family config。
- RemcosRAT: family config または当該 process に帰属した版根拠。
- SpyGlace: 静的に回収した config。
- PureHVNC: terminal managed static config の候補が 1 個だけの場合。
- VenomRAT: exact sample に対応する tria.ge の外部報告。`reported` とし、`confirmed` には数えません。

`schema_version`、Go/.NET runtime、依存 package、packer、PE file version、一般的な family 記事、first-seen 日だけでは版を決めません。根拠がない、候補が複数、情報が衝突する場合は `versions/unknown/` に置きます。

`malware_version.status` は次のいずれかです。

- `confirmed`: 静的 config など sample-specific な直接根拠。
- `reported`: exact sample に帰属する外部報告。
- `unknown`: 許可した根拠がない、または競合している。
- `not_applicable`: supply-chain payload など、マルウェア family version の概念を適用しない。

`malware_version.evidence[].artifact` は移行前 path ではなく、case directory からの相対 path（例: `analysis.json`）です。これにより case 移動後も根拠参照と `artifact_sha256` の対応が失われません。

## writer／consumer の固定 path

- family expansion writer: case は `malware/<family>/versions/unknown/cases/<sha256>`、run 集約は `collections/<run-id>/sources/<family>`。
- IOC generator: 固定深さ case、`research/campaigns`、`research/supply-chain|vulnerabilities|news`、collection source を列挙する。既知版へ移した case は `catalog/cases.json` で解決する。
- coverage audit: hard-case report は `research/audits/static-hard-cases/deep-static-triage.json` を正規 path とする。
- unknown history writer: `result_path` の既定値は `analysis-results/malware/unclassified/versions/unknown/cases/<sha256>/`。
- IOC Markdown: `種別 (Type)`、`値 (Value)`、`役割 (Role)`、`確度 (Confidence)`、`根拠 (Source)` の 5 列を使用する。

## dry-runによる計画

既定動作は読み取り専用です。検体を開かず、公開済み Markdown/JSON と repository metadata だけから計画を作ります。

```powershell
$python = 'C:\path\to\python.exe'
$env:PYTHONPATH = '<repo>\analysis-framework\common'
& $python .\analysis-framework\common\normalize_result_layout.py `
  --repository . `
  --output .\.work\layout-migration-plan.json
```

実 repository に対する基準値は次のとおりです。

| 項目 | 期待値 |
|---|---:|
| 全 SHA case | 554 |
| malware case | 452 |
| unclassified case | 101 |
| サプライチェーンpayloadのcase | 1 |
| 解決した malware version | 62 |
| confirmed | 58 |
| reported | 4 |
| unknown（既知 malware family） | 390 |
| unknown（unclassified） | 101 |
| unknown 合計 | 491 |
| global collection | 4 |
| collection membership | 408 |
| SHA 重複 | 0 |
| content conflict | 0 |

計画には、case/artifact/research の決定的 move map、`catalog/cases.json`、collection manifest、case `metadata.json`、Markdown/JSON/`analysis_history.yaml` の参照更新、checksum manifest の再生成、path 長、衝突、事後条件が含まれます。

## 書込み

`--write` がない限り成果物は移動しません。`--write` は preflight error が 0 の場合だけ適用します。

```powershell
& $python .\analysis-framework\common\normalize_result_layout.py `
  --repository . `
  --output .\.work\layout-migration-applied.json `
  --write
```

適用処理は source/target の repository containment、SHA 重複、同一 stage の二重 move、既存 target、content fingerprint、絶対 path 長を先に検査します。途中で失敗した場合は、移動、生成 metadata、catalog/collection、Markdown、JSON、history、checksum manifest の元 bytes と新規空 directory を復元します。

plan の各 move は fingerprint 方式、digest、除外した case source の一覧を保持します。`--write` は全 move を始める前に同じ方式と同じ除外集合で source fingerprint を再計算し、case または run/family artifact が plan 作成後に変化していれば一切書き込まず stale plan として拒否します。artifact fingerprint から除外した case は、対応する stage-1 case move が個別に検証します。

2026-07-17に実repositoryへ適用済みです。適用後の計画は `.work/layout-migration-applied.json` に保存し、554件のSHA-256 identity、652件のmove fingerprint、版根拠artifactのhash、catalog、collection、固定深度、path長、重複・衝突なしを再検証しました。適用計画のSHA-256は `ad882557cdf4f0f682101b399c31bd63767acf948b949de4e835950057b0d805` です。

移行後の再実行では、各caseの `metadata.json` と既存collection manifestを相互照合し、4 collection／408 membershipを再集計します。既存metadata、catalog、collectionが計画と意味的に同一なら再作成せず、不一致なら書込み前に拒否します。公開処理も、既存caseのschema、SHA-256、case ID、種別、canonical path、版状態と、collection内の各case ID／family sourceを要素単位で検証します。不正要素を黙って削除または上書きしません。`manifest.sha256` も内容または配下参照が変わったものだけを再生成するため、適用直後のdry-runは再生成0件になります。

## 事後条件

- malware case はすべて固定 6 階層。
- unclassified case も `malware/unclassified/versions/unknown/cases/` の固定 6 階層とし、case kind は分離。
- npm supply-chain payload は research namespace。
- SHA case 総数と SHA identity は移行前後で不変。
- `analysis-results` 直下の directory は `_shared`、`catalog`、`collections`、`malware`、`research` だけ。
- root file は `README.md`、`IOC-INDEX.md`、`AGENTS.md` だけ。
- Markdown link、JSON path、`analysis_history.yaml`、checksum manifest は move map と一致。
- 検体実行、CPU/CIL エミュレーション、外部通信はいずれも行わない。
