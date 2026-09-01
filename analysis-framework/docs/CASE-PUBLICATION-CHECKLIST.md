# 新規解析の公開・全体反映チェックリスト

## 目的

新しい検体をcaseディレクトリへ置いただけでは、全件索引、IOC索引、コード類似性、UI、READMEの件数は更新されません。本手順は、解析状態とcase identityを分離し、固定レイアウトに存在する全caseを同じ正本から漏れなく公開するための完了条件です。

`catalog/cases.json`への登録は「このcaseが存在し、どこに格納され、現時点でどのfamilyまたは未分類に属するか」を表します。解析完了を意味しません。`partial`や`triaged_unknown`も登録し、blockerと完了状態は`report.json`およびcollection manifestに残します。

## 対象ファイルのメモ

| 区分 | 正本または生成物 | 更新条件 |
|---|---|---|
| case identity | `analysis-results/malware/<family>/versions/<version-key>/cases/<sha256>/metadata.json` | 全caseで必須。`case_id`、`sha256`、`case_kind`、`family`、`canonical_path`、`collections`、`malware_version`を保持 |
| 解析状態 | case `report.json` | `complete`、`partial`、`triaged_unknown`とblockerを記録 |
| 収集文脈 | `analysis-results/collections/<collection-id>/manifest.json` | collectionに属する場合。`cases`と`family_sources`を同期 |
| 全case索引 | `analysis-results/catalog/cases.json` | 固定レイアウトに存在する全case。手編集せず生成 |
| 解析履歴 | `analysis_history.yaml` | 新規解析または解析レベル・IOC・結果pathを更新した場合 |
| family文書 | familyの`README.md`、`OSINT.md`、`TECHNICAL-ANALYSIS.md`、`VERSIONS.md` | 新規family、版根拠、OSINT、技術知見が増えた場合 |
| 個別成果物 | `README.md`、`FEATURES.md`、`STATIC-LOGIC.md`、`OVERALL-LOGIC.md`、`iocs.json`、rules | 各解析契約と静的根拠に従う |
| IOC生成物 | caseの`IOC-LIST.md`、`analysis-results/IOC-INDEX.md` | case、IOC、履歴を変更した場合 |
| 関数コード類似性生成物 | `analysis-results/catalog/code-similarity.json`、`CODE-SIMILARITY.md` | 静的ロジックを追加・更新した場合 |
| 全体ロジック類似性生成物 | `analysis-results/catalog/logic-similarity.json`、`LOGIC-SIMILARITY.md` | 静的ロジック、復元層、featuresを追加・更新した場合 |
| checksum | 各`manifest.sha256` | 配下の追跡対象成果物を変更した場合 |
| UI生成物 | `ui/data.js`、`ui/api/v1/meta.json`、`ui/api/v1/search.json` | case、catalog、IOC、family文書、campaign、履歴を変更した場合 |
| 件数表示 | ルート`README.md`、`analysis-results/README.md` | case集合を変更した場合。一括反映で生成 |
| campaign | `analysis-results/research/campaigns/correlated-<日付>/`、case label | 相関根拠を追加した場合。単一IOCやfamily名だけで自動確定しない |

## 更新順序

1. caseを固定レイアウトへ配置し、case `metadata.json`と`report.json`を作成します。未分類は`case_kind: unclassified`とし、`attribution_status`を明示します。
2. collectionに属する場合は、公開処理からmanifest membershipとcase metadataの`collections`を同時更新します。後から収集元を推測してはいけません。
3. `analysis_history.yaml`、family文書、版根拠、rules、campaign相関など、人の判断が必要な正本を更新します。
4. 次の一括反映を実行します。

```powershell
py -3.13 .\analysis-framework\common\refresh_case_inventory.py --repository . --write
```

LinuxまたはGitHub Actionsでは`python3`を使用できます。一括反映は、metadata identity、catalog、README件数、IOC、関数コード類似性、全体ロジック類似性、checksum、UI、portal indexの順で更新し、同じ範囲を自動で再検証します。類似pairはendpoint別の有界候補として保持し、checksumはfile全体をメモリへ載せず逐次hashします。検体の読込み、実行、外部通信は行いません。

5. 独立したcheckを再実行します。

```powershell
py -3.13 .\analysis-framework\common\refresh_case_inventory.py --repository . --check
```

6. 対応するunit test、日本語文書監査、local link監査、`git diff --check`を実行します。公開Python APIを変更した場合はpydocも再生成します。
7. `git diff`で検体本体、復元binary、PCAP、資格情報、provider生応答、ローカル絶対pathが混入していないことを確認してからcommitします。

## fail-closed条件

次のいずれかがあれば公開完了にしません。

- 固定レイアウトのcase総数とcatalog件数が一致しない。
- catalogに実体のないcaseがある、またはfamily、version、path、case kindが実体と一致しない。
- collection manifestとcase metadataのmembershipが一致しない。
- UIがfilesystem走査でcatalog不足を補完している。
- README、IOC、関数コード類似性、全体ロジック類似性、checksum、UI、portal indexのいずれかが古い。
- `partial`を隠すためにcatalogから除外している、またはcatalog登録を根拠に`complete`と記載している。

## PR記載事項

- 追加・更新したcase数とSHA-256重複数。
- `complete`、`partial`、`triaged_unknown`の内訳と主要blocker。
- catalog件数と固定レイアウト件数が一致したこと。
- 一括反映とcheckの実行結果。
- 実施したunit test、文書監査、安全確認と、残る未検証事項。
