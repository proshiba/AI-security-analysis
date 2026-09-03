# collection公開集計の再投影

`sync_collection_publication.py` は、caseを追加解析した後に
`publication-summary.json` と `manifest.json` の集計だけが古いまま残ることを防ぎます。
検体、repository外のprivate成果物、外部networkは読みません。

## 同期元

- `report.json`: case状態とblocker
- `c2-analysis.json`: C2解析結果。`c2_analysis_contract`で検証する
- `static-logic.json`: 静的ロジック状態、関数解析coverage、固有program
- `analysis_contract`: report seal、成果物hash、case境界を検証する
- `validate_function_analysis`: 完了を名乗る代表関数解析を検証する

未解決C2や`partial` caseは異常ではありません。未解決状態とfinding数をそのまま投影し、
collection全体を`partial_followup_required`として扱います。一方、case sealの不一致、成果物hashの
不一致、SHA-256境界違反、完了を名乗る不正な関数解析はfail-closedで更新を中止します。
reportが`complete`を名乗る場合は、C2契約の完了と代表関数静的解析の完了も必須です。どちらかが
未完了ならcaseを自動的に`partial`へ降格せず、不整合として同期を停止します。

reportの`classification.selected_families`が空で、既存summaryの`attribution_basis`が
MalwareBazaarやprovider報告に由来する場合は、次の区別をcaseへ明示します。

- `family_attribution_status`: `provider_reported_not_statically_confirmed`
- `statically_confirmed_family`: `null`
- `family_role`: `provider_reported_grouping`

caseのblockerは重複を除いて並べ替え、case表示とcollection全体のblocker件数を同じ集合から生成します。

## 使用方法

差分確認:

```powershell
python analysis-framework/common/sync_collection_publication.py `
  --repository . `
  --collection analysis-results/collections/<collection-id> `
  --check
```

同期:

```powershell
python analysis-framework/common/sync_collection_publication.py `
  --repository . `
  --collection analysis-results/collections/<collection-id> `
  --write
```

`--check`は一致時に終了code 0、stale時に1、入力検証失敗時に2を返します。`--write`は両JSONを
一時fileへ完全に書いてfsyncし、入力が検証時から変化していないことを再確認してから置換します。
置換後は両JSONのbyte列と再parse結果を期待値へ照合します。途中の置換または事後検証に失敗した場合は
置換済みfileを元のsnapshotへ戻して再検証します。`--check`を含むread-only処理も終了直前にsource
snapshotの競合を再確認します。管理対象外の既存fieldは保持します。
