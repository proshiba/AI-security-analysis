# 未完了静的解析follow-upの自動化

## 目的

`collection_followup_planner.py`は、公開済みcollectionの`manifest.json`、`publication-summary.json`、各caseの`report.json`と`c2-analysis.json`を相互検証し、未完了理由を次の静的解析actionへ変換します。`triaged_unknown`のblocker配列が空でも、終端payload、family、config、C2 endpoint、protocolの構造化phaseが未解決ならfollow-up対象になります。

検体の実行、CPU emulation、C2／配布先への接続は行いません。未登録blocker、case集合の不一致、path越境、reparse point、不正JSON、SHA-256不一致は推測で継続せず停止します。C2文書の意味上の不備、必須object欠落、重複phase、または64件を超えるphase配列はcollection全体を中断せず、そのcaseだけを`manual_review_required`へ閉じます。

## 自動処理の順序

1. collection、取得manifest、公開summaryのSHA-256集合を一致させます。
2. canonical case pathをrepository内へ限定し、`artifact_sha256` sealを含むcase整合性と正式C2契約のidentity・安全flagを確認します。sealがないcaseは自動計画へ通しません。
3. 終端payload未取得、終端family未解決、config未回収、endpoint未回収、protocol未確認、関数解析待ち、再公開待ちを機械可読blockerへ正規化します。
4. `remediation_registry.py`の閉じたpolicyだけを使い、上限付き静的復元、family判定、handler、config、protocol、関数確認、再公開の順にactionを並べます。
5. `--input-root`がある場合は、linkを辿らない深さ8・10,000 entry上限の単一走査で対象全件を索引化し、一意な`<sha256>.zip`だけを選びます。各archiveのsizeと取得時SHA-256を照合し、archiveを展開も実行もしません。入力rootの絶対pathは公開計画へ記録しません。
6. `STATIC-FOLLOWUP-PLAN.json`を機械可読正本、`STATIC-FOLLOWUP-PLAN.md`を人間向け要約として出力します。

Ghidraを有効にしたdaily解析では、Ghidraの各chunk後にこの計画を再生成します。復元または追加関数解析でcaseが更新されるたびに、閉じたgapは計画から除外され、残った最小actionが次の実行候補になります。

## 単独実行

全caseを計画する場合:

```powershell
py -3.13 -B .\analysis-framework\common\collection_followup_planner.py --repository . --collection .\analysis-results\collections\<collection-id> --input-root C:\analysis-lab\private\<collection-id>\source --write
```

特定SHA-256だけを再開する場合は`--sha256`を必要数指定します。

```powershell
py -3.13 -B .\analysis-framework\common\collection_followup_planner.py --repository . --collection .\analysis-results\collections\<collection-id> --sha256 <sha256> --write
```

既存計画が現在のcase状態と一致するかは`--check`で確認します。不一致なら終了code 1です。

## 出力の読み方

- `decision=followup_required`: 登録済み静的actionだけで次へ進められ、取得archiveも検証済みです。
- `decision=source_verification_required`: actionは保持していますが、取得archiveが未確認、不在、不一致、重複または不安全なため自動dispatchを止めています。
- `decision=changed_evidence_required`: 取得archiveは検証済みですが、残るactionがすべて新しい証拠を要求します。元archiveの再確認だけを証拠変更とみなさず、同じworkflowを自動再実行しません。
- `decision=manual_review_required`: 未登録blocker、または正式C2契約の非妥当／日次繰越不可findingがあり、自動処理を止めています。
- `automatic_dispatch_allowed=true`: `decision=followup_required`、取得archiveのsize・SHA-256照合済み、かつ少なくとも1つの登録済みactionが同一workflowで再試行可能な場合だけ設定します。
- `source.status=verified`: 取得時archiveのsizeとSHA-256が一致しています。
- `source.status=absent`／`*_mismatch`／`unsafe_or_invalid`: 入力を解析器へ渡しません。
- `minimum_next_action`: 現在の証拠から最初に行う最小の静的手順です。
- `changed_evidence`: 同じ未完了結果の無限再試行を避けるため、次の試行前に更新が必要な証拠です。

## 完了条件

外層を解析した、Ghidra処理が終了した、providerのfamily名がある、またはarchiveを展開できたという理由だけでは完了にしません。終端artifactの由来とSHA-256、静的に裏付けたfamily、必要なconfig、C2 endpointとprotocol、代表関数、case整合性、再公開を順に閉じます。必要byteが入力に存在しない場合は、同じ検体を繰り返さず、別途承認された完全配布chainまたは既存sandbox artifactを入力として追加します。

正式C2契約が`daily_ready=true`のdeferred unresolvedであっても、検体解析自体は完了ではありません。`c2_analysis_unresolved`として計画へ残します。必須phase欠落、invalid status、安全flag不正など`daily_ready=false`の契約は`c2_contract_invalid`としてmanual reviewへ送ります。reportが`complete`を名乗っていてもC2契約が`complete=true`でなければ計画から除外しません。
