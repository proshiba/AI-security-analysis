# 全履歴metadataによる自動化未完了監査

`automation_failure_inventory.py`は公開`catalog/cases.json`から全履歴caseを列挙し、固定した4種類のJSON metadataだけを読んで、未完了blocker、改善action、family別の影響、設定の記録状態、URL役割を標準出力へ集計します。検体、保持payload、PCAP、Ghidra project、任意のartifact pathは読みません。file書込み、network、解析実行、再開、公開更新は行いません。

```powershell
py -3.13 -I -X utf8 -B .\analysis-framework\common\automation_failure_inventory.py --repository .
py -3.13 -B -m pytest .\analysis-framework\tests\test_automation_failure_inventory.py -q
```

既存`summary.json`を持つone-shot runの詳しい集計には`summarize_one_shot_corpus.py`を使用します。本監査はrun summaryが残っていない過去caseもcatalogの分母へ残し、既存corpusの純粋なschema validatorとblocker allowlistを再利用します。collectionの静的action計画は[follow-up planner](STATIC-FOLLOWUP-AUTOMATION.md)、実行stateとretry budgetの判定は[再開planner](AI-FREE-STATIC-ANALYSIS-ORCHESTRATION.md)が正本です。この監査はそれらを代替しません。

## 件数と分母

- `all_cases`: catalogにある全case。非malware、metadata欠落、不明schemaも除外しません。
- `record_valid_cases`: reportの意味seal・identity・安全flagと、reportへhash bindingされたorchestrationの既存schema validatorを通過したcase。全artifact、検体、現在実装との一致を検証した件数ではありません。
- `config_required_cases`: 上の有効caseのうち、config gateが厳密なboolean `true`で設定を要求する件数。
- `config_candidate_cases`: 有効caseの候補回収flagを持つ件数。確認済み設定回収とは独立です。
- `recorded_config_on_required`: 設定必須caseだけを分母とする、確認済み回収の**記録**の割合。
- `recorded_config_on_valid`: 有効record全体を分母とする割合。設定非必須caseを含むため、上の率と混同しません。
- `candidate_only_cases`: 候補は記録されたが確認済み回収は記録されていない件数。

`family_coverage`はcatalog上のfamily別に同じ分母を示します。catalog familyは終端familyの静的確証ではありません。候補回収率を確認済み成功率へ混入させず、未知、古いschema、途中状態、hash未束縛を成功へ昇格しません。`c2_recorded_outcome`も記録された判定に限定し、稼働中C2や独立再実証の件数を意味しません。`full_artifact_seals_verified=false`を常に保持します。

既存corpus validatorはreportの`executed_sample`、`network_contacted`、`ai_used`がすべて厳密な`false`であることを要求します。過去のAI補助解析、明示許可された通信を含む解析、これらのflagがない旧成果物は有効record分母へ入りません。`validation:report_safety_invalid`はこの現行のAI非依存・非接続metadata契約に適合しないという記録監査結果であり、検体が実行されたことや現在のhost侵害を断定するものではありません。

URLはorchestrationの`network_endpoints`からHTTP(S)実値または正規化された`scheme/host/port/path`を内部で識別し、明示roleだけを閉じた対応表へ分類します。case内の同じURL・同じroleは重複除外します。配布、stage、設定、C2、C2候補、exfiltration、decoy、context、unknownを分離し、role未記録のURLを推測でC2へ扱いません。provenanceのfield名から役割を補完せず、未知roleの件数を残します。値、query、token、source name、pathは出力しません。

## 変更条件の比較

前回出力をoperatorが同じリポジトリ内の監査用JSONとして保持した場合、`--baseline <path>`で比較できます。helper自身は保存しません。

- `implementation_contract`: 保存された`analysis_contract.sha256`。実装だけでなく設定やruntimeも含み得る契約fingerprintです。実装のみのdriftと断定しません。
- `input`: 内部SHA-256、size、外装SHA-256、外装size、入力kindのcommitment。未記録input fieldを補完しません。
- `evidence`: 読み込んだ固定metadataのcanonical JSON commitment。formatだけの変更は除外しますが、説明や派生状態の変更も含むため、独立した新証拠の存在を保証しません。

全条件が同じ場合は`unchanged_no_retry`、比較根拠欠落は`comparison_unknown`、いずれかが変化した場合は`successor_review_required`です。どの判定でも`automatic_retry_allowed=false`です。変更検出だけで同じworkflowを再開せず、正式plannerとoperatorが証拠の意味、未登録blocker、残試行回数、successor要否を確認します。

## 読取境界と限界

catalogのcanonical pathを固定malware階層・case identityへ完全一致させ、相対越境、symlink、junction、reparse point、hardlink、file identity変更、重複JSON key、指数overflowを含む非有限数、不正UTF-8を拒否します。単一handle読取後にidentityを照合し、最後にmetadata hashとdirectory identityを再検証します。省略可能metadataの初回欠落もsnapshotに保持し、最後に出現していないことを再確認します。欠落確認とその再検証もfile回数予算へ算入します。任意artifact一覧からfileを開かず、report内の保持binary参照も追跡しません。

既定hard limitは10,000 case、再検証を含む80,004 file読取・欠落確認、単一JSON 8 MiB、再検証を含む合計512 MiB、300秒、JSON深さ64、200,000 nodeです。CLIと内部APIの双方でexact型・正値・hard上限・有限の期限を検証し、上限を下げることだけを許可します。上限到達、整合性違反、未知catalog schemaは終了code 2で停止し、不完全集計を成功出力しません。時間境界はread chunkとcase境界で確認する協調的制限であり、OSのblocking I/OやJSON decodeをhard preemptするsandboxではありません。

未知blockerの本文は`unknown_blocker_redacted`へ集約し、既存registryの完全一致またはレビュー済みprefix以外から改善actionを推測しません。各caseの同じblocker/actionは1件だけ数えるため、blocker件数の合計はcase件数を超え得ます。

この監査は公開metadataの記録品質・偏りを測ります。実検体を再解析した成功率、誤検知率、抽出器の精度、終端payload到達の独立実証、C2 protocolの再確認ではありません。古い成果物のschema不足が多い場合は、handler改善より先に記録契約の欠落を区別してください。取得済み結果を上書き、削除、再公開して数字を改善する機能はありません。
