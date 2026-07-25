# 定期調査タスク一覧

## 優先度

- `P0`: 運用開始時から必要。欠けると新規情報を追跡できない。
- `P1`: baselineが安定した後に必要。関係性と変化を発見する中心タスク。
- `P2`: 月次・四半期で精度と運用効率を改善するタスク。

## タスク一覧

| ID | 周期 | 優先度 | タスク |
|---|---|---:|---|
| `INT-D01` | 毎日 | P0 | 新規・更新caseの差分triage |
| `INT-D02` | 毎日 | P0 | IOC差分、再観測、役割変更の突合 |
| `INT-D03` | 毎日 | P0 | 強い既知fingerprint一致の速報判定 |
| `INT-W01` | 毎週 | P1 | family、config、protocol、配布chainの変化検出 |
| `INT-W02` | 毎週 | P1 | 関数コード類似性と共有componentの整理 |
| `INT-W03` | 毎週 | P1 | インフラ再利用とlifecycleの整理 |
| `INT-W04` | 毎週 | P0 | 未分類・未解決caseの再評価 |
| `INT-W05` | 毎週 | P1 | extractor、detector、hunt ruleのcoverage差分 |
| `INT-M01` | 毎月 | P1 | campaignからoperation候補への統合 |
| `INT-M02` | 毎月 | P1 | OSINT更新とactor帰属仮説のレビュー |
| `INT-M03` | 毎月 | P2 | 相関閾値、誤相関、失効ルールのbacktest |
| `INT-Q01` | 四半期 | P2 | データ品質、schema、解析負債の棚卸し |
| `INT-E01` | 事象発生時 | P0 | 重大情報に対する緊急再相関 |

## `INT-D01`: 新規・更新caseの差分triage

**目的**

前回実行後に追加または更新されたcaseを確定し、後続の相関処理へ渡せる品質かを毎日確認します。

**入力**

- `analysis_history.yaml`
- `analysis-results/malware/*/versions/*/cases/*`
- collectionの`manifest.json`と`publication-summary.json`
- 前回の`intelligence/baselines/YYYY-MM-DD.json`

**自動処理案**

1. SHA-256を主keyとして、新規、更新、移動、重複、削除を区別する。
2. `classification.json`、`static-logic.json`、`features.json`、`iocs.json`、`campaign-labels.json`の存在と更新hashを比較する。
3. `malware_type`、`campaign_type`、解析完了状態、config抽出状態の変化を抽出する。
4. 生成物不足を`quality_gap`として後続の相関対象と分離する。

**人手レビュー**

- family再分類やversion変更に根拠があるか。
- 前回結果の上書きではなく、変化履歴が残っているか。
- 未対応handlerを既知familyへ無理に適用していないか。

**成果物**

- `delta.json`
- 日次READMEの「新規case」「更新case」「品質不足」
- `INT-W04`と`INT-W05`へ渡すqueue

**完了条件**

対象期間の全caseが`new`、`changed`、`unchanged`、`removed`のいずれかに一意に分類され、変更理由が機械可読に記録されていること。

## `INT-D02`: IOC差分、再観測、役割変更の突合

**目的**

IOCを値だけでなく役割と時間で追い、再利用、移行、失効、誤分類を検出します。

**入力**

- `IOC-LIST.md`
- `iocs.json`、`config.json`、`analysis.json`
- `analysis-results/IOC-INDEX.md`
- 前回までのIOC観測履歴

**自動処理案**

1. IOCを`type + normalized_value + role`で正規化する。
2. 同じ値の`first_seen`、`last_seen`、case、family、campaign、sourceを更新する。
3. `distribution`、`stage`、`c2`、`exfiltration`、`context_only`などの役割変更を検出する。
4. 新規IOC、再観測IOC、長期未観測IOC、矛盾するIOCを分ける。
5. URLのcredential、query、fragmentを除去し、共有サービスや正規vendor値を除外する。

**既存処理**

```powershell
python .\analysis-framework\common\generate_ioc_lists.py --repository . --check
```

差分が意図した変更なら`--write`で正本を更新し、再度`--check`を実行します。

**人手レビュー**

- 同一IPでも、同時期、同一port、同一protocol、同一証明書、同一configか。
- 正規サービス、共有hosting、sinkhole、security scannerを悪性IOCとしていないか。
- 配布先をC2へ昇格していないか。

**速報条件**

- artifact hash、完全なC2 endpoint、証明書hashなど、過去campaignの強いfingerprintと一致した。
- 異なるfamilyで2種類以上の非汎用IOCが同時に一致した。
- 既知campaign IOCが長期間の空白後に再観測された。

## `INT-D03`: 強い既知fingerprint一致の速報判定

**目的**

レビュー済みcampaign fingerprintとの強い一致だけを日次で通知候補にし、弱い類似候補の大量発生と分離します。

**入力**

- `analysis-framework/registry/campaign_fingerprints.json`
- 各caseの`campaign-labels.json`
- `INT-D01`の新規・更新case

**自動処理案**

1. artifact hash、URL、endpoint、domain、certificate hashを既存fingerprintへ照合する。
2. fingerprintの`minimum_indicator_matches`を満たすか確認する。
3. family条件、除外host、IOC prevalence、観測時期を確認する。
4. 過去のlabelから新規追加、確度上昇、確度低下、消失を抽出する。

**人手レビュー**

- fingerprint作成時のcampaignと今回の観測期間が連続または合理的か。
- インフラが転売・再割当・sinkhole化されていないか。
- 一致した値の役割が過去と今回で同じか。

**完了条件**

速報対象ごとに、一致根拠、反証、過去観測、今回観測、推奨する次の調査を記載すること。自動一致だけでactor名を付与しないこと。

## `INT-W01`: family、config、protocol、配布chainの変化検出

**目的**

同じfamily内の版差やbuilder差を把握し、extractor、detector、emulator、hunt ruleの追随漏れを見つけます。

**比較項目**

- PE/.NET/スクリプト構造、section、resource、overlay、packer
- config field、暗号鍵長、暗号・圧縮方式、serialization
- C2のscheme、port、URI、header、message framing、command ID
- 永続化、anti-analysis、process injection、credential target
- installer、archive、side-loading、decoy、署名付きhostの組合せ
- 特徴的な関数の追加、削除、分岐、callee、API sequence

**自動処理案**

1. familyごとに前週と今週のfeature prevalenceを比較する。
2. 新規feature、消失feature、急増featureを抽出する。
3. config schemaをfield集合と型で比較し、互換・追加・破壊的変更へ分類する。
4. 関数fingerprintの追加・消失をversion候補へまとめる。
5. 変化がextractor/detectorの前提を壊す場合、`INT-W05`へ連携する。

**昇格条件**

- 2件以上で同じ新規ロジックまたはconfig変更を観測した場合は`variant_candidate`。
- 配布chain、config、通信protocolの複数軸が同時に変化した場合は`major_change_candidate`。
- 1件だけの場合は`singleton_observation`として保留する。

## `INT-W02`: 関数コード類似性と共有componentの整理

**目的**

同一familyの版追跡と、異なるfamily間のloader、crypto、config decoder、通信処理などの共有を区別して整理します。

**既存処理**

```powershell
python .\analysis-framework\common\generate_code_similarity_index.py --repository . --check
```

**順位付け**

1. 異なるfamily間のopcode hashまたは正規化ロジックhash完全一致。
2. `config_decoder`、`network`、`command_dispatcher`、`loader`、`persistence`など情報量の高い役割。
3. repository内で出現頻度が低い関数。
4. 類似関数だけでなく、call graph近傍、API、config形式も一致するpair。
5. 時間的に先行するcaseから後続caseへ実装が移った可能性があるpair。

compiler生成、runtime、既知library、packer stub、短すぎる関数は別bucketへ分離します。

**成果物**

- `component_candidate`: 共有component候補
- `family_lineage_candidate`: 同一family内の系譜候補
- `cross_family_transfer_candidate`: 異なるfamily間の移植候補
- `generic_or_library`: 共通libraryまたは情報量不足
- `rejected`: 反証付き棄却

**完了条件**

候補ごとに、代表関数の役割、類似fingerprint、call graph近傍、共通API、差分、最古観測、代替説明を残すこと。コード類似だけでcampaignやactorへ昇格しないこと。

## `INT-W03`: インフラ再利用とlifecycleの整理

**目的**

domain、IP、endpoint、証明書、ASNなどの利用期間と同時出現を追跡し、単なる共有hostingと運用上の再利用を分離します。

**処理案**

1. IOCごとにfirst/last seenと観測sourceを整理する。
2. domain-IP、domain-certificate、endpoint-config、endpoint-processのedgeを作る。
3. passive DNS、証明書透明性、WHOIS、ASN、hosting情報は取得日時とsourceを付ける。
4. 同じ24時間、7日、30日windowでの共起を別々に集計する。
5. sinkhole、CDN、DDNS、public paste、cloud storage、共有SMTPを分類する。

**安全制約**

既定は公開・受動情報と完全一致hash照会だけです。live C2接続、HTTP probe、JARM収集、stage取得は、現在のタスクでユーザーが明示的に許可した場合だけ別作業として行います。

**成果物**

- `infrastructure_entity`
- `resolves_to`、`served_certificate`、`used_as_c2`、`used_for_distribution`などの役割付きedge
- `active`、`dormant`、`reassigned`、`sinkholed`、`unknown`のlifecycle状態

## `INT-W04`: 未分類・未解決caseの再評価

**目的**

新しい解析器、OSINT、IOC、コードclusterが増えたときだけ未解決caseを再評価し、同じ処理を根拠なく繰り返さないようにします。

**対象queue**

- `unclassified`
- `function_analysis_required`
- config extractor未成功
- C2役割未確定
- campaign未解決
- 競合family label
- ValleyRATの未解決53件など、family固有の未帰属集合

**再実行条件**

- 新規detector/extractor/handlerが追加された。
- 完全一致hashの新しいOSINTが得られた。
- 希少なartifact hash、config、配布chain、関数clusterとの新規一致が得られた。
- 過去の解析失敗原因が解消した。

**成果物**

`resolved`、`partially_resolved`、`still_unresolved`、`not_retried`を分け、再評価のtriggerと新しい根拠を記録します。

## `INT-W05`: extractor、detector、hunt ruleのcoverage差分

**目的**

マルウェアの変化に対して、自動解析と検知材料が追随できているかを確認します。

**測定項目**

- family別のdetector選択率と誤選択率
- handler成功率、config抽出率、C2 role確定率
- 代表関数解析完了率
- YARA/Sigmaの対象variant coverage
- emulatorが対応するprotocol version
- generic triageで停止した構造pattern

**人手レビュー**

- 単一文字列、単一IP、一般的APIだけに依存するruleがないか。
- 新variantに対応するため条件を緩めすぎていないか。
- extractorが候補文字列を復号済みconfigと誤認していないか。

**成果物**

family別の`coverage_gap`、修正優先度、必要なfixture、回帰テスト案を作成します。

## `INT-M01`: campaignからoperation候補への統合

**目的**

レビュー済みcampaign、共有component、インフラlifecycle、配布chain、時間情報を統合し、同じ運用者が関与した可能性があるoperation候補を作ります。

**入力条件**

自動生成だけのcampaignではなく、人手レビュー済みで根拠と反証を持つcampaignを入力にします。

**処理案**

1. campaignをnodeにし、コード、config、インフラ、配布、時間、標的のedgeを付ける。
2. 異なるfamily間のedgeを優先してレビューする。
3. 時間が重なる活動と、長期休止後の再利用を区別する。
4. `同一operator`、`共通builder`、`共通initial-access提供者`、`共通hosting`など複数の仮説を並列に評価する。
5. [相関・評価モデル](ASSESSMENT-MODEL.md)の昇格条件を満たすものだけをoperation候補にする。

**成果物**

- operation IDと期間
- 関連campaign、family、component、infrastructure
- 根拠edgeと確度
- 代替仮説、否定証拠、情報gap
- 次月に継続監視するwatch条件

## `INT-M02`: OSINT更新とactor帰属仮説のレビュー

**目的**

完全一致hashと信頼できる公開報告を中心に、campaign・operation候補へ外部文脈を追加します。

**情報源の扱い**

- vendorの一次調査、政府・CERTの報告、研究者の技術報告を優先する。
- 集約サービスと、その基礎providerを独立した2情報源として重複計上しない。
- community tagや単一provider labelは低確度の手掛かりとして保持する。
- actor別名を正規化し、同名・改名・重複clusterを区別する。

**actor帰属の最低条件**

- actor名を明記する信頼できるOSINTがある。
- repository内の完全一致hash、固有campaign ID、固有インフラ、固有配布chainのいずれかで報告と接続できる。
- actor情報以外の独立した証拠軸がある。
- 反対情報と代替仮説をレビューしている。

これらを満たさない場合は`actor_attribution_hypothesis`ではなく、`osint_context_only`として保存します。

## `INT-M03`: 相関閾値、誤相関、失効ルールのbacktest

**目的**

候補数の増加に合わせてscoreが形骸化しないよう、採用・棄却済み事例で閾値を検証します。

**確認項目**

- same-familyとcross-familyのprecision
- IP、domain、URL、certificate、artifact hashの実測情報量
- `max_indicator_prevalence`と`max_cluster_size`の妥当性
- component/library除外の漏れ
- DDNS、cloud、共有SMTPなどの誤相関率
- 既知campaign fingerprintの期限と再割当リスク

**変更条件**

閾値変更は、採用例と棄却例のfixtureを追加し、旧結果との差分と理由を説明できる場合だけ行います。件数を減らすためだけに閾値を変更しません。

## `INT-Q01`: データ品質、schema、解析負債の棚卸し

**目的**

蓄積量の増加による品質劣化、重複、古いschema、未完了解析を四半期ごとに整理します。

**棚卸し項目**

- canonical caseとcollection sourceの重複
- `analysis_history.yaml`とcase directoryの不一致
- `static-logic.json`、`iocs.json`、`features.json`のschema version
- `unknown` versionの長期滞留
- 生成物の同期差分
- 巨大索引の分割・圧縮・履歴保持方法
- raw artifact、credential、検体混入の安全監査
- family、campaign、operation、actor IDの命名衝突

**成果物**

修正backlogを`data_quality`、`analysis_gap`、`automation_gap`、`documentation_gap`、`safety_gap`に分け、次四半期の優先順位を決めます。

## `INT-E01`: 重大情報に対する緊急再相関

**trigger**

- 新しい重大campaignやactor活動の公開
- 大規模なC2・配布インフラの公開
- 新しい0-day/CVE悪用chain
- 大幅に変更されたmalware versionやbuilder
- repository内caseの完全一致hashが外部報告に掲載された

**実施内容**

1. 情報源、公開時刻、観測時刻、IOCの役割を固定する。
2. 完全一致hashを最初に照合する。
3. IOC、コード、config、配布chain、標的の順で範囲を拡張する。
4. 既存campaign・operation仮説への影響を差分で示す。
5. actor帰属は通常の月次基準を維持し、緊急性を理由に確度を上げない。

**完了条件**

影響あり、影響なし、未確認を分け、照合範囲と未取得情報を明記すること。

## 定期実行の共通チェック

各タスクは次を満たして終了します。

- 入力snapshot、実行日時、対象期間、tool versionを記録した。
- 新規、変更、消失、未確認を区別した。
- 自動判定と人手判断を区別した。
- 根拠、反証、代替仮説、未解決事項を残した。
- actor帰属を単一のmalware、tag、IP、コード類似だけで行っていない。
- live C2接続や検体送信を無断で行っていない。
- 公開成果物にcredential、token、生の復号秘密値、検体が含まれていない。
- 次回baselineとreview queueを確定した。
