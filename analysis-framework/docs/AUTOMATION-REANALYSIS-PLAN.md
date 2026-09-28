# metadata監査から作る人間レビュー専用の再解析計画

`automation_reanalysis_plan.py`は[全履歴metadata監査](AUTOMATION-FAILURE-INVENTORY.md)の結果と現在の監査snapshotを照合し、固定`remediation_registry.py`から最小の次手順を選びます。生成するものはboundedな**計画候補**であり、runner request、検体解析job、resume許可ではありません。job起動、検体・payload読込み、通信、sample path参照、公開成果物変更は行いません。

```powershell
py -3.13 -I -X utf8 -B .\analysis-framework\common\automation_reanalysis_plan.py --repository . --inventory C:\analysis-private\inventory.json
py -3.13 -B -m pytest .\analysis-framework\tests\test_automation_reanalysis_plan.py -q
```

CLIはprivate保存向けJSONを標準出力に返します。file保存はoperator側の管理された出力処理に委ね、helperから任意output pathへ書きません。保存先は公開結果やGit管理対象から分離してください。

## 検証と計画境界

1. 入力inventoryの既知schema、exact field、安全flag、self-SHA、case重複、case数・JSON構造上限を確認します。
2. 現catalogのraw SHA-256を読み、入力inventory・現在inventory・catalogのcase集合とcanonical identityを完全一致させます。
3. 検体を読まない既存inventory処理で現在metadataを独立再投影します。各caseの入力、解析契約、証拠fingerprintに加え、blocker、状態、設定記録などの全fieldを照合します。driftがあれば`inventory_evidence_drift`等の固定errorで計画を中止し、最新auditを取得する必要があります。履歴比較用の`change_decision`と`changed_dimensions`だけは現在投影と分離します。
4. record-invalid、legacy、欠落・未束縛metadata、未知blocker、fingerprint欠落は`metadata_repairs`へ分離します。これらは抽出job候補へ入りません。未知blocker本文を公開せず、固定の修復レビュー理由だけを残します。
5. 適合recordだけをregistryの完全一致・レビュー済みprefix policyへ対応付け、priority、同じactionの影響件数、action ID、case SHA-256の順に決定的に並べます。同じaction・phase・証拠前提は重複除外します。入力に自己申告されたaction一覧をそのまま実行計画へ採用せず、registry再計算結果との一致を要求します。

`build_plan()`はfileやnetworkを扱わない純粋APIです。呼出側は現在catalogのraw bytesから得た`catalog_sha256`と、信頼済みmetadata snapshot処理が再構成した`current_document`を渡します。self-SHAは完全性検査であり、外部文書の認証・署名ではありません。攻撃者が用意した2つの同じ文書をAPIへ渡すだけでは現在証拠を検証したことになりません。CLIは現在snapshotを自分で再構成し、保存inputとcatalogも最後に再検証します。

純粋APIでも通常JSON型だけを受け付けます。inventoryのrootはexact `dict`、各keyとcatalog commitmentはexact `str`を要求し、未知objectのhash・比較・encodeに先行して型と構造を検証します。任意Python objectを安全に実行するsandboxを提供するものではありません。

既存producerが出力するURL役割`unknown_structure`は既知の不明状態として受け付けます。件数が正なら`url_endpoint_structure_unknown`を理由に`metadata_repairs`へ分離し、抽出job候補へは流しません。既知enumであっても件数は上限内のexact整数であり、boolean・float・文字列を数値へ変換しません。

## 旧契約と再試行

すべての候補は`successor_review_required`、`same_workflow_resume_allowed=false`、`automatic_retry_allowed=false`、`automatic_dispatch_allowed=false`です。同じ証拠を盲目的に再実行せず、人間が最小action、証拠変更、入力認証、現在の実装契約を確認します。

保存済み`analysis_contract`は現在の実装が同じである証明ではありません。実装の変更が記録されている場合も旧workflowの継続許可へ変換しません。正式な実行state、失敗envelope、残attempt、現在実装の確認とsuccessor作成は[再開plannerとオーケストレーション契約](AI-FREE-STATIC-ANALYSIS-ORCHESTRATION.md)へ引き継ぎます。

case identityは`case_id`とcanonical catalog identityのSHA-256へ結び付けますが、sample pathは出力しません。proofは監査record、入力、保存解析契約、固定metadataのcommitmentであり、検体や全artifactを独立再実証したproofではありません。設定抽出率、終端到達率、実検体の成功率を新たに測定する機能ではなく、`analysis_success_rate_measured=false`を保持します。

## 上限と出力

既定で最大64 case候補、128 record修復レビューを保持し、APIとCLIでhard上限・exact型を強制します。超過分は件数とcanonical SHA-256 commitmentへ分離し、消えた候補を完了として扱いません。JSON出力は1 MiB以下です。

保存inventoryには専用profileを使います。最大10,000 case、単一32 MiB、文書全体2,000,000 node、case単位20,000 node・UTF-8文字列合計256 KiB、深さ64がhard上限です。case単位上限を満たしていても文書全体の上限を超えれば拒否するため、20,000 node×10,000 caseを許容する仕様ではありません。pure APIでも同じ構造上限を検証し、private構造validatorの上限引上げも拒否します。

専用input readerは初回と最後の2回だけ読み、両方に32 MiB上限を適用して累積64 MiBへ制限します。shared inventory readerの単一8 MiB・200,000 nodeという既定を変更したり、そのdecoderへ巨大inventoryを渡したりはしません。file link・reparse point・複数hardlink・祖先directoryの変化を拒否し、単一handleの前後identity、path identity、最後のraw SHA-256を照合します。3回目のreadまたは再検証は拒否します。

JSON decodeのallocation前にbyte列を走査し、文字列内部の区切りやescapeを考慮したtoken開始数を保守的に見積もります。keyも数え、2,000,000 tokenを超えればdecoderへ渡しません。decode後にもnode・深さ・UTF-8文字列量・finite数値を確認し、duplicate key、非finite定数、指数overflow、surrogateは固定errorで拒否します。keyを含むtoken数はnode数と同義ではないため、node上限近傍の文書も安全側で拒否される場合があります。

現在のcase metadata監査には既存inventoryの単一8 MiB・単一文書200,000 node・全読取512 MiB上限を維持します。catalogの独立読取・再検証は別枠16 MiB、保存inventoryの読取・再検証は別枠64 MiBであり、CLI全体の読取上限は合計592 MiBです。公開catalogは現在の`schema_version=1`と`cases` root、`case_id`・`case_kind`・`family`・`version_key`・`canonical_path` identityへ対応し、未知schemaを成功扱いしません。

CLI全体の300秒制限は協調的な停止判定です。chunk読取、allocation前走査、構造走査、decode前後、最終snapshot検証で確認しますが、OS I/Oや単一`json.loads`のhard preemptionではありません。現在監査も残り時間に制限し、最終期限超過時には計画JSONを出力しません。

合成testは4,017件と10,000件の計画生成、64/128の出力上限、省略分commitment、旧8 MiBを超える10,000件inputの初回・最終読取、32 MiB/64 MiB/2,000,000 token境界、入力driftを確認します。合成scale testは実検体解析の性能や成功率を示すものではありません。

出力の`job_candidates`をrunnerへそのまま渡せる仕様にはしていません。解析要求の作成、file取得、入力検体の探索、network、公開、resumeをこのplannerへ追加する場合は別の明示レビューが必要です。
