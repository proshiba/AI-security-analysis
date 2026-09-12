# ValleyRAT AI非依存設定抽出の100件holdout受入試験

## 目的

ValleyRATの自動解析改善は、referenceに存在しないSHA-256 identityの未知100件に対し、**ファミリー確定とC2設定確定を同じ検体で50件以上**達成した場合だけ目標達成と判定します。ここで「未知」は新規identityを意味し、既知の構造に似ていることは失格条件ではありません。外部AI、公開サービスのfamily label、既知hash、ファイル名、通信先の一致、route-onlyの設定候補は成功件数へ含めません。

この基準は期待値や推定値ではありません。`evaluate_valleyrat_holdout.py`が、事前登録したidentity集合と封印済みone-shot成果物100件を照合して返す受入gateです。現在の開発コーパスで改善しても、別収集の未知100件でgateを通るまでは達成済みとは扱いません。公式reference modeの分母は100件、合格線は同時成功50件に固定され、評価後に変更できません。

## 1件の成功条件

1件を成功と数えるには、次をすべて満たす必要があります。

- familyは`valleyrat`であり、独立した静的detectorが選択したか、一意の候補を必要tierのhandler証拠が裏付けている。
- family根拠が既知hashだけ、または外部metadataだけではない。外部metadataが診断用に併記されていても、選択されたfamilyが独立した静的detectorと必要なhandler証拠だけで成立する場合、そのmetadataは成功根拠へ加点せず無視する。
- configは候補ではなく確定状態である。
- 少なくとも1つのcontrol endpointが、復元した静的設定と相関している。
- endpointの役割はC2／control系であり、配布URL、loopback、exfil専用値をC2成功へ数えない。
- case成果物と入力会計の整合性sealが有効である。

終端payloadへ到達していないloader、sourceからnetwork sinkまでの静的lineageが閉じていない設定、同一socketの送受信やprotocol invariantを証明できない場合は、値を復元できても`route_only`または`candidate_only`に留めます。

## 未知100件の固定方法

- 既知・開発用runとholdout runを別に保管します。
- 実装と100件／50件の目標を凍結した後、holdoutの解析結果を見る前にreferenceとholdoutのSHA-256 identity集合を事前登録します。
- holdout選定時に、解析前のprivate manifestへSHA-256を正確に100件固定します。事前登録の作成経路はこのmanifestとreference runの`summary.json`だけを読み、holdout case成果物、family結果、C2結果、解析成否を読みません。
- 事前登録にはidentity件数と順序非依存の集合commitmentだけを保持し、評価時に実際の集合と厳密に再照合します。個別SHA-256は公開評価結果へ出しません。
- holdoutのroot SHA-256がreferenceに1件でも存在すれば事前登録を拒否します。
- holdout結果を見て抽出器を調整した場合は、その集合を次回のreferenceへ移し、新しいidentity 100件を選定して事前登録からやり直します。
- imphash、telfhash、静的ロジックfingerprint、検証済みloader／route profileで構造的な近縁性を監査します。
- referenceとexact／near／連結成分が一致するholdoutは「既知構造」、一致しないholdoutは「新規構造」として別集計します。構造類似そのものは失格にせず、既知構造への一般化が新しいidentityでも機能した成果として扱います。
- 構造区分は封印済み成果物で観測できた証拠に基づきます。構造証拠が不足してreferenceとの関係を証明できないcaseは新規構造へ入るため、この区分は系統そのものではなく「観測上の既知性」を表します。
- 公開評価結果には個別hash、endpoint、source name、private path、未加工configを出力しません。

評価器はidentity集合と評価契約の一致を検証しますが、事前登録fileが解析より前に作成されたという時系列を単独では証明しません。事前登録JSONは、解析開始前にtrusted timestamp付きのprivate Git commit、WORM storage、または同等の変更不能な監査記録へ保存してください。公開集計の`temporal_order_proven_by_evaluator`はこの限界を明示するため常に`false`です。

## 実行例

次の例では、既知・開発群を`--reference-run`、新しく選定した100件を`--run`へ指定します。shardが複数ある場合は同じoptionを繰り返します。

最初に、解析前の選定時点でholdout identity manifestをprivate領域に作ります。`identities`には重複のない小文字SHA-256を正確に100件入れます。

```json
{
  "schema_version": 1,
  "identity_type": "sha256",
  "identities": [
    "<SHA-256 1>",
    "<SHA-256 2>"
  ]
}
```

続いてidentity集合を事前登録します。このmodeはholdoutのrunやcase成果物を受理せず、解析成否を読みません。

```powershell
py analysis-framework/common/evaluate_valleyrat_holdout.py `
  --reference-run <既知run-1> `
  --reference-run <既知run-2> `
  --holdout-identity-manifest <private領域/holdout-identities.json> `
  --write-pre-registration <private領域/valleyrat-holdout-preregistration.json>
```

実装を変更せずone-shot解析を完了した後、同じ事前登録を指定して評価します。

```powershell
py analysis-framework/common/evaluate_valleyrat_holdout.py `
  --reference-run <既知run-1> `
  --reference-run <既知run-2> `
  --run <未知100件run-1> `
  --run <未知100件run-2> `
  --pre-registration <private領域/valleyrat-holdout-preregistration.json> `
  --output-json <非公開評価結果.json> `
  --output-markdown <公開可能な集計.md> `
  --fail-below-target
```

正常終了の条件は、事前登録が評価時の集合と一致し、holdoutが正確に100件、入力整合性がclean、referenceとのSHA-256 identity重複が0、同時成功が50件以上のすべてです。構造類似は失敗理由にせず、既知構造／新規構造の各分母と成功数をJSONとMarkdownへ出します。同時成功未達または入力整合性不良は終了code 1となり、identity重複、事前登録の欠落・改変・集合不一致、100件以外の登録は評価不能として終了code 2になります。

`--reference-run`を使わないsingle-set modeは、構造連結成分をtrain／holdoutへまたがせない回帰試験用です。解析済み集合からの内部splitなので公式の未知100件受入値には使用しません。

## 改善時に追跡する値

50件という分子だけでなく、次も必ず記録します。

- family確定件数、C2設定確定件数、両方の同時成功件数
- 既知構造と新規構造それぞれのcase数、family確定、C2設定確定、同時成功
- route-only、candidate-only、loader-only、detector未一致の件数
- 誤陽性を検出するnegative fixture
- 未試行、timeout、上限到達、結果省略、seal不整合
- variant別の成功数と、未知構造へ一般化した件数

既知コーパス内だけの改善率は回帰指標です。未知100件の受入値と混同せず、受入結果が50/100未満なら未達として次の一般化改善へ戻します。
