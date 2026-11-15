# 固定選定の静的解析集計

`common/build_static_cohort_report.py`は、MalwareBazaarの固定選定manifestとproduction runnerの解析JSONから、family、構造、設定、C2候補、未解決事項をまとめる非公開集計器です。Windows限定、signature限定、全形式の`recent_newest`に対応し、familyの強制指定は受理しません。

```powershell
py -3.13 analysis-framework/common/build_static_cohort_report.py `
  --selection-manifest C:\private\latest100\source\manifest.json `
  --run C:\private\latest100\jobs\job-001\analysis `
  --run C:\private\latest100\jobs\job-002\analysis `
  --expected-count 100 `
  --output-directory C:\private\latest100\evaluation
```

`--run`は最大4件です。100件以外の明示的な固定選定を集計する場合だけ、`--expected-count`を1～200の範囲で変更します。出力は`summary.json`と日本語`REPORT.md`です。取得済みのcase一覧、layer、変換、endpoint、blockerはJSONへ全件保持し、人向け表の都合で先頭数件へ切り捨てません。

## 検証境界

- 固定選定の件数、一意性、順序、metadata commitment、取得item metadataを照合します。
- 選定SHA-256とroot reportの内側／外側SHA-256を一意に結び、run summaryのroot集合と完全一致させます。derived caseは母数へ加えません。
- report意味seal、安全flag、すべてのmanifest artifact SHA-256を確認します。非通常file、reparse、hardlink、無効JSON、hash不一致は既存snapshot読取器で拒否します。
- 封印されたC2契約が未解決なら未解決のまま表示します。集計器は設定復号、protocol確認、生存確認を独自に行いません。
- provider label、detector／handlerに基づくfamily解決、設定候補、設定復元、qualified static C2を別指標として保持します。
- payload配布、dead-drop、共有resolver、candidate roleを、qualified listに存在するという理由だけでC2へ昇格しません。
- 構造clusterは完全なshape比較であり、family、campaign、actorの確定根拠ではありません。
- 構造layerは同caseの一意rootへ結び、SHA-256の重複、cycle、親の欠落、depth不一致、case identityと異なるrootを拒否します。layer／stepは各4096件、section／segment／markerを含む構造metadata総数は16384件までとし、上限超過を切り捨てて完全扱いにしません。

## 出力と安全性

出力先はrepository外かつ入力run／sourceの外に限定します。検体名、raw config、generic文字列IOC、生コード、ホストpath、資格情報を投影しません。endpointは封印済み意味項目だけから読み、userinfo、query、fragment、秘密値様pathを既存無害化器で再除去します。検体本体を開く、実行する、subprocessを起動する、DNSやC2へ接続する処理はありません。

本集計器は公開case生成器、ジョブ全体の再実行検証、関数解析完了validator、C2ライブ確認の代替ではありません。`processed_followup_required`は処理済み・追加解析待ちであり、全検体の解析完了を意味しません。

## 不完全collectionの明示集計

既定では未取得、解析root欠落、失敗job、実行途中jobを拒否します。容量不足や取得失敗のcheckpointを保存する場合だけ、`--allow-incomplete-collection`を明示できます。この場合は`--run`を0件でも指定でき、固定選定100件の母数を変更せず、全100件のrecordへ取得有無、採用可能な解析有無、未取得／未実施／job失敗／job未完了の理由を残します。

失敗または実行途中のproduction jobは、statusとrequestを確認した段階で解析成果物の採用から除外します。残存reportを成功解析へ数えません。extra input、重複取得、重複root、選定外caseは不完全modeでも拒否します。provider metadataだけからfamilyや検体構造を補完しません。

この出力のglobal状態は`incomplete`、`complete`は`false`です。未取得・未解析caseのC2配列が空なのは「未確認」であり「C2機能なし」ではありません。`coverage`の取得・解析・C2評価済み件数と、各caseの`unavailable_reason`を併読してください。

```powershell
py -3.13 -m pytest analysis-framework/tests/test_build_static_cohort_report.py -q
```
