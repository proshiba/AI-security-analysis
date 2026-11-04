# PureLogs／PureRAT 100検体のAI非依存静的解析監査

## 結論

2026年10月29日にMalwareBazaarから新規取得したPureLogs 50件と
PureRAT 50件を、検体実行・C2接続なしで静的再解析した。最終固定
evaluationでは、PureLogs 13件（26%）で、同一終端layer上のファミリ確定、
protobuf config復元、configured C2取得をすべて満たした。改善前の同じ
厳格条件では0件だった。

PureRATは1件（2%）で同条件を満たした。15件でreview済みの静的経路、
6件でOMLX managed child候補へ到達した。このうち3種類の実候補で、
CILから導出した鍵配列、resource変換、length-prefixed UTF-16 cacheの完全復元を
確認した。ただし、二段目の文字列変換とPFXのファミリ固有根拠がまだ
完全に結合していないため、domainらしい値をC2に昇格させていない。

## 対象と固定性

| 項目 | PureLogs | PureRAT |
|---|---:|---:|
| 新規取得数 | 50 | 50 |
| repositoryからの取得完了 | 50 | 50 |
| 暗号化archiveのまま保持 | 50 | 50 |
| selection commitment | `2eeec0e5b393c0d5dd7079ce9755e3459fb0f4337a50ca1c30780eba462c6d3b` | `cf6350785153f73ac9d70474ee408caa034ceb65855e1951a31a97252a94916b` |
| 既知除外集commitment | `66d4ced24a4b0a33f7c4bdac4224522aa1fb7ee2a7a3d63ef33d16daad308de8` | 同左 |
| 検体実行 | 0 | 0 |
| C2／dead-drop接続 | 0 | 0 |

providerのsignatureは固定cohortの選定とroute hintにだけ使用した。ファミリ確定、
config復元、C2確定の根拠には使用していない。

## 最終固定evaluation

| 指標 | PureLogs | PureRAT | 合計 |
|---|---:|---:|---:|
| root検体数 | 50 | 50 | 100 |
| review済みroute復元 | 23 | 15 | 38 |
| OMLX managed child候補復元 | 18 | 6 | 24 |
| 終端payload到達 | 13 | 1 | 14 |
| 終端ファミリ確定 | 13 | 1 | 14 |
| validated config復元 | 13 | 1 | 14 |
| configured C2取得 | 13 | 1 | 14 |
| 厳格同時成功（strict joint success） | 13（26%） | 1（2%） | 14（14%） |
| 個別評価失敗（case evaluation failure） | 0 | 0 | 0 |
| deadline超過 | 0 | 0 | 0 |
| evaluation中の実装変更 | 0 | 0 | 0 |

`configured C2取得`は、family-bound configから静的に復元した設定値を示す。
endpointの稼働、protocol応答、攻撃者管理の確認は意味しない。また、異なるlayerの
family根拠とconfig候補を組み合わせた成功扱いはしていない。

## 実装した改善

- 認証付き単一member MalwareBazaar ZIPをメモリ上で検証し、外側ZIPと内側検体のSHA-256を分離した。
- evaluatorがtransitive Python依存までimport前に不変snapshotへ固定し、評価中の実装すり替えを検出するようにした。
- Windows long pathをproduction job runnerで事前検証し、中途の暗黙失敗を防いだ。
- CLR `#-` metadata streamを静的解析対象に加えた。
- `dnfile` constructorの前にmetadata table宣言の上限検査とdeadlineを適用し、過大row宣言をfail-closedで拒否した。
- PureLogsでexact `.resources` `ResourceSet`を有界展開し、`System.ByteArray`／`System.Stream`のparser済みexact bytesだけをYqTY／Pn5復号候補にした。
- PureRATでCILからordered key write、mask reverse／XOR、keyed-word resource変換、exact offsetのUTF-16 cacheを一意に結合するfront-endを追加した。
- managed TripleDES／GZip、Eaz／OMLX route、PureRAT v4の既定default省略フィールドを、上限付きの厳密profileとして追加した。
- 7-Zip technical listingで`Alternate Stream = -`だけを未設定扱いとし、link属性の`-`は展開前に拒否するようにした。
- detector、extractor、route、terminal、config、C2を別々に数える固定cohort evaluatorを追加した。
- 親子SHA-256 lineageの完全性をS3保管前に検証し、未完了・循環・共有・跨root childをfail-closedで拒否するようにした。

evaluatorの実行手順と証拠境界は
[`PURE-COHORT-EVALUATION.md`](../../../../analysis-framework/docs/PURE-COHORT-EVALUATION.md)、
PureRATのmanaged CIL相関は
[`PURERAT-MANAGED-CIL-SEMANTICS.md`](../../../../analysis-framework/docs/PURERAT-MANAGED-CIL-SEMANTICS.md)、
UTF-16 cache復元は
[`PURERAT-MANAGED-UTF16-CACHE.md`](../../../../analysis-framework/docs/PURERAT-MANAGED-UTF16-CACHE.md)を参照する。

## 残存blocker

### PureLogsの残存項目

- 10件はroute復元後も、未知`ResourceSet` user type、複数候補の競合、または不完全tableのため昇格していない。
- 27件は内部ファミリ根拠へ到達していない。主要因はinitializer profile不成立、managed method budget、復元候補の曖昧性である。

### PureRATの残存項目

- 6件のOMLX managed childでcache routeを確認したが、二段目の`string,int`変換をinstruction-derived recipeとして完全に一意化できていない。
- 2つのlarge variantでstrict protobuf候補まで非公開診断したが、PFXとterminal schemaの完全確認前なのでfamily／C2に昇格していない。
- 34件は内部ファミリ根拠なし、15件はroute段階までである。

## 非Gitデータの保管

S3 bucket `malware-analysis-datastore-720232834682`へ、対象ごとのWinZip AES-256 ZIPとして
PureRAT 49件、PureLogs 41件を保管した。90件すべてでsize、SSE-S3 `AES256`、
SHA-256 metadata、source-tree commitmentを再検証した。

PureRAT 1件は未完了derived child、PureLogs 9件は未完了または共有／跨root childの
ため、異なる解析対象を混ぜずfail-closed条件で保管を保留した。元sourceと
解析結果は削除していない。receiptとupload情報はGitに収録していない。

## 安全境界

- 検体、復元PE、CIL、scriptは実行していない。
- C2、dead-drop、検体内URLへの接続は行っていない。
- 外部通信はMalwareBazaarからのrepository取得と、規約に従ったS3保管だけである。
- 公開成果物にraw config、endpoint、復元secret、receipt、`datastore-upload.json`は含めていない。
- static configの取得とlive C2の確認は別の概念として扱った。
