# 2026-08-05 日本語マルスパム GuLoader

日本語マルスパムで観測されたGuLoader感染チェーンの対象解析です。

## 結果

- 対象ケース：1
- GuLoader本体まで復元：1
- 親BATとGoogle Driveキャリアの結合解析：完了
- Triageメモリ成果物の追加検査：3取得元・合計21領域
- GuLoader以後のXLoader/FormBook系ペイロード本体：静的復元済み
- XLoader保護関数：91件中80件を静的復元、11件は未解決
- 最終C2設定・設定writer：未解決
- 検体のローカル実行：なし

解析結果：[GuLoaderケース](../../malware/guloader/versions/unknown/cases/8d96249aa92bee27d9ac8ffa8e32e3f8dd3a5c77cbe541b1d0cc97f37e962a1e/README.md)

復元済みペイロードのロジック、残る11関数、最終C2設定の静的解析課題は、ケースのREADME、
OVERALL-LOGIC.md、XLOADER-STATIC-RECOVERY-20260808.mdへ記録しています。
