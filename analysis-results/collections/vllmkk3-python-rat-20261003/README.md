# vllmkk3 Python RAT解析

ユーザー提供 `vllmkk3.zip` を実行せず、外部接続なしで静的解析したcollectionです。

## 結果

- 終端payload：`vllmkk3.py`
- 判定：未分類Python Socket.IO RAT
- C2設定：静的復元済み
- C2 event protocol：静的復元済み
- process chain、永続化、keylogger、画面、遠隔入力、任意shell、双方向file転送、自己削除：確認済み
- 自動AST inventory：101関数
- 代表本文レビュー：18関数
- 既知ファミリー名：未確定
- 検体実行：なし
- C2／外部URL接続：なし

解析結果：[未分類Python Socket.IO RATケース](../../malware/unclassified/versions/unknown/cases/94420ac4dc985b08bdb97b8a24e499bbcf80906165b139d81ca466871a60adb0/README.md)

同梱 `uv.exe` は公式uv 0.12.6 Windows x64 binaryと完全一致したため、悪性本体ではなく正規dual-use bootstrapperとして分離しました。
