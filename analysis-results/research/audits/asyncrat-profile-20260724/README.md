# AsyncRAT 検出プロファイル誤分類監査

## 概要

2026年7月24日に取得した最新Windows検体100件を、11種類のWindowsファミリー検出プロファイルで横断監査した。MalwareBazaarでSalatStealerと報告された1件が、旧AsyncRATプロファイルによって誤検出されていた。

原因は、汎用的な `PONG` と `HWID` をそれぞれファミリーマーカーとして数え、`Hosts`、`Ports`、`Version`、`Install`、`Mutex` などの汎用設定語と無関係なGo／QUIC／DNS技術文書のURL候補を相関条件に使用していたことである。これらの証拠だけではAsyncRAT固有性を示さず、URL候補もC2の根拠ではない。

## 監査結果

| 確認項目 | 結果 |
|---|---:|
| 横断監査した検体 | 100件 |
| 評価したファミリープロファイル | 11種類 |
| 旧AsyncRATプロファイルによる誤検出 | 1件 |
| 検体の実行 | 0件 |
| ライブC2／外部ネットワーク接続 | 0件 |

検体は実行せず、パスワード保護ZIPの標準出力による静的読取りとSHA-256照合だけを行った。抽出物から外部ホストへの要求は送信していない。

## 原因

旧プロファイルは `pastebin`、`pong`、`hwid` をAsyncRATのファミリーマーカーとして扱っていた。このうち `PONG` と `HWID` は、通信確認、端末識別、診断処理などの一般的な文脈でも出現し得る。さらに汎用設定語と任意のURL候補を組み合わせると、AsyncRAT固有の実装証拠がなくても相関条件を満たせた。

今回の誤検出では、文字列の出現以外に次の根拠を確認できなかった。

- AsyncRAT固有の設定オブジェクト
- host、port、証明書／鍵材料を結び付ける復号済み設定
- AsyncRAT固有のフレーミング
- AsyncRAT固有クラスまたはメソッドに結び付く複数の高特異度文字列

したがって、旧判定はファミリー確定に必要な特異度を満たしていなかった。

## 修正内容

[Windowsファミリー検出プロファイル](../../../../extractors/profiles/windows_family_profiles.json)から `pastebin`、`pong`、`hwid` をファミリーマーカーとして除外した。修正後は、次の高特異度文字列から独立した2件以上を要求する。

- `asyncrat`
- `asyncrat server`
- `asyncrat client`
- `readservertdata`
- `keepalivepacket`
- `hwidgen`

長い文字列に含まれる短い別名は重複して数えない。ファミリーマーカー条件を満たしても、設定鍵とendpoint候補の相関は静的候補にとどめる。設定オブジェクト、host、port、証明書／鍵材料、フレーミングを相互確認するまで、復号済み設定または確認済みC2とは扱わない。

共有JSONプロファイルと[AsyncRAT宣言的定義](../../../../analysis-framework/definitions/malware/asyncrat.yaml)を同期し、判定方針を[AsyncRAT解析README](../../../../analysis-framework/malware/asyncrat/README.md)へ反映した。

## 回帰試験

誤検出を防ぐ条件を、次の3層へ追加した。

1. [共有抽出器の試験](../../../../extractors/tests/test_profiled_family.py): `PONG`、`HWID`、汎用設定語、無関係なURL候補だけでは相関しないことを確認する。
2. [ファミリー検出器の試験](../../../../analysis-framework/tests/test_profiled_family_detector.py): 同じ汎用文字列を含む入力をAsyncRATへ昇格しないことを確認する。
3. [宣言的判定エンジンの試験](../../../../analysis-framework/tests/test_declarative_engine.py): 汎用文字列だけではAsyncRATの選択閾値へ達しないことを確認する。

JSONとYAMLのマーカー集合を同期し、抽出器、検出器、宣言的判定のいずれから実行しても同じ誤検出抑止条件へ収束させた。

## 結論

`PONG`、`HWID`、汎用設定語、任意のURL候補は、それぞれ単独でも組合せでもAsyncRAT固有の根拠にならない。今後は、高特異度文字列の独立相関と設定構造を入口とし、復号済み設定および通信仕様の証拠を区別して記録する。

同じ100検体に対する短い部分文字列の横断監査は、[HijackLoader検出プロファイル誤分類監査](../hijackloader-profile-20260724/README.md)も参照する。
