# ClickFix調査

ClickFix、ClearFake、fake CAPTCHA、WebDAV型ClickFixのdomain／case別調査を保存します。
各caseは`<domain>/cases/<case-id>/`へ置き、配布マルウェア、感染チェーン、process／command、
追加通信先、Sigma、ライブ観測を分離します。

## 最新調査

- [2026-08-05 日次調査](collections/clickfix-daily-20260805/README.md)

## 運用原則

- 1回の解析対象は最大50件です。
- 配布domain、stage取得先、dead-drop resolver、終端C2を区別します。
- ClearFake／ClickFix tagだけで終端malware、campaign、actorを確定しません。
- 実サイト確認は上限付きGETと実ブラウザ観測を行い、clipboard値をinterceptして解析します。取得したcommandやmalwareは実行しません。
- 配布マルウェアのhashまたはbinaryを取得した場合は、既存のcanonical malware caseへ別途登録します。
- ペイロード未取得でも、DNS・RDAP・CT・netblock・ASN・Shodan InternetDBによるインフラ調査を継続します。
- Triageの公開済み解析をdomain／取得済み完全URL／hashで照合し、process、command hash、通信、dump／memory／PCAP候補を確認します。
