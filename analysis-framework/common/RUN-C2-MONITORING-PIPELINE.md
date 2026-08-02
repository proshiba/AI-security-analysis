# C2監視・MaxMindエンリッチ統合手順

## 目的

限定したC2候補へのライブチェック、MaxMind GeoLite2 City/ASN照合、機械可読JSONと日本語Markdownの生成を1コマンドで実行します。今後のC2監視では、Geo/ASの付与漏れを防ぐため、この統合ランナーを標準経路として使います。

## 実行

```powershell
py -3.13 -m pip install -r analysis-framework\requirements-maxmind.txt

py -3.13 analysis-framework\common\run_c2_monitoring_pipeline.py `
  --targets analysis-results\research\c2-monitoring\YYYY-MM-DD\targets.json `
  --output-directory analysis-results\research\c2-monitoring\YYYY-MM-DD `
  --maxmind-cache-dir C:\Users\Administrator\MalwareSamples\maxmind\current `
  --allow-network
```

daily解析では`--allow-network`を必須とします。統合ランナーはC2へ接続する前にCity/ASN両DBのbuild時刻を確認し、いずれかが24時間以上前なら公式checksumを検証した最新版へ更新してからライブチェックを開始します。閾値は`--maxmind-max-build-age-hours`で厳しくできますが、dailyでは24時間を超える値へ変更しません。

MaxMindが公開している最新版自体のbuild時刻が24時間以上前の場合も取得は成功として扱いますが、`latest_available_still_stale`とedition別の`stale_after_refresh`を公開結果へ記録します。オペレーターが無条件更新を要求するときだけ`--refresh-maxmind-databases`を追加します。

## 安全境界

- 監視対象は`targets.json`に列挙した完全一致host/portだけです。
- 1対象1回、最大5秒・応答最大256 byteの限定観測です。
- Malware check-in、victim metadata、command polling、認証情報、range scanは送信しません。
- `MAXMIND_LICENSE_KEY`、Authorization header、署名付きdownload URL、MMDB本体は公開結果へ保存しません。
- MMDBはリポジトリ外のprivate cacheへ保存します。
- DB鮮度確認と必要な更新が完了できない場合、C2ライブチェックを開始せずfail-closedで終了します。
- GeoLite2は概略位置情報です。個人・世帯・住所の識別やC2稼働確定には使いません。

## 出力

- `monitoring-results.json`: 観測事実、稼働確度、観測IPごとのGeo/AS、DB build時刻・SHA-256・checksum検証結果、ライブチェック前のDB鮮度判定と更新結果
- `README.md`: C2一覧、confidence、MaxMind Geo/AS一覧、安全境界

公開結果には次のattributionを保持します。

> This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com.
