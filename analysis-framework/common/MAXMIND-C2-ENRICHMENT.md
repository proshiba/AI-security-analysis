# MaxMindによるC2 Geo/ASエンリッチ

## 目的

C2ライブチェックで観測したglobal IPを、private領域に保持するMaxMind GeoLite2 City/ASNで照合します。概略Geo情報とAS番号・組織を監視結果へ加え、同一ホスティング事業者や地域への集約を追跡しやすくします。

GeoLite2の位置情報だけでC2稼働や攻撃者の所在地を確定してはいけません。GeoはIPインフラの概略位置であり、個人・世帯・住所の識別には使用しません。

## 秘密情報とDBの扱い

- `MAXMIND_LICENSE_KEY`を環境変数またはWindowsのユーザー環境変数から読みます。
- 現行認証を使う場合は`MAXMIND_ACCOUNT_ID`も設定します。
- account IDがない場合は、動作確認済みのlicense-key permalinkへfallbackします。将来の廃止に備え、`MAXMIND_ACCOUNT_ID`の設定を推奨します。
- license key、Authorization header、署名付きdownload URLをログ・JSON・Markdownへ出力しません。
- MMDBと取得metadataは`C:\Users\Administrator\MalwareSamples\maxmind\current`へ保存し、repositoryへ保存しません。
- 配布archiveは公式SHA-256 sidecarと照合後に展開し、展開後は削除します。
- 公開結果にはMMDB SHA-256、build時刻、取得時刻、公式checksum照合結果だけを残します。

## 実行

dailyのC2ライブチェックでは[統合手順](RUN-C2-MONITORING-PIPELINE.md)を使います。統合ランナーだけがDB build ageの確認・必要な更新・C2観測の順序を保証します。次の個別コマンドは、既存の監視結果を後から再エンリッチする用途に限定します。

```powershell
py -3.13 -m pip install -r analysis-framework\requirements-maxmind.txt

py -3.13 analysis-framework\common\maxmind_c2_enrichment.py `
  --results analysis-results\research\c2-monitoring\YYYY-MM-DD\monitoring-results.json `
  --cache-dir C:\Users\Administrator\MalwareSamples\maxmind\current `
  --write

py -3.13 analysis-framework\common\render_c2_maxmind_section.py `
  --results analysis-results\research\c2-monitoring\YYYY-MM-DD\monitoring-results.json `
  --readme analysis-results\research\c2-monitoring\YYYY-MM-DD\README.md `
  --write
```

個別コマンドで最新版を明示的に再取得するときだけ`--refresh-databases`を指定します。dailyの統合ランナーはライブチェック前に両DBのbuild epochを確認し、24時間以上前なら自動更新します。更新後も最新版自体が24時間以上前なら、その事実を公開結果へ残します。

## 出力

各C2 targetの`maxmind.records`には次を記録します。

- ライブチェック時に実際にDNS解決したglobal IP
- 大陸、国、第一行政区分、都市、タイムゾーン
- 緯度・経度とaccuracy radius
- AS番号とAS組織名

ループバック、private、予約、documentation用IP、onion addressは照合しません。新たなDNS問い合わせは行わず、C2監視時に記録した`resolved_ips`だけを入力にします。

## ライセンス表記

公開結果には次のattributionを保持します。

> This product includes GeoLite2 Data created by MaxMind, available from https://www.maxmind.com.

## 参考資料

- [MaxMind: Updating GeoIP and GeoLite Databases](https://dev.maxmind.com/geoip/updating-databases/)
- [MaxMind: GeoLite Databases and Web Services](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/)
- [MaxMind: Secure your license key](https://support.maxmind.com/knowledge-base/articles/secure-your-maxmind-license-key)
