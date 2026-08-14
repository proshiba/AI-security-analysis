# ValleyRATエミュレーター

ValleyRAT解析用の防御目的プロトコルエミュレーターを格納します。`vvas_client.py`は、マルウェアコードを実行せず、stageをダウンロードせずに観測済みvvaS check-inを再現します。

`vvas_loopback_emulator.py`はnumeric loopbackだけへbindし、exact `33 32 00` check-inへ、明示flagがある場合だけ14-byteのsynthetic headerを返します。stage bodyは0 byteで、task resultはwire化しません。

## 安全モデル

- レビュー済みプロファイルで上書きしない限り、エミュレーターが送信するのは観測済みvvaSチェックインの `33 32 00` だけです。
- ネットワーク接続は既定で無効です。稼働中ホストの確認には `--allow-network` が必要です。
- 既定の読み取り上限は64バイトです。応答ヘッダーの検証と短いバナー接頭辞の取得には十分です。
- `--allow-stage-download` と `--i-understand-stage-download-risk` は互換引数ですが、live stage downloadは常に拒否します。
- stage bodyは取得、保持、実行しません。
- 稼働中C2との通信は、現在のケースプロファイル、レビュー済み範囲、封じ込め要件に従わなければなりません。

## vvaSクライアントの使用方法

通常利用では、ネットワークへ接続しないprofile dry-runを実行します。

```powershell
py -3.13 -B emulators/valleyrat/vvas_client.py `
  --profile analysis-framework/malware/valleyrat/config/profiles/8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6.json `
  --dry-run
```

出力の`status=dry_run`、`network_contacted=false`、`application_data_sent=false`を確認します。`--host`、`--port`、`--allow-network`は通常手順では使用しません。実endpointへのexact bounded probeは、現在のtaskで個別に明示承認され、review済みprotocol profileと封じ込め条件が再確認された場合だけ実施します。

dry-run JSONには、profileの接続先、固定request、宣言stage size、読み取り上限、network opt-in要件を記録します。live結果を取得する場合もraw stage bodyは保存しません。

## vvaS loopback facadeの使用方法

通常は外部endpointの代わりにpytest fixtureを使います。

```powershell
py -3.13 -B -m pytest -q `
  emulators/valleyrat/tests/test_vvas_loopback_emulator.py
```

手動確認では次のserverがloopbackで1接続だけ待機します。`--allow-synthetic-header-only`を外すと応答を送信しません。

```powershell
py -3.13 -B -m emulators.valleyrat.vvas_loopback_emulator `
  --bind 127.0.0.1 `
  --port 16666 `
  --allow-synthetic-header-only
```

この14-byte headerはparser fixtureであり、実C2確認、stage取得成功、terminal protocol確認を意味しません。valid stage body、PE、shellcode、task resultは生成しません。

## 結果の比較

新しく収集したエミュレーター出力を既存の `c2-live` 証拠と比較します。

```bash
python emulators/valleyrat/compare_results.py \
  analysis-results/malware/valleyrat/versions/unknown/cases/8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6/c2-live/2026-07-13_202.95.8.27_6666.json \
  out/valleyrat-vvas-6666.json
```

`--json` を指定すると、機械可読な比較要約を出力します。

## `analysis-framework/common/c2_detector.py`との関係

`analysis-framework/common/c2_detector.py` は、ワークフローへ統合した範囲限定C2生存確認ツールです。このディレクトリの単体エミュレーターは、プロファイル駆動のvvaSプロトコル再現、再現可能な証拠取得、時期またはポートが異なる観測の比較に使用します。

## オフラインテスト

単体テストは外部ホストへ接続しません。

```bash
python -m pytest emulators/valleyrat/tests
```
