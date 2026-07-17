# ValleyRATエミュレーター

ValleyRAT解析用の防御目的プロトコルエミュレーターを格納します。最初のツールである `vvas_client.py` は、マルウェアコードを実行せず、既定ではペイロード段階もダウンロードせずに、観測済みのvvaSチェックインを再現します。

## 安全モデル

- レビュー済みプロファイルで上書きしない限り、エミュレーターが送信するのは観測済みvvaSチェックインの `33 32 00` だけです。
- ネットワーク接続は既定で無効です。稼働中ホストの確認には `--allow-network` が必要です。
- 既定の読み取り上限は64バイトです。応答ヘッダーの検証と短いバナー接頭辞の取得には十分です。
- `--allow-stage-download` と `--i-understand-stage-download-risk` の両方を指定しない限り、宣言された段階の本文をダウンロードしません。
- ダウンロードした段階のバイト列はマルウェア素材である可能性があるため、このリポジトリへコミットしてはなりません。
- 稼働中C2との通信は、現在のケースプロファイル、レビュー済み範囲、封じ込め要件に従わなければなりません。

## vvaSクライアントの使用方法

範囲を限定した直接チェックインを実行する例:

```bash
python emulators/valleyrat/vvas_client.py \
  --host 202.95.8.27 \
  --port 6666 \
  --allow-network \
  --output out/valleyrat-vvas-6666.json
```

ネットワークへ接続せずに、レビュー済みValleyRATプロファイルの接続先を表示する例:

```bash
python emulators/valleyrat/vvas_client.py \
  --profile analysis-framework/malware/valleyrat/config/profiles/8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6.json \
  --dry-run
```

稼働中ホストとの通信が許可されている場合に、レビュー済みValleyRATプロファイルから実行する例:

```bash
python emulators/valleyrat/vvas_client.py \
  --profile analysis-framework/malware/valleyrat/config/profiles/8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6.json \
  --allow-network \
  --output out/valleyrat-vvas-profile.json
```

JSON出力には、接続先、送信バイト列、宣言された段階サイズ、ヘッダー一致状態、応答ハッシュ、Base64接頭辞、段階ダウンロードを要求したかどうかを記録します。

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
