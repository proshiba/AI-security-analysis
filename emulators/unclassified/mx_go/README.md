# MX-Goローカルプロトコル検証環境

この検証環境は実在インフラへ接続せず、静的に復元したMX-GoのHTTP制御パスとコンテンツパスを再現します。両プログラムともループバックだけで動作します。

## 安全境界

- `server.py` はループバック以外のバインドアドレスを拒否します。
- `client.py` はループバック以外の接続先URLを拒否します。
- `c2_detector.py --protocol mxgo` は既定でオフラインの要求プレビューを生成します。
- 能動的な検出器モードには、ループバックホストと `--mxgo-allow-loopback-network` の両方が必要です。
- ハートビートには合成IDと `LAB_ONLY` を使用し、ホスト名、MACアドレス、実端末の識別子を収集しません。
- 受信者の合成データには予約済み `.invalid` TLDを使います。出力には件数／ハッシュだけを含め、アドレスは含めません。
- 検証環境が返すコマンドフラグは空で、動作しません。メール送信やコマンド実行はできません。

## ローカルC2／コンテンツエミュレーターの起動

```powershell
python .\emulators\unclassified\mx_go\server.py --host 127.0.0.1 --port 5000
```

エミュレートするパス:

- `POST /api/v1/heartbeat_direct`
- `POST /api/v1/activate`
- `POST /api/v1/shutdown`
- `POST /api/v1/selftest_result`
- `GET /api/client_command/<synthetic-client-id>`
- `GET /jp01.txt`, `/html-a.txt`, `/fscs-a.txt`, `/yuming.txt`, `/dimk.txt`

## 単体クライアントエミュレーター

```powershell
python .\emulators\unclassified\mx_go\client.py `
  --base-url http://127.0.0.1:5000 `
  --mode both `
  --output C:\malware-lab\mx-go-lab-client.json
```

## `c2_detector`との連携

ネットワークへ接続せずにハートビートの説明を生成します。プレビューモードは名前解決も接続も行わないため、ホストにはレビュー済みIOCを指定できます。

```powershell
python .\analysis-framework\common\c2_detector.py 43.165.179.173 5000 `
  --protocol mxgo `
  --mxgo-mode preview
```

ローカルエミュレーターに対して合成チェックインを検証します。

```powershell
python .\analysis-framework\common\c2_detector.py 127.0.0.1 5000 `
  --protocol mxgo `
  --mxgo-mode checkin `
  --allow-network `
  --mxgo-allow-loopback-network
```

合成した受信者データを取得して要約します。

```powershell
python .\analysis-framework\common\c2_detector.py 127.0.0.1 5000 `
  --protocol mxgo `
  --mxgo-mode recipients `
  --mxgo-recipient-path /jp01.txt `
  --allow-network `
  --mxgo-allow-loopback-network
```

ループバック以外の能動的接続先は、DNSまたはTCP処理より前の引数検証で失敗します。

## テスト

```powershell
python -m pytest .\analysis-framework\tests\test_c2_detector.py .\emulators\unclassified\mx_go\tests
```
