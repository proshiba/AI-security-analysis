# MX-Goローカルプロトコル検証環境

この検証環境は実在インフラへ接続せず、静的に復元したMX-GoのHTTP制御パスとコンテンツパスを再現します。両プログラムともループバックだけで動作します。

## 安全境界

- `server.py` はループバック以外のバインドアドレスを拒否します。
- `client.py` はループバック以外の接続先URLを拒否します。
- 共通`c2_detector.py`は互換用offline planだけを返し、MX-Goのnetwork動作を実行しません。
- 合成check-inと受信者取得は本ディレクトリの`client.py`だけで行い、接続先をnumeric loopbackへ固定します。
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

## 専用loopback clientとの連携

共通`analysis-framework/common/c2_detector.py`は、現在は互換用offline planを返すだけでnetworkへ接続しません。MX-Goはmalware固有NSEのreview済みwire signatureが未登録であり、外部targetへのactive C2検知対象ではありません。

ローカルエミュレーターへ合成check-inだけを送る場合は、専用clientを使います。

```powershell
python .\emulators\unclassified\mx_go\client.py `
  --base-url http://127.0.0.1:5000 `
  --mode checkin `
  --output C:\malware-lab\mx-go-checkin.json
```

合成受信者データだけを取得する場合は`recipients`、両方を順に確認する場合は`both`を指定します。

```powershell
python .\emulators\unclassified\mx_go\client.py `
  --base-url http://127.0.0.1:5000 `
  --mode recipients `
  --output C:\malware-lab\mx-go-recipients.json
```

`client.py`はループバック以外のURLをHTTP処理より前に拒否します。実C2、実受信者、外部コンテンツserverへの接続には使用できません。

## テスト

```powershell
python -m pytest .\emulators\unclassified\mx_go\tests
```
