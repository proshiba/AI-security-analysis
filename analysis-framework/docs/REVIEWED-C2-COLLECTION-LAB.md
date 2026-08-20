# 複数検体のC2検出・loopback模擬

この機能は、複数検体から静的に回収したendpoint、terminal SHA-256、証明書pin、protocol fingerprintを、検体ごとの完全一致profileへ変換します。検体、復号済みpayload、秘密鍵はprofileへ含めません。

実装は次の2ファイルです。

- [`reviewed_c2_collection.py`](../common/reviewed_c2_collection.py): profile構築、検証、Nmap NSE計画、offline response判定
- [`reviewed_c2_loopback_emulator.py`](../common/reviewed_c2_loopback_emulator.py): 1接続・1要求・1固定応答のloopback facade

## 対応するprotocol

| family | C2検出 | loopback応答 | 実装しない処理 |
|---|---|---|---|
| BwRAT（VenomRAT protocol lineage） | `dotnet-rat-c2.nse`でTLS 1.2、`Pac_ket=Ping`、`Po_ng`を検証する | exact Pingへ固定`Po_ng`を1 frameだけ返す | `ClientInfo`収集、task、plugin、操作結果、file転送 |
| ValleyRAT vvaS | `valleyrat-c2.nse`で`333200`と14-byte stage headerを検証する | exact check-inへ14-byte headerだけを返す | stage body、terminal command、task結果、payload転送 |

証明書の公開部分からprivate keyは復元できません。このためBwRAT facadeは、実検体の証明書pinと一致する完全互換C2ではありません。検出器のapplication protocol検証には`--application-layer-only`を使用できます。TLSを含むloopback検証では、リポジトリ外で生成したlab専用certificateとprivate keyを指定します。証明書不一致だけではfamily C2を除外しません。

## private profile packの構築

profile packはendpointを含むため、対象collectionをGitへ公開しない場合はリポジトリ外へ保存します。既存fileは上書きしません。

```powershell
py -3.13 -B .\analysis-framework\common\reviewed_c2_collection.py build `
  --analysis C:\analysis-private\collection\analysis-results.json `
  --collection-id reviewed-collection-20260819 `
  --source-label "private static analysis" `
  --output C:\analysis-private\collection-lab\profiles.json
```

profileごとにroot SHA-256、terminal SHA-256、family、endpoint、protocol、証明書pinを束縛し、canonical JSON SHA-256を記録します。値やschemaを変更したprofileは読込時に拒否します。

## 検出計画

次の操作は通信を行わず、各外部endpointへ適用するNmap NSE引数だけを表示します。

```powershell
py -3.13 -B .\analysis-framework\common\reviewed_c2_collection.py detector-plans `
  --profiles C:\analysis-private\collection-lab\profiles.json `
  --output C:\analysis-private\collection-lab\detector-plans.json
```

出力される計画は`execution_backend=nmap_nse_only`です。現在のtaskで外部通信が明示許可されていない場合は実行しません。実行する場合も、表示された完全一致profile SHA-256、数値IP、単一port、既存NSEだけを使用し、Python socket、redirect、stage取得へfallbackしません。

## loopback模擬facade

vvaSはnumeric loopbackだけへbindし、stage bodyを送信しません。

```powershell
py -3.13 -B .\analysis-framework\common\reviewed_c2_loopback_emulator.py `
  --profiles C:\analysis-private\collection-lab\profiles.json `
  --profile-id <vvaS-profile-id> `
  --bind 127.0.0.1 --port 0
```

BwRATのapplication-layer試験ではTLSを終端しません。

```powershell
py -3.13 -B .\analysis-framework\common\reviewed_c2_loopback_emulator.py `
  --profiles C:\analysis-private\collection-lab\profiles.json `
  --profile-id <BwRAT-profile-id> `
  --bind 127.0.0.1 --port 0 --application-layer-only
```

TLS込みの試験では、リポジトリ外にあるlab専用certificateとprivate keyを`--tls-cert`／`--tls-key`で指定します。emulatorはloopback外へbindせず、loopback外peerを拒否し、raw request／responseやvictim metadataを保持しません。

## 完了と判定しないもの

- TCP portがopenであるだけの結果
- TLS certificateだけの一致
- profileにある過去のendpoint
- timeoutまたは応答なし
- 証明書rotationだけによる不一致

`Po_ng`またはvvaS固定headerの完全一致をprotocol確認として扱います。静的profileだけでは現在の稼働、運用者、campaignの継続を確認できません。
