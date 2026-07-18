# シルバーフォックスによる偽装仮想私設網経由のアトラスクロス／アトラス遠隔操作型トロイ配布キャンペーン

## 判定

公開技術情報により、正規のおとりソフトウェアをインストールして `Schools.exe` を起動するセットアップファクトリーの誘導チェーンが確認されている。ローダーは324バイトのゴースト形式設定を復号し、`bifa668.com:9899` に接続する。続いて8バイトの `SFuck\0\0\0` ビーコンを送信し、固定長386,380バイトの第2段階を受信して、`AtlasInfo` をエクスポートするアトラス RAT の DLL をリフレクティブロードする。

公開済み検体は MalwareBazaar から取得できなかった。このため本リポジトリでは、公開情報に記載された設定変換を再現し、合成した検証用データで妥当性を確認した。以下のキャンペーン固有値は情報源で確認されているが、今回ダウンロードした検体から独立に抽出した値ではない。

## チェーンと設定

```text
fake VPN/messaging domain
  -> Setup Factory launcher + legitimate decoy
  -> Schools.exe
  -> decrypt 324-byte config (marker By@V<)
  -> TCP bifa668.com:9899; send SFuck + 3 NUL
  -> receive 386,380-byte unencrypted stage
  -> reflective loader at 0x0000; PE at 0x1C04
  -> AtlasInfo(config at shellcode_base + 0x5E408)
```

設定の配置は、ホストが `0x00`（64バイト）、ポートが `0x40`（`uint16le`）、パディングが `0x42`、備考欄が `0x44`（128バイト）、グループ欄が `0xC4`（128バイト）である。ディスク上の INI では `LoginAddress`、`LoginPort`、`REMARK`、`GROUPS`、`Time`、`SIGN` という名前を使用する。備考欄とグループ欄はキャンペーンまたはオペレーターの識別子であり、予備の IP アドレスではない。

## C2 とプロトコル

- 主 C2: `bifa668.com:9899`
- 報告された A レコード: `61.111.250.139`
- 権威 DNS: `a.share-dns.com`、`b.share-dns.net`
- ローダーのチェックイン: 16進数 `53 46 75 63 6b 00 00 00`
- HTTP フォールバック用 UA: `Mozilla/4.0 (compatible)`
- 遠隔操作型トロイの通信: 平文の56バイトヘッダーに、パケットごとの素材を使った ChaCha20 暗号で保護した内容が続く
- ミューテックス: `Global{K8A9C1D9-FUCK-AE99-CLOSE-bifa668.com}`

公開された324バイトの設定から、代替 C2 の一覧は確認できなかった。以前 IPv4 値に見えた REMARK と GROUPS のバイト列は識別子である。

## ホスト上の挙動

確認された機能には、`\Microsoft\Windows\AppID\` 配下のスケジュールタスクによる永続化、`C:\Users\Public\Documents` 内の生成物、スキャン・トレース・言語モード・スクリプトブロックの各種回避を伴うアプリケーションドメイン内のパワーシェル実行、微信プロセスへのインジェクション、セキュリティ製品の通信セッション妨害が含まれる。アトラス RAT の DLL は `AtlasPro.ini` を使用し、オペレーターが供給するモジュールは変化し得る。

## 検出評価

- **誤検出リスク低**: 検体の完全一致ハッシュ、`SFuck\0\0\0` で始まる生の TCP ペイロード、または `AtlasInfo`・`AtlasPro.ini`・ミューテックス雛形の組み合わせ。
- **中程度**: ワークステーションからポート9899への外向き通信、公開文書フォルダー配下の設定ファイル、アプリケーション識別子パス配下のスケジュールタスク、パワーシェル以外のプロセスによる `System.Management.Automation.dll` の読み込み。
- **高い**: 偽ドメインの類似名、古い `Mozilla/4.0 (compatible)` 利用者エージェント、またはウルトラビューアの生成物を単独で使う検出。正規のリモート支援ソフトウェアが存在するためである。

[IOC](iocs.json)、[YARA](rules/atlascross.yar)、[Sigma](rules/atlascross.yml)、および `extractors/atlascross/` 配下の再利用可能な抽出器を参照すること。

## 情報源と制約

- https://hexastrike.com/resources/blog/threat-intelligence/trust-the-tunnel-get-the-trojan-silver-fox-delivers-atlas-rat-via-weaponized-vpn-installers/
- https://www.proofpoint.com/us/blog/threat-insight/ta4922-suspected-chinese-crime-group-going-global

検体の実行および C2 への接続は行っていない。
