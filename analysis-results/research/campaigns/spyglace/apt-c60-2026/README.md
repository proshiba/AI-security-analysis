# APT-C-60／SpyGlace 2026解析

## エグゼクティブサマリー

このケースでは、JPCERT/CCが報告した2026年のAPT-C-60配布チェーンを追跡し、
2026-07-15時点で到達可能だった公開リポジトリ履歴を独自に棚卸ししました。
リポジトリ取得後のワークフローはオフラインのままとし、復元ファイルの実行や
C2への接続は行っていません。

復元したチェーンは次のとおりです。

1. Proton Driveまたはメール添付ファイルを介してRARアーカイブを配布します。
2. LNKが自身をコピーし、埋め込まれた難読化JavaScriptを`mshta.exe`で起動します。
3. スクリプトがjsDelivr経由でcontributing[1].txtをダウンロードし、Base64から
   TARアーカイブへ復号した後、同梱の`git.exe`でインストールスクリプトを起動します。
4. スクリプトが`TMI003.db`、`TMI100.db`、`TMI210.db`、`TMI320.db`、
   `TMI400.db`を連結し、`iconcache.dat`を生成します。
5. Downloader1がGitHub、GitLab、Codeberg、または各CDN表示経由で、符号化された
   Downloader2、ローダー、SpyGlaceのアーティファクトを取得します。
6. リポジトリ層は反復鍵sgznqhtgnghvmzxponumで復号します。後段レイヤーには
   AadDDRTaSPtyAG57er#$ad!lDKTOPLTEL78pEも含まれます。
7. ローダーがCOM Hijackによる永続化を確立し、最終的なx64 SpyGlaceペイロードを
   読み込みます。

## リポジトリ調査

JPCERT/CCの付録Eに記載された29リポジトリを、認証なしの公開Provider APIを
通じて調査しました。

| 結果 | 件数 |
|---|---:|
| 存続しているリポジトリ | 16 |
| 存続し、履歴へ到達可能 | 10 |
| 存続しているが空 | 6 |
| 利用不可 | 13 |

削除済み履歴にも重要な情報がありました。class125の旧Commitには配布アーカイブ、
JavaScript、TMIの断片が残り、tblsesarolには符号化Downloader、ローダー、
SpyGlace v3.1.15ペイロード4件、端末別Taskファイルが残っていました。空でない
10個のMirror全体から、静的XOR復号により有効なx64 PEイメージ27件を復元しました。
調査用コピーでは、Taskファイル名に含まれる被害端末識別子を再掲していません。

各リポジトリの特定時点の状態は`repository-liveness.json`を参照してください。
「利用不可」は、調査時に公開APIからリポジトリが返らなかったことだけを意味し、
削除、所有者、帰属を証明しません。

## 確認済みSpyGlace v3.1.15設定

| 符号化SHA-256 | 復号後SHA-256 | C2 | ユーザーID | リクエストパス | ミューテックス |
|---|---|---|---|---|---|
| e5f2c7068ade7b87d24c3b94bc749c351d53609f5fcaa48dce06234beaa2444f | 7ab9c634216798d50ce3e19bf1650d6b7c2386150340e48ec3af8b38fd30ae4c | 185.18.222.241 | SAPPHIRE | 1l8kad.asp, vdlhtr.asp, 7m3yv3.asp, fp4v2i.asp | K31610KIO9834PG79A471 |
| 9394627e9c44cf2226ddf50012e5cf47ccf7d3bd8afa2395c635a93637e23502 | af24d54d56cbdffe5081c133dae8e8cd54a0d0e2f3059599bc388ef27cf19aa5 | 31.58.136.207 | EVE | x66hjl.asp, fx72rf.asp, guehry.asp, dmd4n2.asp | K31610KIO9834PG79A471 |
| add013bf7ffc8a89789a7fd0ae0ff799c620af9b2755b214880b6a56768fd48c | 88f58087fc7e7a74455d19c0476954c3bd77d36d0683ab57a6598eb72c4ae37c | 31.58.136.207 | EVE | x66hjl.asp, fx72rf.asp, guehry.asp, dmd4n2.asp | K31610KIO9834PG79797 |
| c86f319f64d25f23ac29d9b53c9764f06a150634ee8e2d836424d460e5a99b52 | 7621e4eff855b2679188b33fe4c71c377f6e2d0b9c25d939452e18992c52e067 | 31.58.136.207 | EVE | x66hjl.asp, fx72rf.asp, guehry.asp, dmd4n2.asp | K31610KIO9834PG79787 |

各設定JSON内のC2 URL方式は、WinHTTPの使用とASPパスから推定したものです。
ホストの到達性、ポート、エンドポイントの挙動は能動的に試験していません。

JPCERT/CCは、v3.1.17を1件、v3.1.18を5件挙げています。存続していた
リポジトリ履歴には存在せず、2026-07-15にMalwareBazaarで6件すべてが
`file_not_found`となったため、設定を復元済みとはしていません。

## 静的リバースエンジニアリング

復号後ペイロード7ab9c634...をGhidraで解析し、1バイト単位の文字列変換を
2種類特定しました。

- API／コマンド文字列: 復号後バイト =（符号化バイト XOR 3）- 1。
- 設定文字列: 復号後バイト =（符号化バイト XOR 2）- 1。

1つ目の変換では、WinHttpOpen、WinHttpConnect、WinHttpOpenRequest、
WinHttpSendRequestと関連APIのほか、次のコマンドを復元します。

- procspawn、prockill、proclist、diskinfo
- download、downfree、upload、cancel
- screenupload、screenauto、turn on/off
- extension、stopextension、ddir、ddel
- attach、detach

2つ目では、ipaddr$$$$、userid$$$$、各ASPパス、`api.ipify.org`、独自RC4鍵
90b149c69b149c4b99c04d1dc9b940b9を復元します。

JPCERT/CCによる2025年のProtocol解析では、a001からa004、MD5由来識別子、
独自の3Round RC4亜種によるBase64を用いるHTTP POSTフォームが報告されています。
また、AES-128-CBCダウンロード定数B0747C82C23359D1342B47A669796989と
21A44712685A8BA42985783B67883999も記録されています。これらの定数は
プロトコル知識として保持しますが、今回復号した4つのバイナリ内にリテラルバイトとしては
見つかりませんでした。

## 検出指針

| 確度 | 検出条件 | 想定される誤検知 |
|---|---|---|
| 高 | 1つのPE内にある複数の符号化SpyGlaceコマンド／API／設定マーカーに対するYARA一致、COM Hijack CLSIDとCachedImageローダー文字列、JPCERTの完全一致ハッシュ | 非常に低い。ただしハッシュ一致が無害な調査用コピーを識別する場合はあります。 |
| 中 | LNKまたはアーカイブに続くmshta、certutil復号、tar展開、同梱gitバイナリ、TMI*.db断片からの`iconcache.dat`生成 | 管理用パッケージ作成や開発自動化でも個々のツールは使用されますが、この組み合わせは異例です。 |
| 低 | GitHub、GitLab、Codeberg、jsDelivr、Proton Drive、StatCounterのいずれかへの単独アクセス | 高い。すべて正規サービスであり、宛先だけの遮断は通常業務を過検知します。 |

プロセス／レジストリのテレメトリには同梱Sigmaルールを、ファイルまたはメモリには
YARAルールを使用してください。Provider全体を遮断せず、正規サービスへの通信を
正確なアカウント／パス、プロセスの親子関係、ファイル名、エンドポイント上の
ファイルハッシュと相関してください。

## 受動的なインフラのピボット情報

受動検出器は、静的に復元したC2値に対するIPベースのShodanクエリとリクエストパス
ピボットを生成します。ホストへの確認を行っておらず、認可された受動データアカウントも
使用していないため、バナー、HTTPタイトル、証明書ハッシュ、JARMは導出していません。
これらの項目は推測せずnullのままにする必要があります。

## ファイル

- jpcert-ioc-files.csv: JPCERT/CC付録の103行すべて。重複するファイル名／ハッシュ行を保持し、重複しないSHA-256は98件。
- delivery-reconstruction.json: Base64／TARおよびTMI断片の再構成を検証し、JPCERT Downloader1のハッシュ866564bb...1d065を取得。
- lnk-ipo6.json、lnk-idx2.json: 復元した2つのLNKについて、埋め込みスクリプト、アクション、jsDelivr URLを静的に棚卸し。
- recovered-pe-inventory.json: 復号したPE 27件（Downloader1 4件、Downloader2 9件、SpyGlaceローダー7件、SpyGlaceペイロード4件、未解決PE 3件）の識別情報。
- network-and-account-iocs.csv: C2、悪用URL、フィッシング送信者、コミット識別情報を情報源別に収録。
- repository-liveness.json: 公開リポジトリ29件すべての観測結果。
- ../../cases/: 検体別の設定結果。
- ../../../../analysis-framework/malware/spyglace/rules/: SigmaおよびYARA検出。

## 制約と来歴

リポジトリ状態とCommit履歴は2026-07-15に観測しました。公開Commit Metadataは
偽装できるため、AddressやUsernameは調査用Pivotであり、帰属の証明ではありません。
v3.1.15検体は静的に復号してDecompileしましたが、起動していません。稼働中C2、
Phishing送信者、被害システム、リポジトリAccountのいずれも変更していません。

一次資料:

- https://blogs.jpcert.or.jp/en/2026/07/apt-c-60_2026.html
- https://blogs.jpcert.or.jp/en/2025/11/APT-C-60_update.html
- https://blogs.jpcert.or.jp/en/2024/12/APT-C-60.html
