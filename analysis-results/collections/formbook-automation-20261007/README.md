# FormBook／XLoader AI非依存静的解析の拡張（2026-10-07）

## 結論

FormBook／XLoaderの提供元ラベル候補401件と、版を一次資料で特定できるXLoader v8.5／v8.7の3件を、検体を実行せずに調査した。今回の主眼は、提供元ラベルをそのまま正解にすることではなく、次回から同じ構造をLLMなしのコマンドだけで復元できるようにすることである。

JavaScript、WSF／VBScript、PowerShell、.NET resource、bitmap resource、native x86 memory imageまでを固定点解析へ接続し、復元物を親子SHA-256付きで再投入する経路を拡張した。C2側は、保存済み通信と検体固有鍵を使うオフラインcodecとlocal loopbackを整備した一方、TCP open、HTTP status、証明書、bannerだけをFormBook／XLoader C2の確認根拠にはしていない。

## 対象集合

| 区分 | 件数 | 扱い |
|---|---:|---|
| FormBook提供元ラベルの独立4波 | 400 | ラベル単独ではファミリー確定に使用しない |
| 最新100件照会で新規だったroot | 1 | 既存400件との重複99件を除外 |
| 一次資料で版を特定できるXLoader root | 3 | v8.5が2件、v8.7が1件 |
| 合計root | 404 | 検体集合は非公開領域、公開側は集合commitmentを保持 |
| `XLoader`別名ラベルの除外候補 | 3 | すべてAndroid APKで、Windows FormBook／XLoader系の根拠なし |

404件のsorted unique SHA-256集合は、末尾LF付きUTF-8で正規化したSHA-256 `61c07b81ad316e4a3fd21d3dc3fe38ee1b3d021cc6d404e45168735925cc9043` に固定した。完全なmember一覧、検体、復号payload、memory dumpはリポジトリへ保存していない。

提供元の候補照会は `max-results` 上限で打ち切られており、401件はFormBook／XLoader候補の網羅集合ではない。公開集計の機械可読版は [`summary.json`](./summary.json) に分離し、集合の選択境界と解析完了条件を明示した。

## 初期300件の再現ベンチマーク

最初の独立3波300件を、family強制、family hint、AI利用なしで同じCLIへ投入した。これは改善前後を比較するbaselineであり、提供元ラベルの正解率ではない。

| 指標 | 1波目 | 2波目 | 3波目 | 合計 |
|---|---:|---:|---:|---:|
| root解析 | 100 | 100 | 100 | 300 |
| `dotnet_resource_loader`へ内部選択 | 21 | 5 | 10 | 36 |
| automation routeあり | 21 | 29 | 31 | 81 |
| 復元子の追加解析 | 10 | 9 | 7 | 26 |
| fixed-point node | 114 | 109 | 108 | 331 |
| fixed-point edge | 32 | 13 | 27 | 72 |
| terminal frontier | 15 | 9 | 8 | 32 |
| terminal選択済み | 0 | 0 | 0 | 0 |
| `complete` | 0 | 0 | 0 | 0 |

`automation routeあり`はloader／resource構造を再現可能に認識した件数であり、FormBook終端ファミリーやC2設定の確定件数ではない。初期300件では、終端payload、real C2、C2 protocolまで揃った検体は0件だった。この0件を隠すためにprovider labelをfamilyへ強制せず、復元阻害点をdecoderと固定点解析の改善対象にした。

## 第4波100件の独立評価

第4波は、解析結果から逆算せずに固定したselection manifestとroot SHA-256を照合して評価した。100件すべてを一意に対応付け、`sample.sha256`で96件、外側archiveの`outer_sha256`で5件を照合した。このうち1件は同一SHA-256が両方の欄に存在するため、和集合は100件である。

| 指標 | 件数 |
|---|---:|
| 選択root／照合済みroot | 100／100 |
| family解決 | 29 |
| `dotnet_resource_loader` | 28 |
| `remcosrat` | 1 |
| family未解決 | 71 |
| automation routeあり | 29 |
| `partial` | 86 |
| `triaged_unknown` | 14 |
| `complete` | 0 |
| terminal到達／未解決 | 0／100 |
| protocolで確認したC2 | 0 |

AI利用、検体実行、network接触はいずれも0件だった。run直下の `summary.json`、`follow-on-analysis.json`、`terminal-payload-acquisition.json` が生成されていなかったため、derived case数、fixed-point node／edge、frontier、terminal選択数は0ではなく `not_available` とした。欠落したrun-level集計を、各caseの不在だけから0へ丸めない。

`remcosrat` 1件は、提供元のFormBook候補ラベルと静的解析結果が一致しない例である。provider labelをfamily確定へ使わず、内部証拠に基づいて分類する境界が機能した結果として扱う。

### 大容量scriptの再評価

第4波のroot `021d369e929769603851acade92af051024192b69a28dca96569a4327449a005` を、調整後の標準CLIで再解析した。旧解析では2 MiB超のscript／単一行と16,384行超の層によって6件の `static_layer_issues` が残っていたが、8 MiBのplain string array上限、16 MiBの総script／単一行上限、65,536行の上限へ調整後は0件になった。入力、行数、carrier、展開量、処理量の上限自体は解除していない。

固定点解析はrootからnative PE `a6bdd034155b7fd22d659d279215a1dcbce229d2f9d36d05e7682a1312a2b0a0`、さらに `d79563c392e82fc306b748d2acdbbb8bea3f2c64cf40af44f4a09925aae696b5` へ進み、node 3、edge 2、error 0、frontier 1を得た。2つのnative子では64件のprimary seed poolを含む構造を確認したが、終端family、C2 endpoint、protocolはいずれも未確定である。この再評価は「上限による解析漏れを減らした」検証であり、FormBook確定件数やC2抽出成功件数へ数えていない。

## 実装した自動復元

### Script配布層

- JavaScriptのRC4文字列配列について、別名代入を推移的に解決し、循環、複数候補、件数・深さ・時間上限超過をfail-closedで拒否する。
- formatted plain string array、comma-separated alias、先行decoy配列を区別し、実際にHTTP取得とPowerShell起動へ流れる配列だけを選ぶ。
- 大容量のminified scriptは旧2 MiB境界だけで拒否せず、plain string arrayは8 MiB、Batch／PowerShell polyglotは総入力16 MiBを上限に解析する。行数、展開量、carrier量、処理量の独立上限は維持する。
- WSF／VBScriptは、同じXMLHTTP objectに対する `open(GET, url, false)`、`send`、status 200確認、`responseText`利用を順序付きで証明する。別object、動的URL、非同期通信、複数URL callsiteは採用しない。
- URLは配布stageとC2を分離し、userinfoを拒否し、query／fragmentを公開値から除く。

### PowerShell／managed層

- AES envelope、repeating-XOR envelope、ghosted payload、Base64分割列を静的に復元する。
- managed resourceはCILの定数・配列・loopを上限付きで解釈し、RC4＋UInt32 swap系とXOR／sub feedback系を復元する。
- 復元したmanaged childやPEを `recovered_payload` として固定点queueへ渡し、親子SHA-256と深さを維持する。loader componentの一致だけでは終端FormBook／XLoaderへ昇格しない。

### native XLoader層

- importless i386 PEとheaderなしx86 memory imageを別々に選別する。
- 一次資料対応の検証物として、XLoader v8.5のmapped PE 3件とv8.7のraw memory image 1件を解析した。stack上のbyte構築順を復元し、175個のbuilder、20-byte base key helper、64個のprimary seed候補と9個のnon-primary候補を自動inventory化した。
- provider labelや既知hashに依存せず、mapped PE／raw x86形状、dominant decrypt target、単一20-byte key helper、完全な64-entry seed poolの組合せを高コストnative解析器へのroute根拠にできる。
- この構造routeはファミリー確定、real C2判定、terminal payload確認を意味しない。v2.5用の3層鍵profileをv8系へ流用しない。

## 最新JavaScriptチェーンの検証

最新照会で唯一新規だったroot `b85d4673ac19ee208e96eff1e860d4b110a1eac0620464193bde12a85fb54115` は、次の7段を静的に追跡した。

1. RC4難読化されたJavaScript文字列配列
2. 復号後のplain string arrayと同期HTTP GET
3. responseTextを一時PowerShell fileへ保存してhidden起動する処理
4. PowerShellのAES復号で得られるmanaged loader
5. managed loaderから得られるnative PE `c244dc93f8a675b0c0012b07d9f09f89e1d65db87f44ffee9fa04dc57dc711f3`
6. `c244...` のdispatcherと二段RC4復号から得られるanalysis PE `e6de6ce31e7e19a610d24ddd3d72fd390272a0b44f1e6d7998ca81158a67a9a7`
7. `e6de...` のnative inventory（builder 175、canonical Base64 73、primary seed 64、non-primary seed 9）

`c244...` からの固定点解析はnode 2、edge 1、frontier 1、terminal選択0である。Ghidraでは明示的なprogram selectorを使用し、importなし、単一section、entry pointからVM dispatcher、RC4復号、復号領域へのin-memory callへ至る経路を確認した。任意スクリプトや検体は実行していない。

外部取得は、同一データフローでpayload stageと証明できたURLへ、redirectなし・1回・byte上限付きGETだけを実施した。取得物と復元物は実行していない。配布URLはC2へ昇格していない。

`e6de...` ではC2 endpointを0件と判定し、終端familyも未確定のままにした。未解決理由は `base64_decoder_unproven`、`layer_key_roles_unproven`、`rc4_sub_transform_unproven`、`network_consumer_not_scanned_missing_required_roles`、`same_path_dataflow_unproven` である。構造inventoryだけでendpointや終端FormBook／XLoaderを推測せず、decoder、鍵role、network consumerが同一路で結合されるまで保留する。

追加のGhidra MCP監査では、明示的なprogram selectorを使い、133関数、1,218 symbol、741個のstandard prologue候補を全走査した。pure RC4 KSA／PRGAとWinINet resolver thunkは確認したが、Base64 decoder、RC4-sub、network consumerの同一路到達性は0件だった。opaque dispatcherとindirect callを推測で補完せず、次の最小手順はdispatcher／間接call siteへ限定したbounded value-set evaluatorの追加としている。このため上記5 blocker、endpoint 0件、終端family未確定を維持する。

## C2プロトコルの自動化範囲

| 系統 | 自動化済み | 未解決または意図的に無効 |
|---|---|---|
| FormBook legacy | URL由来DWORD反転SHA-1鍵、RC4、変形Base64、`FBNG` command 1～9、保存済みrequest／response評価 | process帰属と信頼できるcapture provenanceがないendpoint確定 |
| macOS XLoader 1.1 | 二重RC4、`XLNG`登録、command 1～9 | 検体固有鍵の自動導出 |
| XLoader 2.5 | Key0CommからKey1Comm／Key2Commを導出し、保存済み通信を二層RC4復号 | sample固有VM／switch対応が未復元の検体での鍵推測 |
| XLoader 6／7 | real／decoy候補、index 64、path token、RC4-subの構造metadata | 検体固有鍵scheduleが不足する入力の完全serializer |
| XLoader 8.1～8.7 | `PKT2`、固定鍵相殺、URL SHA-1鍵、URL seed派生鍵、GET wire、保存済みresponseのcommand文法 | 実C2へのapplication-layer送信、captureなしのreal／decoy判定 |

外部endpointを `confirmed_protocol_c2` とするには、静的設定endpoint、検体固有鍵、同一endpointへ束縛されたrequest／response、対象世代のcommand frame、malware process帰属、real／decoy曖昧性解消、各証跡のhash bindingが必要である。client側登録だけは自己生成できるため、server機能の証拠にしない。

現行のloopbackは無操作commandだけを返し、command本文を実行、保存、別通信へ転送しない。外部FormBook／XLoader application probeは `passive_only` であり、port openだけからC2を肯定する機能は実装していない。

## 安全境界

- 検体、復号payload、managed loader、native PE、memory imageを実行していない。
- C2／dead-dropへapplication dataを送っていない。
- 外部通信は、検体repository API、完全SHA-256一致の公開sandbox artifact API、静的に証明したpayload stageへの限定GET、暗号化解析データのS3保管に限定した。
- 復元物は対象ごとにpassword `infected` のWinZip AES-256 archiveへ分離し、S3のsize、SSE、SHA-256 metadataを検証した。sourceは保持した。
- provider label、file name、TCP open、HTTP応答、証明書を単独のファミリー／C2確定根拠にしていない。

## コマンドによる再実行

MalwareBazaar形式の暗号化ZIPは、familyを強制せず次の入口へ渡す。解析器は検体を起動せず、復元子を固定点queueへ再投入する。

```powershell
python .\analysis-framework\common\analyze_sample.py `
  --input C:\malware-lab\sample.zip `
  --output C:\malware-lab\formbook-static `
  --archive-mode malwarebazaar `
  --max-static-layers 64 `
  --retry-max-static-layers 256 `
  --sevenzip "C:\Program Files\7-Zip\7z.exe"
```

保存済み通信の復号は [`formbook_protocol.py`](../../../analysis-framework/malware/formbook_loader/formbook_protocol.py)、世代別の証拠境界とCLI例は [`C2-PROTOCOL-OFFLINE.md`](../../../analysis-framework/malware/formbook_loader/C2-PROTOCOL-OFFLINE.md) に記載した。外部endpointへのapplication probeはこのCLIへ含まれない。

## 一次資料

- Zscaler ThreatLabz、[XLoader v8.7の難読化とnetwork protocol](https://www.zscaler.com/blogs/security-research/latest-xloader-obfuscation-methods-and-network-protocol)
- Zscaler ThreatLabz、[XLoader 2.5のC2 network encryption](https://www.zscaler.com/blogs/security-research/analysis-xloader-s-c2-network-encryption)
- Zscaler ThreatLabz、[XLoader 6／7の技術解析 Part 1](https://www.zscaler.com/blogs/security-research/technical-analysis-xloader-versions-6-and-7-part-1)
- Zscaler ThreatLabz、[XLoader 6／7の技術解析 Part 2](https://www.zscaler.com/mx/blogs/security-research/technical-analysis-xloader-versions-6-and-7-part-2)
- Mandiant、[FormBookの配布、通信、command形式](https://cloud.google.com/blog/topics/threat-intelligence/formbook-malware-distribution-campaigns/)
