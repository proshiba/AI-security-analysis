# 日本語マルスパム3件の静的解析（2026-10-16）

## 結論

2026年10月16日に公開報告された日本語マルスパム3件を、検体を実行せず、取得できたファイルのhash照合、script復号、PE構造確認、Ghidra逆コンパイル、公開sandboxの完全一致証跡によって比較しました。

| ケース | 評価したファミリー | 静的に確認した実行チェーン | C2評価 | 解析状態 |
|---|---|---|---|---|
| 1 | PureRAT | 正規WinWord bundle→`msvcr100.dll`→Python runtime／`run.py`→Donut→.NET loader→終端PE | `trump.sharevideocenter.com:56001/56002/56003`を終端configから静的確認。動的観測は56001のみ | 終端／config解析済み、protocol未解析 |
| 2 | PureLogs | 正規WPS PDF host→`krpt.dll`→Python runtime→`instructions.pdf`→.NET終端PE | `tea.vexexo.com:56001`はsandbox観測と独立OSINTで補強。今回の終端PEからは直接抽出できず | 終端復元済み、config未復元 |
| 3 | Remcos RAT | 指定JS→PowerShellを完全一致公開挙動で確認。別ケースはJS→PowerShell→process hollowing→Remcosまで静的復元 | `23.132.164.3:2404`は指定事例と別ケースで補強。指定JS自体の静的configからは未確認 | 指定検体未取得のため未完了 |

ケース1と2は、同日の破損／返金テーマ、`share.google`から`.co.nz/download.php/<動画風名称>?f=<32hex>`への誘導、正規hostと悪性DLL、Python runtime、TCP/56001という複数の一致を持ちます。ITOCHU Cyber & Intelligenceが報告した先行campaign像とも整合するため、同一配布clusterである可能性は中～高です。一方、PureRATとPureLogsは別製品であり、同一operator／actorと断定できません。ケース3は入口とインフラが異なる別clusterです。

## 証拠水準

- **confirmed（確認済み）**: 取得したbytesのSHA-256、PE import／export、復号したscript、Ghidraで確認した処理、または完全一致SHA-256に結び付く公開成果物から直接確認した事実です。
- **corroborated（補強済み）**: 提供情報に加え、完全一致公開sandboxまたは独立した比較ケースが整合しますが、対象終端payloadの静的configからは直接確認できていない事項です。
- **unconfirmed（未確認）**: 指定検体を取得できない、親子hashを結び付けられない、または後段を復元できず、現時点で対象検体へ直接帰属できない事項です。

ファイルhashの`confirmed`は、そのbytesとhashの一致を示します。hashが確認済みであっても、ファミリー、C2、実行順が自動的に確認済みになるわけではありません。

## ケース1: PureRAT（高確度）

### 配布とside-loading

メール件名は「使用できない商品の対応手順について」です。共有サービスのURLから、`get-file.thuthukafs.co.nz`上のダウンロードURLへ誘導し、`Complete_Product_Condition_Review_mp4_4f8a1b63.zip`を配布します。共有サービス自体は汎用サービスなのでIOCには採用していません。

取得した内側ZIPのSHA-256は`962fcefe103538fc1ccef51e664faf7ce3bb572d4f48eb9020b8200bacee5c13`です。ZIP内の正規WinWord host `Complete_Product_Condition_Review_mp4_4f8a1b63.exe`はSHA-256 `3d46e95284f93bbb76b3b7e1bf0e1b2d51e8a9411c2b6e649112f22f92de63c2`、side-loadされる`msvcr100.dll`は`cd8dfd0f587dfece900a7316bf1f98abfd11e3fa92546a304069919148f8ce2e`でした。正規hostのhashは悪性IOCではなく、bundle文脈専用です。

正規hostはMSVCR100系の25 exportsをimportしますが、今回の悪性DLLがそれらをすべて提供することは確認できませんでした。公開sandboxでは`regsvr32 /s <DLL>`でDLLを直接起動しています。このため、通常のdouble-clickで自然なDLL side-loadingが成立すると断定せず、bundleのside-load意図とsandboxでの直接実行を分けています。

### 悪性DLLの静的ロジック

`msvcr100.dll`は大量の囮exportを`_guard_check_icall`相当の同一stubへ集約し、実処理を目立ちにくくしています。entry処理はmodule初期化後にworker threadを作成し、workerは短い待機の後に暗号化runtime／payloadの展開へ進みます。Ghidraでは次を確認しました。

- custom archiveはmagic、version、file数、相対path、sizeを検証し、絶対path、drive指定、`..` traversalを拒否して複数fileを書き出します。
- Python runtimeとpayload blobを複数の候補rootから探索し、復号・展開後にPythonを複数のcreation flagで再試行します。
- `%SystemRoot%\System32\regsvr32.exe`を組み立てて子processを作成する経路と、復号したPE候補を一時`.dat`へ書く経路があります。
- 失敗時はbuild IDを含む内部診断文字列へ到達します。これはloaderの復元／起動pipelineを示しますが、文字列だけで各分岐がこの観測で成功したとは断定していません。

PE overlayの`L1PK` containerをRC4復号すると、Python 3.11 x86 runtime、`n69x8r5.py`、`run.py`、`13681.bin`など70 entriesを持つ`LABZ` archiveを復元できます。復号keyは公開していません。`n69x8r5.py`は同梱indexを復号してzlib展開し、`%LOCALAPPDATA%\Drivers\macOS`へruntimeを配置して`python.exe run.py`をwindowなしで起動します。

### `run.py`と永続化

完全一致で取得した`run.py`はSHA-256 `2558f63f0bf8090c12e1130678cc6a642386155181005e5a21c1d1fb608b4e14`、`13681.bin`は`8b4691c853ddc52a2e6e3c37e6080053c7a03f32ca0e3ccd6bdd56a89b802015`です。`run.py`は次を行います。

1. scriptと同じdirectoryの`13681.bin`を読み、単一byteの反復XORで復号します。復号秘密値は公開していません。
2. 32-bit processであることを確認し、`VirtualAlloc`で実行可能memoryを確保して復号bytesをcopyし、関数pointerとして呼び出します。
3. 並行threadで`%LOCALAPPDATA%\Drivers\run.vbs`を作り、Python processが存在しない場合だけ`%LOCALAPPDATA%\Drivers\macOS\python.exe`から`run.py`を非表示起動させます。
4. `Drivers_EveryMinute`というscheduled taskをXMLから作成します。taskはinteractive token／least privilegeで`wscript.exe`を起動し、1分間隔、実質無期限、同時実行抑止の設定を持ちます。

XOR後の`13681.bin`はx86/x64両方を含むDonut shellcodeでした。x86 branchから.NET loader（SHA-256 `172be46175d3f7c9c979a0200ae61b1f0e1977e82cb829923e1e590fd039b809`）を復元しました。このloaderはresource `PayloadSource.zip`をTripleDES-CBCで復号し、先頭4-byte lengthの後ろをGZip展開して、終端PE（SHA-256 `9f201e04b49a958a120b2ea2e9cda048d94feddd9278b6fe03fb6cac24c05b83`）をmemory loadします。生key／IVは公開していません。

### 終端config

終端configから次を静的に復元しました。

| 項目 | 値 |
|---|---|
| C2 host | `trump.sharevideocenter.com` |
| C2 ports | `56001`, `56002`, `56003` |
| campaign | `Default` |
| version候補 | `4.4.1` |
| 永続化flag／sleep抑止flag | `false`／`false` |
| install environment | `APPDATA` |
| mutex | `purecrack-default` |
| 埋込みcertificate | Subject／Issuer `CN=PureRAT Agent` |
| certificate SHA-256 | `82aeafab427674c4ab36f5483a6ee136e1bc25c326ce1c04d5abd74722332493` |

### sandbox観測

公開sandboxの約600秒の2 runでは、`Drivers\macOS\python.exe`から`82.47.180.159:56001`へのTLS接続が観測されました。56002と56003は設定値ですが、今回のrunでは通信を観測していません。

現行strict detectorは`matched=false`、`confidence=insufficient`を返します。復元configのfield inventoryは`1,2,3,4,5,6,8,9,10`で、空のscheduled-task field 7が省略されています。config復号、C2、PKCS#12、`PureRAT Agent` certificate、version、campaignは確認できましたが、detectorはfield 1～9の明示存在を要求するためfield 7欠落だけでgateを落とします。したがってC2/configは静的確認済み、ファミリーは複数の固有anchorと独立OSINTからPureRAT 4.4.1に高確度で整合しますが、現行自動strict判定では未確定です。

ITOCHUが解析した同系PureRATは、初回C2通信でsecurity product名、webcam有無、user／domain、OS version／architecture、idle time、active window title、実行file path、screenshotを送ります。browser、暗号資産wallet、Telegram／Foxmail等の情報窃取能力も報告されています。これは今回個体と独立にfamily帰属を補強する同系実装情報であり、今回終端の全command dispatcherを再解析して列挙したものではありません。

## ケース2: PureLogs（高確度）

### 配布とside-loading

メール件名は「商品の破損について返金対応を希望します」です。共有サービスから`get-file.gilmorebrown.co.nz`へ誘導し、SHA-256 `59ceb7b47ebb9ed5189afe1afe79a80c854bb2ddec62a23ec2c380465a9598a8`のZIPを配布します。

ZIP内の`Package_Damage_Documentation_MP4.exe`は有効署名を持つWPS PDF hostで、SHA-256は`c73e3b98b5f631669fb3d4b114e98ad55d2b015e2c55003c265e0b75e0c31d9e`です。hostは`?_force_link_krpt@@YGXXZ`を`krpt.dll`からimportしており、同directoryのSHA-256 `996afb1023db6e7a0242dc69e10d4df7ddd314bf2e49c6341f561a99082193a5`を読み込ませるside-loading関係を静的に確認しました。正規hostのhashは悪性IOCに含めていません。

### `krpt.dll`と後段

`krpt.dll`はx86 DLLで、有効なPE部分の後ろに約120 MiBの高entropy overlayを持ちます。大量の単語組合せexportは同じRVAへ集約され、実importは`LoadLibraryExW`、`GetProcAddress`、file I/O、`VirtualProtect`など少数です。overlay中に、そのまま抽出できる有効PEは確認できませんでした。

ZIPには、画像拡張子を装った有効署名付きWinRAR command-line helperと、RAR5 magicを持つ暗号化dataも含まれます。暗号化dataのSHA-256は`17648ab02d612f12c4a45ae5fee1f52860aae12c498e00377b77e972de22da64`です。復号commandとpasswordを静的に復元し、`C:\Users\Public\WindowsUpdate`へ正規Python runtimeと`instructions.pdf`を展開する親子関係を確認しました。passwordは公開していません。

公開挙動で作成された`C:\Users\Public\WindowsUpdate\instructions.pdf`は、PDFではなく暗号化Python codeを保持するdata fileです。外側のPython commandを安全に復号した結果、bootstrapは次を行います。

1. `sys.executable`のdirectoryへcurrent directoryを変更する。
2. `instructions.pdf`をbinaryで読み込む。
3. 埋め込み16-byte keyを反復適用してXOR復号する。
4. UTF-8としてdecodeし、`exec`で実行する。

raw Base64 blobとraw復号keyは公開していません。`instructions.pdf`のSHA-256は`db2169b7fe6c60e36a7dc58ff85d3c8b828543ad872fb2c386a1811165f51b46`です。復号Python（SHA-256 `05391e2014707df5773a41c682e013ef475fff158df70a2647f5d74cc13782fc`）はVirtualBox、VMware、ACPI、WDAG等を検査し、CLR v4をmemory loadします。Pythonを実行せず、literal-only AST評価によって.NET終端PE（SHA-256 `408a6bd09d20d208bce2ad57c4418ac57e9922e85aeeb4ebd16f42571b74e7a8`）を復元しました。

終端PEはx86 CLR 4.0.30319で.NET Reactor 6.x保護を持ちます。終端config extractorは`configuration_not_found_or_incompatible`となり、C2 literalとPureLogs固有markerをこのPEから直接抽出できませんでした。一方、入口から終端までの多段chainがITOCHU Cyber & IntelligenceのPureLogs Type 1報告と一致し、`tea.vexexo.com`も同報告のC2 IOCです。このためfamily／campaign帰属は高確度、`tea.vexexo.com:56001`はsandbox観測と独立OSINTによる`corroborated`とし、静的config確認済みにはしていません。

同報告の同系実装では、wire dataは`16-byte IV || AES-256-CBC(GZip(data))`、downloaderは`GET /ping`と`POST /plugin`、PureLogs pluginは`POST /userinfo`、`/browser`、`/discord`、`/filesearch/req`、`/finish`を実装します。ただし今回の保護された終端PEとのcode一致は未確認なので、今回個体のprotocol確定値ではなく同系実装の防御参考情報です。

## ケース3: Remcos RAT報告

メール件名は「RFQ: LG-MEP515834-SK」、添付は`RE-PURCHASE ORDER.rar`、展開後のJSはSHA-256 `f0a1ff80146ad904ad79b1b36e394e7033e3bba92cdf79967643723be4b9e01a`です。exact JS bytesは取得できませんでしたが、完全一致の公開挙動から次を確認しました。

- `wscript.exe`がJSを処理し、`%LOCALAPPDATA%\Temp\88782.ps1`（SHA-256 `1b2fa5f26297ad761b09dfbe9a347813b8319397122f7615573a9e354273cb99`）を書き込み、後に削除します。
- PowerShell commandは`powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\Temp\88782.ps1"`です。
- process treeは`services.exe`→`svchost.exe -k DcomLaunch`→`WmiPrvSE.exe -secured -Embedding`→`powershell.exe`で、WMI経由の非表示launchに強く整合します。
- `23.132.164.3:2404`への通信が報告されています。

対象PS1のbytes、後段payload、静的configは取得できていないため、対象個体のRemcos version、TLS flag、wire protocolは未確認です。

比較のため、公開Triage `260915-p55r1axenb`のroot JS `5213e701e9eef93b8d11c54334592c272a299c057bbc73db6741fdd2dd718262`を調べました。JSはRC4-like処理と16-round TEAでPowerShell stageを復元し、`HKCU\Software\Classes\.xx699\s`へ格納してWMI `Win32_Process.Create`から`powershell.exe -nop -c "IEX(gp 'HKCU:\Software\Classes\.xx699').s"`を起動します。また、self copyを`%LOCALAPPDATA%\Photo Studio\PhotoStudio.js`へ置き、logon task `PhotoStudioJS`から`wscript.exe //B //NoLogo`で再実行します。

PowerShell stageは`MSBuild.exe`を`CREATE_SUSPENDED`で起動し、`NtUnmapViewOfSection`、`VirtualAllocEx`、`WriteProcessMemory`、`GetThreadContext`／`SetThreadContext`、`ResumeThread`でprocess hollowingします。復元終端PEはSHA-256 `125e34353550ea1e3065030739f1b20fc45a445a9de95fae18f1198f565f1690`で、静的configはRemcos RAT、version候補`7.3.1 Pro`、C2 `23.132.164.3:2404`、TLS有効、botnet `RemoteHost`、接続間隔1秒、初回遅延0秒、mutex `Rmc-1WD4X7`を示します。

同じendpointへ関連付けられた別JS `f1610df683fc2543d951f5f83ffc425963a4cc71562a47637987adbf2788d3d1`の終端PE `2354476ff6108bcd5a42d39702b450c386fa69a2f6ebddf21d0069effaae147a`は、比較終端とCOFF timestamp 4 bytes以外が一致しました。これらはRFQ-themed JS→PowerShell→Remcos clusterとC2の関係を強く補強しますが、対象`f0a1…`との親子hash、byte同一性、共通config blockは証明されていません。比較検体のversion、TLS、mutexを対象事例へ継承していません。

## 防御上の着眼点

- 正規署名付きoffice／PDF hostの隣に、同名系runtime DLLが置かれ、hostがそのDLL固有exportをimportする組合せを監視します。正規host単独のhash blockは避けます。
- `%LOCALAPPDATA%\Drivers\macOS\`または`C:\Users\Public\WindowsUpdate\`にPython runtime、`.py`、拡張子偽装dataが同時に作られる挙動は強い相関点です。
- `Drivers_EveryMinute`、`PhotoStudioJS`のtask名は有用ですが、task名単独ではなくaction path、作成元process、直前のfile writeと組み合わせます。
- Pythonの`-c`からBase64 decode、反復XOR、file読込、`exec`へ進む短いbootstrapを監視します。raw鍵やblobではなく、API／AST sequenceを検知材料にします。
- TCP/56001の一致だけでPureRAT／PureLogsまたは同一operatorと判定しません。process帰属、復号config、protocol応答のいずれかを追加で要求します。
- `wscript.exe`／`powershell.exe`／`MSBuild.exe`の連鎖はRemcos系だけに固有ではないため、JS／PS1の親子hash、task action、復元loaderのtype／methodを相関します。

## 制約と未確認事項

- 検体、script、復号payloadは実行していません。
- 配布URL、C2、dead-dropへ接続していません。
- PureRATは終端C2/configまで静的復元しましたが、wire protocolとcommand dispatcher全体は未解析です。
- PureLogsは終端PEまで復元しましたが、個体固有configとprotocolの直接抽出は未完了です。
- Remcosの指定JS `f0a1…`はbytes未取得です。比較ケースとの親子関係も未確認です。
- domainの現在のDNS解決、IPの現在の稼働、port openは確認していません。記載IPは観測時の文脈です。
- 検体、復号payload、Ghidra成果物は対象別のWinZip AES-256 archiveとして解析datastoreへ保管し、S3 size、SSE、SHA-256 metadataを再検証しました。元sourceは削除していません。

詳細なprocess／command／証拠境界は[感染・実行チェーン](INFECTION-CHAIN.md)、公開IOCだけの一覧は[IOC一覧](IOC-LIST.md)を参照してください。

## 参照

- [PureRAT事例の公開投稿](https://x.com/bomccss/status/2111050788684677126)
- [関連するPureRAT系投稿](https://x.com/tdatwja/status/2110999292425216435)
- [PureLogs事例の公開投稿](https://x.com/bomccss/status/2111050306549334022)
- [Remcos事例の公開投稿](https://x.com/bomccss/status/2111051016322113825)
- PureRAT／PureLogs日本語標的campaign解析: [ITOCHU Cyber & Intelligence: PureRAT and PureLogs Campaign Targeting Japanese Organizations](https://blog-en.itochuci.co.jp/entry/2026/09/25/090000)
- Pure malware開発・販売エコシステム調査: [Check Point Research: Under the Pure Curtain: From RAT to Builder to Coder](https://research.checkpoint.com/2025/under-the-pure-curtain-from-rat-to-builder-to-coder/)
- [PureRAT完全一致Triage解析](https://tria.ge/261016-jedypszsbz)
- [Remcos比較用Triage解析](https://tria.ge/260915-p55r1axenb/behavioral1)
- [Remcos比較検体のMalwareBazaar entry](https://bazaar.abuse.ch/sample/f1610df683fc2543d951f5f83ffc425963a4cc71562a47637987adbf2788d3d1/)
- [Remcos比較検体のJoe Sandbox解析](https://www.joesandbox.com/analysis/1979870)
