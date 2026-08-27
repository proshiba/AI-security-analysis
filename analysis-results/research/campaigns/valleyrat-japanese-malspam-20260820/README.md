# ValleyRAT日本語マルスパム比較（2026-08-20〜2026-08-24）

## 結論

3件はいずれも、ZIPからIMGを開かせ、IMG内の正規EXEに同梱DLLをside-loadさせるValleyRAT配布です。ClickFixの特徴である偽CAPTCHA、クリップボードへのコマンド格納、ユーザーによる`Win+R`／PowerShell実行は確認できません。本集合は「ClickFix」ではなく「ZIP→IMG→DLL side-loading」です。

悪性挙動は同一ではありません。1件目は`ms-settings`／`ComputerDefaults.exe`によるUAC bypass後に`NvDLISR.NVX.exe`を起動し、2件目は`OpenraVPN`を装ったディレクトリへ正規hostと悪性`vulkan-1.dll`を配置します。3件目は`MSOCF.dll`内の暗号化stageをmemory実行し、`svchostsr.exe`、Run key、driverを展開します。メール言語とfamily名だけを根拠に単一actorとは断定しません。

| ケース | 入口／side-load | 主な悪性プロセス | 永続化・昇格 | 実観測C2 | 後段 |
|---|---|---|---|---|---|
| 1 請求書 | `CIT-Number.20260824112143.EXE`＋`nW_Elf.dLL` | `ComputerDefaults.exe`→`NvDLISR.NVX.exe`＋CMD watchdog | `ms-settings` UAC bypass | `121.127.253.206:8856/8868` | x86 PE `4df8bda2…733e2` |
| 2 情報更新 | `2026081829618475_setup.exe`＋`vulkan-1.dll` | `Loader.exe --summary`→`cmd.exe`→`Loader.exe --portability` | HKLM Run `ServiceController` | `170.62.130.47:449` | x64 PE `807361fe…168e` |
| 3 見積・取引 | `20260824.EXE`＋`MSOCF.dll` | `20260824.exe`→`svchostsr.exe`、driver load | HKCU Run `Microsoft Office`、service | `202.61.140.222:448` | raw stage `c77c885c…dbf0`＋C2 stage |

## 個別マルウェア解析

悪性DLLを主キーにしたcanonicalケースを`analysis-results/malware/valleyrat`へ登録しています。3件目の3 DLLはcode／復号stageが同一でも、resource／overlay差分を個別に追跡できるよう別ケースにしています。

- 1件目 `nW_Elf.dLL`: [da33a95b…be066](../../../malware/valleyrat/versions/unknown/cases/da33a95b2ed28e2c50da002584eb81e4e94fe4a55e98945146842ed9e23be066/README.md)
- 2件目 `vulkan-1.dll`: [22d1b557…67f](../../../malware/valleyrat/versions/unknown/cases/22d1b5576ccb3c425a94e405076a0665efa0dd2d59325bfb561b6b16969e267f/README.md)
- 3件目 `MSOCF.dll` resource増量: [041a0aeb…3b51](../../../malware/valleyrat/versions/unknown/cases/041a0aeb76e63f67abb258036b089e27174074c5367d7c7a2a644e3bf9dd3b51/README.md)
- 3件目 `MSOCF.dll` overlay増量: [04c9eae9…a81f](../../../malware/valleyrat/versions/unknown/cases/04c9eae9f19a63e4a84da108fe6b768ab6e558c89126dbb6c35a0c383739a81f/README.md)
- 3件目 `MSOCF.dll` 基準size: [ad755d2d…57ab](../../../malware/valleyrat/versions/unknown/cases/ad755d2dfeaa23b80d561656848d12d8e66edd99b1169d63a936fe7b01da57ab/README.md)

## 確認水準

- 「実観測」は取得済み公開sandbox reportまたはPCAPから確認した事実です。
- 「静的確認」はPE構造、復号器、Ghidra逆コンパイルから確認したコード能力です。
- 「推定」は証拠と整合するものの、この観測中の実行までは証明できない事項です。
- 検体、復号stage、取得stageはローカルで実行していません。C2への能動接続やコマンド送信も行っていません。

## 主要な静的解析結果

### 1件目: nW_Elf.dLL／Winos `ca00`

`nW_Elf.dLL`はx86のChrome ELF互換exportを持つ大容量・高entropy DLLです。正規hostは`GetInstallDetailsPayload`等をimportするため、DLL search orderで悪性DLLが読み込まれます。外層は強くvirtualize／packされ、FLOSSは4分超で出力を返さなかったため打ち切りました。

8856/TCPのPCAPを10-byte session header依存XORで復号し、338,962-byteのcommand `0x01` frameから334,848-byteのx86 PEを復元しました。SHA-256は`4df8bda2718afbd6ee42a96e0097d24592e451a1c6a05d9bffa8921c683733e2`、exportは`run`です。Ghidraでは次を確認しました。

- `run`からthreadを作成し、controller loopへ移行する。
- `SeDebugPrivilege`、`SeLoadDriverPrivilege`、`SeTcbPrivilege`等を有効化しようとする。
- 自身をhidden／system／read-onlyへ変更する。
- `svchost.exe`を作成し、`OpenProcess`、`VirtualAllocEx`、`WriteProcessMemory`、`CreateRemoteThread`またはthread context変更でcodeを注入する能力を持つ。
- C2から渡されたpath／command lineを`CreateProcessW`で起動する能力を持つ。
- screenshot、clipboard、key state、process／drive列挙、registry操作、event log消去、shutdown等のremote administration能力を持つ。

コード中の`192.168.1.200:6669/9999`はprivate development／fallback値と評価し、通信IOCには採用しません。

### 2件目: vulkan-1.dll／Winos `ca01`

`vulkan-1.dll`はx64 DLLで、`vkEnumerateInstanceVersion`から主処理へ入り、`DllMain`でconsoleを隠します。静的文字列と逆コンパイルでは、`ip-api.com`への`GET /json/`、`avp.exe`確認、`OpenraVPN`配下へのfile copy、firewall rule、Run key、`--summary`／`--portability`／`-onlyctrl`／`-reonlyctrl`のmode切替を確認しました。

このcampaignのWinos frameはheader末尾が`ca01`で、payload全体を固定値`0xCC`でXORします。PCAPから301,860-byteのcommand `0x01` frameを復号し、offset 4,374から297,472-byteのx64 PEを復元しました。SHA-256は`807361fe1ff663ff3716a7e667e964f9d8fd15a20766bd2796bd46b1f67e168e`、entry RVAは`0x18c7c`、imphashは`c0a26bd617201b9f9917177a3a03c4af`、exportは`run`です。

復元PEはprocess creation／injection API、drive・process列挙、screenshot、registry、networkの広い能力をimportします。PCAPではstage取得後にclient registration、registration完了、heartbeat／status、`Program Manager`等の状態報告を確認しましたが、serverからの操作commandは確認できませんでした。

設定情報には`170.62.130.47:443`もありますが、取得済みreportとPCAPで実際に観測した接続は`170.62.130.47:449`だけです。443は「静的設定・未観測」として区別します。

### 3件目: MSOCF.dll 3変種

3つの`MSOCF.dll`はimphash `fc1d45e2b662c656e1a56e88c9fc63e6`、`.text` SHA-256 `54fccae925318cddeac08a5aacac618e60b9cea9a8ae98110f37eb353e2a0862`、54 exports、暗号化blob、1,000-byte keyが一致します。RC4復号後に各byteを`0xFF`でXORすると、3つすべてから同一2,381-byte stageが得られます。

| MSOCF SHA-256 | 対応IMG | size | 差分 |
|---|---|---:|---|
| `041a0aeb76e63f67abb258036b089e27174074c5367d7c7a2a644e3bf9dd3b51` | `b326409c…d3bf` | 950,784 | resource増量 |
| `04c9eae9f19a63e4a84da108fe6b768ab6e558c89126dbb6c35a0c383739a81f` | `8b141a7c…65ff` | 2,377,389 | 2,250,925-byte高entropy overlay |
| `ad755d2dfeaa23b80d561656848d12d8e66edd99b1169d63a936fe7b01da57ab` | `810e5310…5cca` | 126,464 | 基準size |

overlayはentropy 7.9999で、有効な埋め込みPE／archive magicは確認できません。したがって3つは別機能buildではなく、resource／overlayでhashを変えた同一loaderの多型化と評価します。配布ミスの可能性は完全には排除できませんが、機能差を示す証拠はありません。

復元stage SHA-256は`c77c885cae806025691827fa44ad1e40cdb737713473979212e0c986ceafdbf0`です。API hash resolverを持ち、configのprimary／secondary slotはいずれも`202.61.140.222:448`、TCP選択flagは`1`でした。TCP routineは接続後に正確に`39 39 00`（ASCII `99\0`）を送信し、14-byte headerを除いて受信stageを`0xCC`でXORしてmemory実行します。PCAPの最初のclient payloadも`393900`と一致しました。UDP routineも存在しますが、このconfigでは選択されません。

`kvckiller.sys`のdrop／load、`SeLoadDriverPrivilege`／`SeDebugPrivilege`使用、`svchostsr.exe`の永続化は、security product停止を目的とするBYOVD chainと整合します。ただしdriver内部の対象製品・IOCTLまでは独立に逆解析していないため、この目的評価は中確度です。

## 3 branchの通信契約比較

| branch | exact後段／dispatcher | frame・cipher | 静的に確認した範囲 | 未解決範囲 |
|---|---|---|---|---|
| 1 `nW_Elf` CA00 x86 | `4df8bda2…733e2`／`FUN_100108b6` | `uint32le total + 10-byte header + payload`、`rolling_header_plus_0x36`、suffix `CA00` | server→client `00`〜`14`,`64`,`65`,`C9`,`CA`の長さ・最小構造分類 | CA00 parserのwire cap、operation result serializer、実reply body |
| 2 Vulkan CA01 x64 | `807361fe…168e`／`FUN_18000f6a0` | 同じframe、固定`0xCC` XOR、suffix `CA01` | server→client `00`〜`13`,`64`,`65`,`C9`,`CA`。CA00とのID意味差とunchecked-copy risk | 32 MiBはoffline防御capのみ。operation result serializer、実reply body |
| 3 MSOCF raw bootstrap | `c77c885c…dbf0` raw shellcode | client `39 39 00`（ASCII `99\0`）、serverは14-byte prefix＋固定`0xCC` XOR stage | TCP選択、固定要求、stage受信・復号shape。UDP fallbackは静的能力のみ | 受信stage以降のcommand dispatcherとoperation result schema |

`CA01` suffixだけではcipherを判定できません。2件目はfixed XORですが、別キャンペーンのNVML `39b206…`／`024ab2…`／`9ad36b…`は同じ`CA01`でrolling方式です。必ずroot lineage、sample SHA-256、Ghidra selector、dispatcher、suffix、cipherをexact profileとして束縛します。

MSOCF 3 DLLは同じ`99\0` raw bootstrapを共有しますが、これはCA00／CA01 command frameでも、NVML predecessorの`33 32 00`（ASCII `32\0`）transportでもありません。今回復元したCA00、CA01、NVML bootstrap／主制御／remote desktopのdispatcher契約をMSOCFへ一般化しません。

公開するoffline結果はcommand ID、role、方向、長さ、最小構造、SHA-256へ限定します。復号本文、被害端末情報、鍵、画面、clipboard、入力、operation resultは公開せず、socket接続、payload実行、OS作用、reply wire生成を行いません。今回の追解析でも検体や追加payloadを実行せず、live C2へ接続していません。

## 相関評価

1件目と2件目は、stage channelでcommand `0x04`→`0x05`、server応答`0x04`→`0x01`、control channelで`0x06`登録、`0xCA`完了、`0xC9` heartbeatを使う同じWinos系統です。一方、XOR mode、architecture、外層proxy、永続化、C2 infrastructureは異なります。

3件目は小型RC4＋XOR loaderと`99\0` bootstrapで、外層protocolが異なります。ただしsandbox family判定、復元後段の遠隔操作能力、drive／process discovery、driver／process injection挙動はValleyRAT chainと整合します。以上から「同familyの複数配布branch」と評価し、「同一operator」とは断定しません。

## 参照

- [1件目の公開投稿](https://x.com/bomccss/status/2091823024131711072)／[Triage](https://tria.ge/260824-k3a3dsz1ds)
- [2件目の公開投稿](https://x.com/bomccss/status/2091822824076021954)／[Triage](https://tria.ge/260820-swclmsep5z)
- [3件目の公開投稿](https://x.com/bomccss/status/2091722745038221561)／[Triage](https://tria.ge/260824-crsjascl4v/behavioral1)

詳細なprocess tree、command line、registry値、最終通信は[INFECTION-CHAIN.md](INFECTION-CHAIN.md)、IOCは[IOC-LIST.md](IOC-LIST.md)を参照してください。
