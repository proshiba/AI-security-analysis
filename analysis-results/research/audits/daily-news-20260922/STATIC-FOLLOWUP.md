# 2026-09-22 ニュース検体の追加静的解析

## 判定と対象

本記録は日次ニュース経由の3検体を、実行・CLRロード・Node実行・外部通信をせずに追加調査した結果である。既存の日次ニュース成果物は昇格・上書きしていない。MSIの内包層と2つの単独PEの関係は、MSIの `File` / `Component` / `Directory` / `CustomAction` / `Media` テーブル、CABメンバーのSHA-256、および.NETのCIL本文で確認した。

| 種別 | SHA-256 | 静的に確認した役割 |
| --- | --- | --- |
| 親MSI | `20a9e297220fe4cb9f939eaa82582c6e9a8f6dd4424635206dec08fa1986b8fa` | Windows Installer。CABを1つ内包 |
| 内包CAB | `13dcee0e6f00c3f8b127f31dca36510c7d165315e8be9acf89937a4d5f9c3f87` | 2,294ファイル、169フォルダーのMSZIP CAB |
| `ProfileQuickHost.exe` | `9fa80577b8b3cb9c3062e5e1986cc9fe0c26eed023f7d430dfa5c60169c15c45` | `WinAgentLauncher.Main` によるNodeエージェント起動補助 |
| `SearchTrustedRuntimeSvc.exe` | `7969ccaf1db750bc3b02d51626d6916ecbd0c0cf2f7de3c7bc0be240f5f2978d` | `CaptureScreen.Main` による画面取得補助 |

後ろの2件は、親MSIのCABにあるそれぞれ `filAAA9A9A440568A239366D8AD393C4731` と `fil9B3D87E2554C23B515EB594359A6A8F2` の内容とSHA-256が一致する。したがって独立した別ファミリーの根拠はなく、同じ配布物の補助コンポーネントである。ただし、公知のマルウェアファミリー名への帰属はこの証拠だけでは確定しない。現時点の分類は「ファミリー未確定のNode.jsベース遠隔操作エージェント」であり、C2稼働や実際の指令受信も未確認である。

## インストール後のプロセス・永続化挙動

MSI表は `File` 2,294/2,294、`CustomAction` 2/2、`InstallExecuteSequence` 21件、`Media` 1件を行数切り捨てなしで読み取った。`Media.Cabinet` は `#cab1.cab`、最終シーケンスは2,294である。2つのカスタムアクションは次の順序で定義されている。これはコード上の実行予定であり、この調査で実際に起動したプロセスではない。

1. `ScatterInstall`（Type `98`、実行シーケンス `6601`）：`powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "[INSTALLFOLDER]\._scatter.ps1" -AnchorDir "[INSTALLFOLDER]"`
2. `StartAgent`（Type `98`、実行シーケンス `6602`）：`wscript.exe //B "[INSTALLFOLDER]\._agent.vbs"`

`._scatter.ps1`（SHA-256 `62ddf451cc096ae70f46b1ce046ef1518ceff4ae9c9d6ce0b7caee904a07b794`）は `install-meta.json` を読み、Node実行環境、アプリ、設定、補助ツールを別々のユーザープロファイル配下へ移動する。平文の `config.json` を削除し、非表示起動用 `._agent.vbs` を書き直す。メタデータには、アンカーが `%LOCALAPPDATA%\Microsoft\Windows\Themes\SharedSecureHelper30`、ランタイムが `%LOCALAPPDATA%\Microsoft\Windows\Libraries\QuickSystemSearch`、アプリが `%APPDATA%\Microsoft\Windows\Themes\SettingsHostStandard58`、設定が `%LOCALAPPDATA%\Microsoft\Windows\INetCache\FilterManager`、補助ツールが `%LOCALAPPDATA%\Microsoft\Windows\Shell\RemoteTempPrimary` と記録されている。これらは設定値から推定される配置先であり、実ファイル作成を観測したものではない。

`._agent.vbs`（SHA-256 `cebadf07237d51a11dc559519c0fbf44818705bf7be0f27b1dafccc08ca5302f`）は `node.exe` と `app\src\index.js` が存在すれば `WScript.Shell.Run` のウィンドウ非表示指定で起動し、なければ `ProfileQuickHost.exe` を起動する。後者の.NET `Main`（CIL命令132件）は `node.exe` と `app\src\index.js` を連結して `ProcessStartInfo` を作り、作業ディレクトリ、シェル不使用、非表示ウィンドウを設定して `Process.Start` する。引数 `--uninstall` の場合に終了を待って終了コードを返す分岐もCILで確認した。もう1件の.NET `CaptureScreen.Main`（CIL命令94件）は `SystemInformation.VirtualScreen`、`Bitmap`、`Graphics.CopyFromScreen`、`Image.Save`、`ImageFormat.Png` を使い、引数の出力パスへ画面全体をPNG保存する構造である。両PEとも2/2メソッド本体の静的パースに成功し、CLRのロードや実行はしていない。

Node側 `install.js`（SHA-256 `3608003cb5f6f819c2f1952fed789191fc268f270ca7f501f058acada4b3a245`）は `StreamServiceSharedBridge.ps1`（SHA-256 `eabdcb1881a6b2e2ac5ff6818a836614c80e7cde7370509e4bf3f658a71adb23`）を非表示のPowerShellで呼ぶ。後者はログオン時の隠しスケジュールタスク `ComponentTask33Agent` を登録し、失敗時には `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` を使うコードである。これは静的な到達可能性であり、実際の登録は観測していない。

## 設定・C2通信の静的根拠

`install-meta.json`（SHA-256 `09f2993b4c4fc016b0b70d5ffe9b2000f7ab1aa5d5ad7a5870b33169c991afbc`）の `buildSeed` を鍵に、`HiddenVirtualSilentLoader.dat`（SHA-256 `601a84adaa7100f10060f1e8432d5a1981491cef944aa8212fab87bcb11dfcfc`）をBase64復号し、`configPack.js`（SHA-256 `af0827dc65b82fbd1dbdeba79612ab6c114c6223fede001a94d69001fb879c1f`）に実装された繰り返し鍵XORを逆適用してJSONを確認した。復号は隔離したメモリ上の静的バイト操作だけで行い、認証トークンの値とハッシュは公開しない。復元された通信関連値は次のとおり。

| 設定項目 | 復元値 | 解釈上の限界 |
| --- | --- | --- |
| `panelUrl` | `ws://shift-api-control.com:3847` | 設定上のフォールバック候補。疎通・稼働未確認 |
| `contractDiscovery.address` | `0xf9099d0d747368cce8C10226CC9AF2bFD4DDbCF4` | Polygon上の取得先として設定。実際の返却URL未取得 |
| `contractDiscovery.rpcUrl` / `chainId` | `https://polygon-bor.publicnode.com` / `137` | 設定値。今回RPCへ通信していない |
| `heartbeatIntervalMs` / `reconnectDelayMs` | `720000` / `15000` | 実行時には12分間隔／15秒後再接続を意図 |
| `cacheTtlMs` | `300000` | コントラクト返却URLの5分キャッシュを意図 |

`contractDiscovery.js`（SHA-256 `c0a9a628d4809e600c2d0253badb8fc30b600d1fb5250c8376b218595c1520d2`）はPolygon RPCへ `eth_call`、コントラクトセレクタ `0x4ab7874e`、ブロック `latest` を指定し、返却されたABI文字列をWebSocket URLへ正規化するコードである。取得失敗時は設定の `panelUrl` へフォールバックする。`app\src\index.js`（SHA-256 `70634eb46af74faa0a624a3e77c1dda3386d4d82f72dc6fd92236f5ccf37737d`）は `X-Agent-Token` ヘッダー付きWebSocketを生成し、接続時に `register`、その直後と所定間隔で `heartbeat` を送る。受信は `ping`、`shell`、`command` を分岐し、応答は `pong`、`command_result`、条件付き `wallet_report` である。`config.js` は登録情報としてホスト名、ユーザー名、OS、CPU、メモリ、ローカルIP、ドメイン参加状態、MachineGuid由来IDなどを組み立てる。

`commands.js`（SHA-256 `6cdcb7065e4e01954fbd244f9247b5b3eb33bec969ab139564c152fe4163d1a5`）には `powershell`、`cmd`、`eval`、`download_run`、`deploy`、`files`、`screenshot`、`load_script`、`reconnect`、`kill`、`wallet_scan`、`agent_update`、`capabilities` の分岐がある。さらに `remoteScript.js`（SHA-256 `744aa3ac588e607d3cd8c7680e7730a1ce9e080b29f9ab44a0ad2ec286cc6c11`）は接続先の `/api/agent/script` をトークン付きHTTP GETで取得し、Nodeの `vm.runInNewContext` でロードする実装である。今回そのリモートスクリプトは取得も実行もしていないため、追加コマンドや実際のC2指令内容は不明である。

## 完了範囲と保留事項

CABは宣言2,294メンバーを全件照合したが、後段解析へ保持した高価値層は上限128件で、候補集合は未完である。多数のCABメンバー名はMSIの `File` キーであり拡張子を持たないため、内容判定とMSI表の対応が必要だった。完全一致の共有extentは136件、部分重複は0件であり、完全一致のみ許す検証と大規模CABの選択保持を追加した。全件の終端解析、動的URL、リモートスクリプト、C2稼働、攻撃者からの実指令は確認できていない。ファミリー確定と通信先の稼働確認には追加証拠が必要である。

元の暗号化source ZIPと追加調査用のMSI・MSI表棚卸し結果は、解析対象単位のWinZip AES-256 archiveとしてS3のサイズ・SSE-S3・SHA-256 metadata照合を済ませた。検体本体、復号済み認証値、S3 upload receipt、raw payloadは本リポジトリへ含めていない。
