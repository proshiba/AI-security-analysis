# 感染・実行チェーン

## 読み方

この文書は、対象検体から直接確認した処理と、公開挙動で観測された処理、比較ケースだけで確認した処理を分離します。

- `confirmed`: 対象bytes、復号script、PE構造、完全一致sandbox成果物から直接確認。
- `corroborated`: 対象報告と独立証拠が整合するが、終端payload／configからは未確認。
- `unconfirmed`: 対象検体に結び付くbytesまたは親子edgeがない。

## ケース1: PureRAT（高確度）

### チェーン

```text
メール「使用できない商品の対応手順について」
  └─ share.google（汎用共有サービス、IOC対象外）
      └─ get-file.thuthukafs.co.nz（配布）
          └─ Complete_Product_Condition_Review_mp4_4f8a1b63.zip
              ├─ Complete_Product_Condition_Review_mp4_4f8a1b63.exe（正規WinWord host）
              └─ msvcr100.dll（悪性side-load DLL）
                  └─ runtime／custom archiveの復号・展開
                      ├─ %LOCALAPPDATA%\Drivers\run.vbs
                      └─ %LOCALAPPDATA%\Drivers\macOS\
                          ├─ python.exe
                          ├─ run.py
                          └─ 13681.bin
                              └─ 単一byte反復XOR→Donut shellcode
                                  └─ .NET loader 172be461…
                                      └─ TripleDES-CBC→GZip
                                          └─ 終端PE 9f201e04…
```

ZIP、正規host、悪性DLL、`run.py`、`13681.bin`、Donut内loader、終端PEのhashと親子変換は静的確認済みです。`n69x8r5.py`は同じ`LABZ` archiveに同梱され、Python runtimeを`Drivers\macOS`へ展開します。正規hostは必要なMSVCR100 exportsをすべて悪性DLLから解決できると確認できず、公開sandboxもDLLを`regsvr32 /s`で直接起動したため、double-clickからの自然なside-loading成立は未確認です。

### processとcommand

公開挙動と復号済み`run.py`から、次のprocess／commandを確認しました。`<USER>`と`<RANDOM>`は環境依存値です。

```text
公開sandbox:
regsvr32.exe /s "<BUNDLE>\msvcr100.dll"
  └─ Python runtime展開
      ├─ "%LOCALAPPDATA%\Drivers\macOS\python.exe" "%LOCALAPPDATA%\Drivers\macOS\run.py"
      └─ cmd.exe /c "schtasks /Create /TN "Drivers_EveryMinute" /XML "%TEMP%\tmp<RANDOM>.xml" /F"
```

task actionは次の構造です。

```text
wscript.exe "%LOCALAPPDATA%\Drivers\run.vbs"
  └─ Win32_Processでpython.exeを照会
      └─ 未起動の場合のみ:
         "%LOCALAPPDATA%\Drivers\macOS\python.exe" "%LOCALAPPDATA%\Drivers\macOS\run.py"
```

task XMLの主要設定は次のとおりです。

| 項目 | 値 | 証拠水準 |
|---|---|---|
| task名 | `Drivers_EveryMinute` | confirmed |
| trigger | `2025-01-01T00:00:00`開始、`PT1M`反復 | confirmed |
| duration | `P9999DT23H59M59S` | confirmed |
| logon／権限 | `InteractiveToken`／`LeastPrivilege` | confirmed |
| 多重起動 | `IgnoreNew` | confirmed |
| 実行時間上限 | `PT0S` | confirmed |
| action | `wscript.exe`＋`run.vbs` | confirmed |

`run.py`は永続化作成とblob実行を別threadで並行実行します。blob側は32-bit architectureを確認し、実行可能memoryへ復号bytesをcopyして呼び出します。復号bytesはDonutで、.NET loaderを経て終端PEまで静的復元しました。wire protocolと受信command／reply形式は未解析です。

終端configはhost `trump.sharevideocenter.com`、ports `56001/56002/56003`、campaign `Default`、version候補`4.4.1`、install environment `APPDATA`、mutex `purecrack-default`、Subject／Issuer `CN=PureRAT Agent`の埋込みcertificateを保持します。現行strict detectorは、空のscheduled-task field 7がprotobufから省略されているためfamily gateを拒否しますが、configとC2の復元自体は成功しています。

### 通信

| endpoint | 評価 | 根拠 | 未確認点 |
|---|---|---|---|
| `trump.sharevideocenter.com:56001` | 静的確認済み＋動的補強 | 終端config、exact公開sandboxでTLS接続 | wire protocol |
| `trump.sharevideocenter.com:56002` | 静的確認済み | 終端config | 今回runでの通信、wire protocol |
| `trump.sharevideocenter.com:56003` | 静的確認済み | 終端config | 今回runでの通信、wire protocol |
| `82.47.180.159:56001` | 補強済み | 観測時のdomain解決先とprocess帰属通信 | 現在のDNS、現在の稼働、protocol応答 |

## ケース2: PureLogs（高確度）

### チェーン

```text
メール「商品の破損について返金対応を希望します」
  └─ share.google（汎用共有サービス、IOC対象外）
      └─ get-file.gilmorebrown.co.nz（配布）
          └─ Package_Damage_Documentation_MP4.zip
              ├─ Package_Damage_Documentation_MP4.exe（正規WPS PDF host）
              ├─ krpt.dll（悪性side-load DLL）
              ├─ 画像拡張子を装った正規RAR helper
              └─ 暗号化RAR5 data（復号command／passwordを静的確認）
                  └─ C:\Users\Public\WindowsUpdate\
                      ├─ svchost.exe（Python runtime）
                      └─ instructions.pdf（暗号化Python code）
                          └─ 反復XOR→復号Python 05391e20…
                              └─ literal-only AST復号
                                  └─ .NET終端PE 408a6bd0…
```

正規hostが`krpt.dll`固有exportをimportするため、side-loading edgeは静的確認済みです。`krpt.dll`は偽PDF末尾からRC4 materialを取得してcommandを復号し、署名付きWinRAR CLIでRAR5 dataを展開します。RAR password、RC4／XOR keyは公開していません。

### processとcommand

公開挙動で観測された外側commandは次の構造です。raw Base64 bootstrap、raw復号key、末尾の実行識別子は公開していません。

```text
C:\Users\Public\WindowsUpdate\svchost.exe -c "exec(__import__('base64').b64decode(<REDACTED_BOOTSTRAP>).decode())" <REDACTED_ARGUMENT>
```

Base64を安全にdecodeして得たbootstrapの処理は次のとおりです。

```text
chdir(dirname(abspath(sys.executable)))
  └─ open("instructions.pdf", "rb").read()
      └─ 埋め込み16-byte keyを反復してXOR
          └─ decode("utf-8")
              └─ exec(...)
```

復号PythonはVirtualBox、VMware、ACPI、WDAG等を検査してCLR v4をmemory loadします。Python自体は実行せず、literal-only AST評価で.NET終端PEを復元しました。終端は.NET Reactor 6.x保護され、config extractorは`configuration_not_found_or_incompatible`となったため、今回個体のC2登録、tasking、exfiltration schemaは未確認です。

ITOCHUが解析した同系PureLogs Type 1は、`16-byte IV || AES-256-CBC(GZip(data))`のwire形式、downloaderの`GET /ping`／`POST /plugin`、pluginの`POST /userinfo`、`/browser`、`/discord`、`/filesearch/req`、`/finish`を実装します。今回終端とのcode一致は未確認なので、同系実装の参考情報として分離しています。

### 通信

| endpoint | 評価 | 根拠 | 未確認点 |
|---|---|---|---|
| `tea.vexexo.com:56001` | corroborated | 指定事例のprocess通信観測 | `instructions.pdf`平文中のconfig、wire protocol |
| `185.139.214.102:56001` | corroborated | 観測時のdomain解決先として提供 | 現在のDNS、現在の稼働、protocol応答 |

## ケース3: Remcos RAT報告

### 指定事例で確認できた範囲

```text
メール「RFQ: LG-MEP515834-SK」
  └─ RE-PURCHASE ORDER.rar
      └─ RE-PURCHASE ORDER.js（f0a1…）
          └─ %LOCALAPPDATA%\Temp\88782.ps1
              └─ 後段未取得
```

JS hash、PowerShell file write、C2は完全一致の公開挙動情報です。exact JS bytesは取得できませんでしたが、次のPowerShell起動commandとWMI process treeを確認しました。

```text
powershell.exe -NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "%LOCALAPPDATA%\Temp\88782.ps1"

services.exe
  └─ svchost.exe -k DcomLaunch
      └─ WmiPrvSE.exe -secured -Embedding
          └─ powershell.exe ... -File "%LOCALAPPDATA%\Temp\88782.ps1"
```

`88782.ps1`のSHA-256は`1b2fa5f26297ad761b09dfbe9a347813b8319397122f7615573a9e354273cb99`です。PS1 bytesと後段を取得できていないため、対象個体の復号方式、Remcos config、wire protocolは未確認です。

### 比較ケースでのみ確認した範囲

以下は同一endpointと関連付けられた別JSから静的復元したchainで、指定JS `f0a1…`のchainではありません。

```text
別JS 5213e701…
  ├─ RC4-like＋16-round TEA→PowerShell stage d9ddee55…
  ├─ HKCU\Software\Classes\.xx699\sへPowerShellを格納
  ├─ WMI Win32_Process.Create→powershell.exe -nop -c "IEX(gp ...).s"
  ├─ PhotoStudioJS scheduled task→wscript.exe //B //NoLogo
  └─ PowerShell／.NET loader
      └─ MSBuild.exeをprocess hollowing
          └─ terminal PE 125e3435…
```

終端PE `125e34353550ea1e3065030739f1b20fc45a445a9de95fae18f1198f565f1690`の静的configは、Remcos RAT、version候補`7.3.1 Pro`、C2 `23.132.164.3:2404`、TLS有効、botnet `RemoteHost`、接続間隔1秒、初回遅延0秒、mutex `Rmc-1WD4X7`を示します。別JS `f1610df6…`の終端`2354476f…`はこの終端とCOFF timestamp 4 bytes以外が一致しました。ただし、指定JSとのbyte同一性、親子hash、共通復号key、共通config blockは確認できません。

### 通信

| endpoint | 評価 | 根拠 | 未確認点 |
|---|---|---|---|
| `23.132.164.3:2404` | corroborated | 指定事例の観測値と別ケースの関連情報が一致 | 指定JS／終端payloadの静的config、Remcos handshake、現在の稼働 |

## 横断比較

| 特徴 | PureRAT | PureLogs | Remcos指定事例 |
|---|---|---|---|
| 入口 | ZIP内正規host＋DLL | ZIP内正規host＋DLL | RAR内JS |
| 初期実行 | sandboxでは`regsvr32 /s`。自然なside-loadingは未確認 | DLL side-loading | `wscript.exe`、WMI経由PowerShell |
| runtime | 同梱Python | 同梱Python | PowerShell、比較例では.NET loader |
| 永続化 | `Drivers_EveryMinute` | active経路は未確認 | 指定事例では未確認。比較例のみ`PhotoStudioJS` |
| memory実行 | Python→Donut→.NET終端 | Python→CLR memory load | 比較例では`MSBuild.exe`へのprocess hollowing |
| C2 port | 56001/56002/56003 | 56001（補強済み） | 2404（補強済み） |
| protocol | config確認、wire未解析 | 同系OSINTあり、今回個体は未確認 | 指定検体では未確認 |

TCP/56001の共有だけでは、PureRATとPureLogsの同一性、operator共有、protocol互換性を立証できません。PureRATは終端configまで復元済みです。PureLogsは保護された終端のconfig／通信routine、Remcos指定事例は対象bytesと後段が次の未解決点です。
