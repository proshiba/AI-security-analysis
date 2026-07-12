# ValleyRAT case: b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c

## 1. 概要と判定

| 項目 | 内容 |
|---|---|
| Malware type | ValleyRAT |
| Campaign / chain type | `msi_embedded_cab_custom_actions` |
| 提出ZIP SHA-256 | `b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c` |
| MSI SHA-256 | `ee1f25b74bc40c30ef3dac839257e6e75c3ef5e84e6c8b464f1984943132f166` |
| 判定信頼度 | 高。MSI/CAB構造、PE import関係、process帰属付き通信の一致 |
| ローカルでの検体実行 | なし |
| ライブC2接続 | なし |

感染チェーン:

```text
LetsVPN.zip
  └─ KL-X86Gicasc.msi
       └─ embedded CAB
            ├─ latst.exe             (正規LetsVPN installer/decoy)
            ├─ mesedge.exe           (署名付きsideload host)
            └─ cef_frame.dll         (protected ValleyRAT loader)
                 └─ export TbsAppInstance
                      └─ www.tq8j.com:443 / 103.45.64.246:443
```

## 2. ファイルIOC

| Role | File/object | Size | SHA-256 | 特徴 |
|---|---|---:|---|---|
| Submitted ZIP | `LetsVPN.zip` | 29,191,779 | `b433ecdf855beaaf91d57522eebe9c9e1c3fc756f711bd79ac1b3ecf6c75016c` | 内側にMSI 1件 |
| MSI | `KL-X86Gicasc.msi` | 30,135,808 | `ee1f25b74bc40c30ef3dac839257e6e75c3ef5e84e6c8b464f1984943132f166` | OLE 61 streams、CAB 1、PE streams 2 |
| Embedded CAB | OLE CAB stream | 28,470,946 | `353a58f77f2b1f85dc5a439708f153f37d94d1cb7c3fc8f830c3e11599e62d4c` | 3 payloads |
| Malicious loader | `cef_frame.dll` | 11,390,976 | `8ebc92ac9ddf6b7757b28cde9357a8e8e045125fa150a3bfc65932854132e157` | protected/high entropy、export `TbsAppInstance` |
| Sideload host | `mesedge.exe` | 20,072 | `10e990bbbda70da62c668908d0dbb4c9b21ffe95f186795c3a5ae98b5d302881` | `cef_frame.dll!TbsAppInstance`をimport、Tencent署名 |
| Decoy installer | `latst.exe` | 17,488,792 | `796640f54bdad0f8a77fdde41ef8d15bde06cc5e1d6920159ebd8ab06a0e4bc9` | LetsGo Network署名。単体で悪性判定しない |
| MSI custom-action PE | OLE PE stream | 736,368 | `066c52ed8ebf63a33ab8290b7c58d0c13f79c14faa8bf12b1b41f643d3ebe281` | installer/custom action exports |
| MSI task PE | OLE PE stream | 211,056 | `ee42c70ed98ef30a312ba31a4e2c30d400bfba3419f6fd3409d1857d73f804a9` | exports `DeleteTasks`, `ProcessTasks`, `ScheduleTasks`, `UninstallTasks` |

DefenderによりMSI直接読み取りが遮断されたため、hashとstream解析は内側ZIPからメモリ上で実施した。

## 3. C2・通信IOC

| 種別 | 値 | Process | 信頼度 | 根拠 |
|---|---|---|---|---|
| C2 domain | `www.tq8j.com` | `mesedge.exe` PID 2068 | 高 | DNSがsideload hostへ帰属、複数回観測 |
| C2 endpoint | `103.45.64.246:443/TCP` | `mesedge.exe` PID 2068 | 高 | 同domain解決後に反復TCP接続 |
| DNS destination | port 53 | `mesedge.exe` | 高 | sandboxのprocess帰属付きflow |

出典: `https://tria.ge/260710-pvzs1acy91/behavioral1`。

以下は正規LetsVPN側 `LetsPRO.exe` の通信としてC2から除外する:

- Sentry ingest、Google、Bing、Yandex、Baidu、Ctrip、CloudFront、証明書失効確認。
- `119.29.29.29:53`、`8.8.8.8:53`等の正規アプリ側DNS。

`103.45.64.246`は観測時の解決先であり、domainの将来的な解決先変更を考慮する。

## 4. PE・YARA向け静的特徴

### `mesedge.exe`

- PE entry RVA: `0x1249`
- import: `cef_frame.dll!TbsAppInstance`
- anti-debug関連import: `IsDebuggerPresent`
- 小容量の署名付きhostと、同階層の巨大な未署名/protected DLLという組合せ。

### `cef_frame.dll`

- PE entry RVA: `0xe31848`
- exports: `CreateBrowser`, `IsNameReolveError`, `TbsAppInstance`
- importsは極端に少ない:
  - `KERNEL32.dll!Sleep`
  - `SHELL32.dll!ShellExecuteA`
  - `SHLWAPI.dll!PathRemoveFileSpecA`
  - `ADVAPI32.dll!SystemFunction036`
- `.text`/`.rdata`/`.data`のraw dataが異常、large high-entropy protector section。
- `IsNameReolveError`の綴りを含むexport集合は比較的特徴的。
- 汎用single-byte XOR走査は高entropy由来の偽IOCが多いためYARA根拠にしない。

### MSI/CAB構造

- OLE/MSI magic `D0 CF 11 E0 A1 B1 1A E1`
- embedded CAB magic `MSCF`
- CAB内で `mesedge.exe` と `cef_frame.dll` が同居。
- host import tableが同梱DLLの固有exportを参照。

## 5. プロセス・永続化・防御回避

Triageで観測された悪性chain側の挙動:

- `msiexec.exe /I ...\KL-X86Gicasc.msi`
- MSIが `C:\Program Files (x86)\LK\mesedge.exe` と `cef_frame.dll`を配置。
- `mesedge.exe`から `schtasks /create /tn "MyAutoStartApp" /tr "C:\Program Files (x86)\LK\mesedge.exe" /sc onlogon /rl highest /f`。
- `mesedge.exe`からPowerShellを起動し、`Add-MpPreference -ExclusionPath C:\Program Files (x86)\LK`。
- `mesedge.exe` PID 2068がC2へDNS/TCP通信。

正規/decoy側として分離する挙動:

- `latst.exe`によるLetsVPN導入。
- `LetsPRO.exe`によるnetwork discovery (`ipconfig /all`, `route print`, `arp -a`) と正規サービス通信。
- VPN driver、firewall rule操作は悪性chainとの相関なしに単独検知しない。

## 6. Sigma生成に必要な情報

### 推奨データソース

- Security 4688 / Sysmon 1 / EDR process telemetry
- Sysmon 7 / EDR image-load
- Sysmon 3 / EDR network
- DNS query telemetry with process/PID
- PowerShell 4104 / AMSI / process command line
- Task Scheduler Operational 106/140/141、Security 4698
- Defender Operational log / EDR configuration changes
- File create/hash/signature telemetry
- MSI installer logs

### Sigma候補と誤検知

| 検知ロジック | 必要フィールド | 信頼度 | 誤検知可能性 |
|---|---|---|---|
| `mesedge.exe`が`cef_frame.dll`をロード | `Image`, `ImageLoaded`, hash, signer | 高 | 低。同名正規ソフトをhash/signature/pathで除外 |
| `mesedge.exe`→`www.tq8j.com`または`103.45.64.246:443` | process, domain/IP, port | 高 | 低。domain/IP再利用時はhost hash/pathを必須化 |
| scheduled task `MyAutoStartApp`がLK配下`mesedge.exe`をonlogon/highestで実行 | TaskName, TaskContent/Command | 高 | 低。組織固有task名衝突を確認 |
| `mesedge.exe`子PowerShellで`Add-MpPreference -ExclusionPath ...\LK` | ParentImage, Image, CommandLine/ScriptBlock | 高 | 低～中。管理ツールによるDefender除外を署名済み管理parentで除外 |
| MSIが`Program Files (x86)\LK`へ小型host＋巨大protected DLLを配置 | installer/file telemetry | 中～高 | 中。正規installerをpublisher/package hashで除外 |
| `msiexec.exe`実行のみ | Image, CommandLine | 低 | 高。単独では使用不可 |

推奨Sigma selection要素:

```yaml
Image|endswith: '\mesedge.exe'
ImageLoaded|endswith: '\cef_frame.dll'
ParentImage|endswith: '\mesedge.exe'
CommandLine|contains|all: ['Add-MpPreference', '-ExclusionPath', '\LK']
TaskName|endswith: '\MyAutoStartApp'
DestinationHostname: 'www.tq8j.com'
DestinationIp: '103.45.64.246'
DestinationPort: 443
```

正規LetsVPN (`latst.exe`, `LetsPRO.exe`) の一般通信やVPN driver/firewall変更を単独条件にすると過検知しやすい。

## 7. YARA生成に必要な情報

### 推奨rule分割

1. exact-hash IOC rule: MSI、CAB、`cef_frame.dll`、`mesedge.exe`。
2. `cef_frame.dll` structural rule: export集合、import最小集合、entry/section異常、size範囲。
3. sideload bundle rule: CAB内のhost/DLL名、host import/export関係。
4. MSI container rule: OLE + CAB + campaign固有filenames。これはdelivery検知でありfamily断定には使わない。

### `cef_frame.dll`条件案

```yara
$e1 = "TbsAppInstance" ascii
$e2 = "CreateBrowser" ascii
$e3 = "IsNameReolveError" ascii
$i1 = "SystemFunction036" ascii
$i2 = "PathRemoveFileSpecA" ascii
condition:
  uint16(0) == 0x5a4d and
  filesize > 10MB and filesize < 12MB and
  3 of ($e*) and 1 of ($i*)
```

PE export/import table解析が利用できる環境では、単なるraw stringより `pe.exports()` / `pe.imports()` 相当を優先する。protector変更でsize/sectionが変わる可能性があるため、exact sizeは補助条件にする。

### sideload host条件案

```yara
$target_dll = "cef_frame.dll" ascii wide
$target_export = "TbsAppInstance" ascii
condition:
  uint16(0) == 0x5a4d and filesize < 64KB and all of them
```

短いhostは再ビルドされやすいため、hash、Tencent署名、同階層DLL hash、pathの相関をEDR側で補完する。

## 8. 検知・ハンティング優先度

1. 高: `mesedge.exe`と`cef_frame.dll`のload edge + C2または永続化/Defender除外。
2. 高: `cef_frame.dll` hash/export/import集合。
3. 中: MSI/CAB構造とLK配下へのhost/DLL配置。
4. 低: `msiexec.exe`、LetsVPNの一般通信、VPN driver/firewall操作単体。

## 9. MITRE ATT&CK観点

- T1218.007: `msiexec`によるMSI実行。
- T1574.002: DLL side-loading。
- T1053.005: Scheduled Task (`MyAutoStartApp`)。
- T1562.001: Defender exclusion追加。
- T1071/T1095相当: C2通信（port 443、application protocolは未確定）。
- T1518 / T1016: 正規decoy process側でもsoftware/network discoveryが観測されるため帰属に注意。

## 10. 制約と参照成果物

- `cef_frame.dll`はvirtualized/protectedで、内部configの静的復号は未完了。
- C2確定は静的sideload関係とprocess帰属付きsandbox観測の相関による。
- IP/domainの現在の稼働確認は実施していない。
- `msi-analysis.json`: OLE/CAB/PE stream inventory。
- `msi-chain-c2-analysis.json`: hashes、imports/exports、sideload edge、C2 evidence。
- `file-inventory.csv`: Defender遮断を含むfilesystem inventory。

## 11. 現在のC2生存確認とShodan条件

確認日時: `2026-07-12T17:39:23Z`（JST 2026-07-13）。

| 項目 | 結果 |
|---|---|
| Domain | `www.tq8j.com` |
| 現在の解決IP | `18.166.72.101` |
| 過去のsandbox観測IP | `103.45.64.246` |
| TCP/443 | connection refused |
| 現在の生存判定 | **inactive / not reachable** |
| HTTP status/title/banner | 取得不能 |
| TLS version/cipher | 取得不能 |
| Certificate SHA-256 | 取得不能 |
| JARM | 取得不能。全ゼロ値はno fingerprintとして破棄 |

過去のTriage観測では`mesedge.exe`が`www.tq8j.com`解決後に`103.45.64.246:443`へ反復接続しているため、C2帰属自体は高信頼のまま。ただし現在はDNS解決先が変化し、443/TCPを拒否しているため、現在稼働中とは判定しない。

Shodan候補:

```text
hostname:www.tq8j.com port:443
ip:18.166.72.101 port:443
ip:103.45.64.246 port:443
```

現在はbannerが得られないため`hash:`、`http.title:`、`ssl.cert.fingerprint:`、`ssl.jarm:`の実値を生成できない。将来serviceが復帰した場合、`c2_detector.py --protocol https --collect-jarm`のJSONから次の形式を追加する。

```text
hash:<signed_murmur3_banner_hash>
http.title:"<observed title>"
ssl.cert.fingerprint:<certificate_sha256>
ssl.jarm:<62-character non-zero JARM>
```

これらは単独で悪性を示さない。共有hosting/CDN、再発行証明書、同一TLS stackによる誤検知があるため、`hostname + port + certificate/JARM + malware process evidence`を組み合わせる。IPは最も変化しやすいため履歴・現在値を分ける。

保存結果: `c2-live/2026-07-13_www.tq8j.com_443.json`。
