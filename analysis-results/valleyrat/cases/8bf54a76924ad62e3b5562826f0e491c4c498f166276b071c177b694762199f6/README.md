# ValleyRAT case: 8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6

## 1. 概要と判定

| 項目 | 内容 |
|---|---|
| Malware type | ValleyRAT |
| Campaign / chain type | `dll_sideload_vvas_bundle` |
| 提出検体 SHA-256 | `8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6` |
| 判定信頼度 | 高。固有bundle構造、復号済みconfig、通信実装の一致 |
| ローカルでの検体実行 | なし |
| このリポジトリのworkflowによる通信 | なし |

感染チェーン:

```text
chgport.exe (署名付きhost)
  └─ LoggerCollector.dll (未署名side-loader)
       └─ vvaS.bin (single-byte XOR 0x14)
            └─ x86 shellcode
                 ├─ rundll32.exeへのinjection
                 └─ ValleyRAT C2 check-in / stage取得
```

## 2. ファイルIOC

| Role | File | Size | SHA-256 | 特徴 |
|---|---|---:|---|---|
| Submitted bundle | ZIP | 3,822,100 | `8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6` | 26 member |
| Sideload host | `chgport.exe` | 2,328,544 | `255e4c5b81ddabc02455b7b4560e168b4064e63ec3721230201d1a7928c9f158` | 有効署名: Hithink RoyalFlush Information Network Co., Ltd. |
| Loader | `LoggerCollector.dll` | 226,304 | `65773d8a11bb0e816722e7fbfaee27641ce09e3f7b9ebb9e5a9b61cc698f5a1e` | 未署名、同一ディレクトリからロード |
| Encrypted payload | `vvaS.bin` | 1,528 | `39a99f1ee435835d6130ce147c477acc4882b2fb0c881ec89db9c930f4b18d11` | 全byte XOR `0x14` |
| Decrypted shellcode | `vvaS.xor.bin` | 1,528 | `b2586edb216bdb27ffbf5be5c091c94c62df8d87500ceacdc519e3016f7d7e2a` | x86-32、設定markerを内包 |
| Decoy/alternate signed host | `vmtoolsd.exe` | 93,616 | `61d4473cff983c93df36b127c87fa682de89b49858723a22b814483632559556` | 有効VMware署名。単独hashだけでは悪性判定不可 |
| Companion signed DLL | `vmtools.dll` | 841,136 | `4504dee573d0b4655da2362d89532fa30ddffbfb3e95575bfa0aac6684138553` | 有効VMware署名。単独hashだけでは悪性判定不可 |

全memberは `file-inventory.csv` を参照。署名済み正規ファイルはbundle内共存関係がなければIOCとして扱わない。

## 3. C2・config

| 種別 | 値 | 信頼度 | 根拠 |
|---|---|---|---|
| Primary C2 | `202.95.8.27:6666/TCP` | 高 | 復号configとconnect実装、別タスクで限定check-in応答を確認 |
| Secondary endpoint | `202.95.8.27:8888/TCP` | 高（config）、通信未確認 | 同じconfig構造の第2エントリ |
| Config marker | `odaktomk` | 高 | 復号offset `0x474` / decimal 1140 |
| Initial check-in | hex `33 32 00` | 高 | 解析済みprotocol field |
| Expected stage-2 size | `307214` bytes | 高（応答header） | 限定check-in時のdeclared size。stage本体は未取得 |
| Stage-2 XOR key | `0x9d` | 高（protocol解析） | 応答処理で使用される復号key |
| Stage-2 header size | `14` bytes | 高（protocol解析） | 応答header parser |

IPはcampaign間・時間経過で変更されるため、IP単独検知は短寿命IOCとして扱う。

## 4. 特徴的な文字列・コード特性

YARA候補となる値:

- ASCII marker: `odaktomk`
- C2文字列: `202.95.8.27`（復号後に2回）
- 分割/構築文字列: `Ws2_`, `32.d`, `ntdl`, `l.dlf`
- x86 entry bytes: `55 8b ec 83 e4 f8 81 ec f8 01 00 00`
- loader API hash群:
  - `LoadLibraryA=0x0148be54`
  - `VirtualAlloc=0x00293836`
  - `CreateThread=0x5ec13a5a`
  - `WSAStartup=0xc18bc488`
  - `socket=0x9816abed`
  - `connect=0xf9b83296`
  - `send=0x039bb598`
  - `recv=0xf4178b7a`

単一の短い文字列やAPI hashは衝突・誤検知し得るため、marker、ファイルサイズ範囲、x86 prologue、ネットワークAPI hash群を組み合わせる。

## 5. プロセス・ホスト挙動

確定または強く支持される挙動:

- 署名付き `chgport.exe` と未署名 `LoggerCollector.dll` の同一ディレクトリ配置。
- DLL side-loadingを起点として `vvaS.bin` を読み込み、`0x14`で復号。
- `VirtualAlloc`/memory copy/thread API相当をhash解決するx86 shellcode。
- `rundll32.exe`を悪用したprocess injection。
- Winsock APIをhash解決し、TCP C2へcheck-in。

この成果物では永続化レジストリ操作、service作成、scheduled task作成は確認されていない。未観測事項を推測でSigma条件へ追加しない。

## 6. Sigma生成に必要な情報

### 推奨データソース

- Security 4688 / Sysmon Event ID 1 / EDR process telemetry
- Sysmon Event ID 7またはEDR image-load telemetry
- Sysmon Event ID 10またはEDR process-access/injection telemetry
- Sysmon Event ID 3またはEDR network connection
- DNS telemetry（IPのみのため補助的）
- File create/hash/signature telemetry

### Sigma候補と誤検知

| 検知ロジック | 必要フィールド | 信頼度 | 誤検知可能性 |
|---|---|---|---|
| `chgport.exe` SHA-256一致 | `Image`, `Hashes` | 高 | 低。ただしhash変更に弱い |
| 未署名 `LoggerCollector.dll` が `chgport.exe` にロード | `ImageLoaded`, `Image`, `Signed`, `SignatureStatus` | 高 | 低。正規製品の同名DLL更新をhash/署名で除外 |
| `chgport.exe`/関連hostから `rundll32.exe` + process access/injection | `SourceImage`, `TargetImage`, `GrantedAccess`, call telemetry | 高 | 中。管理・監視製品によるrundll32操作を除外 |
| bundle directoryの `vvaS.bin` 読み込み後、`202.95.8.27:6666/8888`へ接続 | file/network correlation | 高 | 低。IP再利用時はprocess/hash条件を必須化 |
| signed hostと同階層の未署名DLL・小容量BINの同時作成 | path, signature, size, hashes | 中 | 中。自己展開installerをpublisher/path allowlistで除外 |

推奨Sigma selection要素:

```yaml
Image|endswith: '\chgport.exe'
ImageLoaded|endswith: '\LoggerCollector.dll'
TargetImage|endswith: '\rundll32.exe'
DestinationIp: '202.95.8.27'
DestinationPort: [6666, 8888]
```

IPだけ、`rundll32.exe`だけ、`LoggerCollector.dll`という名前だけのルールは作らない。

## 7. YARA生成に必要な情報

### 推奨スコープ

1. encrypted bundle component (`vvaS.bin`) のexact/hash rule。
2. 復号shellcodeのstructural rule。
3. `LoggerCollector.dll` loader rule（FLOSS文字列とPE import/section情報を別途併用）。

### 復号shellcode条件案

```yara
$marker = "odaktomk" ascii
$c2 = "202.95.8.27" ascii
$prologue = { 55 8B EC 83 E4 F8 81 EC F8 01 00 00 }
condition:
  filesize == 1528 and $prologue at 0 and $marker and #c2 >= 2
```

運用ruleではC2を必須にするとconfig変更を逃すため、`$marker + prologue + size range + API-hash byte patterns`を主条件とし、C2は補助条件にする。exact hashはIOC rule、structural ruleとは分離する。

## 8. 検知・ハンティング優先度

1. 高: loader/host hash、`odaktomk`、sideload関係、C2とprocessの相関。
2. 中: signed host + unsigned sibling DLL + small encrypted BINの組合せ。
3. 低: `rundll32.exe`、Winsock利用、署名付き正規ファイル単体。

## 9. 制約と参照成果物

- stage-2本体は取得・保存していない。
- 公開結果には検体・復号BIN・PCAPを含めない。
- `decoded-analysis/vvas-static-summary.json`: marker、IP、ports、API hashes。
- `decoded-analysis/vvas-shellcode.asm`: linear disassembly。
- `floss/*.static.txt`: loader/host文字列。
- `file-inventory.csv`: bundle全memberのhash・署名。

## 10. 現在のC2生存確認とShodan条件

確認日時: `2026-07-12T17:33:34Z`～`17:33:35Z`（JST 2026-07-13）。`c2_detector.py`から`33 32 00`だけを送信し、64 bytesで受信を打ち切った。

| Endpoint | TCP | Protocol confirmation | Response banner SHA-256 | Shodan MurmurHash3 |
|---|---|---|---|---:|
| `202.95.8.27:6666` | open | `confirmed_vvas_c2`、declared stage `307214` | `32fda28a442899190076b888be57aa09e29590549039f5e7ae8e1e158df0d531` | `-481009216` |
| `202.95.8.27:8888` | open | `confirmed_vvas_c2`、declared stage `307214` | `32fda28a442899190076b888be57aa09e29590549039f5e7ae8e1e158df0d531` | `-481009216` |

判定: **両ポートとも現在生存し、復元したvvaS protocolに一致**。TCP openだけでなく、14-byte headerとstage sizeの一致を根拠とする。

Shodan候補:

```text
ip:202.95.8.27 port:6666
ip:202.95.8.27 port:8888
hash:-481009216
```

`hash:-481009216`はcustom check-in後に得たraw response 64 bytesのsigned MurmurHash3である。Shodanのscannerが同じprotocol payloadを送らない場合、このbannerは収集されず検索結果に現れない可能性が高い。したがってIP/port条件を主、banner hashを補助とする。このserviceはHTTP/TLSではないため、`http.title`、証明書hash、JARMは該当しない。

保存結果:

- `c2-live/2026-07-13_202.95.8.27_6666.json`
- `c2-live/2026-07-13_202.95.8.27_8888.json`
