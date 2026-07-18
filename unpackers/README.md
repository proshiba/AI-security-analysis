# 静的 unpacker

この directory には、共通の上限付き unpack pipeline があります。検体、復元 payload、installer callback、script、packer stub を起動せず、抽出したインフラへ接続することもありません。

## 対応する復元経路

| Layer | 静的方法 | 結果 |
|---|---|---|
| ZIP/CAB/7z/RAR | 上限付き 7-Zip inventory と抽出 | 保持対象 member と再帰解析 |
| NSIS | NSIS 対応 7-Zip による script decompile | `[NSIS].nsi`、member、明示された script 変換 |
| NSIS hexadecimal XOR stream | `IntOp` と `IntFmt %08X` の word decode を再現 | System plugin の call stream |
| NSIS native XOR loader | 上限付き x64 定数伝播後に dword XOR | 実行しない中間 loader |
| UPX | 隔離した入力に対して信頼済み UPX utility を実行 | UPX が file を検証できた場合の unpack 済み PE |
| PE resource と overlay | offset と size を parse し、有効な PE 範囲を carve | child PE/resource |
| .NET ResourceSet | object を deserialize せず serialized resource を parse | string、byte array、image |
| .NET bitmap steganography | 上限付き RGB column traversal を再現 | 埋め込み managed PE |
| AutoIt A3X | script が手順を明示する場合に literal、RC4、LZNT1 を decode | 埋め込み PE |
| JavaScript string array 難読化 | array を parse し、rotation を解き、alias を decode して literal を畳み込み | 可読化した script と URL |
| UTF-16 JavaScript dropper | numeric array、repeating Unicode key 変換、environment chunk を畳み込み | PowerShell と terminal PE |
| JavaScript AES/GZip chain | 埋め込み AES-CBC key/IV と GZip 手順を parse | terminal managed PE |
| CMD echo Base64 stream | target 別に redirection をまとめ、chunk を連結して検証 | fragment noise を除いた terminal PE/archive |
| Jadoo split bundle | manifest の offset と length を検証 | 再構築した file |
| 一般的な base64/hex | size と format を gate とする decode | child layer |
| Mach-O | header と segment の inventory | packing 評価だけ |

`static_unpacker.py` が orchestrator です。`javascript_obfuscator.py` は script encoding と string array layer、`javascript_dropper_unpacker.py` は numeric array、Unicode environment、AES-CBC、GZip chain、`nsis_unpacker.py` は明示的な NSIS script と native constant XOR layer を処理します。`static_control_flow.py` は、上限付きの再帰的 x86/x64 entry CFG triage を提供します。`managed_il_triage.py` は CLR を load せず、managed metadata、CIL、resource を棚卸しします。

## 使用 tool

推奨する 7-Zip binary は NSIS decompile 対応 build です。信頼済み archive parser としてだけ使用し、installer は実行しません。

```powershell
$Python = 'C:\Users\Administrator\Tools\Python313\python.exe'
$SevenZipNSIS = 'C:\Users\Administrator\Tools\7z-nsis-26.02\7z.exe'
$UPX = 'C:\Users\Administrator\Tools\upx\upx-5.1.1-win64\upx.exe'
$DiE = 'C:\Users\Administrator\Tools\DetectItEasy-3.21\die\diec.exe'

& $Python .\unpackers\static_unpacker.py `
  --input C:\analysis\sample.quarantine.bin `
  --output C:\analysis\unpack.json `
  --artifact-zip C:\analysis\recovered-artifacts.zip `
  --upx $UPX `
  --sevenzip $SevenZipNSIS `
  --archive-password infected `
  --diec $DiE
```

`--artifact-zip` を指定した場合だけ、復元 byte を書き出します。archive は解析 password `infected` を使って AES で暗号化します。Git へ追加しないでください。`--force-container-probe` は、レビュー済み inventory hint がある場合だけ使用します。この option は入力を実行せず、設定済み 7-Zip binary に PE/container の parse を要求します。archive password を公開 report へコピーすることはありません。

report には hash、size、format、変換、信頼度、検体を実行していないこと、network 接続を行っていないことを記録します。

NSIS native 定数解析には Python package `capstone` が必要です。register/immediate 演算の線形な伝播だけを行い、memory、call、branch、検体を emulate しません。

## 再帰的 family pipeline

family 全体を offline で解析する場合は、NSIS 対応 binary を使用します。収集日を directory 階層に混ぜず、private sample と隔離出力でも family/version の深さを揃えます。

```powershell
& $Python .\analysis-framework\common\analyze_stealer_set.py `
  --manifest C:\Users\Administrator\MalwareSamples\remcosrat\<version-key>\manifest.json `
  --output C:\Users\Administrator\malware-lab\remcosrat\<version-key> `
  --definitions .\analysis-framework\definitions `
  --upx $UPX `
  --sevenzip $SevenZipNSIS `
  --diec $DiE
```

pipeline は復元 layer を最大 2 generation まで再帰的に検査し、復元 byte は暗号化したローカル解析 archive にだけ保存します。公開 case は `analysis-results/malware/remcosrat/versions/<version-key>/cases/<sha256>/` に保存し、収集元と収集日は `analysis-results/collections/<collection-id>/manifest.json` の membership として管理します。

## Status の解釈

`artifacts_recovered` は inner layer を 1 つ以上再構築できたことを意味します。最終 malware payload の unpack 完了を意味しません。terminal executable または script が構造的に有効で、追加の packing/protection layer を示す根拠がない場合だけ、case を完全に unpack 済みとします。

report では次の blocker class を使用します。

- `unsupported_static_transform`: decoder が未実装です。
- `native_control_flow_obfuscation`: 検証済み変換後も native loader が残っており、確実に継続するには実行または emulation が必要です。
- `runtime_derived_key`: key が machine state、timing、remote content に依存します。
- `missing_external_payload`: delivery layer が、提出 archive に存在しない content を参照しています。
- `encrypted_container`: 必要な password が不明です。
- `corrupt_or_truncated`: 宣言された境界または header を検証できません。
- `not_packed`: 高 entropy または難読化はありますが、除去できる独立した packer layer がありません。

## 失敗時の確認

1. outer archive が引き続き AES で暗号化され、想定 intake password で読めることを確認します。
2. NSIS 対応 7-Zip build を使用します。標準 7-Zip は、decompile 済み `[NSIS].nsi` control flow を生成せずに file だけを抽出する場合があります。
3. 空の `recovered` list を最終結果とする前に、`inventory`、`retained_members`、`split_reassembly`、`nsis_script_recovery` を確認します。
4. decoder の offset、size、key、source offset、出力 SHA-256、magic を report と比較します。範囲外または曖昧な変換は拒否します。
5. 復元したすべての layer を再帰的に解析します。有効な PE 自体が pack されている場合があります。
6. DiE/entropy の finding は hint として扱います。それだけでは packing の証明になりません。
7. 残った stage が control flow を難読化した native loader なら、blocker を記録し、完全 unpack 済みと暗黙に分類しません。

## 検証と API 文書

```powershell
& $Python -m pytest .\unpackers\tests -q
& $Python -m pydoc unpackers.static_unpacker
& $Python -m pydoc unpackers.javascript_obfuscator
& $Python -m pydoc unpackers.javascript_dropper_unpacker
& $Python -m pydoc unpackers.nsis_unpacker
```

unit test は、上限付き decode、malformed input、正確な hash/size、JavaScript rotation、UTF-16 normalization、numeric array と Unicode environment の復元、AES-CBC/GZip 変換、分割 CMD Base64 の再構築、.NET bitmap 復元、AutoIt layer、split reconstruction、NSIS word decode、静的 XOR loop 認識、synthetic NSIS の end-to-end 復元を検証します。

## PureHVNC と CHRD/Donut の復元

- `purehvnc_unpacker.py` は、観測済みの first-byte/index-XOR envelope の内側から、sparse stride-four storage を含む構造的に有効な PE を検索します。
- `donut_unpacker.py` は、レビュー済みの modern `0x290` layout と legacy `0x23c` layout、Chaskey CTR、非圧縮 module、任意の aPLib 復元に対応します。
- `chrd_donut_unpacker.py` は、WAV、numeric segment、outer transform、Donut、managed TripleDES/GZip resource loader、terminal PE の順に、レビュー済み CHRD resource carrier を再構築します。

CHRD integration fixture は、実行も network 接続も行わずに terminal SHA-256 `c1a2b48d4f639b46cf6cde8322666f0991531ef32ffe571140418ae40342ffe8` を復元しました。生成 binary は隔離/output path に保存し、commit してはいけません。

## APT-C-60 / SpyGlace の復元

- `apt_c60_delivery.py` は LNK string と厳密な Base64/TAR carrier を安全に検査し、明示された `copy /b` fragment 連結だけを再現します。
- `spyglace_unpacker.py` は literal PE data と、レビュー済みの 2 種類の repeating XOR envelope を認識し、PE 構造を検証して静的 role を割り当てます。
- どちらの module も LNK、JavaScript、Git、script、loader、復元 PE を起動しません。

command の順序と失敗時の確認は `docs/APT-C60-2026-WORKFLOW.md` を参照してください。

## 現行 Donut、container、大容量 file への対応

- `donut_unpacker.py` は、レビュー済みの modern/legacy layout に加えて、現行の `0x240` と `0x230` array layout に対応します。call-over-instance prologue、API 数、DLL basename list、復号済み PE 範囲、出力 hash を検証します。
- `donut_wrapper_unpacker.py` は、decode 後の `SystemRoot`、`System32\conhost.exe`、quoted argument template を検証してから、レビュー済み 32 byte XOR wrapper を復元します。
- `container_recovery.py` は、連結 XZ stream、上限付き XML plist trailer、Mach-O FAT slice、拡張された PE certificate gap を処理します。
- `static_unpacker.py` は Apple disk image と複数 member を持つ malware 所有 archive を再帰 layer として扱います。64 MiB を超える file には、決定的な上限付き entropy sampling と marker probe を使用します。

すべての変換は構造を検証し、memory 内または隔離した一時 path で行います。復元 PE は再帰的に解析しますが、起動しません。

## Electron ASAR と Java/Mach-O の境界

- `asar_unpacker.py` は、memory 内 member を返す前に Chromium ASAR pickle の境界、member offset、integrity metadata、path traversal を防ぐ name、総出力上限を検証します。
- `electron_nsis_unpacker.py` は 7-Zip を parser としてだけ使用し、入れ子の Electron archive を特定して `resources/app.asar` を復元します。NSIS、Electron、JavaScript、復元 payload は起動しません。
- `static_unpacker.py` は両経路を再帰的に適用し、JavaScript を評価せず、レビュー済みの plain JavaScript string array rotation を難読化解除できます。
- Java class file と universal Mach-O は `CAFEBABE` magic を共有します。format detector は、妥当で上限付きの Mach-O architecture table を要求し、それ以外を `java-class` と分類します。

関連 test は `test_asar_unpacker.py`、`test_electron_nsis_unpacker.py`、`test_javascript_plain_array.py`、`test_static_unpacker.py` の Java/Mach-O regression です。
