# Malware config extractor の概要

`extractors/` は、解析済み malware の config 抽出機能を解析 engine や emulator から分離して提供します。検体を実行せず、外部通信も行いません。すべての family で共通の JSON 契約を使用します。

## 対応 family

| ID | 抽出対象 | 確定条件 |
|---|---|---|
| `valleyrat` | variant、endpoint、config/stage URL | 復号済み config を伴わない文字列候補は `inferred` |
| `agenttesla` | FTP/SMTP/HTTP/Telegram/Discord 候補 | credential 値は出力せず、存在 flag だけを保持 |
| `stealc` | v1 Base64/RC4 skip-key profile と paired-buffer XOR C2 profile | 保護された generation または未対応 generation は、inner payload が復元されるまで未解決 |
| `remcosrat` | family marker、endpoint 候補 | 暗号化された config または resource config を復元できない場合は確定しない |
| `shadowpad` | ScatterBee resource config と x86/x64 Casper Config module | private builder/test endpoint は文脈情報だけとし、packed variant は別途 unpack が必要 |
| `venomrat` | Quasar/xClient marker、endpoint 候補 | marker の相関があっても、config 参照を確認するまでは `inferred` |
| `mx-go` | 埋め込み JSON、control server | 埋め込み JSON 内の値は `confirmed`、secret に相当する field は除外 |

## 使用方法

```powershell
$env:PYTHONPATH = '<repo-root>'
python -m extractors.config_extractor `
  --family valleyrat `
  --input C:\malware-lab\quarantine\sample.bin `
  --output C:\malware-lab\output\config.json
```

入力には、隔離領域の検体、復元済み payload、または復号済み config artifact を指定します。公開結果へ実行可能 byte や credential をコピーしません。

## 共通出力

- `family`、`sample_sha256`。
- `config`: family 固有ですが、公開して安全な config。
- `findings`: `kind`、`value`、`role`、`confidence`、`source`。
- `limitations`。
- `credentials_published=false`。
- `executed=false`、`network_contacted=false`。

## Test と pydoc

```powershell
python -m pytest -q extractors/tests
```

生成済み API 文書は `docs/pydoc/` を参照してください。

## 追加の stealer family

- `formbook`: delivery 形状、injection/credential marker、再帰的に復元したインフラ literal を抽出します。
- `vidar`: unpack 済みの collection、dependency、dead-drop 候補を抽出します。
- `lummastealer`: loader/packer、build、browser/wallet、API 候補を抽出します。
- `remusstealer`: 暗号化 archive、Go/native loader、browser/wallet、インフラ候補を抽出します。
- `amosstealer`: Mach-O/script 形状、keychain/browser/wallet 機能、`/ledger/` exfiltration 候補を抽出します。

上記 5 family はすべて `stealer_common.py` を使用します。false positive を抑えるため、既知の certificate/vendor URL と、他の根拠がない bare endpoint は出力しません。

## PureHVNC、PureRAT、DonutLoader の抽出

- `purehvnc` は native `10FX` profile と、managed Base64/GZip/protobuf PureRAT config に対応します。公開 certificate fingerprint は出力しますが、埋め込まれた private key は公開しません。
- `donutloader` は delivery layer marker を記録し、静的 unpack 後の terminal config 抽出を対応 extractor へ委譲します。
- alias は `pure`、`purerat`、`donut` です。

family extractor は復元済み payload byte を入力できますが、検体を実行せず、設定されたインフラにも接続しません。

## SpyGlace の抽出

`spyglace` extractor は、encode された APT-C-60 repository artifact と decode 済み PE のどちらも受け付けます。既知の repeating XOR envelope を memory 内で復元し、API/command と config の独立した string domain を decode して、C2 IP、campaign user ID、ASP path、mutex、command、API、custom RC4 key、persistence string を返します。推定した HTTP request を送信することはありません。

```powershell
python -m extractors.config_extractor --family spyglace --input C:\analysis\encoded.tmp --output C:\analysis\config.json
```

詳しい実行順序と失敗時の処理は `docs/APT-C60-2026-WORKFLOW.md` を参照してください。

## ShadowPad の抽出

`shadowpad` は最初に ScatterBee resource decoder を適用し、その後 PE section から構造的に有効な x86/x64 Casper outer stream を検索します。legacy payload は PE を load せずに復号し、QuickLZ で伸長して parse します。出力では、公開 config endpoint、RFC1918 の builder/test 文脈、完全一致 hash に基づく公開情報源の帰属を分離します。

## StealC の抽出

`stealc` は Base64/RC4 skip-key profile と x86 paired-buffer XOR call site を識別します。完全な PHP gate、dependency directory、build ID、存在する場合は string key、decode 済み string 数を返します。復元 endpoint は静的 config の根拠にすぎません。検体の実行や network request は行いません。

## Profile 定義型 Windows family

AsyncRAT、XWorm、QuasarRAT、njRAT、DarkComet、DCRat、RedLine Stealer、Snake Keylogger、GuLoader、HijackLoader は `profiles/windows_family_profiles.json` で登録されています。`profiled_family.py` は、上限付き ASCII/UTF-16LE 抽出、marker/config key の相関、secret を出さない URL sanitization、endpoint role の分類、共通結果契約を提供します。

情報源 signature またはレビュー済みの完全一致 hash で family を選択できますが、復元済み config の確定には、検証済みの decode 構造が必要です。delivery URL、public IP discovery service、certificate/documentation URL、C2 候補には別々の role を割り当てます。extractor は値へ接続せず、liveness も報告しません。関係図と検証手順は `analysis-framework/docs/PROFILED-FAMILY-EXPANSION.md` を参照してください。

## 最近の campaign 用 extractor

- `npm_supply_chain` は Node.js を起動せず、axios/plain-crypto-js の postinstall を decode します。
- `atlascross` は文書化済みの 324 byte AtlasCross config を復号します。

## Amadey と Latrodectus

- `amadey` は、レビュー済みの x86/x64 custom alphabet/Base64 layout を検証してから、C2 URL、version、campaign ID、installation name、RC4 key を返します。Themida/WinLicense wrapper は、terminal PE を復元するまで未解決のままです。
- `latrodectus` は、レビュー済みの legacy PRNG string layout を復号し、C2 URL、version、group name/FNV-1a ID、RC4 key、discovery/update 機能を返します。AES-CTR generation は別の parser profile として扱います。

family 固有の検証構造を伴わない literal インフラは、確定 C2 ではなく候補として報告します。extractor が接続することはありません。
