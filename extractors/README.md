# Malware configuration extractors

`extractors/` は解析済みマルウェアの設定抽出を、解析engineやemulatorから独立して提供する。
検体を実行せず、外部通信も行わない。出力は全familyで共通のJSON契約を使用する。

## Supported families

| ID | 抽出対象 | 確定条件 |
|---|---|---|
| `valleyrat` | variant、endpoint、config/stage URL | 復号済みconfigがない文字列候補は`inferred` |
| `agenttesla` | FTP/SMTP/HTTP/Telegram/Discord候補 | credential値は出力せず、存在フラグだけを残す |
| `stealc` | v1 Base64/RC4 skip-key and paired-buffer XOR C2 profiles | protected or unsupported generations remain unresolved until an inner payload is recovered |
| `remcosrat` | family marker、endpoint候補 | encrypted/resource config未復元時は確定しない |
| `shadowpad` | ScatterBee resource config and x86/x64 Casper Config modules | private builder/test endpoints remain context-only; packed variants require separate unpacking |
| `venomrat` | Quasar/xClient marker、endpoint候補 | marker相関があってもconfig参照までは`inferred` |
| `mx-go` | embedded JSON、control server | embedded JSON内の値は`confirmed`、secret-like fieldは除外 |

## Usage

```powershell
$env:PYTHONPATH = '<repo-root>'
python -m extractors.config_extractor `
  --family valleyrat `
  --input C:\malware-lab\quarantine\sample.bin `
  --output C:\malware-lab\output\config.json
```

入力は隔離領域の検体、復元済みpayload、または復号済みconfig artifactを想定する。公開結果へ
実行可能bytesやcredentialをコピーしない。

## Common output

- `family`, `sample_sha256`
- `config`: family固有だがpublish-safeな設定
- `findings`: kind、value、role、confidence、source
- `limitations`
- `credentials_published=false`
- `executed=false`, `network_contacted=false`

## Test and pydoc

```powershell
python -m pytest -q extractors/tests
```

生成済みAPI文書は `docs/pydoc/` を参照する。


## Additional stealer families

-
ormbook: delivery shape, injection/credential markers, and recursively recovered infrastructure literals
-
idar: unpacked collection/dependency/dead-drop candidates
- lummastealer: loader/packer, build, browser/wallet, and API candidates
-
emusstealer: encrypted-archive, Go/native loader, browser/wallet, and infrastructure candidates
- mosstealer: Mach-O/script shape, keychain/browser/wallet features, and /ledger/ exfiltration candidates

All five use stealer_common.py; known certificate/vendor URLs and uncorroborated bare endpoints are suppressed to reduce false positives.

## PureHVNC, PureRAT, and DonutLoader

- `purehvnc` supports a native `10FX` profile and managed Base64/GZip/protobuf PureRAT configuration, including public certificate fingerprints without publishing the embedded private key.

## SpyGlace

The spyglace extractor accepts either the encoded APT-C-60 repository artifact or a decoded PE. It recovers known repeating-XOR envelopes in memory, decodes the separate API/command and configuration string domains, and returns the C2 IP, campaign user ID, ASP paths, mutex, commands, APIs, custom-RC4 key and persistence strings. It never sends the inferred HTTP requests.

    python -m extractors.config_extractor --family spyglace --input C:\analysis\encoded.tmp --output C:\analysis\config.json

Detailed execution order and failure handling are in docs/APT-C60-2026-WORKFLOW.md.
- `donutloader` records delivery-layer markers and delegates terminal configuration extraction after static unpacking.
- Aliases: `pure`, `purerat`, and `donut`.
The family extractor accepts recovered payload bytes. It never executes the sample and never connects to configured infrastructure.


## ShadowPad


`shadowpad` first applies the ScatterBee resource decoder, then searches PE sections for
structurally valid x86/x64 Casper outer streams. Legacy payloads are decrypted, QuickLZ
decompressed, and parsed without loading the PE. The output separates public config
endpoints, RFC1918 builder/test context, and exact-hash public-source attribution.

## StealC

`stealc` identifies Base64/RC4 skip-key profiles and x86 paired-buffer XOR call sites.
It returns the full PHP gate, dependency directory, build ID, string key when present,
and decoded string count. Recovered endpoints are static configuration evidence only;
the extractor never executes a sample or performs a network request.

## Profile-defined Windows families

AsyncRAT, XWorm, QuasarRAT, njRAT, DarkComet, DCRat, RedLine Stealer,
Snake Keylogger, GuLoader, and HijackLoader are registered through
`profiles/windows_family_profiles.json`. `profiled_family.py` supplies bounded
ASCII/UTF-16LE extraction, marker/config-key correlation, secret-safe URL
sanitization, endpoint-role classification, and the common result contract.

A source signature or reviewed exact hash selects a family, but only a validated
decoded structure may establish a recovered config. Delivery URLs, public-IP
discovery services, certificate/documentation URLs, and C2 candidates have
separate roles. The extractor never contacts a value and never reports liveness.
See `analysis-framework/docs/PROFILED-FAMILY-EXPANSION.md` for the relationship
diagram and validation workflow.
## News campaign extractors

- `npm_supply_chain` decodes the axios/plain-crypto-js postinstall without invoking Node.js.
- `atlascross` decrypts the documented 324-byte AtlasCross configuration.

## Amadey and Latrodectus

- `amadey` validates the reviewed x86/x64 custom-alphabet/Base64 layout before
  returning C2 URLs, versions, campaign IDs, installation names, and RC4 keys.
  Themida/WinLicense wrappers remain unresolved until a terminal PE is
  recovered.
- `latrodectus` decrypts the reviewed legacy PRNG string layout and returns
  C2 URLs, versions, group names/FNV-1a IDs, RC4 keys, and discovery/update
  features. AES-CTR generations remain a separate parser profile.

Literal infrastructure without the family-specific validation structure is
reported as a candidate rather than confirmed C2. Extractors never contact it.
