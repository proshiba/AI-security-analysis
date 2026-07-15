# Malware configuration extractors

`extractors/` は解析済みマルウェアの設定抽出を、解析engineやemulatorから独立して提供する。
検体を実行せず、外部通信も行わない。出力は全familyで共通のJSON契約を使用する。

## Supported families

| ID | 抽出対象 | 確定条件 |
|---|---|---|
| `valleyrat` | variant、endpoint、config/stage URL | 復号済みconfigがない文字列候補は`inferred` |
| `agenttesla` | FTP/SMTP/HTTP/Telegram/Discord候補 | credential値は出力せず、存在フラグだけを残す |
| `remcosrat` | family marker、endpoint候補 | encrypted/resource config未復元時は確定しない |
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

- ormbook: delivery shape, injection/credential markers, and recursively recovered infrastructure literals
- idar: unpacked collection/dependency/dead-drop candidates
- lummastealer: loader/packer, build, browser/wallet, and API candidates
- emusstealer: encrypted-archive, Go/native loader, browser/wallet, and infrastructure candidates
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
