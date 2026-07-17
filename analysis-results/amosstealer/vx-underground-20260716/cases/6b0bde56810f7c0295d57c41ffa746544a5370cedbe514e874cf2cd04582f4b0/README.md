# amosstealer case 6b0bde56810f7c0295d57c41ffa746544a5370cedbe514e874cf2cd04582f4b0

## Overview

- Original name: `6b0bde56810f7c0295d57c41ffa746544a5370cedbe514e874cf2cd04582f4b0`
- SHA-256: `6b0bde56810f7c0295d57c41ffa746544a5370cedbe514e874cf2cd04582f4b0`
- Campaign shape: `xz_macho_delivery`
- Format: `xz`
- Packing suspected: `false`
- Packing classification: `not_applicable`
- Unpack status: `artifacts_recovered`
- Recovered static layers: 3
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | static extraction incomplete |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "campaign_shape": "unknown_or_nested_delivery",
  "features": {
    "keychain_collection": false,
    "browser_collection": false,
    "wallet_collection": false,
    "apple_script": false,
    "user_prompt": false
  },
  "static_config_recovered": false
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `xz-decompressed` | `3e64db660cb31e357a7b53421b3bf15ee28d5c057734f3fe96ba229096838272` | 3023360 | `apple-disk-image` |
| 2 | `7z-macho` | `91cca8b573d9bfdbe2d7ff74ce31acee7a3a9f8e0034841af38d96a1d4ad02f4` | 381088 | `macho` |
| 2 | `7z-macho` | `7668dcab16c2f16396dd0d3a580bca89a3675462c1e9f98e79d75d6e7e6c8c1f` | 386640 | `macho` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.9944
- Root packing assessment: `False`
- Recursive layers analyzed: 3
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- The `/ledger/` URL pattern is treated as probable exfil/C2 infrastructure, not proof of server ownership.
- Script and macro submissions can be delivery stages rather than the final Mach-O payload.
