# amosstealer case ce3c57e6c025911a916a61a716ff32f2699f3e3a84eb0ebbe892a5d4b8fb9c7a

## Overview

- Original name: `ce3c57e6c025911a916a61a716ff32f2699f3e3a84eb0ebbe892a5d4b8fb9c7a`
- SHA-256: `ce3c57e6c025911a916a61a716ff32f2699f3e3a84eb0ebbe892a5d4b8fb9c7a`
- Campaign shape: `direct_macho`
- Format: `macho`
- Packing suspected: `false`
- Packing classification: `not_applicable`
- Unpack status: `artifacts_recovered`
- Recovered static layers: 2
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
  "campaign_shape": "direct_macho",
  "family_markers": [
    "Atomic",
    "Login Data",
    "keychain",
    "osascript"
  ],
  "features": {
    "keychain_collection": true,
    "browser_collection": true,
    "wallet_collection": true,
    "apple_script": true,
    "user_prompt": true
  },
  "static_config_recovered": false
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `macho-slice-0` | `7668dcab16c2f16396dd0d3a580bca89a3675462c1e9f98e79d75d6e7e6c8c1f` | 386640 | `macho` |
| 1 | `macho-slice-1` | `91cca8b573d9bfdbe2d7ff74ce31acee7a3a9f8e0034841af38d96a1d4ad02f4` | 381088 | `macho` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 5.3567
- Root packing assessment: `False`
- Recursive layers analyzed: 2
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- The `/ledger/` URL pattern is treated as probable exfil/C2 infrastructure, not proof of server ownership.
- Script and macro submissions can be delivery stages rather than the final Mach-O payload.
