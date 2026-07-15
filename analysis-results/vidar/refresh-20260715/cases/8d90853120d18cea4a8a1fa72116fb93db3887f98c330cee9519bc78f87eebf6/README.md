# vidar case 8d90853120d18cea4a8a1fa72116fb93db3887f98c330cee9519bc78f87eebf6

## Overview

- Original name: `8d90853120d18cea4a8a1fa72116fb93db3887f98c330cee9519bc78f87eebf6.exe`
- SHA-256: `8d90853120d18cea4a8a1fa72116fb93db3887f98c330cee9519bc78f87eebf6`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `false`
- Recovered static layers: 0
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | static extraction incomplete |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Collection/behavior features

```json
{
  "browser_collection": false,
  "wallet_collection": true,
  "telegram_dead_drop": false,
  "dependency_download": false
}
```

## Unpacking status

- Root entropy: 7.0152
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
