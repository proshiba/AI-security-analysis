# vidar case 07c295310759ecd7a42fbf3cb96ca1c5b7f45c7e59ac9704b78431000fae5a87

## Overview

- Original name: `07c295310759ecd7a42fbf3cb96ca1c5b7f45c7e59ac9704b78431000fae5a87.exe`
- SHA-256: `07c295310759ecd7a42fbf3cb96ca1c5b7f45c7e59ac9704b78431000fae5a87`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `true`
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
  "wallet_collection": false,
  "telegram_dead_drop": false,
  "dependency_download": false
}
```

## Unpacking status

- Root entropy: 8.0
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
