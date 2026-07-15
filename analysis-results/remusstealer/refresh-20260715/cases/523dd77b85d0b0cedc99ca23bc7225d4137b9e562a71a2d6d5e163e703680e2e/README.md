# remusstealer case 523dd77b85d0b0cedc99ca23bc7225d4137b9e562a71a2d6d5e163e703680e2e

## Overview

- Original name: `523dd77b85d0b0cedc99ca23bc7225d4137b9e562a71a2d6d5e163e703680e2e.exe`
- SHA-256: `523dd77b85d0b0cedc99ca23bc7225d4137b9e562a71a2d6d5e163e703680e2e`
- Campaign shape: `go_pe_loader`
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
  "go_runtime": true,
  "archive_delivery": true
}
```

## Unpacking status

- Root entropy: 6.425
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Encrypted inner 7z deliveries require the campaign password; password guessing is not performed.
- Remus attribution and infrastructure require recovered payload-level corroboration.
