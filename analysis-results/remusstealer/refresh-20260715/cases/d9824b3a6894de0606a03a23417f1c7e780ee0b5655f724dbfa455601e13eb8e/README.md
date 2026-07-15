# remusstealer case d9824b3a6894de0606a03a23417f1c7e780ee0b5655f724dbfa455601e13eb8e

## Overview

- Original name: `d9824b3a6894de0606a03a23417f1c7e780ee0b5655f724dbfa455601e13eb8e.exe`
- SHA-256: `d9824b3a6894de0606a03a23417f1c7e780ee0b5655f724dbfa455601e13eb8e`
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
  "go_runtime": false,
  "archive_delivery": true
}
```

## Unpacking status

- Root entropy: 7.9631
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Encrypted inner 7z deliveries require the campaign password; password guessing is not performed.
- Remus attribution and infrastructure require recovered payload-level corroboration.
