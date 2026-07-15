# remusstealer case 5eb378956ee84899b8ec8a59d0b9d5e95bef39cfce2acdfe72b032ea4e704227

## Overview

- Original name: `5eb378956ee84899b8ec8a59d0b9d5e95bef39cfce2acdfe72b032ea4e704227.exe`
- SHA-256: `5eb378956ee84899b8ec8a59d0b9d5e95bef39cfce2acdfe72b032ea4e704227`
- Campaign shape: `go_pe_loader`
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
  "wallet_collection": false,
  "go_runtime": true,
  "archive_delivery": false
}
```

## Unpacking status

- Root entropy: 6.4161
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Encrypted inner 7z deliveries require the campaign password; password guessing is not performed.
- Remus attribution and infrastructure require recovered payload-level corroboration.
