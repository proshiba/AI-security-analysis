# remusstealer case d5d5465b53f72727b8218dab4165b954748d29ab8f8de275fbd3a6fac0e08b6d

## Overview

- Original name: `d5d5465b53f72727b8218dab4165b954748d29ab8f8de275fbd3a6fac0e08b6d.exe`
- SHA-256: `d5d5465b53f72727b8218dab4165b954748d29ab8f8de275fbd3a6fac0e08b6d`
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

- Root entropy: 6.4258
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Encrypted inner 7z deliveries require the campaign password; password guessing is not performed.
- Remus attribution and infrastructure require recovered payload-level corroboration.
