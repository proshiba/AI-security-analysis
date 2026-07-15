# remusstealer case cd362b63aa5130a6290d1326abc883309aa218a5869e82ecd2c106a80de61047

## Overview

- Original name: `cd362b63aa5130a6290d1326abc883309aa218a5869e82ecd2c106a80de61047.exe`
- SHA-256: `cd362b63aa5130a6290d1326abc883309aa218a5869e82ecd2c106a80de61047`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `true`
- Recovered static layers: 1
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
  "archive_delivery": false
}
```

## Unpacking status

- Root entropy: 6.9786
- Root packing assessment: `True`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Encrypted inner 7z deliveries require the campaign password; password guessing is not performed.
- Remus attribution and infrastructure require recovered payload-level corroboration.
