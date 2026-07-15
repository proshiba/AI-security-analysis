# remusstealer case c20a551057c10e699156ebeb57677cb51625534d8256a3dd3cd8b3efbca5235c

## Overview

- Original name: `c20a551057c10e699156ebeb57677cb51625534d8256a3dd3cd8b3efbca5235c.exe`
- SHA-256: `c20a551057c10e699156ebeb57677cb51625534d8256a3dd3cd8b3efbca5235c`
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
  "wallet_collection": false,
  "go_runtime": false,
  "archive_delivery": false
}
```

## Unpacking status

- Root entropy: 6.3076
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Encrypted inner 7z deliveries require the campaign password; password guessing is not performed.
- Remus attribution and infrastructure require recovered payload-level corroboration.
