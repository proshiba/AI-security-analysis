# remusstealer case 4049128f0308d05dcb8d24b668f69238d720199de32ba0d8304cd3c3b3bde1b9

## Overview

- Original name: `4049128f0308d05dcb8d24b668f69238d720199de32ba0d8304cd3c3b3bde1b9.exe`
- SHA-256: `4049128f0308d05dcb8d24b668f69238d720199de32ba0d8304cd3c3b3bde1b9`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `false`
- Recovered static layers: 0
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| `http://31.77.168.180:5000/umvbr.bin` | candidate_infrastructure | candidate | embedded_literal |

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

- Root entropy: 6.2921
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Encrypted inner 7z deliveries require the campaign password; password guessing is not performed.
- Remus attribution and infrastructure require recovered payload-level corroboration.
