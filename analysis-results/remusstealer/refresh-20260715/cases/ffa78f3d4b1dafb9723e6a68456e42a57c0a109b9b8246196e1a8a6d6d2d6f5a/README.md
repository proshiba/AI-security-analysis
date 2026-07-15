# remusstealer case ffa78f3d4b1dafb9723e6a68456e42a57c0a109b9b8246196e1a8a6d6d2d6f5a

## Overview

- Original name: `ffa78f3d4b1dafb9723e6a68456e42a57c0a109b9b8246196e1a8a6d6d2d6f5a.exe`
- SHA-256: `ffa78f3d4b1dafb9723e6a68456e42a57c0a109b9b8246196e1a8a6d6d2d6f5a`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `false`
- Recovered static layers: 0
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| `http://31.77.168.180:5000/piva.exe` | payload_or_dependency_url | candidate | embedded_literal |

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

- Root entropy: 6.0858
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Encrypted inner 7z deliveries require the campaign password; password guessing is not performed.
- Remus attribution and infrastructure require recovered payload-level corroboration.
