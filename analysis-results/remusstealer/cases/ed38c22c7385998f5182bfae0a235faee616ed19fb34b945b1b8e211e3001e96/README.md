# remusstealer case ed38c22c7385998f5182bfae0a235faee616ed19fb34b945b1b8e211e3001e96

## Overview

- Original name: `ed38c22c7385998f5182bfae0a235faee616ed19fb34b945b1b8e211e3001e96.7z`
- SHA-256: `ed38c22c7385998f5182bfae0a235faee616ed19fb34b945b1b8e211e3001e96`
- Campaign shape: `encrypted_7z_delivery`
- Format: `7z`
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
  "archive_delivery": true
}
```

## Unpacking status

- Root entropy: 8.0
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `encrypted_or_unsupported`
- UPX status: `not_applicable`

## Limitations

- Encrypted inner 7z deliveries require the campaign password; password guessing is not performed.
- Remus attribution and infrastructure require recovered payload-level corroboration.
