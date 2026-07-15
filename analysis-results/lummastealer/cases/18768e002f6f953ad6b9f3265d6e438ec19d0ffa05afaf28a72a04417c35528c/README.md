# lummastealer case 18768e002f6f953ad6b9f3265d6e438ec19d0ffa05afaf28a72a04417c35528c

## Overview

- Original name: `18768e002f6f953ad6b9f3265d6e438ec19d0ffa05afaf28a72a04417c35528c.exe`
- SHA-256: `18768e002f6f953ad6b9f3265d6e438ec19d0ffa05afaf28a72a04417c35528c`
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
  "loader_or_packer": true,
  "c2_api": false
}
```

## Unpacking status

- Root entropy: 2.9694
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Current Lumma deliveries often contain a loader or protected layer instead of plaintext final config.
- Literal infrastructure remains candidate until family config use is established.
