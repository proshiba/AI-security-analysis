# lummastealer case 4e5b2ae91379b8069c04c6639bb0bca5ddea0dde567bea8cb9bc9822b9cdda0d

## Overview

- Original name: `4e5b2ae91379b8069c04c6639bb0bca5ddea0dde567bea8cb9bc9822b9cdda0d.exe`
- SHA-256: `4e5b2ae91379b8069c04c6639bb0bca5ddea0dde567bea8cb9bc9822b9cdda0d`
- Campaign shape: `packed_native_pe`
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

- Root entropy: 7.9828
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Current Lumma deliveries often contain a loader or protected layer instead of plaintext final config.
- Literal infrastructure remains candidate until family config use is established.
