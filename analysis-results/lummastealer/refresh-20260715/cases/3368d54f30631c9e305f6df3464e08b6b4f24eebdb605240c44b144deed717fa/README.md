# lummastealer case 3368d54f30631c9e305f6df3464e08b6b4f24eebdb605240c44b144deed717fa

## Overview

- Original name: `3368d54f30631c9e305f6df3464e08b6b4f24eebdb605240c44b144deed717fa.exe`
- SHA-256: `3368d54f30631c9e305f6df3464e08b6b4f24eebdb605240c44b144deed717fa`
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
  "browser_collection": true,
  "wallet_collection": true,
  "loader_or_packer": true,
  "c2_api": true
}
```

## Unpacking status

- Root entropy: 6.4282
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Current Lumma deliveries often contain a loader or protected layer instead of plaintext final config.
- Literal infrastructure remains candidate until family config use is established.
