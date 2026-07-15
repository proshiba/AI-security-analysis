# lummastealer case c1d067c076f8d0d818aca72cefa32df501a6a887d96e407bdfe08d712b6ff781

## Overview

- Original name: `c1d067c076f8d0d818aca72cefa32df501a6a887d96e407bdfe08d712b6ff781.exe`
- SHA-256: `c1d067c076f8d0d818aca72cefa32df501a6a887d96e407bdfe08d712b6ff781`
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

- Root entropy: 6.9523
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Current Lumma deliveries often contain a loader or protected layer instead of plaintext final config.
- Literal infrastructure remains candidate until family config use is established.
