# lummastealer case 794a4e96a5f9590ae52fc0b9fb8cffed73f8b4bdd915a55bb207bfcacb45b92d

## Overview

- Original name: `794a4e96a5f9590ae52fc0b9fb8cffed73f8b4bdd915a55bb207bfcacb45b92d.exe`
- SHA-256: `794a4e96a5f9590ae52fc0b9fb8cffed73f8b4bdd915a55bb207bfcacb45b92d`
- Campaign shape: `go_pe_loader`
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
  "loader_or_packer": true,
  "c2_api": false
}
```

## Unpacking status

- Root entropy: 6.6288
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Current Lumma deliveries often contain a loader or protected layer instead of plaintext final config.
- Literal infrastructure remains candidate until family config use is established.
