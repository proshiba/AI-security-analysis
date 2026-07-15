# lummastealer case afa807cee34e8b931688ccf2be76b7ea5337af3d64714a348bead839c756643a

## Overview

- Original name: `afa807cee34e8b931688ccf2be76b7ea5337af3d64714a348bead839c756643a.exe`
- SHA-256: `afa807cee34e8b931688ccf2be76b7ea5337af3d64714a348bead839c756643a`
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

- Root entropy: 6.7219
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Current Lumma deliveries often contain a loader or protected layer instead of plaintext final config.
- Literal infrastructure remains candidate until family config use is established.
