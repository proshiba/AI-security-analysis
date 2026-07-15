# vidar case 1e13c2c9eac72daf63fd00a9946878949e159ae6ec51b54ec64f942d79d61913

## Overview

- Original name: `1e13c2c9eac72daf63fd00a9946878949e159ae6ec51b54ec64f942d79d61913.exe`
- SHA-256: `1e13c2c9eac72daf63fd00a9946878949e159ae6ec51b54ec64f942d79d61913`
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
  "wallet_collection": true,
  "telegram_dead_drop": false,
  "dependency_download": false
}
```

## Unpacking status

- Root entropy: 6.9494
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
