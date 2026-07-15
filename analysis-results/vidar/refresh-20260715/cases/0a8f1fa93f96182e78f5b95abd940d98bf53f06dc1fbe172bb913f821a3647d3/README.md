# vidar case 0a8f1fa93f96182e78f5b95abd940d98bf53f06dc1fbe172bb913f821a3647d3

## Overview

- Original name: `0a8f1fa93f96182e78f5b95abd940d98bf53f06dc1fbe172bb913f821a3647d3.exe`
- SHA-256: `0a8f1fa93f96182e78f5b95abd940d98bf53f06dc1fbe172bb913f821a3647d3`
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

- Root entropy: 7.0331
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
