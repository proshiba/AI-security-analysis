# vidar case 71911c8f6eacf5ba5414bc8a66ac83a981aaf4d1141f5117ed6c2ad196c558fc

## Overview

- Original name: `71911c8f6eacf5ba5414bc8a66ac83a981aaf4d1141f5117ed6c2ad196c558fc.exe`
- SHA-256: `71911c8f6eacf5ba5414bc8a66ac83a981aaf4d1141f5117ed6c2ad196c558fc`
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

- Root entropy: 7.0572
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
