# vidar case 4c958205aa4c56b148377b2bd984a7b3b6525bbc914cf8e5aaa34ce91f71d4cc

## Overview

- Original name: `4c958205aa4c56b148377b2bd984a7b3b6525bbc914cf8e5aaa34ce91f71d4cc.exe`
- SHA-256: `4c958205aa4c56b148377b2bd984a7b3b6525bbc914cf8e5aaa34ce91f71d4cc`
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
  "wallet_collection": false,
  "telegram_dead_drop": false,
  "dependency_download": false
}
```

## Unpacking status

- Root entropy: 7.9977
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
