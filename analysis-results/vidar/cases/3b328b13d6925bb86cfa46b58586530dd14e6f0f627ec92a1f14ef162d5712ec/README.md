# vidar case 3b328b13d6925bb86cfa46b58586530dd14e6f0f627ec92a1f14ef162d5712ec

## Overview

- Original name: `3b328b13d6925bb86cfa46b58586530dd14e6f0f627ec92a1f14ef162d5712ec.exe`
- SHA-256: `3b328b13d6925bb86cfa46b58586530dd14e6f0f627ec92a1f14ef162d5712ec`
- Campaign shape: `direct_pe_or_pe_loader`
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
  "telegram_dead_drop": false,
  "dependency_download": false
}
```

## Unpacking status

- Root entropy: 7.2435
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
