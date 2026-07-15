# vidar case 5bcc428f37655c7bc16110cc2127c510f66827a382cb1c9fa251b15a7d2c214b

## Overview

- Original name: `5bcc428f37655c7bc16110cc2127c510f66827a382cb1c9fa251b15a7d2c214b.exe`
- SHA-256: `5bcc428f37655c7bc16110cc2127c510f66827a382cb1c9fa251b15a7d2c214b`
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

- Root entropy: 6.9677
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
