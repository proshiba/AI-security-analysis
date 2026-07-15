# remcosrat case 78b21599a83dbfad39c17202d37dd2b6d552c9679755bc199a9826f3dd0e40db

## Overview

- Original name: `78b21599a83dbfad39c17202d37dd2b6d552c9679755bc199a9826f3dd0e40db.exe`
- SHA-256: `78b21599a83dbfad39c17202d37dd2b6d552c9679755bc199a9826f3dd0e40db`
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
{}
```

## Unpacking status

- Root entropy: 7.8037
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Remcos configuration may be encrypted or resource-backed.
- Literal endpoints require config-reference or process-attributed validation.

## 2026-07-15 unpacking reassessment

- NSIS word-XOR key 0x17d68b37 recovered a 1,024-byte System-plugin command stream.
- Static x64 constant propagation identified source offset 8,282, dword XOR key 0xe7c94882, length 435,824, and step 4.
- Intermediate loader SHA-256 e9ed0be544b08189ceca2ec8e6ae8f74d62335ed006f0b207fb211df6bbdcb3a was recovered.
- The intermediate begins with native code rather than a PE header and remains control-flow obfuscated. Final payload recovery is incomplete.
- Blocker: native_control_flow_obfuscation; no loader execution or emulation was performed.