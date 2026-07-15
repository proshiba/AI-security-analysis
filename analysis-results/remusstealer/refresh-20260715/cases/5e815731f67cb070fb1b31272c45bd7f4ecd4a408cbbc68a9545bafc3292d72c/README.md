# remusstealer case 5e815731f67cb070fb1b31272c45bd7f4ecd4a408cbbc68a9545bafc3292d72c

## Overview

- Original name: `5e815731f67cb070fb1b31272c45bd7f4ecd4a408cbbc68a9545bafc3292d72c.exe`
- SHA-256: `5e815731f67cb070fb1b31272c45bd7f4ecd4a408cbbc68a9545bafc3292d72c`
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
  "go_runtime": false,
  "archive_delivery": true
}
```

## Unpacking status

- Root entropy: 7.002
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Encrypted inner 7z deliveries require the campaign password; password guessing is not performed.
- Remus attribution and infrastructure require recovered payload-level corroboration.

## 2026-07-15 unpacking reassessment

- This remains a true unresolved native protector, not an encrypted 7z case.
- x64 PE, zero imports, .rdata entropy 7.9942, API hash resolution, approximately 0x36400-byte RWX allocation, and an in-memory loader were confirmed.
- Ghidra analysis identified the bespoke transform/state-machine area around 0x140001730; no stable constant-key transform could be extracted safely.
- Blocker: native_control_flow_obfuscation. The sample and loader stub were not executed or emulated.