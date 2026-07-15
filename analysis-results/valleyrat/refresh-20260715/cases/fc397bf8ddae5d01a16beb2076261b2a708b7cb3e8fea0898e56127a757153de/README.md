# valleyrat case fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de

## Overview

- Original name: `fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de.msi`
- SHA-256: `fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de`
- Campaign shape: `macro_office_delivery`
- Format: `ole`
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
{}
```

## Unpacking status

- Root entropy: 7.9843
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Static strings alone do not prove an endpoint is C2.
- Campaign-specific decoded config should supersede candidates when available.


## 2026-07-15 unpacking reassessment

- OLE extraction recovered protected PE db720e674a25318cd09e35d8fae5b43faaa3acf9dfe04f5b6ea23d8c0c414779, 3,819,008 bytes.
- The x64 image has only KERNEL32!GetLastError imported, zero-raw normal sections, and a high-entropy random-name RX entry section.
- Ghidra evidence confirms overlapping instructions, opaque predicates, internal thunks, rdtsc, and stack-state manipulation.
- Blocker: native_control_flow_obfuscation. The protected PE is not marked fully unpacked and was not executed or emulated.
