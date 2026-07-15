# valleyrat case ad4a584f5e622c10703bca28c58ee8372899edb48cc1ccf28a2cff87d1afbf2d

## Overview

- Original name: `ad4a584f5e622c10703bca28c58ee8372899edb48cc1ccf28a2cff87d1afbf2d.msi`
- SHA-256: `ad4a584f5e622c10703bca28c58ee8372899edb48cc1ccf28a2cff87d1afbf2d`
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

- Root entropy: 7.99
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Static strings alone do not prove an endpoint is C2.
- Campaign-specific decoded config should supersede candidates when available.


## 2026-07-15 unpacking reassessment

- OLE extraction recovered protected PE 136bdce277b8c810656eccc0b0e4b47f0fde81e1d5aba86a475a08d96b7a22a9, 3,778,560 bytes.
- The x64 image has only KERNEL32!GetLastError imported, zero-raw normal sections, and a high-entropy random-name RX entry section.
- Ghidra evidence confirms overlapping instructions, opaque predicates, internal thunks, rdtsc, and stack-state manipulation.
- Blocker: native_control_flow_obfuscation. The protected PE is not marked fully unpacked and was not executed or emulated.
