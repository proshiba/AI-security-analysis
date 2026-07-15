# valleyrat case 81f68f61a8f7cf1accca338fd196051020bf60885aad409332091b759ff818d9

## Overview

- Original name: `81f68f61a8f7cf1accca338fd196051020bf60885aad409332091b759ff818d9.msi`
- SHA-256: `81f68f61a8f7cf1accca338fd196051020bf60885aad409332091b759ff818d9`
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

- Root entropy: 7.9831
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Static strings alone do not prove an endpoint is C2.
- Campaign-specific decoded config should supersede candidates when available.


## 2026-07-15 unpacking reassessment

- OLE extraction recovered protected PE 1982d5168c430ee373e6bcbd99322b844bdb5942f778bc9d4b141e7c27182105, 3,764,736 bytes.
- The x64 image has only KERNEL32!GetLastError imported, zero-raw normal sections, and a high-entropy random-name RX entry section.
- Ghidra evidence confirms overlapping instructions, opaque predicates, internal thunks, rdtsc, and stack-state manipulation.
- Blocker: native_control_flow_obfuscation. The protected PE is not marked fully unpacked and was not executed or emulated.
