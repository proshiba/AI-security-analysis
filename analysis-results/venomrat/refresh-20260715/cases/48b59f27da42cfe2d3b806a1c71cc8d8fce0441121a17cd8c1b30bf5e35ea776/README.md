# venomrat case 48b59f27da42cfe2d3b806a1c71cc8d8fce0441121a17cd8c1b30bf5e35ea776

## Overview

- Original name: `48b59f27da42cfe2d3b806a1c71cc8d8fce0441121a17cd8c1b30bf5e35ea776.rar`
- SHA-256: `48b59f27da42cfe2d3b806a1c71cc8d8fce0441121a17cd8c1b30bf5e35ea776`
- Campaign shape: `unknown_or_nested_delivery`
- Format: rar
- Packing suspected: `false`
- Recovered static layers: 3
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

- Root entropy: 7.9976
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Encrypted resource loaders require a recovered final payload before config can be confirmed.

## 2026-07-15 unpacking reassessment

- RAR5 extraction recovered JavaScript SHA-256 579085581348296ae88419296edc6a8e91acf4463c7994112b5c3f7f3653710e.
- Recursive static processing recovered PowerShell 8e79cf0ca453f8aaaf9e145ba0678790e4adf6e1fdc3c3e8ab8d3126641af08d and terminal PE 4246bf9121476cc6fb8d2f69c6263a7b4d31a331bd02dd9a7603e6200fb9725b.
- Terminal PE is 361,984-byte x64 .NET and is not packed.