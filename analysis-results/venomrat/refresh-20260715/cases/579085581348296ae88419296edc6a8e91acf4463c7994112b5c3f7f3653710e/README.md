# venomrat case 579085581348296ae88419296edc6a8e91acf4463c7994112b5c3f7f3653710e

## Overview

- Original name: `579085581348296ae88419296edc6a8e91acf4463c7994112b5c3f7f3653710e.js`
- SHA-256: `579085581348296ae88419296edc6a8e91acf4463c7994112b5c3f7f3653710e`
- Campaign shape: `script_delivery`
- Format: `script`
- Packing suspected: `false`
- Recovered static layers: 2
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

- Root entropy: 3.2552
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Encrypted resource loaders require a recovered final payload before config can be confirmed.

## 2026-07-15 unpacking reassessment

- Recovered 7,983-byte PowerShell SHA-256 8e79cf0ca453f8aaaf9e145ba0678790e4adf6e1fdc3c3e8ab8d3126641af08d by bounded numeric-array XOR evaluation.
- Reassembled 366 Unicode environment chunks with the explicit char-minus-19968 transform.
- Terminal PE SHA-256 4246bf9121476cc6fb8d2f69c6263a7b4d31a331bd02dd9a7603e6200fb9725b, 361,984 bytes, x64 .NET, not packed.
- No JavaScript, PowerShell, or recovered PE was executed; no network was contacted.