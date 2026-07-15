# venomrat case d7de7d851061a99e6f2ca256aba5badf90778f566fc528db6396a4180901ac26

## Overview

- Original name: `d7de7d851061a99e6f2ca256aba5badf90778f566fc528db6396a4180901ac26.js`
- SHA-256: `d7de7d851061a99e6f2ca256aba5badf90778f566fc528db6396a4180901ac26`
- Campaign shape: `script_delivery`
- Format: `script`
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

- Root entropy: 5.2908
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Encrypted resource loaders require a recovered final payload before config can be confirmed.

## 2026-07-15 unpacking reassessment

- Recovered 2,642-byte PowerShell SHA-256 e6c6e79551e53a899c72312c663af8f8ffefa401cd51972255a07bd01b7bb051.
- Reassembled 80 Unicode environment chunks, then reproduced the embedded AES-CBC/PKCS7 and GZip recipe.
- Terminal PE SHA-256 16109f93bcddf8dec5e21057f35b3da437d94976f503f45b217232c26b65515e, 237,568 bytes, x64 .NET, not packed.
- One script resource was also retained for recursive analysis.