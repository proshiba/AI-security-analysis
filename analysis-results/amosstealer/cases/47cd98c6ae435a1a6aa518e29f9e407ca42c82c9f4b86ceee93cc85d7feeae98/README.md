# amosstealer case 47cd98c6ae435a1a6aa518e29f9e407ca42c82c9f4b86ceee93cc85d7feeae98

## Overview

- Original name: `47cd98c6ae435a1a6aa518e29f9e407ca42c82c9f4b86ceee93cc85d7feeae98.vbs`
- SHA-256: `47cd98c6ae435a1a6aa518e29f9e407ca42c82c9f4b86ceee93cc85d7feeae98`
- Campaign shape: `script_delivery`
- Format: `script`
- Packing suspected: `false`
- Recovered static layers: 0
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| `https://northernvirginiapainting.com/ledger/2fc78a36ea00d10a6d4fbba34bd924464f978f9598d97014a4a78a90eb3c6525` | c2_or_exfil_candidate | probable | embedded_literal |
| `https://northernvirginiapainting.com/ledger/live/2fc78a36ea00d10a6d4fbba34bd924464f978f9598d97014a4a78a90eb3c6525` | c2_or_exfil_candidate | probable | embedded_literal |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Collection/behavior features

```json
{
  "keychain_collection": true,
  "browser_collection": true,
  "wallet_collection": true,
  "apple_script": true,
  "user_prompt": true
}
```

## Unpacking status

- Root entropy: 3.3149
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- The `/ledger/` URL pattern is treated as probable exfil/C2 infrastructure, not proof of server ownership.
- Script and macro submissions can be delivery stages rather than the final Mach-O payload.
