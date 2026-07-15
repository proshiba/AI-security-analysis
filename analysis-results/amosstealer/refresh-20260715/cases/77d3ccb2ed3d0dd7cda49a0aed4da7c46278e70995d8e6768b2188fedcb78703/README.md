# amosstealer case 77d3ccb2ed3d0dd7cda49a0aed4da7c46278e70995d8e6768b2188fedcb78703

## Overview

- Original name: `77d3ccb2ed3d0dd7cda49a0aed4da7c46278e70995d8e6768b2188fedcb78703.macho`
- SHA-256: `77d3ccb2ed3d0dd7cda49a0aed4da7c46278e70995d8e6768b2188fedcb78703`
- Campaign shape: `direct_macho`
- Format: `macho`
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
  "keychain_collection": false,
  "browser_collection": false,
  "wallet_collection": false,
  "apple_script": false,
  "user_prompt": false
}
```

## Unpacking status

- Root entropy: 6.119
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- The `/ledger/` URL pattern is treated as probable exfil/C2 infrastructure, not proof of server ownership.
- Script and macro submissions can be delivery stages rather than the final Mach-O payload.
