# amosstealer case a0e66f3067e4aaf5b83e45b7845cc43b2fc96032a4398cab7cc9d11f4f962e91

## Overview

- Original name: `a0e66f3067e4aaf5b83e45b7845cc43b2fc96032a4398cab7cc9d11f4f962e91.macho`
- SHA-256: `a0e66f3067e4aaf5b83e45b7845cc43b2fc96032a4398cab7cc9d11f4f962e91`
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

- Root entropy: 6.1189
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- The `/ledger/` URL pattern is treated as probable exfil/C2 infrastructure, not proof of server ownership.
- Script and macro submissions can be delivery stages rather than the final Mach-O payload.
