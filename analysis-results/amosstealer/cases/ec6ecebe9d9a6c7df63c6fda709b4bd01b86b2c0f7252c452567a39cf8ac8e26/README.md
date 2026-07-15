# amosstealer case ec6ecebe9d9a6c7df63c6fda709b4bd01b86b2c0f7252c452567a39cf8ac8e26

## Overview

- Original name: `ec6ecebe9d9a6c7df63c6fda709b4bd01b86b2c0f7252c452567a39cf8ac8e26.macho`
- SHA-256: `ec6ecebe9d9a6c7df63c6fda709b4bd01b86b2c0f7252c452567a39cf8ac8e26`
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

- Root entropy: 6.3663
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- The `/ledger/` URL pattern is treated as probable exfil/C2 infrastructure, not proof of server ownership.
- Script and macro submissions can be delivery stages rather than the final Mach-O payload.
