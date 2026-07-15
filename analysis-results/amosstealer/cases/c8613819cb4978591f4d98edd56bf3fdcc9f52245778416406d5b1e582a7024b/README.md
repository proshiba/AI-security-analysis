# amosstealer case c8613819cb4978591f4d98edd56bf3fdcc9f52245778416406d5b1e582a7024b

## Overview

- Original name: `c8613819cb4978591f4d98edd56bf3fdcc9f52245778416406d5b1e582a7024b.macho`
- SHA-256: `c8613819cb4978591f4d98edd56bf3fdcc9f52245778416406d5b1e582a7024b`
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

- Root entropy: 6.0301
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- The `/ledger/` URL pattern is treated as probable exfil/C2 infrastructure, not proof of server ownership.
- Script and macro submissions can be delivery stages rather than the final Mach-O payload.
