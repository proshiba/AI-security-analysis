# amosstealer case e3b5a5dbbccab4cf36c7abf5cb5ae83062dd1b5dee7db04bddbf53fc9ebdb233

## Overview

- Original name: `e3b5a5dbbccab4cf36c7abf5cb5ae83062dd1b5dee7db04bddbf53fc9ebdb233.sh`
- SHA-256: `e3b5a5dbbccab4cf36c7abf5cb5ae83062dd1b5dee7db04bddbf53fc9ebdb233`
- Campaign shape: `script_delivery`
- Format: `data`
- Packing suspected: `false`
- Recovered static layers: 0
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| `http://91.92.242.30/dx2w5j5bka6qkwxi` | candidate_infrastructure | candidate | embedded_literal |

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

- Root entropy: 4.8289
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- The `/ledger/` URL pattern is treated as probable exfil/C2 infrastructure, not proof of server ownership.
- Script and macro submissions can be delivery stages rather than the final Mach-O payload.
