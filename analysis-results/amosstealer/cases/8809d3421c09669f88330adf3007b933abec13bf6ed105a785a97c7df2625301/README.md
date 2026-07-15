# amosstealer case 8809d3421c09669f88330adf3007b933abec13bf6ed105a785a97c7df2625301

## Overview

- Original name: `8809d3421c09669f88330adf3007b933abec13bf6ed105a785a97c7df2625301.osascript`
- SHA-256: `8809d3421c09669f88330adf3007b933abec13bf6ed105a785a97c7df2625301`
- Campaign shape: `script_delivery`
- Format: `script`
- Packing suspected: `false`
- Recovered static layers: 0
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| `https://flwoagent.com/ledger/484e513fdf967e35d2e21b8b88df0a2867c1abf6045e4ec41974ae927abb2140` | c2_or_exfil_candidate | probable | embedded_literal |
| `https://flwoagent.com/ledger/live/484e513fdf967e35d2e21b8b88df0a2867c1abf6045e4ec41974ae927abb2140` | c2_or_exfil_candidate | probable | embedded_literal |

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

- Root entropy: 4.5798
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- The `/ledger/` URL pattern is treated as probable exfil/C2 infrastructure, not proof of server ownership.
- Script and macro submissions can be delivery stages rather than the final Mach-O payload.
