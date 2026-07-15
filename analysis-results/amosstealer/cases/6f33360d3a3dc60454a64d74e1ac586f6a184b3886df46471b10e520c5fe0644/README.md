# amosstealer case 6f33360d3a3dc60454a64d74e1ac586f6a184b3886df46471b10e520c5fe0644

## Overview

- Original name: `6f33360d3a3dc60454a64d74e1ac586f6a184b3886df46471b10e520c5fe0644.vba`
- SHA-256: `6f33360d3a3dc60454a64d74e1ac586f6a184b3886df46471b10e520c5fe0644`
- Campaign shape: `script_delivery`
- Format: `script`
- Packing suspected: `false`
- Recovered static layers: 0
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| `https://nvoaagent.com/ledger/93ea36a257de15f2fe3f9d5d32fb19ee6e040fa3cd57131dedc33c740d868a89` | c2_or_exfil_candidate | probable | embedded_literal |
| `https://nvoaagent.com/ledger/live/93ea36a257de15f2fe3f9d5d32fb19ee6e040fa3cd57131dedc33c740d868a89` | c2_or_exfil_candidate | probable | embedded_literal |

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

- Root entropy: 4.5745
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- The `/ledger/` URL pattern is treated as probable exfil/C2 infrastructure, not proof of server ownership.
- Script and macro submissions can be delivery stages rather than the final Mach-O payload.
