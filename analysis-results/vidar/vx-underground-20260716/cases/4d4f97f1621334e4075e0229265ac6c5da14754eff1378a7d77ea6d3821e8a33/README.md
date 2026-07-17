# vidar case 4d4f97f1621334e4075e0229265ac6c5da14754eff1378a7d77ea6d3821e8a33

## Overview

- Original name: `4d4f97f1621334e4075e0229265ac6c5da14754eff1378a7d77ea6d3821e8a33`
- SHA-256: `4d4f97f1621334e4075e0229265ac6c5da14754eff1378a7d77ea6d3821e8a33`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `false`
- Packing classification: `managed_loader_or_obfuscated`
- Unpack status: `artifacts_recovered`
- Recovered static layers: 1
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | static extraction incomplete |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "campaign_shape": "direct_pe_or_pe_loader",
  "features": {
    "browser_collection": true,
    "wallet_collection": false,
    "telegram_dead_drop": false,
    "dependency_download": false
  },
  "static_config_recovered": false,
  "candidate_infrastructure_recovered": false,
  "scan_source": "complete_input",
  "original_size": 589312
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `dotnet-resource-opaque` | `cba5f445f663486fe835ee898c4a431fa414b251052cba0998492173f0bf56ef` | 329982 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.6796
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
