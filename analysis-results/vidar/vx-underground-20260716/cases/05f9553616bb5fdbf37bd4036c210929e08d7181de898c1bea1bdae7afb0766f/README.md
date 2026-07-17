# vidar case 05f9553616bb5fdbf37bd4036c210929e08d7181de898c1bea1bdae7afb0766f

## Overview

- Original name: `05f9553616bb5fdbf37bd4036c210929e08d7181de898c1bea1bdae7afb0766f`
- SHA-256: `05f9553616bb5fdbf37bd4036c210929e08d7181de898c1bea1bdae7afb0766f`
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
    "browser_collection": false,
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
| 1 | `dotnet-resource-opaque` | `0069f99ba31c52f1dfc1b1f61dd0062469a9eef45b89175060b41cec598e8850` | 329982 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.6342
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
