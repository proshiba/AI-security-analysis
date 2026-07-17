# vidar case 3a521823d79686fad0595f9e90940c8a7451f7343bf64f4dbfcdcbde9115957d

## Overview

- Original name: `3a521823d79686fad0595f9e90940c8a7451f7343bf64f4dbfcdcbde9115957d`
- SHA-256: `3a521823d79686fad0595f9e90940c8a7451f7343bf64f4dbfcdcbde9115957d`
- Campaign shape: `nested_or_protected_delivery`
- Format: `data`
- Packing suspected: `false`
- Packing classification: `not_applicable`
- Unpack status: `no_artifact_recovered`
- Recovered static layers: 0
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
  "campaign_shape": "unknown_or_nested_delivery",
  "features": {
    "browser_collection": false,
    "wallet_collection": false,
    "telegram_dead_drop": false,
    "dependency_download": false
  },
  "static_config_recovered": false,
  "candidate_infrastructure_recovered": false,
  "scan_source": "complete_input",
  "original_size": 2710
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| - | none recovered | - | - | - |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 5.3521
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
