# vidar case b6b6df6abb52d7d2e2eb8496c04d76e2a01e51703b7ce44aa127d60ce53a0be7

## Overview

- Original name: `b6b6df6abb52d7d2e2eb8496c04d76e2a01e51703b7ce44aa127d60ce53a0be7`
- SHA-256: `b6b6df6abb52d7d2e2eb8496c04d76e2a01e51703b7ce44aa127d60ce53a0be7`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `false`
- Packing classification: `not_packed`
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
  "original_size": 674304
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| - | none recovered | - | - | - |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.6447
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
