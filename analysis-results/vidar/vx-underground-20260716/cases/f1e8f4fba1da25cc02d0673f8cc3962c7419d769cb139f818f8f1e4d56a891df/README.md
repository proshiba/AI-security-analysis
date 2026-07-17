# vidar case f1e8f4fba1da25cc02d0673f8cc3962c7419d769cb139f818f8f1e4d56a891df

## Overview

- Original name: `f1e8f4fba1da25cc02d0673f8cc3962c7419d769cb139f818f8f1e4d56a891df`
- SHA-256: `f1e8f4fba1da25cc02d0673f8cc3962c7419d769cb139f818f8f1e4d56a891df`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `false`
- Packing classification: `not_packed`
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
  "scan_source": "inflated_pe_compacted",
  "original_size": 761452376
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `pe-inflated-gap-removed` | `0b609f79c18acb2ccada73ca2df6da0433d71bda671a2599f64bb7f7016a8657` | 2199040 | `pe` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 0.9258
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
