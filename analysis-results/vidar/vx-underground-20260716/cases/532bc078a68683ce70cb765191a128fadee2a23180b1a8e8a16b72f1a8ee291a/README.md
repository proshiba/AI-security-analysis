# vidar case 532bc078a68683ce70cb765191a128fadee2a23180b1a8e8a16b72f1a8ee291a

## Overview

- Original name: `532BC078A68683CE70CB765191A128FADEE2A23180B1A8E8A16B72F1A8EE291A`
- SHA-256: `532bc078a68683ce70cb765191a128fadee2a23180b1a8e8a16b72f1a8ee291a`
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
  "family_markers": [
    "Autofill",
    "information.txt",
    "passwords.txt",
    "wallets"
  ],
  "features": {
    "browser_collection": true,
    "wallet_collection": false,
    "telegram_dead_drop": false,
    "dependency_download": true
  },
  "static_config_recovered": false,
  "candidate_infrastructure_recovered": false,
  "scan_source": "complete_input",
  "original_size": 879104
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| - | none recovered | - | - | - |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 6.6896
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
