# vidar case 28db05fffe5f32ee8df60a400c97d19270d23327ebb49ae86e455ea14d59f113

## Overview

- Original name: `28db05fffe5f32ee8df60a400c97d19270d23327ebb49ae86e455ea14d59f113`
- SHA-256: `28db05fffe5f32ee8df60a400c97d19270d23327ebb49ae86e455ea14d59f113`
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
| `http://157.90.113.100:80` | candidate_infrastructure | candidate | embedded_literal |
| `https://steamcommunity.com/profiles/76561199482248283` | candidate_infrastructure | candidate | embedded_literal |
| `https://t.me/dionysus_tg` | candidate_infrastructure | candidate | embedded_literal |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "campaign_shape": "direct_pe_or_pe_loader",
  "family_markers": [
    "Autofill"
  ],
  "features": {
    "browser_collection": true,
    "wallet_collection": true,
    "telegram_dead_drop": true,
    "dependency_download": true
  },
  "urls": [
    "http://157.90.113.100:80",
    "https://steamcommunity.com/profiles/76561199482248283",
    "https://t.me/dionysus_tg"
  ],
  "static_config_recovered": false,
  "candidate_infrastructure_recovered": true,
  "scan_source": "complete_input",
  "original_size": 372224
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| - | none recovered | - | - | - |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 6.5482
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
