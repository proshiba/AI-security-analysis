# amadey case 8fb3b241a2578c6fbaf43a7c4d1481dc5083d62601edece49d1ce68b0b600197

## Overview

- Original name: `8fb3b241a2578c6fbaf43a7c4d1481dc5083d62601edece49d1ce68b0b600197`
- SHA-256: `8fb3b241a2578c6fbaf43a7c4d1481dc5083d62601edece49d1ce68b0b600197`
- Campaign shape: `direct_pe_or_container`
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
  "static_config_recovered": false,
  "features": {
    "persistence": true,
    "plugin_download": true,
    "system_discovery": true,
    "rc4_protected_traffic": false
  }
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| - | none recovered | - | - | - |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.2666
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
