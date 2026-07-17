# amadey case 8babde64a6d3b85c2c4315205ae58884ee01f6364477a777f09d5b9c3ceef2a6

## Overview

- Original name: `cc5e48eb9cf7308dedf57d5e468e836f`
- SHA-256: `8babde64a6d3b85c2c4315205ae58884ee01f6364477a777f09d5b9c3ceef2a6`
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
    "system_discovery": false,
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

- Root entropy: 6.9457
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
