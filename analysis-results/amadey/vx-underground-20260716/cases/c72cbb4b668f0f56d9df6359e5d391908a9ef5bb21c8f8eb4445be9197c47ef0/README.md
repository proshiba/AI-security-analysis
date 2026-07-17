# amadey case c72cbb4b668f0f56d9df6359e5d391908a9ef5bb21c8f8eb4445be9197c47ef0

## Overview

- Original name: `c72cbb4b668f0f56d9df6359e5d391908a9ef5bb21c8f8eb4445be9197c47ef0`
- SHA-256: `c72cbb4b668f0f56d9df6359e5d391908a9ef5bb21c8f8eb4445be9197c47ef0`
- Campaign shape: `protected_wrapper`
- Format: `pe`
- Packing suspected: `true`
- Packing classification: `suspected_packed`
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
    "persistence": false,
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

- Root entropy: 7.9493
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
