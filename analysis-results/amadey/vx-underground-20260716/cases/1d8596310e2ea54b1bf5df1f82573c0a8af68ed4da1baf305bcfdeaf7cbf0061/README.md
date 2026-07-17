# amadey case 1d8596310e2ea54b1bf5df1f82573c0a8af68ed4da1baf305bcfdeaf7cbf0061

## Overview

- Original name: `1d8596310e2ea54b1bf5df1f82573c0a8af68ed4da1baf305bcfdeaf7cbf0061`
- SHA-256: `1d8596310e2ea54b1bf5df1f82573c0a8af68ed4da1baf305bcfdeaf7cbf0061`
- Campaign shape: `direct_pe_or_container`
- Format: `zip`
- Packing suspected: `false`
- Packing classification: `not_applicable`
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
  "static_config_recovered": false,
  "features": {
    "persistence": false,
    "plugin_download": false,
    "system_discovery": false,
    "rc4_protected_traffic": false
  }
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `zip-ole` | `ffdf82acd234d4c60b3a0b208ca1a034b49bbfffdf38a4d4f566eed8e60ea1a3` | 9216 | `ole` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.4129
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
