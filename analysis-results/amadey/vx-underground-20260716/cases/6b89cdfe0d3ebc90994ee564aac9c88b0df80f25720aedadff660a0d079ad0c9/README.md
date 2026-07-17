# amadey case 6b89cdfe0d3ebc90994ee564aac9c88b0df80f25720aedadff660a0d079ad0c9

## Overview

- Original name: `6b89cdfe0d3ebc90994ee564aac9c88b0df80f25720aedadff660a0d079ad0c9`
- SHA-256: `6b89cdfe0d3ebc90994ee564aac9c88b0df80f25720aedadff660a0d079ad0c9`
- Campaign shape: `direct_pe_or_container`
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
  "static_config_recovered": false,
  "features": {
    "persistence": true,
    "plugin_download": true,
    "system_discovery": true,
    "rc4_protected_traffic": true
  }
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `pe-resource-opaque` | `34d3a33125060650e6f593e33e9405c2acdb17f4a573e772c311efa4b67d81a0` | 427062 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 6.7816
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
