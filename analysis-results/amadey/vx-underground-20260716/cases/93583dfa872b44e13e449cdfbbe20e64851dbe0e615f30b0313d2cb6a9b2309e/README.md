# amadey case 93583dfa872b44e13e449cdfbbe20e64851dbe0e615f30b0313d2cb6a9b2309e

## Overview

- Original name: `93583dfa872b44e13e449cdfbbe20e64851dbe0e615f30b0313d2cb6a9b2309e`
- SHA-256: `93583dfa872b44e13e449cdfbbe20e64851dbe0e615f30b0313d2cb6a9b2309e`
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
| 1 | `dotnet-resource-opaque` | `96c5c1a0345007a49b238bfe6e3644b4f7fdbb1287a9f9ee40247a8cdca7cd83` | 469722 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 6.6633
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
