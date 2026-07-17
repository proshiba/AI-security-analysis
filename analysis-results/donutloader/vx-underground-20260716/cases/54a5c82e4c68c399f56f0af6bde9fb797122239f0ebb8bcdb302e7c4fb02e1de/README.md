# donutloader case 54a5c82e4c68c399f56f0af6bde9fb797122239f0ebb8bcdb302e7c4fb02e1de

## Overview

- Original name: `54a5c82e4c68c399f56f0af6bde9fb797122239f0ebb8bcdb302e7c4fb02e1de`
- SHA-256: `54a5c82e4c68c399f56f0af6bde9fb797122239f0ebb8bcdb302e7c4fb02e1de`
- Campaign shape: `pe_wrapper_or_loader`
- Format: `pe`
- Packing suspected: `false`
- Packing classification: `not_packed`
- Unpack status: `artifacts_recovered`
- Recovered static layers: 3
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
  "layer_markers": [
    "portable_executable"
  ],
  "delivery_profile": "unrecognized",
  "donut_confirmed": false,
  "static_config_recovered": false
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `xor32-donut-shellcode` | `05d27b5a98c56300a35abdc42146520d35970f5d1d16a527c43555f5f8aeb465` | 2226607 | `data` |
| 2 | `donut-terminal-payload` | `c54f5ece85d890e5a3d51109fe0488ef4a8fbd81c1844afdddfc6c03a296a8e8` | 2210304 | `pe` |
| 3 | `dotnet-resource-opaque` | `3142061dfd56a4d407744b3d54928842f9e2154d4a43cbdf981046667215c870` | 2197362 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.9997
- Root packing assessment: `False`
- Recursive layers analyzed: 3
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Static extraction only; no payload execution or C2 contact was performed.
- No strict Donut call-over-instance structure was recovered; a family label alone is not confirmation.
