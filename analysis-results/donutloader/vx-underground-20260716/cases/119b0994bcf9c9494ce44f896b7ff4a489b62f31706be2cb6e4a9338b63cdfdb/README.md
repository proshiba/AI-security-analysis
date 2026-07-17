# donutloader case 119b0994bcf9c9494ce44f896b7ff4a489b62f31706be2cb6e4a9338b63cdfdb

## Overview

- Original name: `119b0994bcf9c9494ce44f896b7ff4a489b62f31706be2cb6e4a9338b63cdfdb`
- SHA-256: `119b0994bcf9c9494ce44f896b7ff4a489b62f31706be2cb6e4a9338b63cdfdb`
- Campaign shape: `direct_shellcode`
- Format: `data`
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
  "layer_markers": [
    "portable_executable",
    "strict_donut_shellcode"
  ],
  "delivery_profile": "embedded_donut",
  "donut_confirmed": true,
  "donut_candidates": [
    {
      "offset": 0,
      "stride": 1,
      "shellcode_sha256": "685437d2b82dc5f41ea828da25a120b8038272ecdde58266db9d35b51d33386e",
      "shellcode_size": 6891410,
      "layout": "current-0x230-array",
      "instance_sha256": "e199ef132428ece3a12deb874404c72f5d1608db2dd7ca55bdfea7e9689b6193",
      "payloads": [
        {
          "sha256": "e5588d0970d3a1825b4c1280fd16d9149901c4bcfcf636fcee7b3e9d5ae5170f",
          "size": 6876672
        }
      ]
    }
  ],
  "static_config_recovered": false
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `donut-terminal-payload` | `e5588d0970d3a1825b4c1280fd16d9149901c4bcfcf636fcee7b3e9d5ae5170f` | 6876672 | `pe` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.9999
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Static extraction only; no payload execution or C2 contact was performed.
