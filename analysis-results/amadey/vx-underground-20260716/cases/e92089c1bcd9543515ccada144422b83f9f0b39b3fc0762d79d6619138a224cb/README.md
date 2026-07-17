# amadey case e92089c1bcd9543515ccada144422b83f9f0b39b3fc0762d79d6619138a224cb

## Overview

- Original name: `e92089c1bcd9543515ccada144422b83f9f0b39b3fc0762d79d6619138a224cb`
- SHA-256: `e92089c1bcd9543515ccada144422b83f9f0b39b3fc0762d79d6619138a224cb`
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

- Root entropy: 7.9491
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
