# amadey case fda0fc105ffd6faae12d08c243fe684be8c69696bd654d733f5caf487b59baae

## Overview

- Original name: `fda0fc105ffd6faae12d08c243fe684be8c69696bd654d733f5caf487b59baae`
- SHA-256: `fda0fc105ffd6faae12d08c243fe684be8c69696bd654d733f5caf487b59baae`
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

- Root entropy: 7.9555
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
