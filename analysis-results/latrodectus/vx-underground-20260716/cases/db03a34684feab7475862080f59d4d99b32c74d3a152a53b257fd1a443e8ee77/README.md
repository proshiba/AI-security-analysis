# latrodectus case db03a34684feab7475862080f59d4d99b32c74d3a152a53b257fd1a443e8ee77

## Overview

- Original name: `db03a34684feab7475862080f59d4d99b32c74d3a152a53b257fd1a443e8ee77`
- SHA-256: `db03a34684feab7475862080f59d4d99b32c74d3a152a53b257fd1a443e8ee77`
- Campaign shape: `direct_dll_or_loader`
- Format: `data`
- Packing suspected: `false`
- Packing classification: `not_applicable`
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
    "host_discovery": false,
    "domain_discovery": false,
    "security_discovery": false,
    "scheduled_task_persistence": false,
    "payload_download": false,
    "rundll32_execution": true
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

- Root entropy: 2.4596
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
