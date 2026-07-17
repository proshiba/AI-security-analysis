# latrodectus case aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c

## Overview

- Original name: `aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c`
- SHA-256: `aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c`
- Campaign shape: `direct_dll_or_loader`
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
    "host_discovery": true,
    "domain_discovery": false,
    "security_discovery": false,
    "scheduled_task_persistence": false,
    "payload_download": false,
    "rundll32_execution": false
  }
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `pe-resource-opaque` | `e339c648ec2621d00e91ff31ebb44eeebb6416d52b51014b044fcbb63c5f5bc3` | 60416 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 6.5615
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
