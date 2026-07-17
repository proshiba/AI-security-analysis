# latrodectus case 62536e1486be7e31df6c111ed96777b9e3f2a912a2d7111253ae6a5519e71830

## Overview

- Original name: `62536e1486be7e31df6c111ed96777b9e3f2a912a2d7111253ae6a5519e71830`
- SHA-256: `62536e1486be7e31df6c111ed96777b9e3f2a912a2d7111253ae6a5519e71830`
- Campaign shape: `direct_dll_or_loader`
- Format: `pe`
- Packing suspected: `false`
- Packing classification: `not_packed`
- Unpack status: `artifacts_recovered`
- Recovered static layers: 2
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
    "rundll32_execution": false
  }
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `pe-resource-opaque` | `18482454a42d6c0383360d5fca080f78f41acaff34339dbf618bb57a1a585425` | 375824 | `data` |
| 1 | `pe-resource-opaque` | `e78414fc91e6f2f7342101149b12cede93de4b4bdcbff0e52f84b2a0a1fe64eb` | 6007664 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.9921
- Root packing assessment: `False`
- Recursive layers analyzed: 2
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
