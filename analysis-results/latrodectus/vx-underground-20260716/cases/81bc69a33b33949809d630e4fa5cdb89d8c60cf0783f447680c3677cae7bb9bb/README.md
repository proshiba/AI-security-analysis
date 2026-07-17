# latrodectus case 81bc69a33b33949809d630e4fa5cdb89d8c60cf0783f447680c3677cae7bb9bb

## Overview

- Original name: `81bc69a33b33949809d630e4fa5cdb89d8c60cf0783f447680c3677cae7bb9bb`
- SHA-256: `81bc69a33b33949809d630e4fa5cdb89d8c60cf0783f447680c3677cae7bb9bb`
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
| 1 | `pe-resource-opaque` | `40ba612d77c83560ad8d13bf0f82d188fb3ee8523a58120ad44f3ede65725f95` | 61456 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 6.8068
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
