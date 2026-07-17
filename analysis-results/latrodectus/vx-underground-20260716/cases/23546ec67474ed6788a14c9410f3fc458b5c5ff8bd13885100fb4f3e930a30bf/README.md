# latrodectus case 23546ec67474ed6788a14c9410f3fc458b5c5ff8bd13885100fb4f3e930a30bf

## Overview

- Original name: `23546ec67474ed6788a14c9410f3fc458b5c5ff8bd13885100fb4f3e930a30bf`
- SHA-256: `23546ec67474ed6788a14c9410f3fc458b5c5ff8bd13885100fb4f3e930a30bf`
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
| 1 | `pe-resource-opaque` | `0218fba348f6ce7046de084a20791a544f307148dcce5390fe826778101b1d48` | 62976 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 5.8683
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
