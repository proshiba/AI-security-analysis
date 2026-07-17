# latrodectus case 326d297b441a40bb3f53bb55cb727e0fbed422470977ca167b1c919029be746b

## Overview

- Original name: `326d297b441a40bb3f53bb55cb727e0fbed422470977ca167b1c919029be746b`
- SHA-256: `326d297b441a40bb3f53bb55cb727e0fbed422470977ca167b1c919029be746b`
- Campaign shape: `direct_dll_or_loader`
- Format: `pe`
- Packing suspected: `false`
- Packing classification: `not_packed`
- Unpack status: `no_artifact_recovered`
- Recovered static layers: 0
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| `https://arsimonopa.com/live/` | c2 | confirmed | latrodectus_string_decryption |
| `https://lemonimonakio.com/live/` | c2 | confirmed | latrodectus_string_decryption |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "c2_urls": [
    "https://arsimonopa.com/live/",
    "https://lemonimonakio.com/live/"
  ],
  "version": "1.1.12",
  "group_name": "Novik",
  "group_id": 1053565364,
  "rc4_key": "12345",
  "profile": "latrodectus_legacy_prng_strings",
  "static_config_recovered": true,
  "features": {
    "host_discovery": true,
    "domain_discovery": true,
    "security_discovery": true,
    "scheduled_task_persistence": true,
    "payload_download": true,
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

- Root entropy: 5.641
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
