# latrodectus case fc4932314471c91434fde050e85967de31701e0b391440c1c5f9aa5d6fde615d

## Overview

- Original name: `fc4932314471c91434fde050e85967de31701e0b391440c1c5f9aa5d6fde615d`
- SHA-256: `fc4932314471c91434fde050e85967de31701e0b391440c1c5f9aa5d6fde615d`
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
| `https://antyparkov.site/live/` | c2 | confirmed | latrodectus_string_decryption |
| `https://saicetyapy.space/live/` | c2 | confirmed | latrodectus_string_decryption |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "c2_urls": [
    "https://antyparkov.site/live/",
    "https://saicetyapy.space/live/"
  ],
  "version": "1.1.6",
  "group_name": "Supted",
  "group_id": 1081065992,
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

- Root entropy: 5.6438
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
