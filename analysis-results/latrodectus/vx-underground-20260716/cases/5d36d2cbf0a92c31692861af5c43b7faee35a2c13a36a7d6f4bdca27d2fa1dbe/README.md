# latrodectus case 5d36d2cbf0a92c31692861af5c43b7faee35a2c13a36a7d6f4bdca27d2fa1dbe

## Overview

- Original name: `5d36d2cbf0a92c31692861af5c43b7faee35a2c13a36a7d6f4bdca27d2fa1dbe`
- SHA-256: `5d36d2cbf0a92c31692861af5c43b7faee35a2c13a36a7d6f4bdca27d2fa1dbe`
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
| `https://illoskanawer.com/live/` | c2 | confirmed | latrodectus_string_decryption |
| `https://workspacin.cloud/live/` | c2 | confirmed | latrodectus_string_decryption |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "c2_urls": [
    "https://illoskanawer.com/live/",
    "https://workspacin.cloud/live/"
  ],
  "version": "1.3.4",
  "group_name": "Electrol",
  "group_id": 2221766521,
  "rc4_key": "xkxp7pKhnkQxUokR2dl00qsRa6Hx0xvQ31jTD7EwUqj4RXWtHwELbZFbOoqCnXl8",
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

- Root entropy: 4.6249
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
