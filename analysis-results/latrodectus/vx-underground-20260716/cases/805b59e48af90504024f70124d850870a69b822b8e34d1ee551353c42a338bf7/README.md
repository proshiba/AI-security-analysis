# latrodectus case 805b59e48af90504024f70124d850870a69b822b8e34d1ee551353c42a338bf7

## Overview

- Original name: `805b59e48af90504024f70124d850870a69b822b8e34d1ee551353c42a338bf7`
- SHA-256: `805b59e48af90504024f70124d850870a69b822b8e34d1ee551353c42a338bf7`
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
| `https://skinnyjeanso.com/live/` | c2 | confirmed | latrodectus_string_decryption |
| `https://titnovacrion.top/live/` | c2 | confirmed | latrodectus_string_decryption |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "c2_urls": [
    "https://skinnyjeanso.com/live/",
    "https://titnovacrion.top/live/"
  ],
  "version": "1.2.24",
  "group_name": "Littlehw",
  "group_id": 510584660,
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

- Root entropy: 5.6167
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
