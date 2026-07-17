# latrodectus case 7040402574a686f031c3af5fed37509d8979855397787aab70b2d1059099d2da

## Overview

- Original name: `7040402574a686f031c3af5fed37509d8979855397787aab70b2d1059099d2da`
- SHA-256: `7040402574a686f031c3af5fed37509d8979855397787aab70b2d1059099d2da`
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
| `https://stratimasesstr.com/live/` | c2 | confirmed | latrodectus_string_decryption |
| `https://winarkamaps.com/live/` | c2 | confirmed | latrodectus_string_decryption |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "static_config_recovered": true,
  "features": {
    "host_discovery": true,
    "domain_discovery": false,
    "security_discovery": false,
    "scheduled_task_persistence": false,
    "payload_download": false,
    "rundll32_execution": false
  },
  "selected_recovered_layer": {
    "sha256": "56e7557f5c9ac629c5b6e0bf6b8d377be33cc4e6d7d9dc2ca44728af08ba3d41",
    "kind": "embedded-pe",
    "depth": 1,
    "config": {
      "c2_urls": [
        "https://stratimasesstr.com/live/",
        "https://winarkamaps.com/live/"
      ],
      "version": "1.2.2",
      "group_name": "Facial",
      "group_id": 3828029093,
      "rc4_key": "eNIHaXC815vAqddR21qsuD35eJFL7CnSOLI9vUBdcb5RPcS0h6",
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
  }
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `embedded-pe` | `56e7557f5c9ac629c5b6e0bf6b8d377be33cc4e6d7d9dc2ca44728af08ba3d41` | 60928 | `pe` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 5.5389
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
