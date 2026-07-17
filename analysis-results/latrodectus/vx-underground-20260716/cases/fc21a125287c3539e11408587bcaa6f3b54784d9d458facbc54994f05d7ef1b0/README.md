# latrodectus case fc21a125287c3539e11408587bcaa6f3b54784d9d458facbc54994f05d7ef1b0

## Overview

- Original name: `fc21a125287c3539e11408587bcaa6f3b54784d9d458facbc54994f05d7ef1b0`
- SHA-256: `fc21a125287c3539e11408587bcaa6f3b54784d9d458facbc54994f05d7ef1b0`
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
    "sha256": "bbd8e4cc395c8afc5c8687fd33f97fa669454d4a3288536fd14dea1f7b5ec70c",
    "kind": "embedded-pe",
    "depth": 1,
    "config": {
      "c2_urls": [
        "https://stratimasesstr.com/live/",
        "https://winarkamaps.com/live/"
      ],
      "version": "1.2.3",
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
| 1 | `embedded-pe` | `bbd8e4cc395c8afc5c8687fd33f97fa669454d4a3288536fd14dea1f7b5ec70c` | 60928 | `pe` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 5.5379
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
