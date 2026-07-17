# latrodectus case 65da6d9f781ff5fc2865b8850cfa64993b36f00151387fdce25859781c1eb711

## Overview

- Original name: `65da6d9f781ff5fc2865b8850cfa64993b36f00151387fdce25859781c1eb711`
- SHA-256: `65da6d9f781ff5fc2865b8850cfa64993b36f00151387fdce25859781c1eb711`
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
| `https://skinnyjeanso.com/live/` | c2 | confirmed | latrodectus_string_decryption |
| `https://titnovacrion.top/live/` | c2 | confirmed | latrodectus_string_decryption |

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
    "sha256": "8629d68dd68640f3d3c3e20dc18ac0b80ab4ea6ff1503e2d2b8fc29adb374d6a",
    "kind": "embedded-pe",
    "depth": 1,
    "config": {
      "c2_urls": [
        "https://skinnyjeanso.com/live/",
        "https://titnovacrion.top/live/"
      ],
      "version": "1.2.19",
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
  }
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `embedded-pe` | `8629d68dd68640f3d3c3e20dc18ac0b80ab4ea6ff1503e2d2b8fc29adb374d6a` | 60928 | `pe` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 5.5528
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
