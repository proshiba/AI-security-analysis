# latrodectus case 3a950d7e6736f17c3df90844c76d934dc66c17ec76841a4ad58de07af7955f0f

## Overview

- Original name: `3a950d7e6736f17c3df90844c76d934dc66c17ec76841a4ad58de07af7955f0f`
- SHA-256: `3a950d7e6736f17c3df90844c76d934dc66c17ec76841a4ad58de07af7955f0f`
- Campaign shape: `office_delivery`
- Format: `ole`
- Packing suspected: `false`
- Packing classification: `not_applicable`
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
    "rundll32_execution": true
  }
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `embedded-pe` | `1e0e63b446eecf6c9781c7d1cae1f46a3bb31654a70612f71f31538fb4f4729a` | 399328 | `pe` |
| 1 | `embedded-pe` | `426e6cf199a8268e8a7763ec3a4dd7add982b28c51d89ebea90ca792cbae14dd` | 446944 | `pe` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.0939
- Root packing assessment: `False`
- Recursive layers analyzed: 2
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed values require the characteristic decrypted registration format and at least one URL.
- AES-CTR string generations and protected delivery wrappers may require a recovered memory image or a later parser profile.
- No check-in or infrastructure contact was performed.
