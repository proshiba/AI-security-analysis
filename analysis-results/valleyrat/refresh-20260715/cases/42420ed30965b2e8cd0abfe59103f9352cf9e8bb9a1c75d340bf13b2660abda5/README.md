# valleyrat case 42420ed30965b2e8cd0abfe59103f9352cf9e8bb9a1c75d340bf13b2660abda5

## Overview

- Original name: `42420ed30965b2e8cd0abfe59103f9352cf9e8bb9a1c75d340bf13b2660abda5.exe`
- SHA-256: `42420ed30965b2e8cd0abfe59103f9352cf9e8bb9a1c75d340bf13b2660abda5`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `false`
- Recovered static layers: 0
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| `103.43.11.40:1443` | candidate_c2 | confirmed | decoded_vvas_config |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Collection/behavior features

```json
{}
```

## Unpacking status

- Root entropy: 6.2889
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Static strings alone do not prove an endpoint is C2.
- Campaign-specific decoded config should supersede candidates when available.
