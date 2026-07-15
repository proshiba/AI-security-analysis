# valleyrat case dfacebad09d75d41ee5f477754815ae7e4afd926638d7b72a6a25338cd2479da

## Overview

- Original name: `dfacebad09d75d41ee5f477754815ae7e4afd926638d7b72a6a25338cd2479da.exe`
- SHA-256: `dfacebad09d75d41ee5f477754815ae7e4afd926638d7b72a6a25338cd2479da`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `true`
- Recovered static layers: 0
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| `https://xjsjkjdsjjd.s3.ap-southeast-1.amazonaws.com/11100.zip` | config_or_stage_url | inferred | static_string |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Collection/behavior features

```json
{}
```

## Unpacking status

- Root entropy: 7.1054
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Static strings alone do not prove an endpoint is C2.
- Campaign-specific decoded config should supersede candidates when available.
