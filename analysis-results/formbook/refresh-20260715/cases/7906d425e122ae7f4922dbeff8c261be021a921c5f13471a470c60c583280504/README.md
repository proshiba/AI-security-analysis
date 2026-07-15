# formbook case 7906d425e122ae7f4922dbeff8c261be021a921c5f13471a470c60c583280504

## Overview

- Original name: `7906d425e122ae7f4922dbeff8c261be021a921c5f13471a470c60c583280504.exe`
- SHA-256: `7906d425e122ae7f4922dbeff8c261be021a921c5f13471a470c60c583280504`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `true`
- Recovered static layers: 0
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | static extraction incomplete |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Collection/behavior features

```json
{
  "browser_credential_theft": false,
  "mail_credential_theft": false,
  "process_injection": false,
  "script_loader": false
}
```

## Unpacking status

- Root entropy: 7.8647
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Formbook payload configuration is commonly encrypted and may require a recovered process image.
- Loader URLs and certificate references are not promoted to confirmed C2.
