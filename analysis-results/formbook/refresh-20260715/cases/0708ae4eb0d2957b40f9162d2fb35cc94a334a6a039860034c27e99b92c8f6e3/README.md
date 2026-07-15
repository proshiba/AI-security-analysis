# formbook case 0708ae4eb0d2957b40f9162d2fb35cc94a334a6a039860034c27e99b92c8f6e3

## Overview

- Original name: `0708ae4eb0d2957b40f9162d2fb35cc94a334a6a039860034c27e99b92c8f6e3.hta`
- SHA-256: `0708ae4eb0d2957b40f9162d2fb35cc94a334a6a039860034c27e99b92c8f6e3`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `script`
- Packing suspected: `false`
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
  "script_loader": true
}
```

## Unpacking status

- Root entropy: 4.6895
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Formbook payload configuration is commonly encrypted and may require a recovered process image.
- Loader URLs and certificate references are not promoted to confirmed C2.
