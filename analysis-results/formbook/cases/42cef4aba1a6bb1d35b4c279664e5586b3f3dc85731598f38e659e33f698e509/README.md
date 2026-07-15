# formbook case 42cef4aba1a6bb1d35b4c279664e5586b3f3dc85731598f38e659e33f698e509

## Overview

- Original name: `42cef4aba1a6bb1d35b4c279664e5586b3f3dc85731598f38e659e33f698e509.ps1`
- SHA-256: `42cef4aba1a6bb1d35b4c279664e5586b3f3dc85731598f38e659e33f698e509`
- Campaign shape: `script_delivery`
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

- Root entropy: 6.048
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Formbook payload configuration is commonly encrypted and may require a recovered process image.
- Loader URLs and certificate references are not promoted to confirmed C2.
