# formbook case 9344ddd2906925b386bad207e1fb416739a5657a7103feed770d6d6b8d042556

## Overview

- Original name: `9344ddd2906925b386bad207e1fb416739a5657a7103feed770d6d6b8d042556.exe`
- SHA-256: `9344ddd2906925b386bad207e1fb416739a5657a7103feed770d6d6b8d042556`
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

- Root entropy: 7.8959
- Root packing assessment: `True`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_upx_or_failed`

## Limitations

- Formbook payload configuration is commonly encrypted and may require a recovered process image.
- Loader URLs and certificate references are not promoted to confirmed C2.
