# formbook case 5baa58fbd2a9309d6853cf1cd5be83adbced95bbdc1a7471c11ee5455f85bfa9

## Overview

- Original name: `5baa58fbd2a9309d6853cf1cd5be83adbced95bbdc1a7471c11ee5455f85bfa9.js`
- SHA-256: `5baa58fbd2a9309d6853cf1cd5be83adbced95bbdc1a7471c11ee5455f85bfa9`
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

- Root entropy: 5.3412
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Formbook payload configuration is commonly encrypted and may require a recovered process image.
- Loader URLs and certificate references are not promoted to confirmed C2.
