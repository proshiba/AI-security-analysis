# formbook case 7d9512cf29b9d9792a1018f41eaa156902a16e2f20e4da4f1c308501822b39ad

## Overview

- Original name: `7d9512cf29b9d9792a1018f41eaa156902a16e2f20e4da4f1c308501822b39ad.js`
- SHA-256: `7d9512cf29b9d9792a1018f41eaa156902a16e2f20e4da4f1c308501822b39ad`
- Campaign shape: `script_delivery`
- Format: `script`
- Packing suspected: `false`
- Recovered static layers: 1
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

- Root entropy: 5.7777
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Formbook payload configuration is commonly encrypted and may require a recovered process image.
- Loader URLs and certificate references are not promoted to confirmed C2.
