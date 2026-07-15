# formbook case f1a1c2a13764f2621ec0181696fcf7e6f74886ec7bf7f4ef4f56ba986c782b6d

## Overview

- Original name: `f1a1c2a13764f2621ec0181696fcf7e6f74886ec7bf7f4ef4f56ba986c782b6d.vbs`
- SHA-256: `f1a1c2a13764f2621ec0181696fcf7e6f74886ec7bf7f4ef4f56ba986c782b6d`
- Campaign shape: `script_delivery`
- Format: `script`
- Packing suspected: `false`
- Recovered static layers: 95
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

- Root entropy: 6.019
- Root packing assessment: `False`
- Recursive layers analyzed: 64
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Formbook payload configuration is commonly encrypted and may require a recovered process image.
- Loader URLs and certificate references are not promoted to confirmed C2.
