# formbook case e3ee5d56ae3281d15eb73228e5cd94d955b4f664ac73de9651a16d034f32c93b

## Overview

- Original name: `e3ee5d56ae3281d15eb73228e5cd94d955b4f664ac73de9651a16d034f32c93b.vbs`
- SHA-256: `e3ee5d56ae3281d15eb73228e5cd94d955b4f664ac73de9651a16d034f32c93b`
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

- Root entropy: 6.0037
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Formbook payload configuration is commonly encrypted and may require a recovered process image.
- Loader URLs and certificate references are not promoted to confirmed C2.
