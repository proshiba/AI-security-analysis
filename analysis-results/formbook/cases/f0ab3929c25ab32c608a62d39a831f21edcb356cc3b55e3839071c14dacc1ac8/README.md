# formbook case f0ab3929c25ab32c608a62d39a831f21edcb356cc3b55e3839071c14dacc1ac8

## Overview

- Original name: `f0ab3929c25ab32c608a62d39a831f21edcb356cc3b55e3839071c14dacc1ac8.js`
- SHA-256: `f0ab3929c25ab32c608a62d39a831f21edcb356cc3b55e3839071c14dacc1ac8`
- Campaign shape: `script_delivery`
- Format: `script`
- Packing suspected: `false`
- Recovered static layers: 1
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| `https://misty-cherry-cea3.uploadsimg.workers.dev/EzUaK` | candidate_infrastructure | candidate | embedded_literal |

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

- Root entropy: 5.3556
- Root packing assessment: `False`
- Recursive layers analyzed: 1
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Formbook payload configuration is commonly encrypted and may require a recovered process image.
- Loader URLs and certificate references are not promoted to confirmed C2.
