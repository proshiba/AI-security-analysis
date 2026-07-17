# vidar case 7b217c20a30ab1bdc4534f4adb62df226d128ec4d03c0eb2feb5ab35d2b7dc9f

## Overview

- Original name: `7b217c20a30ab1bdc4534f4adb62df226d128ec4d03c0eb2feb5ab35d2b7dc9f`
- SHA-256: `7b217c20a30ab1bdc4534f4adb62df226d128ec4d03c0eb2feb5ab35d2b7dc9f`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `false`
- Packing classification: `self_extracting_container`
- Unpack status: `artifacts_recovered`
- Recovered static layers: 8
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | static extraction incomplete |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "campaign_shape": "direct_pe_or_pe_loader",
  "features": {
    "browser_collection": false,
    "wallet_collection": false,
    "telegram_dead_drop": false,
    "dependency_download": false
  },
  "static_config_recovered": false,
  "candidate_infrastructure_recovered": false,
  "scan_source": "complete_input",
  "original_size": 970199
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `7z-data` | `7f571225134b741568874f6e72d08174c48501db05bb2ffbd719857970c7bc38` | 92160 | `data` |
| 1 | `7z-data` | `8af2aaa9d6616de4e6799ecb35cf882317ffa4227c57489eb0d7912b1c294a7e` | 906 | `data` |
| 1 | `7z-data` | `102f69a170b82804b0038e63a23cdedc50fea8ad209e6b050067446386fa70c3` | 58971 | `data` |
| 1 | `7z-data` | `cc2ba5405468b7d1f71c99f2d3b10008d8b8114a86863dc575526a50cc22f19d` | 11031 | `data` |
| 1 | `7z-data` | `8e44baed392dc600c4f926975c3ae93fc606ada87a1b3d31f2fc6aa68255d14f` | 75776 | `data` |
| 1 | `7z-data` | `3f315a5d96f829380fc88fde25adc7c6783aa9cc2c4f8d97c4dede5b40ff2ac6` | 81920 | `data` |
| 1 | `7z-data` | `8e1f28dcf29368b5f98307bf26d089c9cd9783a0aff5aba610b79454d46eb105` | 82944 | `data` |
| 1 | `7z-data` | `0a9155a0588b2c6c187c0ef40c697150084f7ced898f94e924a642a565102bfe` | 892736 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.8997
- Root packing assessment: `False`
- Recursive layers analyzed: 8
- 7z status: `extracted`
- UPX status: `not_applicable`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
