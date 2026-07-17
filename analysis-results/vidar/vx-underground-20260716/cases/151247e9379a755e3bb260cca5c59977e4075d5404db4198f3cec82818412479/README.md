# vidar case 151247e9379a755e3bb260cca5c59977e4075d5404db4198f3cec82818412479

## Overview

- Original name: `151247e9379a755e3bb260cca5c59977e4075d5404db4198f3cec82818412479`
- SHA-256: `151247e9379a755e3bb260cca5c59977e4075d5404db4198f3cec82818412479`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `false`
- Packing classification: `self_extracting_container`
- Unpack status: `artifacts_recovered`
- Recovered static layers: 27
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
  "original_size": 834674
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `pe-resource-opaque` | `69b3d014b5053502a626d189699f11a80ec2610af3ac2350f526df5b91955e04` | 9738 | `data` |
| 1 | `7z-data` | `64aa151e343829cc4b1d337c410ab786228cd64f37456d0929e6f05768ba9cf6` | 22528 | `data` |
| 1 | `7z-data` | `4bf7f1bcd2744f0e38e31c78586df5b020bd14c72c15e287523eb9864a0e1b29` | 53248 | `data` |
| 1 | `7z-data` | `ab3cfa206585ca600f599485f2063082e5e7fcf22aa26be460bd4043e0f936cb` | 48128 | `data` |
| 1 | `7z-data` | `970527fcafc7952b2c97cd4833680a9b4420c14711deb6edbceaeb34259a9883` | 34816 | `data` |
| 1 | `7z-data` | `6f2f6dcfb3a1a506fdbab909bb76621307cc08a19ca86bb136c1fae68c75708a` | 30720 | `data` |
| 1 | `7z-data` | `6bd7ff074df7f2097e1a3349286cc613c97fd4ca47a7bc64fcb099494b1d3cbc` | 61440 | `data` |
| 1 | `7z-data` | `0eeab4e2c06b3fcac8ffa673e9a47d2fc746168b1d4f87679e7775f5940742a5` | 55296 | `data` |
| 1 | `7z-data` | `2a6556abb0971b84cba5249234d57de5bdb424009b67d7ad1f2591f8db7a2970` | 35840 | `data` |
| 1 | `7z-data` | `c04c589932fd74272bf0f58a078f79ffd9fe159ef9a3710a602b1530d9ea63da` | 67584 | `data` |
| 1 | `7z-data` | `a6fad3d46b0a8e74318b87ae8553261274e39617d1e27b7c3c6e1988eb588e4e` | 48128 | `data` |
| 1 | `7z-data` | `015a5397fbe4822cd1f4ed2f49bd7065a384949342fc3b33a57f3dfdb7ee9818` | 114 | `data` |
| 1 | `7z-data` | `2cd989421ca19c294fb517ad67af162261c8b7266e17f213ba5d7f0ebdfb9fa7` | 30720 | `data` |
| 1 | `7z-data` | `4886af9dc9fbd57ce7c8fd486247790bfacd468184cf1ec8f66931d262e06729` | 75776 | `data` |
| 1 | `7z-data` | `ecc8abc33adddba1a6fe1dc626698aba572b61fe8a6988ce541ddb7b16f2e7c7` | 22996 | `data` |
| 1 | `7z-data` | `d46cd3ce10c355622f4123a28f907292a65e0746ab8a6385c0ea212ee9eb2a0b` | 69632 | `data` |
| 1 | `7z-data` | `bdc02640cb3d780b5ec58b66328d6591bf53f3786a5a9b14e56a132e4dd6db6f` | 46859 | `data` |
| 1 | `7z-data` | `56143152cf4ef32820bbf2c358ebaf3faaafe857f802e04d11f7a6c34a9df3d1` | 34816 | `data` |
| 1 | `7z-data` | `60a85ea86f3bbb20466842f0937bcb4794799afe9766cd46881c9cfe6ab0bbf5` | 57344 | `data` |
| 1 | `7z-data` | `1016415bd80a9943c3c103aa74bb3b6c3feae31437b97b52eeae8b6a765280a5` | 50176 | `data` |
| 1 | `7z-data` | `012804834cda2559dbdfe72599126689d71901666ede8e5d3830b0e3ff72eb47` | 27648 | `data` |
| 1 | `7z-data` | `d2af659e6b06c7551951c547f9ee9f1def04edb77fecf2429114a337dea14168` | 59392 | `data` |
| 1 | `7z-data` | `98773e10ff7bcf174b7c73f1bbd8e47f08e996ba201b2a30ac34897bcef0f5fd` | 202752 | `data` |
| 1 | `7z-data` | `00401eacd2abcd9d19c0a5196260f5ac627fedb8375b932d94a35a26bef34c1d` | 24576 | `data` |
| 1 | `7z-data` | `56ff0739cef74a4abd0635950f07435b627e384495737f5b7285fb95f91e2ddc` | 27648 | `data` |
| 1 | `7z-data` | `779f46fc17c935261963cd5b0686fee09b75937894d0818c77b04f7570caba63` | 46080 | `data` |
| 1 | `7z-data` | `e99aeed2c33405a2128b1eeb3fcf77c05a45a840b7c2a1caa5340b92e222b99b` | 7770 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.9719
- Root packing assessment: `False`
- Recursive layers analyzed: 27
- 7z status: `extracted`
- UPX status: `not_applicable`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
