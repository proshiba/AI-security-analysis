# vidar case 416b40630daa924136b9d10e0faa8c800a7a882416f4e5b7944f9bc2553a414b

## Overview

- Original name: `416b40630daa924136b9d10e0faa8c800a7a882416f4e5b7944f9bc2553a414b`
- SHA-256: `416b40630daa924136b9d10e0faa8c800a7a882416f4e5b7944f9bc2553a414b`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `false`
- Packing classification: `managed_loader_or_obfuscated`
- Unpack status: `artifacts_recovered`
- Recovered static layers: 9
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
    "browser_collection": true,
    "wallet_collection": false,
    "telegram_dead_drop": false,
    "dependency_download": false
  },
  "static_config_recovered": false,
  "candidate_infrastructure_recovered": false,
  "scan_source": "complete_input",
  "original_size": 4585688
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `pe-resource-opaque` | `2787d68e9edfaf08a7be70c8a29ab1a02978c808b444bbc6a154564a0adf6193` | 29471 | `data` |
| 1 | `dotnet-resource-opaque` | `0730d84f06965a271ae553936d7a51506ec8418b3536ea694f018a3bf8fc1ec5` | 1063136 | `data` |
| 1 | `dotnet-resource-opaque` | `516ada191ce161be39d20c06c79dccf762a29367992decc3e0712704847b81a5` | 7712 | `data` |
| 1 | `dotnet-resource-opaque` | `9012ba0f377ea32a9896268fbdf324a3f247b6fab9aad7ecfaf80e0a58769855` | 71568 | `data` |
| 1 | `dotnet-resource-opaque` | `3c1b507c3b5e543401b43d43a4bf4aaee8e4e95d760a346c33fa1f6851a717bf` | 128328 | `data` |
| 1 | `dotnet-resource-opaque` | `3c77a8ab5386a380a674a0c6076a2291ffbd5807df7ec602593e42b3ef64f2ee` | 89232 | `data` |
| 1 | `dotnet-resource-opaque` | `0b05fc30c4227251abaaaa31d48504ed000d00e6c7db9184133746b9e10b3e02` | 63910 | `data` |
| 1 | `dotnet-resource-opaque` | `18a9ca3bb708ca30958d658fa0128d94b379588b2eb90828d3acc9276a3b10d1` | 7984 | `data` |
| 1 | `dotnet-resource-opaque` | `f0b6c66f186422afd791d340807820bf7cecb07e24761566907018c1de2d1eeb` | 387788 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.2415
- Root packing assessment: `False`
- Recursive layers analyzed: 9
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
