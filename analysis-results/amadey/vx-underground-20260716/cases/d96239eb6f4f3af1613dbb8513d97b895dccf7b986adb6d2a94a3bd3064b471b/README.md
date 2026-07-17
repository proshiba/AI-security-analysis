# amadey case d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b

## Overview

- Original name: `d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b`
- SHA-256: `d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b`
- Campaign shape: `direct_pe_or_container`
- Format: `pe`
- Packing suspected: `false`
- Packing classification: `self_extracting_container`
- Unpack status: `artifacts_recovered`
- Recovered static layers: 13
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| `http://212.113.119.255/joomla/index.php` | c2 | confirmed | amadey_config_decryption |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "static_config_recovered": true,
  "features": {
    "persistence": true,
    "plugin_download": true,
    "system_discovery": true,
    "rc4_protected_traffic": true
  },
  "selected_recovered_layer": {
    "sha256": "13b4b17671c12fd3f9db5491efb7fb389601b57ac7f89fd78638625c1ef201e4",
    "kind": "7z-pe",
    "depth": 1,
    "config": {
      "c2_urls": [
        "http://212.113.119.255/joomla/index.php"
      ],
      "version": "3.70",
      "campaign_id": "5d3738",
      "install_directory": "5cb6818d6c",
      "install_filename": "oneetx.exe",
      "rc4_key": "a091ec0a6e22276a96a99c1d34ef679c",
      "profile": "amadey_custom_alphabet_base64",
      "static_config_recovered": true,
      "features": {
        "persistence": true,
        "plugin_download": true,
        "system_discovery": true,
        "rc4_protected_traffic": false
      }
    }
  }
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `pe-resource-opaque` | `f169eed8248d8f9efd20dd716790f2b3bb0547687546811b4137be21b5c63b71` | 55762 | `data` |
| 1 | `pe-resource-cab` | `d08bdc7321cd68d3dbddfb8ef7f64520b8d32f28b368d62e6dbd63d0c4f8afd7` | 1027737 | `cab` |
| 1 | `7z-pe` | `13b4b17671c12fd3f9db5491efb7fb389601b57ac7f89fd78638625c1ef201e4` | 234496 | `pe` |
| 1 | `7z-pe` | `0dd2080a38e06136c21e27527cc0b07baa99c01e52fbb28a55afe4a89be6487a` | 988160 | `pe` |
| 2 | `pe-resource-cab` | `1224399d7bb6d345cf019a32221deb2a353ec7459403a5be936c602fb40ab768` | 841273 | `cab` |
| 2 | `7z-pe` | `787ddf6f20f4cfcd1c9a496da4332723c8c37f8345d0f661ad6d3eb802b186cb` | 390656 | `pe` |
| 2 | `7z-pe` | `c36beed857f3f79293c7c1b8f3a5f0ac327a7958cd193eb6072d768827ff9f49` | 711168 | `pe` |
| 3 | `pe-resource-cab` | `1ee533aad0a83d34e19f5e7fba2ac7d25bd58f9e784e0823175d29f5be9b7f5d` | 564323 | `cab` |
| 3 | `7z-pe` | `9e06e62d114820eca15135fc869777999014e70e283e5b9f0351854010d24af2` | 306176 | `pe` |
| 3 | `7z-pe` | `d2884e7548ef989f11bf3ac8ae34b870868a53c3b47590e489de0fe77572bc7c` | 424448 | `pe` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.9488
- Root packing assessment: `False`
- Recursive layers analyzed: 10
- 7z status: `extracted`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
