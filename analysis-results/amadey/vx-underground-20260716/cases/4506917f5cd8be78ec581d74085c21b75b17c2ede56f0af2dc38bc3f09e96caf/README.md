# amadey case 4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf

## Overview

- Original name: `4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf`
- SHA-256: `4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf`
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
    "system_discovery": false,
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
| 1 | `pe-resource-cab` | `8fd5bb5f589740c31876597dd4ab8abe83f2adf1ece5af8474f10c60ab06b347` | 1027673 | `cab` |
| 1 | `7z-pe` | `13b4b17671c12fd3f9db5491efb7fb389601b57ac7f89fd78638625c1ef201e4` | 234496 | `pe` |
| 1 | `7z-pe` | `d4a8f54790b569f241166c56b4c196542fc5daf1f9cdc79bb0ce5c27d5309568` | 988672 | `pe` |
| 2 | `pe-resource-cab` | `af6452de9eba13a6e3d48c991943264b87248f7613aad1eb6d6a0eff34b2fa07` | 841453 | `cab` |
| 2 | `7z-pe` | `e7d88b07f286f4304d082210ed35b70613776c21e3549f9c50699e6fb308433d` | 390656 | `pe` |
| 2 | `7z-pe` | `0203550251a726353268b2d844909714090f254fc6e318d66fabd5fac684359e` | 711168 | `pe` |
| 3 | `pe-resource-cab` | `f5c8d25dbf30fe0b482494153c71e571fd47f0b428ecb80ddb37794e5f39cb33` | 563995 | `cab` |
| 3 | `7z-pe` | `3a33b74f4a1d0b3ead49175962e9435c8a24b8a023905adafa7f87a9b90f15a8` | 306176 | `pe` |
| 3 | `7z-pe` | `002cb504857c7f2e4318f3d68f8cf1945987fba10c6fb94482d9b1bf8dfc57e3` | 424448 | `pe` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.9484
- Root packing assessment: `False`
- Recursive layers analyzed: 10
- 7z status: `extracted`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
