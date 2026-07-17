# amadey case ea07b2d53fa8793d39a63f4f787e3951cf3eb9fab05cc5a2b5cd3e303c241c10

## Overview

- Original name: `ea07b2d53fa8793d39a63f4f787e3951cf3eb9fab05cc5a2b5cd3e303c241c10`
- SHA-256: `ea07b2d53fa8793d39a63f4f787e3951cf3eb9fab05cc5a2b5cd3e303c241c10`
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
| 1 | `pe-resource-cab` | `0b77d9c7765c70567c2702f46acc8cac806699306d5c53619bdf5d5aeb640bef` | 925997 | `cab` |
| 1 | `7z-pe` | `13b4b17671c12fd3f9db5491efb7fb389601b57ac7f89fd78638625c1ef201e4` | 234496 | `pe` |
| 1 | `7z-pe` | `d0c24e50bb14c48e66d4d428170a80e50eb0f2993b3f15fe760edd896ba4840a` | 886272 | `pe` |
| 2 | `pe-resource-cab` | `654ce671c29a342b952d8d13e1cda9b7b1ad3433df055b051936f8b416092b74` | 739157 | `cab` |
| 2 | `7z-pe` | `d5959016421e5ee8e9728dd75063e38e853afcee1e830666798da13f44dca085` | 371200 | `pe` |
| 2 | `7z-pe` | `8d784a666f522f0ec605fb16ee6acffd593bd44a2889d4c1256c08768918ae86` | 710656 | `pe` |
| 3 | `pe-resource-cab` | `e1138eb9af83dc77ef6d369aad48cdace32707eaff98da6340436baf395c5042` | 563539 | `cab` |
| 3 | `7z-pe` | `43319b571c0e9b9859f2e52bb53c5c4fd99771e660af4d8510f6f1606dd098ea` | 286208 | `pe` |
| 3 | `7z-pe` | `55e8ebaac67d64552c1f532243ebfd7b17c45e3731f6071a72c34c12aa1f74dd` | 424448 | `pe` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.9411
- Root packing assessment: `False`
- Recursive layers analyzed: 10
- 7z status: `extracted`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
