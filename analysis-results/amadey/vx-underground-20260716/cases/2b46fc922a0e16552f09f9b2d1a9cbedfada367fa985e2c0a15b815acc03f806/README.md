# amadey case 2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806

## Overview

- Original name: `2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806`
- SHA-256: `2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806`
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
| 1 | `pe-resource-cab` | `11089574efbb52bd069bb26718718078198db815b41611bb733b57dacde2ab37` | 993009 | `cab` |
| 1 | `7z-pe` | `13b4b17671c12fd3f9db5491efb7fb389601b57ac7f89fd78638625c1ef201e4` | 234496 | `pe` |
| 1 | `7z-pe` | `5ab2e69ef533adaa95312463a36293e2e99aefa07059066dc426c949dac8d88f` | 953344 | `pe` |
| 2 | `pe-resource-cab` | `ed8527539792ca5a4e9d6ab43a8e17e18bd0c3022cffd38067290edbbfb809ba` | 806453 | `cab` |
| 2 | `7z-pe` | `f17118884b0e8de9101666b145382094968ddd63196f0d982fa7e6f0bb325346` | 391680 | `pe` |
| 2 | `7z-pe` | `7580c7bdffe53c574e5b792618fb3425889b55575272d144a1929b8349d79893` | 712704 | `pe` |
| 3 | `pe-resource-cab` | `355a40fa619677d332aa349fe0b28874a9e98d520783b9597aaaab78290f1d89` | 565589 | `cab` |
| 3 | `7z-pe` | `7b1facc0ecec575c90ce4ed98d19ed38ab04cc8265b45faa517ba41ad7b590e6` | 306176 | `pe` |
| 3 | `7z-pe` | `66db55d1d689d451d56a324dafc4d72893bad5a886d2e81b23113663c9117974` | 424960 | `pe` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.9462
- Root packing assessment: `False`
- Recursive layers analyzed: 10
- 7z status: `extracted`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
