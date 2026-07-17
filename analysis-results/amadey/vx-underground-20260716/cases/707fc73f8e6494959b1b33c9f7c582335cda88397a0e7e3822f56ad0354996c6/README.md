# amadey case 707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6

## Overview

- Original name: `707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6`
- SHA-256: `707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6`
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
| 1 | `pe-resource-cab` | `574b34d6e6f9697d85c369146f666fb7a1a5b3d986191d9af3ca6bc027511ffb` | 986997 | `cab` |
| 1 | `7z-pe` | `13b4b17671c12fd3f9db5491efb7fb389601b57ac7f89fd78638625c1ef201e4` | 234496 | `pe` |
| 1 | `7z-pe` | `f8d201424ae5f3611bace8a5b2ceebf8af9dfe5c0070d43acae7c4912edd287d` | 952320 | `pe` |
| 2 | `pe-resource-cab` | `4ffcf8de9a51f9c85dcaea882b0ed60b4d6a17ea7d576659e3d65a857208f0f2` | 805201 | `cab` |
| 2 | `7z-pe` | `cb6ca243164eff6d3b696e5e148ba3119e42b39e3c5df15c2174a444c5177a30` | 391680 | `pe` |
| 2 | `7z-pe` | `40933f0becde48bcf44d2b2940b255f21d57a234efa0101bd2549dd501b68c5a` | 711680 | `pe` |
| 3 | `pe-resource-cab` | `9be1b87deeeda14ee4405f92f4c3e747fe25011b121a1d2e3f09df1a2c6e63b4` | 564657 | `cab` |
| 3 | `7z-pe` | `a69b6204b3ed318ff4ea60b54d621be2379eb9a2c335374043f9d601d4488603` | 306176 | `pe` |
| 3 | `7z-pe` | `9df10d5302da6191fa27e4839ff01547bd3c05b3b4d4db650c0c1a6c7426e8df` | 424960 | `pe` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.9458
- Root packing assessment: `False`
- Recursive layers analyzed: 10
- 7z status: `extracted`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
