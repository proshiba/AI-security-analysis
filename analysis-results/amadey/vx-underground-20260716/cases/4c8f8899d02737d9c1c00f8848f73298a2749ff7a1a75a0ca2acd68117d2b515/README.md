# amadey case 4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515

## Overview

- Original name: `4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515`
- SHA-256: `4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515`
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
| 1 | `pe-resource-cab` | `f4ed2efa19ae120c66021928cfc899be27abc41424edae270d6df0bb2c889230` | 962945 | `cab` |
| 1 | `7z-pe` | `13b4b17671c12fd3f9db5491efb7fb389601b57ac7f89fd78638625c1ef201e4` | 234496 | `pe` |
| 1 | `7z-pe` | `39dc2a3e790fc63707c308292bb394b251534329de1b15801cd2538f25f9ec0d` | 923648 | `pe` |
| 2 | `pe-resource-cab` | `69ab5b820e4f418388bcfcde19d5f47348eb562bd1ddc30336650dc338f7579d` | 776733 | `cab` |
| 2 | `7z-pe` | `c9c321788daa2d2c8c59a46426f113591651b8232396c4f0f6cab2d0cfc46ef6` | 360448 | `pe` |
| 2 | `7z-pe` | `397844edbe05f7e680800bb7fcb3d06efc1fef97623cc943516183a91985f871` | 692224 | `pe` |
| 3 | `pe-resource-cab` | `44ec2ec9b21564b6a8f26b1f7dc6e7302482c71e5a6c62731d70b56f01a5c570` | 545229 | `cab` |
| 3 | `7z-pe` | `6452272d08dd94032221d31211829780db356ca9cadc423293ab5c034611e708` | 275456 | `pe` |
| 3 | `7z-pe` | `5cb122a26c5f71b7c730ad7dbcc44d4e2d4599c9fef2d24480d47c3fbaca9df5` | 415744 | `pe` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.9434
- Root packing assessment: `False`
- Recursive layers analyzed: 10
- 7z status: `extracted`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
