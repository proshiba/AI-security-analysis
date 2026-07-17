# amadey case 12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1

## Overview

- Original name: `12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1`
- SHA-256: `12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1`
- Campaign shape: `direct_pe_or_container`
- Format: `pe`
- Packing suspected: `false`
- Packing classification: `not_packed`
- Unpack status: `no_artifact_recovered`
- Recovered static layers: 0
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| `http://5.42.65.125/k92lsA3dpb/index.php` | c2 | confirmed | amadey_config_decryption |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "c2_urls": [
    "http://5.42.65.125/k92lsA3dpb/index.php"
  ],
  "version": "4.13",
  "campaign_id": "810740",
  "install_directory": "0de90fc5c7",
  "install_filename": "Utsysc.exe",
  "rc4_key": "07c6bc37dc50874878dcb010336ed906",
  "profile": "amadey_custom_alphabet_base64",
  "static_config_recovered": true,
  "features": {
    "persistence": true,
    "plugin_download": true,
    "system_discovery": true,
    "rc4_protected_traffic": false
  }
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| - | none recovered | - | - | - |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 6.4966
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
