# amadey case ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839

## Overview

- Original name: `ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839`
- SHA-256: `ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839`
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
| `http://185.215.113.19/Vi9leo/index.php` | c2 | confirmed | amadey_config_decryption |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "c2_urls": [
    "http://185.215.113.19/Vi9leo/index.php"
  ],
  "version": "4.41",
  "campaign_id": "0657d1",
  "install_directory": "0d8f5eb8a7",
  "install_filename": "explorti.exe",
  "rc4_key": "006700e5a2ab05704bbb0c589b88924d",
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

- Root entropy: 6.5164
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
