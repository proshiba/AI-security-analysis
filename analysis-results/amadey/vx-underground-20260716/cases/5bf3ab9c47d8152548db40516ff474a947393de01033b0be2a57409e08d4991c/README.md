# amadey case 5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c

## Overview

- Original name: `5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c`
- SHA-256: `5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c`
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
| `http://31.41.244.10/Dem7kTu/index.php` | c2 | confirmed | amadey_config_decryption |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "c2_urls": [
    "http://31.41.244.10/Dem7kTu/index.php"
  ],
  "version": "4.41",
  "campaign_id": "c7817d",
  "install_directory": "0e8d0864aa",
  "install_filename": "svoutse.exe",
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

- Root entropy: 6.514
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
