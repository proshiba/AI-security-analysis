# amadey case b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65

## Overview

- Original name: `b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65`
- SHA-256: `b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65`
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
| `http://62.204.41.242/9vZbns/index.php` | c2 | confirmed | amadey_config_decryption |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "c2_urls": [
    "http://62.204.41.242/9vZbns/index.php"
  ],
  "version": "3.66",
  "campaign_id": "62fadb",
  "install_directory": "4b9a106e76",
  "install_filename": "nbveek.exe",
  "rc4_key": "c1ec479e5342a25940592acf24703eb2",
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

- Root entropy: 6.3608
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Confirmed C2 status requires the reviewed custom-alphabet/Base64 config structure; literal-only URLs remain candidates.
- Themida/WinLicense wrappers require a recovered inner PE before configuration extraction can be complete.
- No recovered endpoint was contacted.
