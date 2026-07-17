# StealC case `0b2079978ba2073cfde3c6bc39847431e4e2ab64db27d592df01c4f93d209ca1`

## Overview

- Source: VX-Underground StealC family directory
- SHA-256: `0b2079978ba2073cfde3c6bc39847431e4e2ab64db27d592df01c4f93d209ca1`
- Size: 258,048 bytes
- Format: x86 native PE (not .NET)
- Static state: `high_entropy_native_wrapper`
- Sample executed: no
- Network contacted: no

## Recovered configuration

| Field | Value |
|---|---|
| Static config | Not recovered |
| Protection/profile state | `high_entropy_native_wrapper` |
| C2 | Unknown from this static layer |

The submitted outer layer is retained as a confirmed corpus hash, but no C2 is promoted from unverified strings. Isolated runtime unpacking would be required to obtain a plaintext inner payload.

## Behavioral model

Decoded v1 profiles expose browser credential/cookie/autofill/history/card collection, Firefox and Chromium data access, Telegram/Discord/Outlook/Pidgin/Steam/Tox targets, screenshot and file-grabber support, optional loader behavior, and delayed self-deletion. The reviewed v1 transport constructs WinINet HTTP multipart POST bodies with fields such as `hwid`, `build`, `token`, `file_name`, `file`, and `message`. These are static code/config observations; this case was not allowed to execute.

## Detection notes

- Low false-positive risk: exact SHA-256, with low longevity against rebuilding.
- Medium false-positive risk: StealC v1 YARA structural rules; dense Base64/resource tables or repeated x86 wrapper calls can overlap with protected legitimate software.
- Medium false-positive risk: the Sigma delayed `cmd.exe /c timeout /t 5 ... del /f /q` pattern can match installers and cleanup tools.
- High false-positive risk: generic browser database, Telegram, Discord, Outlook, or Steam file access also occurs in backup, migration, and endpoint-security products and needs process lineage plus destination context.

## Limitations

No endpoint was contacted, so reachability, HTTP title, response banner, TLS certificate, JARM, and Shodan banner hash are intentionally not asserted. `confirmed_static_config` describes decoded bytes, not current C2 ownership or liveness.
