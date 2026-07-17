# StealC case `87f18bd70353e44aa74d3c2fda27a2ae5dd6e7d238c3d875f6240283bc909ba6`

## Overview

- Source: VX-Underground StealC family directory
- SHA-256: `87f18bd70353e44aa74d3c2fda27a2ae5dd6e7d238c3d875f6240283bc909ba6`
- Size: 82,329 bytes
- Format: x86 native PE (not .NET)
- Static state: `decoded_v1_config`
- Sample executed: no
- Network contacted: no

## Recovered configuration

| Field | Value |
|---|---|
| Generation | `StealC-v1` |
| Decode method | `v1-base64-rc4-skip-key` |
| C2 gate | `http://777palm.com/bef7fb05c9ef6540.php` |
| Dependency directory | `http://777palm.com/2ccaf544c0cf7de7/` |
| Build ID | `default` |
| Decoded strings | 325 |

C2 and dependency paths were recovered from the sample bytes. No liveness check was performed.

## Behavioral model

Decoded v1 profiles expose browser credential/cookie/autofill/history/card collection, Firefox and Chromium data access, Telegram/Discord/Outlook/Pidgin/Steam/Tox targets, screenshot and file-grabber support, optional loader behavior, and delayed self-deletion. The reviewed v1 transport constructs WinINet HTTP multipart POST bodies with fields such as `hwid`, `build`, `token`, `file_name`, `file`, and `message`. These are static code/config observations; this case was not allowed to execute.

## Detection notes

- Low false-positive risk: exact SHA-256, with low longevity against rebuilding.
- Medium false-positive risk: StealC v1 YARA structural rules; dense Base64/resource tables or repeated x86 wrapper calls can overlap with protected legitimate software.
- Medium false-positive risk: the Sigma delayed `cmd.exe /c timeout /t 5 ... del /f /q` pattern can match installers and cleanup tools.
- High false-positive risk: generic browser database, Telegram, Discord, Outlook, or Steam file access also occurs in backup, migration, and endpoint-security products and needs process lineage plus destination context.

## Limitations

No endpoint was contacted, so reachability, HTTP title, response banner, TLS certificate, JARM, and Shodan banner hash are intentionally not asserted. `confirmed_static_config` describes decoded bytes, not current C2 ownership or liveness.
