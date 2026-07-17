# ShadowPad case 88a60c235a2fbf9b681d9b67daf8f67e9a21edd53fc84b8babfa8f286c38e6b8

- Source: VX-Underground ShadowPad collection
- Artifact: 131,584-byte x64 native PE
- Pattern: `casper_chickenkiller`
- Analysis: static only; no execution and no endpoint contact

## Decryption and configuration

This artifact uses the same x64 outer stream, proprietary module format, ID-102 Config module, single-byte block cipher, QuickLZ framing, and 0x85c structure as `284c...`. The independently recovered campaign ID is `uq2kKaadPToLV5qZj`.

Persistence masquerades as `System Event Manager` and installs `C:\Windows\inf\Termservice\tslabels.exe` through the Windows Run key. Injection targets are `svchost.exe`, `SearchIndexer.exe`, `WmiPrvSE.exe`, and Windows Media Player.

## C2 and IOC evidence

The only server string is `HTTPS://gfsg.chickenkiller.com`. It is confirmed static configuration. As with the other URL-only x64 config, port 443 is conventional but not explicitly stored and therefore is not promoted to an observed endpoint.

## Detection material

Combine the x64 Casper algorithm/layout rule with the unusual `C:\Windows\inf\Termservice\tslabels.exe` path and the configured domain. `System Event Manager` alone is generic and creates substantial false positives. Dynamic analytics should correlate service or Run-key persistence, the unusual binary path, and subsequent HTTPS activity.

