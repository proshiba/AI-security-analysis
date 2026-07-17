# ShadowPad case 231d21ceefd5c70aa952e8a21523dfe6b5aae9ae6e2b71a0cdbe4e5430b4f5b3

- Source: VX-Underground ShadowPad collection
- Artifact: 144,728-byte x86 TosBtKbd/Casper loader
- Pattern: `casper_grandfoodtony`
- Analysis: static only; no execution and no endpoint contact

## Decryption and configuration

The loader seed was found structurally at RVA `0x77f8`; the encrypted stream begins at `0x77fc`. Static decoding recovered the proprietary Root module and a four-state-encrypted, QuickLZ level-1 Config block at decoded offset `0x2d7c`.

Campaign ID is `D0a2MkJLmoTKHbCAn`. Persistence masquerades as `ChromeUpdateService` at `%ALLUSERSPROFILE%\Chrome\AppData\Update\ChromeUpdate.exe`, using `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`. Configured injection targets include both 32-bit and 64-bit Kaspersky NetworkAgent `klrbtagt.exe` paths, `%windir%\system32\svchost.exe`, and `%windir%\system32\taskhost.exe`. These values are static intent rather than observed actions.

## C2 and IOC evidence

The config contains `www.grandfoodtony.com` on ports 80, 443, and 8080 for each of TCP, HTTP, and UDP. All nine protocol entries are confirmed static config values. Public campaign reporting also associates this domain with ShadowPad activity, but current liveness was not tested.

## Detection material

The strongest static rule combines the x86 outer key schedule, proprietary module header, Config flags `0x12345678`, QuickLZ framing, and TosBtKbd sideload context. Detecting `ChromeUpdateService` alone has medium-to-high false-positive risk; combining the exact path, Kaspersky injection targets, and network domain lowers it. Domain-only detection remains time-sensitive.

Reference: [Kaspersky ICS ShadowPad campaign analysis](https://ics-cert.kaspersky.com/publications/reports/2022/06/27/attacks-on-industrial-control-systems-using-shadowpad/).

