# ShadowPad case d9438cd2cdc83e8efad7b0c9a825466efea709335b63d6181dfdc57fb1f4a4e3

- Source: VX-Underground ShadowPad collection
- Artifact: 123,904-byte x86 TosBtKbd/Casper loader
- Pattern: `casper_internal_test_config`
- Analysis: static only; no execution and no endpoint contact

## Decryption and configuration

The seed at RVA `0x7808` decrypts the same x86 Casper Root and 0x858-byte Config format as the other TosBtKbd cases. Campaign ID is `CLwKvjhHyeuLPsS6Z`. It installs `%ALLUSERSPROFILE%\MUI\service.exe`, uses service/Run-key name `MUI`, and configures injection into `svchost.exe`, `taskhost.exe`, `SearchIndexer.exe`, and `winlogon.exe`.

## C2 and IOC evidence

The server slots contain HTTP and TCP variants of `10.0.123.1` on ports 65234, 8080, and 57223. Because `10.0.123.1` is RFC1918 private space, these are confirmed builder/test configuration values but are `context_only`, not publishable Internet C2 IOCs. They may indicate an internal test environment, an unfinished build, or a configuration template.

No public C2 domain or address was recovered from this sample.

## Detection material

The sample hash and Casper algorithm/layout remain useful. Do not block `10.0.123.1` globally based on this report: private address reuse makes that condition extremely prone to false positives. Host analytics should instead focus on the exact MUI installation path combined with persistence and the loader signature.

