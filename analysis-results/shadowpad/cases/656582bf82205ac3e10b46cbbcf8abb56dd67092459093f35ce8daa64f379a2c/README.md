# ShadowPad case 656582bf82205ac3e10b46cbbcf8abb56dd67092459093f35ce8daa64f379a2c

- Source: VX-Underground ShadowPad collection
- Artifact: 123,392-byte x86 TosBtKbd/Casper loader
- Pattern: `casper_websencl`
- Analysis: static only; no execution and no endpoint contact

## Decryption and configuration

The loader seed was found at RVA `0x77f8`; static decoding recovered the same proprietary module and 0x858-byte Config structure as the `grandfoodtony` case. The campaign ID is `9AsW5rVRZ4qiR7AgU`.

Persistence masquerades as `VMware Snapshot Provider Service` and installs `%ProgramData%\VMware\RawdskCompatibility\virtual\vmrawdsk.exe` through the Windows Run key. The four configured injection targets are `%windir%\system32\svchost.exe`, `%windir%\system32\winlogon.exe`, `%windir%\system32\taskhost.exe`, and another `svchost.exe` fallback.

## C2 and IOC evidence

The config contains TCP and HTTP entries for `websencl.com` on ports 8080, 80, and 443. UDP slots are empty. Confidence is `confirmed_static_config`; no liveness or ownership test was performed.

## Detection material

Correlate the Casper key schedule and module layout with the VMware-masquerading path and `websencl.com`. VMware service names and paths in isolation can collide with legitimate virtualization software, giving a medium false-positive risk. The exact nonstandard `RawdskCompatibility\virtual\vmrawdsk.exe` path plus decoded domain is substantially stronger.

