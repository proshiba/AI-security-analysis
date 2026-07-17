# Silver Fox fake-VPN AtlasCross / Atlas RAT campaign

## Judgment

Public technical reporting confirms a Setup Factory lure chain that installs legitimate decoy software and launches `Schools.exe`. The loader decrypts a 324-byte Gh0st-style configuration, connects to `bifa668.com:9899`, sends the 8-byte `SFuck\0\0\0` beacon, receives a fixed 386,380-byte second stage, and reflectively loads an Atlas RAT DLL exporting `AtlasInfo`.

The published samples were unavailable from MalwareBazaar. The repository therefore reproduces the published config transform and validates it against a synthetic fixture. The campaign values below are source-confirmed but not independently extracted from a downloaded sample in this run.

## Chain and configuration

```text
fake VPN/messaging domain
  -> Setup Factory launcher + legitimate decoy
  -> Schools.exe
  -> decrypt 324-byte config (marker By@V<)
  -> TCP bifa668.com:9899; send SFuck + 3 NUL
  -> receive 386,380-byte unencrypted stage
  -> reflective loader at 0x0000; PE at 0x1C04
  -> AtlasInfo(config at shellcode_base + 0x5E408)
```

Config layout: host at `0x00` (64 bytes), port at `0x40` (`uint16le`), padding at `0x42`, REMARK at `0x44` (128 bytes), GROUPS at `0xC4` (128 bytes). The on-disk INI names `LoginAddress`, `LoginPort`, `REMARK`, `GROUPS`, `Time` and `SIGN`; REMARK/GROUPS are campaign/operator identifiers, not fallback IP addresses.

## C2 and protocol

- primary C2: `bifa668.com:9899`
- reported A record: `61.111.250.139`
- authoritative DNS: `a.share-dns.com`, `b.share-dns.net`
- loader check-in: hex `53 46 75 63 6b 00 00 00`
- HTTP fallback UA: `Mozilla/4.0 (compatible)`
- RAT traffic: clear 56-byte header followed by ChaCha20-protected content with per-packet material
- mutex: `Global{K8A9C1D9-FUCK-AE99-CLOSE-bifa668.com}`

No alternate C2 list was established from the published 324-byte config. REMARK/GROUPS bytes previously resembling IPv4 values are identifiers.

## Host behavior

Observed capabilities include scheduled-task persistence under `\Microsoft\Windows\AppID\`, artifacts in `C:\Users\Public\Documents`, PowerShell-in-AppDomain execution with AMSI/ETW/CLM/script-block bypasses, WeChat process injection, and disruption of security-product TCP sessions. The Atlas RAT DLL uses `AtlasPro.ini`; operator-supplied modules can vary.

## Detection assessment

- **Low false-positive risk**: exact sample hashes; raw TCP payload starting with `SFuck\0\0\0`; `AtlasInfo` plus `AtlasPro.ini` plus the mutex template.
- **Medium**: outbound workstation TCP/9899, config files under Public Documents, scheduled tasks under the AppID path, or non-PowerShell processes loading `System.Management.Automation.dll`.
- **High**: fake-domain lookalikes, old `Mozilla/4.0 (compatible)` UA, or UltraViewer artifacts individually because legitimate remote-support installations exist.

See [IOCs](iocs.json), [YARA](rules/atlascross.yar), [Sigma](rules/atlascross.yml), and the reusable extractor under `extractors/atlascross/`.

## Sources and limitations

- https://hexastrike.com/resources/blog/threat-intelligence/trust-the-tunnel-get-the-trojan-silver-fox-delivers-atlas-rat-via-weaponized-vpn-installers/
- https://www.proofpoint.com/us/blog/threat-insight/ta4922-suspected-chinese-crime-group-going-global

No sample was executed and no C2 was contacted.
