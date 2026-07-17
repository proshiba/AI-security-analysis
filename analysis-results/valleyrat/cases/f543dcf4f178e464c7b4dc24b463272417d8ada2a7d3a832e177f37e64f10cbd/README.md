# ValleyRAT Japanese bonus-notice malspam

## Judgment

- `confirmed`: outer archive `f543dcf4...f10cbd` contains a signed CEF host and malicious `libcef.dll`; the delivery chain is consistent with DLL side-loading.
- `confirmed`: campaign reporting and public sandbox relations associate the archive with `ljowqjd.cn` and the lure subject `【重要通知】賞与に関する新着情報があります`.
- `unverified`: the malicious DLL was unavailable from MalwareBazaar, so its embedded ValleyRAT configuration and final C2 were not independently recovered here.
- `not an IOC`: `02698279...90e89` is the validly signed `cefclient.exe`-style host. Treating this hash alone as malware would create serious false positives.

## Infection chain

```text
Japanese malspam
  -> xjvbn.com delivery page / ZIP
  -> 解凍してご確認ください.zip
  -> signed 20260327003703.EXE loads sibling libcef.dll
  -> malicious DLL / ValleyRAT execution chain
```

## File evidence

| Role | SHA-256 | Confidence |
|---|---|---|
| Outer ZIP | `f543dcf4f178e464c7b4dc24b463272417d8ada2a7d3a832e177f37e64f10cbd` | confirmed malicious |
| Malicious `libcef.dll` | `07ead27a736604b28876f4a0c940279983bd7076c2e1fed4039c4f0a81f3e0d5` | confirmed malicious |
| Signed host | `02698279d30b2d95f571ba613c80980a84574f3b334eafe0c8d2c0839be90e89` | dual-use; context only |

The signed host has SHA-1 `54f5175d5c69665c84fca7deb61c50930e2a359c`, imphash `058a1f1647379ead0102eec3e36d4266`, and authentihash `cf35a9fac6ac926e102d041404b6a763a72cd52b5141d73dd6f0d2c5f3ede88d`. These values describe the host, not the malicious DLL.

## Network evidence

| Value | Role | Confidence / caution |
|---|---|---|
| `xjvbn.com` | delivery site | confirmed by campaign reporting |
| `ljowqjd.cn` | contacted domain | confirmed public relation; exact protocol not recovered locally |
| `198.44.170.58` | reported infrastructure | unverified in the unavailable config |
| `162.159.36.2` | Cloudflare-related resolution | infrastructure context only; do not label as ValleyRAT C2 |

## Detection assessment

- **Low false-positive risk**: exact SHA-256 of the outer ZIP or malicious DLL. Hash rules are brittle against repacking.
- **Medium**: a nonstandard executable loading a sibling `libcef.dll` from a user-writable extraction directory, combined with the mail lure or network IOC.
- **High**: `libcef.dll` filename, a CEF host, or the signed host hash alone. Legitimate Chromium/CEF applications commonly use this layout.

Rules: [YARA](rules/valleyrat_cef_sideload.yar) and [Sigma](rules/valleyrat_cef_sideload.yml). See [IOCs](iocs.json).

## Limitations

MalwareBazaar returned `file_not_found` for the outer ZIP and malicious DLL. VirusTotal public metadata and the ITOCHU campaign report were used without downloading or executing the sample. No live C2 check was authorized or performed.
