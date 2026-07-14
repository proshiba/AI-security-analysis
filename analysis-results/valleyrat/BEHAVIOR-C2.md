# ValleyRAT behavior and C2 model

This document consolidates the behavior and command-and-control assessment for 11 analyzed cases. It distinguishes what was directly recovered from each artifact from broader family capability and from campaign-level inference. Some cases are associated with SilverFox-style delivery and may represent different operators using leaked or shared builders.

## Confidence model

- confirmed: recovered configuration, process-attributed communication, or protocol response supports the conclusion.
- confirmed_config: a configuration was recovered, but current protocol response or liveness was not established.
- confirmed_distribution_only: a payload or bundle distribution URL was confirmed, but no final implant C2 was recovered.
- inferred_external: public sandbox or other external evidence supports the endpoint, but local final configuration was not recovered.
- unverified: a related-campaign lead exists but is not attributed to this sample.

## Campaign behavior model

| Pattern | Observed infection behavior | Expected C2 role |
|---|---|---|
| dll_sideload_vvas_bundle | Signed host loads a malicious DLL; XOR-decoded vvaS stager exposes marker, API hashes, and endpoint structure | Protocol-bearing endpoints in the recovered header |
| msi_embedded variants | MSI custom action, embedded CAB or PE, side-loading, task creation, and Defender weakening | Distribution and final C2 must be separated |
| installer_overlay_dropper | Installer or overlay stages files under temporary or program directories and launches a host process | Process-attributed endpoint is stronger than an installer string |
| single_pe_n520_managed | HTTP encrypted config followed by a custom TLS server-first protocol | Config distribution on port 9000; interactive C2 on port 9999 |
| upx_nrv2e_silverfox_http_bundle | UPX unpacking, HTTP bundle retrieval, modified RC4 recovery, and signed-host DLL side-loading | Confirmed URL is distribution only until implant config is recovered |
| unresolved Inno or Qt | Final child payload or configuration was unavailable | External IOC remains inferred or unverified |

## N520 protocol confirmed scope

- Configuration source: http://118.107.21.88:9000/config.enc.
- Configuration cryptography: AES-256-CBC using a key derived from SHA-256 of N520CfgKey!@#2026.
- Recovered C2: 118.107.21.88:9999 with a 60-second sleep value.
- TLS presentation: SNI update.microsoft.com and certificate common name Windows Update - A4608A21.
- Server-first handshake: 44 bytes containing a session identifier, CRC32, and fixed magic validation.
- Session protection: a key derived from handshake bytes 8 through 39 and the session identifier, with AES-CBC and truncated HMAC-SHA256.
- Client command roles recovered statically: command 1 registration or heartbeat, command 3 station identifier, command 2 result upload, and command 17 plugin request or execution.
- Server command roles recovered statically: commands 16 and 18 provide plugin DLL content. Recovered plugin names indicate terminal, desktop, file, process, registry, and SOCKS-related capabilities.
- Bounded validation on 2026-07-15 sent one empty command-1 check-in. During the 20-second and 16 MiB collection bound, no response, station identifier, plugin, fallback C2, or command was received.
- No guessed operator command, brute force, arbitrary execution, or server modification was attempted.

## Case matrix

| SHA-256 prefix | Observed behavior | C2 or infrastructure | Confidence |
|---|---|---|---|
| 8bf54a76924a | chgport.exe and LoggerCollector.dll side-load; XOR 0x14 vvaS recovery | 202.95.8.27:6666 and :8888 | confirmed |
| b433ecdf855b | MSI/OLE, embedded CAB, mesedge.exe and cef_frame.dll side-load, task and Defender changes | www.tq8j.com:443 and sandbox-associated 103.45.64.246 | confirmed |
| 942be7e0bd06 | Large-overlay installer stages and starts setup.exe from user-writable locations | 150.158.50.175:443 | confirmed |
| eab4918ea758 | Signed x86 PE, WinUpdateService logon task, and WriteProcessMemory activity | 154.81.37.130:4444 and :5555 | confirmed |
| 15015ac752a8 | vvaS side-load bundle and XOR 0x14 configuration recovery | 134.122.128.66:6666 and :8888 | confirmed_config |
| 5bdcf2d4fd8a | SysCEO-style bundle, dwmhost.exe side-load, and qt64.dat stage | 27.124.18.166:63016 and :63026 | confirmed |
| 0e4931df7ea3 | MSI custom action, OSS stage, SYSTEM task, Defender exclusion, and final host execution | 8.210.15.149:28300 | confirmed |
| d11e793159f0 | Managed N520 implant, encrypted HTTP config, and custom TLS protocol | config 118.107.21.88:9000; C2 118.107.21.88:9999 | confirmed |
| df603ed55cbf | Inno installer with SilverFox-style child execution; local child quarantined | oidng2.duoshit.com and 51.79.18.52:443 | inferred_external |
| 6546aad60371 | UPX and modified-RC4 bundle recovery; signed Tencent host and nvml.dll pair | 43.198.235.91/getinstall64 distribution | confirmed_distribution_only |
| 32146526cbc3 | Large Qt-linked obfuscated artifact with domain correlation | cqbxbkj.cn and 18.167.91.239; port 8880 unverified | mixed_inferred_unverified |

## Detection implications

- Do not equate a stage URL, CDN, object-storage host, or configuration URL with final C2.
- Do not classify TCP openness, port 443, DNS resolution, or a Shodan hash alone as proof of ValleyRAT.
- Prefer relationships: signed host plus unexpected DLL, loader plus encrypted data file, task or Defender change, recovered configuration, and protocol framing.
- Multiple ports may be fallback endpoints, but each endpoint should retain its own evidence and confidence.