# ShadowPad analysis results

Eight VX-Underground ShadowPad artifacts were reviewed using static PE inspection, loader decryption, proprietary-module parsing, QuickLZ decompression, and Config-module string recovery. No sample was executed and no recovered endpoint was contacted.

## Result matrix

| SHA-256 | Role / generation | Static config result | Configured network value |
|---|---|---|---|
| `f7ef194f2dcc341ba03f76872cb7c0dfbae8f79118f99cf73dfccfb146c4e966` | x64 resource dropper, ScatterBee AES-MD5 generation | Fully decoded | `TCP://fljhcqwe.com:80` |
| `1e06fd5b9aa0e5260369e52ec2d9f87060941de835234afd198b1d4c0b161678` | `IVIEWERS.dll` sideload component embedded in the preceding case | Component identified; no standalone config in this DLL | Inherited only through parent chain; none attributed to this DLL alone |
| `231d21ceefd5c70aa952e8a21523dfe6b5aae9ae6e2b71a0cdbe4e5430b4f5b3` | x86 TosBtKbd/Casper loader | Fully decoded | `www.grandfoodtony.com` on 80/443/8080 via TCP, HTTP, UDP |
| `656582bf82205ac3e10b46cbbcf8abb56dd67092459093f35ce8daa64f379a2c` | x86 TosBtKbd/Casper loader | Fully decoded | `websencl.com` on 8080/80/443 via TCP and HTTP |
| `d9438cd2cdc83e8efad7b0c9a825466efea709335b63d6181dfdc57fb1f4a4e3` | x86 TosBtKbd/Casper loader | Fully decoded | private builder/test value `10.0.123.1` on 65234/8080/57223 via HTTP/TCP |
| `284c664b4baff90444c4ed96cfcb4ef6d26cc7aedc46c1e996c359ecea95f697` | x64 Casper loader | Fully decoded | `https://goods.kankuedu.org` |
| `88a60c235a2fbf9b681d9b67daf8f67e9a21edd53fc84b8babfa8f286c38e6b8` | x64 Casper loader | Fully decoded | `HTTPS://gfsg.chickenkiller.com` |
| `ac6938e03f2a076152ee4ce23a39a0bfcd676e4f0b031574d442b6e2df532646` | x86 nsPack-wrapped TosBtKbd loader | Exact-hash primary-source config; generic static nsPack recovery remains unresolved | `www.pneword.net` on 80/443/53 via HTTP/TCP/UDP |

`confirmed static config` means the value was recovered from the sample's decoded configuration. It does not establish that an endpoint is online, malicious today, or controlled by the same operator. `10.0.123.1` is RFC1918 space and is retained only as builder/test context, not a public C2 IOC.

## Common behavior

The reviewed Casper generation decrypts a Root module from a high-entropy PE section, reconstructs proprietary module sections, loads embedded Plugins/Config/Install/transport modules, and keeps its network and persistence strings encrypted. The older x86 configuration is 0x858 bytes; the reviewed x64 generation adds four bytes and uses a 0x85c-byte layout. Both carry installation paths, service masquerades, a Run-key path, injection targets, up to nine server strings, four proxy strings, DNS resolver fields, and retry timing.

The newer ScatterBee chain stores a legitimate OLEVIEW executable, `IVIEWERS.dll`, and an opaque encrypted payload in PE resources. The decoded payload configures `Windows_Search_Update`, `wsuhost.exe`, DLL sideloading through `IVIEWERS.dll`, Run-key persistence, `svchost.exe` injection targets, and `TCP://fljhcqwe.com:80`.

ShadowPad is modular. Root initializes additional modules and delegates configuration, installation, online state, and transport operations. Public technical reports describe TCP/HTTP/UDP/DNS transports, persistence through services and Run keys, and process injection. Those family capabilities are not automatically attributed as observed execution in these cases; the case reports distinguish decoded intent from host telemetry.

## Detection assessment

| Confidence / false-positive risk | Detection material | Likely false positives |
|---|---|---|
| High / Low | Exact reviewed hashes; complete Casper key-schedule cluster plus proprietary-module layout; OLEVIEW loading `IVIEWERS.dll` from an unusual writable directory | Repacked samples evade hashes; internal reverse-engineering fixtures may reproduce the constants |
| Medium / Medium | `TosBtKbd.dll` or `mscoree.dll` sideload pattern combined with high-entropy `.rdata`, service/Run-key creation, and injection into configured system processes | Legitimate Toshiba/.NET components and enterprise service software can share individual names or behaviors |
| Low / High | Domain-only or path-only matching; generic Run-key, service creation, or `svchost.exe` injection alerts | Domains can be sinkholed/reassigned; service and Run-key operations are common administration activity |

Use the included YARA rules as triage, then confirm the decoded configuration. Use the Sigma rule only with image-load and path context. Domain indicators should remain supplemental and time-scoped.

## Primary references

- [PwC ScatterBee analysis and scripts](https://github.com/PwCUK-CTO/ScatterBee_Analysis)
- [Dr.Web BackDoor.ShadowPad.1 technical description](https://vms.drweb.com/virus/?i=21995048)
- [Dr.Web ShadowPad and PlugX study](https://st.drweb.com/static/new-www/news/2020/october/Study_of_the_ShadowPad_APT_backdoor_and_its_relation_to_PlugX_en.pdf)
- [ESET Winnti university campaign analysis](https://www.welivesecurity.com/2020/01/31/winnti-group-targeting-universities-hong-kong/)
- [Cyfirma report covering the reviewed OLEVIEW resource chain](https://www.cyfirma.com/research/shadowpad-malware-report/)
- [Kaspersky ICS ShadowPad campaign analysis](https://ics-cert.kaspersky.com/publications/reports/2022/06/27/attacks-on-industrial-control-systems-using-shadowpad/)

