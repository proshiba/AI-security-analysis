# Reassigned DonutLoader submission: index-XOR multi-PE chain

## Scope and classification outcome

- Submission: `260715-khdyjsbs41_pw_infected.zip`
- Submission SHA-256: `c4cc4a60f12b13d5f0348b5c4c34db56ec2119eca45c77259d3bbdee6e8a0f0`
- Primary malicious DLL: `netutils.dll`
- Primary SHA-256: `e8a4f2026d5aac1b74acbf7033ea0ec626055d3dbf5d645c9f741a75ad17ea37`
- Requested analysis assignment: DonutLoader
- Static delivery profile: `index_xor_multi_pe`
- Strict Donut structure: **not recovered**
- Terminal payload: native `10FX` RAT / PureHVNC-like, high confidence
- Analysis: static only; no execution and no network contact

This case was rebuilt after the two submitted Triage samples were reported as
reversed. The directory follows the corrected DonutLoader assignment, but the
static evidence does not contain the supported Donut call-over-instance layout.
The result therefore retains the submitted label while explicitly marking Donut
as unconfirmed. It must not be used as a positive DonutLoader training sample.

## Recovered infection chain

| Layer | Size | SHA-256 | Interpretation |
|---|---:|---|---|
| Nested ZIP | 788,792 | `af05c0b7aefa3554b15792bab2ed7460b011d62ae64841541ebc24a33dd103d6` | delivery container |
| IMG | 1,087,488 | `3b69050c148e6309a1e0b0f21c54cc3ee99da3c542e8f6d00fb3a93d6c7dcb21` | disk-image lure |
| Renamed `easinvoker.exe` | 100,608 | `26c642331d6c1fb00a5be9895c636c7e4db7912a4d2920e896ee1ccf3a2a40e5` | signed side-load host; context only |
| `netutils.dll` | 923,372 | `e8a4f2026d5aac1b74acbf7033ea0ec626055d3dbf5d645c9f741a75ad17ea37` | malicious loader/orchestrator |
| Recovered PE 1 | 9,728 | `d8678e6aa75212e00a63fc29b2e6789498f745e2bbf0568a6c945a0229adc806` | WinIo-style physical-memory driver |
| Recovered PE 2 | 393,216 | `9d1e785c40f5c3974c3bb09a03bab75a13cd80b031b3f071ac9703679779b729` | persistence, kill-AV and BYOVD orchestrator |
| Recovered PE 3 | 278,016 | `2e12fa92aae24cf0ec9890151f28fa402324439ccd671135370cb3a2f541087e` | native `10FX` terminal RAT |
| Recovered PE 4 | 28,672 | `742d314f3403f6184c1a5119adc75f45ee205b9532c1a9f094306bae6f54cb3e` | Sysinternals Process Explorer driver; dual-use context |

The family-neutral recovery transform is
`clear[i] = cipher[i+1] XOR ((key+i) & 0xff)`. Four structurally valid PE files
were recovered at offsets 9,080, 27,793, 424,222 and 761,579. Earlier claims of
a sparse Donut payload and the hashes `65fa23…` / `7c76e0…` were not reproducible
from the original archive and have been withdrawn.

## Configuration and C2

- Configured C2: `154.82.93.206:8080`
- Confidence: high; adjacent static config strings and terminal protocol markers
- Frame header: three little-endian `uint32` values
- Magic: `0x58463031` (`10FX` in memory bytes)
- Type roles observed statically: heartbeat/echo, registration JSON, shell,
  binary input, task JSON, plugin and SOCKS5 relay

The extractor now associates an IP only with an adjacent standalone port or an
explicit `host:port` string. This prevents `WOW6432Node` registry paths from
being incorrectly emitted as port 6432. The endpoint was not contacted; banner,
JARM, certificate, HTTP title and current service state are unknown. A passive
Shodan lead is `ip:154.82.93.206 port:8080`, not proof of current activity.

## Behavior

The loader uses a renamed Microsoft host and adjacent `netutils.dll`, performs
anti-analysis checks, stages files below `%ProgramData%\Microsoft\NetTokenBroker`,
uses `runtime.tmp` and `heartbeat.bin`, and contains Defender policy/exclusion,
kill-AV and BYOVD logic. The terminal RAT exposes screen capture and streaming,
browser credential/cookie access, process/service/window/file inventory, shell,
SOCKS5, plugins, update and restart functions. These are static capabilities;
they do not prove execution on this host.

## Detection and false positives

- Low FP: exact malicious hashes, the recovered terminal hash plus `10FX`
  capability cluster, or the full side-load/persistence/C2 correlation.
- Medium FP: renamed `easinvoker.exe` loading adjacent `netutils.dll` followed by
  `NetTokenBroker` writes or Defender exclusion changes. Enterprise wrappers can
  side-load DLLs or configure exclusions.
- High FP: filename `netutils.dll`, the lure name, port 8080, or a single
  Defender exclusion. These are common individually.

The YARA rules intentionally distinguish the reviewed XOR carrier from the
terminal `10FX` family. No YARA rule calls the carrier confirmed DonutLoader.

