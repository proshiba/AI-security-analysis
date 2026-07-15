# PureHVNC native `10FX` case

## Scope and identity

- Submission: `260715-khdyjsbs41_pw_infected.zip`
- Submission SHA-256: `c4cc4a60f12b13d5f0348b5c4c34db56ec2119eca45c77259d3bbdee6e8a0f0`
- Primary malicious DLL: `netutils.dll`
- Primary SHA-256: `e8a4f2026d5aac1b74acbf7033ea0ec626055d3dbf5d645c9f741a75ad17ea37`
- Classification: native PureHVNC-like RAT, high confidence
- Analysis: deep static recovery; no execution and no network contact

The archive contains a second ZIP and an IMG volume named `DOCUMENTS`. A genuine
Microsoft `easinvoker.exe`, renamed `Notice from Tax Department.exe`, imports
`NetApiBufferFree` from the hidden malicious `netutils.dll`. The embedded
Authenticode material was inventoried but its trust chain was not independently
validated.

## Recovered chain

| Layer | Size | SHA-256 | Interpretation |
|---|---:|---|---|
| Nested ZIP | 788,792 | `af05c0b7aefa3554b15792bab2ed7460b011d62ae64841541ebc24a33dd103d6` | delivery container |
| IMG | 1,087,488 | `3b69050c148e6309a1e0b0f21c54cc3ee99da3c542e8f6d00fb3a93d6c7dcb21` | disk-image lure |
| Host EXE | 100,608 | `26c642331d6c1fb00a5be9895c636c7e4db7912a4d2920e896ee1ccf3a2a40e5` | signed Microsoft side-load host |
| First-byte/index-XOR stage | 393,406 | `deea77c040d56b78381afe82bdb08c4e043f5436941f2ef5737550e9b481115a` | decoded envelope |
| Sparse Donut shellcode | 28,885 | `65fa23f24a4841bc1fa97dca020ec7b926b9be66d6b471d15940c5e305db3f22` | embedded loader |
| Native RAT core | 337,356 | `7c76e0e234b8700ba041e444547883bf681284076a02b2045a6a746c6387e4e0` | terminal payload |
| `killav_sc.dll` | 18,432 | `61723d024780817f23d63646be04dd88be0f5111e78e81d2adf4ff094fa3b129` | defense-evasion helper, not C2 payload |

The first envelope transform is `clear[i] = cipher[i+1] XOR ((key+i) & 0xff)`.
`unpackers/purehvnc_unpacker.py` detects both contiguous and sparse-stride-four
forms and requires a structurally valid PE before accepting output.

## Configuration and C2

- Configured terminal C2: `154.82.93.206:8080`
- Confidence: high; static config and call-site association
- Wire header: three little-endian `uint32` values: magic, payload length, type
- Magic: `0x58463031` (`10FX` in memory bytes)
- Observed type roles: `0` heartbeat/echo, `1` registration JSON, `2` shell,
  `8` binary input, `16` task JSON, `0x21` plugin, `0x30` SOCKS5

Registration fields enumerate computer/user/OS/architecture/CPU/memory,
administrative and integrity state, camera, foreground window, install date,
security products, wallets, and screen metadata. Capability strings cover
screen streaming, preview screenshots, browser passwords, network/process/
service/window/file inventory, shell, SOCKS5, plugins, update, and restart.

The endpoint was not contacted. Banner hash, JARM, service state, and TLS
certificate are therefore unknown. A passive Shodan lead is
`ip:154.82.93.206 port:8080`; it is a pivot, not proof that the service remains
active or uniquely identifies PureHVNC.

## Host behavior

The loader checks virtualization artifacts, CPU/RAM/disk/uptime, windows, and
environment paths. It copies the host/DLL below
`%ProgramData%\Microsoft\NetTokenBroker`, uses `runtime.tmp` and `heartbeat.bin`,
adds Defender exclusions/policies, and launches in the active console session.
The helper includes Defender policy/exclusion and driver-oriented strings.

## Detection and false positives

- Low FP: correlate the exact hidden `netutils.dll` hash, lure host hash, decoded
  `10FX` protocol/capability markers, and outbound `154.82.93.206:8080`.
- Medium FP: signed `easinvoker.exe` loading an adjacent `netutils.dll`, followed
  by ProgramData `NetTokenBroker` writes or Defender exclusion changes. Legitimate
  deployment wrappers can side-load or alter exclusions, so correlation matters.
- High FP: the lure filename, `netutils.dll` name, a single Defender exclusion,
  or a single connection to port 8080. These are common individually.

The bundled YARA rules target static family/chain combinations. Sigma rules
cover image-load and persistence/defense-evasion telemetry. Hash and C2 matches
should be highest priority; generic names alone should not be blocked.
