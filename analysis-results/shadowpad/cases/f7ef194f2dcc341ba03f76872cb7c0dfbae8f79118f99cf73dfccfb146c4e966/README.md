# ShadowPad case f7ef194f2dcc341ba03f76872cb7c0dfbae8f79118f99cf73dfccfb146c4e966

- Source: VX-Underground ShadowPad collection
- Artifact: 1,282,048-byte x64 PE resource dropper
- Pattern: `scatterbee_oleview_resource_chain`
- Analysis: static only; no execution and no endpoint contact

## Infection chain

The PE contains 24 resources. Static extraction recovered three material objects:

- `d05f80d5ccb1b6d4aea847ad38ef7e8ab619ff33601aa54cc836704e4fb53520`, a 676,644-byte opaque encrypted payload.
- `1e06fd5b9aa0e5260369e52ec2d9f87060941de835234afd198b1d4c0b161678`, a 231,424-byte x64 `IVIEWERS.dll` sideload component.
- `2e642afdd36c129e6b50ae919ca608ac0006ce337f2a5a7a6fb1eef6a4ad99e7`, a 234,832-byte legitimate OLEVIEW executable. This decoy/sideload host is chain context, not a standalone malicious IOC.

The opaque resource matches a ScatterBee AES-MD5 key variant. In-memory decryption produced payload SHA-256 `b3428803a202f39a97a0594cee2950e0975dac82195d98c8df9c66a7fc8b18bc`; the recovered binary was not written to the repository.

## Behavior and configuration

The decoded configuration uses `Windows_Search_Update`, `wsuhost.exe`, and `IVIEWERS.dll`. Candidate installation locations include `%ProgramFiles%\Windows_Search_Update\wsuhost.exe` and `%ALLUSERSPROFILE%\DRM\Windows_Search_Update\wsuhost.exe`. It contains the Windows Run-key path and `svchost.exe` injection targets. These are decoded intended behaviors, not observed host events.

## C2 and IOC evidence

The config contains `TCP://fljhcqwe.com:80`. Confidence is `confirmed_static_config`: the domain, protocol, and port were recovered from the decrypted sample configuration. Liveness and present ownership were not tested.

## Detection material

High-confidence correlation combines the submitted hash, the encrypted resource hash, the embedded `IVIEWERS.dll` hash, and OLEVIEW loading `IVIEWERS.dll` from a user-writable or unexpected directory. String-only matching on `OLEVIEW` has high false-positive risk because OLE/COM inspection tooling is legitimate. Domain-only detection is medium-to-high risk over time due to expiration, reassignment, or sinkholing.

Primary chain comparison: [Cyfirma ShadowPad malware report](https://www.cyfirma.com/research/shadowpad-malware-report/). Decryption implementation comparison: [PwC ScatterBee scripts](https://github.com/PwCUK-CTO/ScatterBee_Analysis).

