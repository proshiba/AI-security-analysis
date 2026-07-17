# Managed PureRAT 4.4.1 through CHRD/Donut delivery

## Scope and identity

- Submission: `260715-l25q2scy6x_pw_infected.zip`
- Submission SHA-256: `2f8ca67e26a6688231d4d86f75fb979d0414c4b549e40531045b633854e80161`
- Primary malicious DLL: hidden `AppVIsvSubsystems64.dll`
- Primary SHA-256: `e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0`
- Terminal family: managed PureRAT / PureHVNC, confirmed
- Terminal version: `4.4.1`
- Delivery profile: CHRD/WAV → Donut → .NET resource loader
- Analysis: complete static recovery; no execution and no network contact

This case was rebuilt under PureHVNC after the two submitted Triage samples were
reported as reversed. The final family classification is based on the recovered
managed payload and protobuf configuration. Donut is retained as a delivery
layer, not treated as the terminal family.

## Fully recovered chain

| Layer | Size | SHA-256 |
|---|---:|---|
| Inner ZIP | 68,652,664 | `9d8e67acc8362da1eb87339e548db45d8112175404df30b9960ecad208c329eb` |
| CHRD config | 1,567 | `9c382435a539afb1ccd33d5ed7a1c390e52bfa223cdf88e48ca5a656fb9592e2` |
| Low-nibble WAV | 11,272,240 | `7fd4a8e93e52aed3c35ea19f1e88c028391c5c0da4bd9d6f86fcc7c1341f3751` |
| Numeric stream | 11,271,138 | `0592616f6bf154f785ecb85401bd6f23c75c91b656e9ca1ef112faa6ccb0cae9` |
| Reconstructed outer blob | 352,222 | `b2cd92d98a61a6a0718a9adef9ee5ee393cb345d85ba361380a42f5d50228c3d` |
| Donut shellcode | 352,222 | `da4fa1b8f0e80693cfecefc70afdac3cccc13aeabb44149a3cf2e48aad9a42a1` |
| Decrypted Donut instance | 334,864 | `2915d96f496c7b56ae4f473a347778f89920caca0d30b973d3ea9817f53df571` |
| .NET resource loader | 328,704 | `96d2f935f7973f4c31c320cd2ee2173bd6f67ac32758ecc242f928409ecf92d7` |
| Encrypted `PayloadSource.zip` | 35,608 | `bd2255191c24706704d64d70bd176225e44aa90428d1968cdbaf3b8f385b7e9e` |
| Terminal managed payload | 76,800 | `c1a2b48d4f639b46cf6cde8322666f0991531ef32ffe571140418ae40342ffe8` |

The CHRD carrier has 175 numeric resources. Its decoded numeric stream contains
a 298,635-value Jacobi segment (80 iterations) and a 53,587-value affine segment.
Donut uses the modern `0x290` layout, Chaskey CTR, entropy profile 3 and an
uncompressed type-2 .NET EXE module for runtime `v4.0.30319`, AppDomain
`PN33Y67X`. The terminal loader applies TripleDES-CBC, PKCS#7 validation and
GZip decompression to `PayloadSource.zip`. No network payload was needed.

## Terminal configuration and C2

- C2 domain: `tirakian.com`
- C2 endpoints: `tirakian.com:56001`, `tirakian.com:56002`, `tirakian.com:56003`
- Campaign ID: `bem`
- Install environment: `APPDATA`
- Persistence: false; prevent-sleep: false; scheduled task and mutex empty
- PFX SHA-256: `01034a2cf003614de716ee94393e0fb2a80e6f1d0ddead61b4cb57c200f4cb96`
- Leaf subject/issuer: `CN=PureRAT Agent`
- Leaf DER SHA-256: `67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b`
- Certificate validity: 2026-07-04 15:16:54Z to 2027-07-05 15:16:54Z

The config is a Base64/GZip/protobuf object in the terminal assembly. The agent
contains TLS client-authentication, GZip and protobuf serialization logic plus
browser, wallet, Telegram, in-memory module, registry and task capabilities.
Flags describe this build and do not prove all capabilities executed.

Passive Shodan pivots are `hostname:"tirakian.com" port:56001` (and ports
56002/56003), `ssl.cert.fingerprint:"67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b"`,
and `ssl.cert.subject.cn:"PureRAT Agent"`. No live banner was collected, so
banner hash, HTTP title, JARM and current service state remain unknown.

## Detection and false positives

- Low FP: exact hashes, decoded C2/campaign/certificate combination, or a
  successful CHRD→Donut→PureRAT recovery.
- Medium FP: PDF-named Excel host loading adjacent `AppVIsvSubsystems64.dll`,
  or `CHRD` plus the numbered-resource and fake `Harbor Lantern` metadata.
- High FP: AppV/Excel filenames, GZip/protobuf/TLS strings, a generic PureRAT
  certificate CN, or any one high port. These occur in legitimate software.

YARA covers delivery, resource loader and terminal profiles. Sigma covers the
Excel/AppV side-load chain. Detection logic must preserve delivery and terminal
family roles rather than relabeling the whole chain as DonutLoader.

