# CHRD/WAV DonutLoader to PureRAT case

## Scope and identity

- Submission: `260715-l25q2scy6x_pw_infected.zip`
- Submission SHA-256: `2f8ca67e26a6688231d4d86f75fb979d0414c4b549e40531045b633854e80161`
- Primary malicious DLL: hidden `AppVIsvSubsystems64.dll`
- Primary SHA-256: `e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0`
- Delivery classification: DonutLoader, custom `chrd_wave_donut` campaign profile
- Terminal family: managed PureRAT/PureHVNC 4.4.1, high confidence
- Analysis: complete deep-static unpack; no execution and no network contact

The inner archive pairs the DLL with a PDF-named, genuine Microsoft Excel host
(`2e05d97ed7bfabea8f7370ba627e0705ec2c0fbf3974b39437e9d95d45d1a76d`)
that imports DLL ordinal 1. The DLL uses fake `Harbor Lantern` calendar-planner
metadata. Its `.rsrc` contains CHRD config ID 4000 and 175 numbered resources;
the 52 MB overlay is not itself the terminal payload.

## Fully recovered embedded chain

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

The numeric stream contains a 298,635-value Jacobi segment (80 iterations) and
a 53,587-value affine segment. Donut uses the modern `0x290` encrypted-instance
layout, Chaskey CTR, entropy profile 3, and an uncompressed type-2 .NET EXE
module for runtime `v4.0.30319`, AppDomain `PN33Y67X`. Imported API groups name
`ole32`, `oleaut32`, `wininet`, `mscoree`, and `shell32`.

The .NET loader decrypts `PayloadSource.zip` with TripleDES-CBC, removes PKCS#7,
checks the stored clear length, and GZip-decompresses the final PE. The reusable
chain finds the embedded key/IV candidates from IL user strings and accepts only
a length-matching PE output. No additional network payload was necessary.

## Terminal PureRAT configuration

- C2 domain: `tirakian.com`
- Ports: `56001`, `56002`, `56003`
- Campaign ID: `bem`
- Version candidate: `4.4.1`
- Install environment: `APPDATA`
- Persistence: false; prevent-sleep: false; task and mutex empty
- PFX SHA-256: `01034a2cf003614de716ee94393e0fb2a80e6f1d0ddead61b4cb57c200f4cb96`
- Leaf certificate: `CN=PureRAT Agent`, self-issued
- Leaf DER SHA-256: `67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b`
- Certificate validity: 2026-07-04 15:16:54Z to 2027-07-05 15:16:54Z

The configuration is decoded from a Base64/GZip/protobuf object embedded in the
terminal assembly. The agent uses TLS client authentication logic plus GZip and
protobuf serialization. Static namespaces/strings cover browser, wallet, and
Telegram collection, in-memory modules, registry persistence, and scheduled-task
PowerShell logic. Configuration flags describe this build; they do not prove all
capabilities ran on a host.

Passive Shodan pivots are:

- `hostname:"tirakian.com" port:56001` (repeat for ports 56002 and 56003)
- `ssl.cert.fingerprint:"67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b"`
- `ssl.cert.subject.cn:"PureRAT Agent"`

No live banner was collected, so banner hash, HTTP title, JARM, and current
service state remain unknown. Certificate reuse and generic CNs can create false
positives; combine them with endpoint, port, and payload/config evidence.

## Detection and false positives

- Low FP: exact hashes, decoded config/certificate fingerprint, or the correlated
  CHRD resource profile plus successful terminal PureRAT extraction.
- Medium FP: PDF-named Excel host loading adjacent `AppVIsvSubsystems64.dll`, or
  `CHRD` plus the numbered-resource range and fake Harbor Lantern metadata.
- High FP: Excel/AppV filenames, GZip/protobuf/TLS strings, or any one high port.
  These occur in legitimate software and must not stand alone.

YARA rules cover the CHRD carrier, managed resource loader, and final PureRAT
markers. Sigma covers the Excel/AppV side-load chain. Detection should preserve
the distinction between delivery artifact, intermediate loader, terminal family,
and configured C2.
