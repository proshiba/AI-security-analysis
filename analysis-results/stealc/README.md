# StealC analysis

## Scope and outcome

The complete VX-Underground StealC directory was acquired on 2026-07-16: 41 password-protected archives, 41 successful extractions, and 41 x86 native PE files whose extracted SHA-256 matched the archive name. No sample was executed and no recovered endpoint was contacted.

Static configuration was fully recovered from 5 files. The remaining 36 outer layers separate into 11 Themida/WinLicense files, 1 Enigma file, 1 NSIS container, 3 identical Delphi resource carriers, and 20 native wrappers/unsupported string generations with high-entropy code or data buffers. These are not reported as “cleanly unpacked”; their C2 remains unknown from the current static layer.

The full per-file inventory is in [inventory.json](inventory.json), and every hash has a case directory under `cases/<sha256>/` with `README.md`, `config.json`, `iocs.json`, and generated `IOC-LIST.md`.

## Recovered configurations

| SHA-256 | Method | Build | C2 gate | Dependency directory |
|---|---|---|---|---|
| `1e09d04c793205661d88d6993cb3e0ef5e5a37a8660f504c1d36b0d8562e63a2` | Base64 + RC4 skip-key | `default` | `http://fff-ttt.com/984dd96064cb23d7.php` | `http://fff-ttt.com/a02fc2187db8cd88/` |
| `262a400b339deea5089433709ce559d23253e23d23c07595b515755114147e2f` | paired-buffer XOR | `ZOV` | `http://40.86.87.10/108e010e8f91c38c.php` | `http://40.86.87.10/b13597c85f807692/` |
| `77d6f1914af6caf909fa2a246fcec05f500f79dd56e5d0d466d55924695c702d` | Base64 + RC4 skip-key | `default` | `http://162.0.238.10/752e382b4dcf5e3f.php` | `http://162.0.238.10/dbe4ef521ee4cc21/` |
| `87f18bd70353e44aa74d3c2fda27a2ae5dd6e7d238c3d875f6240283bc909ba6` | Base64 + RC4 skip-key | `default` | `http://777palm.com/bef7fb05c9ef6540.php` | `http://777palm.com/2ccaf544c0cf7de7/` |
| `e978871a3a76c83f94e589fd22a91c7c1a58175ca5d2110b95d71b7805b25b8d` | Base64 + RC4 skip-key | `GoogleMaps` | `http://185.106.94.206/4e815d9f1ec482dd.php` | `http://185.106.94.206/49171d9bb28d893a/` |

The RC4 variant is a skip-key implementation: when normal RC4 XOR would produce NUL, the ciphertext byte is retained while the RC4 state still advances. This detail repairs otherwise truncated values such as `777palm.com` and `HttpSendRequestA`.

## Behavioral findings

The decoded v1 code targets Chromium and Firefox logins, cookies, autofill, browsing history, and cards; it also contains paths or handlers for Telegram, Discord, Outlook, Pidgin, Steam, Tox, screenshots, a file grabber, optional payload loading, and delayed self-deletion. The transport uses WinINet and multipart HTTP POST fields including `hwid`, `build`, `token`, `file_name`, `file`, and `message`.

This is consistent with public StealC v1 research. Public reporting also distinguishes v2: it uses WinHTTP and JSON operations such as `create`, `upload_file`, `loader`, and `done`, while newer v2 builds use standard RC4 for network traffic. Those v2 properties are a family model and are not automatically assigned to an unresolved file in this corpus.

References: [SEKOIA v1 configuration extraction](https://blog.sekoia.io/stealc-a-copycat-of-vidar-and-raccoon-infostealers-gaining-in-popularity-part-2/), [Zscaler StealC v2 technical analysis](https://www.zscaler.com/fr/blogs/security-research/i-stealc-you-tracking-rapid-changes-stealc), [IBM X-Force configuration model](https://www.ibm.com/think/x-force/stealc-you-later-proofpoint-x-force-support-operation-endgame-disruptions), and [Bitsight detection material](https://github.com/bitsight-research/threat_research/tree/main/stealc).

## Detection assessment

- Low false-positive risk: exact file hashes and full decoded PHP gate URLs. Hashes have low durability, and infrastructure may later be reallocated, so neither should be treated as permanent attribution.
- Medium false-positive risk: the included YARA rules require either at least 40 paired-buffer decoder call sites or a PE with a numeric key plus at least 100 Base64 strings. Large protected applications or embedded resource tables may overlap and should be correlated with family behavior.
- Medium false-positive risk: the Sigma rule detects `cmd.exe` with `timeout /t 5` and `del /f /q`; legitimate installers, updaters, and cleanup scripts can produce the same command.
- High false-positive risk: browser database, Telegram, Discord, Outlook, Pidgin, or Steam access alone. Backup, migration, password-manager, and endpoint-security software must be excluded with signer, path, parent process, and outbound destination context.

No liveness, banner, HTTP title, certificate hash, JARM, or Shodan banner hash is present because the recovered infrastructure was not contacted. Static configuration evidence is not a current C2 ownership claim.
