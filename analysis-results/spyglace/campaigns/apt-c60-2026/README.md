# APT-C-60 / SpyGlace 2026 analysis

## Executive summary

This case tracks the 2026 APT-C-60 delivery chain documented by JPCERT/CC and independently inventories the public repository history that was still reachable on 2026-07-15. The workflow remained offline after repository acquisition: no recovered file was executed and no C2 was contacted.

The recovered chain is:

1. Proton Drive or an email attachment delivers a RAR archive.
2. An LNK copies itself and starts embedded, obfuscated JavaScript through mshta.exe.
3. The script downloads contributing[1].txt through jsDelivr, Base64-decodes a TAR archive and uses a bundled git.exe to launch an installation script.
4. The script concatenates TMI003.db, TMI100.db, TMI210.db, TMI320.db and TMI400.db into iconcache.dat.
5. Downloader1 retrieves encoded Downloader2, loader and SpyGlace artifacts from GitHub, GitLab, Codeberg or their CDN views.
6. The repository layer is decoded with the repeating key sgznqhtgnghvmzxponum. A downstream layer also contains AadDDRTaSPtyAG57er#$ad!lDKTOPLTEL78pE.
7. Loaders establish COM-hijack persistence and load the final x64 SpyGlace payload.

## Repository survey

The 29 repositories in JPCERT/CC Appendix E were sampled through unauthenticated public provider APIs.

| Result | Count |
|---|---:|
| Live repositories | 16 |
| Live with reachable history | 10 |
| Live but empty | 6 |
| Unavailable | 13 |

Deleted history was material. class125 retained delivery archives, JavaScript and TMI fragments in earlier commits; tblsesarol retained encoded downloaders, loaders, four SpyGlace v3.1.15 payloads and per-device task files. Across the ten non-empty mirrors, 27 valid x64 PE images were recovered by static XOR decoding. The research copy does not reproduce victim host identifiers from task filenames.

See repository-liveness.json for the point-in-time status of every listed repository. "Unavailable" means only that the public API did not return the repository at the sampling time; it does not prove deletion, ownership or attribution.

## Confirmed SpyGlace v3.1.15 configurations

| Encoded SHA-256 | Decoded SHA-256 | C2 | User ID | Request paths | Mutex |
|---|---|---|---|---|---|
| e5f2c7068ade7b87d24c3b94bc749c351d53609f5fcaa48dce06234beaa2444f | 7ab9c634216798d50ce3e19bf1650d6b7c2386150340e48ec3af8b38fd30ae4c | 185.18.222.241 | SAPPHIRE | 1l8kad.asp, vdlhtr.asp, 7m3yv3.asp, fp4v2i.asp | K31610KIO9834PG79A471 |
| 9394627e9c44cf2226ddf50012e5cf47ccf7d3bd8afa2395c635a93637e23502 | af24d54d56cbdffe5081c133dae8e8cd54a0d0e2f3059599bc388ef27cf19aa5 | 31.58.136.207 | EVE | x66hjl.asp, fx72rf.asp, guehry.asp, dmd4n2.asp | K31610KIO9834PG79A471 |
| add013bf7ffc8a89789a7fd0ae0ff799c620af9b2755b214880b6a56768fd48c | 88f58087fc7e7a74455d19c0476954c3bd77d36d0683ab57a6598eb72c4ae37c | 31.58.136.207 | EVE | x66hjl.asp, fx72rf.asp, guehry.asp, dmd4n2.asp | K31610KIO9834PG79797 |
| c86f319f64d25f23ac29d9b53c9764f06a150634ee8e2d836424d460e5a99b52 | 7621e4eff855b2679188b33fe4c71c377f6e2d0b9c25d939452e18992c52e067 | 31.58.136.207 | EVE | x66hjl.asp, fx72rf.asp, guehry.asp, dmd4n2.asp | K31610KIO9834PG79787 |

The C2 URL scheme in each config JSON is inferred from WinHTTP use and ASP paths. Host availability, port and endpoint behavior were not actively tested.

JPCERT/CC also lists one v3.1.17 and five v3.1.18 hashes. They were absent from the surviving repository history and MalwareBazaar returned file_not_found for all six on 2026-07-15, so their configurations were not claimed as recovered.

## Static reverse engineering

Ghidra analysis of decoded payload 7ab9c634... identified two one-byte string transforms:

- API and command strings: decoded byte = (encoded byte XOR 3) - 1.
- Configuration strings: decoded byte = (encoded byte XOR 2) - 1.

The first transform recovers WinHttpOpen, WinHttpConnect, WinHttpOpenRequest, WinHttpSendRequest and related APIs, plus commands including procspawn, prockill, proclist, diskinfo, download, downfree, upload, cancel, screenupload, screenauto, turn on/off, extension, stopextension, ddir, ddel, attach and detach. The second recovers ipaddr$$$$, userid$$$$, the ASP paths, api.ipify.org and custom-RC4 key 90b149c69b149c4b99c04d1dc9b940b9.

JPCERT/CC's 2025 protocol analysis documents an HTTP POST form using a001 through a004, MD5-derived identifiers and Base64 over a custom three-round RC4 variant. It also records AES-128-CBC download constants B0747C82C23359D1342B47A669796989 and 21A44712685A8BA42985783B67883999. Those constants are retained as protocol knowledge, but were not found as literal bytes in these four decoded binaries.

## Detection guidance

| Confidence | Detection | Expected false positives |
|---|---|---|
| High | YARA match on several encoded SpyGlace command/API/config markers inside one PE; COM-hijack CLSID plus CachedImage loader strings; exact JPCERT hashes | Very low. A hash match can still identify a benign research copy. |
| Medium | LNK or archive leading to mshta, certutil decode, tar extraction and a bundled git binary; creation of iconcache.dat from TMI*.db fragments | Administrative packaging and developer automation can use individual tools, but the combined sequence is unusual. |
| Low | Access to GitHub, GitLab, Codeberg, jsDelivr, Proton Drive or StatCounter alone | High. All are legitimate services and destination-only blocking will over-detect normal work. |

Use the supplied Sigma rules for process and registry telemetry and the YARA rules for files or memory. Correlate legitimate-service traffic with the exact account/path, process ancestry, filenames and endpoint file hashes instead of blocking a whole provider.

## Passive infrastructure pivots

The passive detector emits IP-based Shodan queries for statically recovered C2 values and request-path pivots. No banner, HTTP title, certificate hash or JARM was derived because the analysis did not probe the hosts and no authorized passive-data account was used. These fields must remain null rather than be guessed.

## Files

- jpcert-ioc-files.csv: all 103 file rows from the JPCERT/CC appendix, preserving duplicate filename/hash rows; 98 unique SHA-256 values.
- delivery-reconstruction.json: verified Base64/TAR and TMI fragment reconstruction yielding JPCERT Downloader1 hash 866564bb...1d065.
- lnk-ipo6.json and lnk-idx2.json: static embedded-script, action and jsDelivr URL inventories for two recovered LNK files.
- recovered-pe-inventory.json: 27 decoded PE identities (4 Downloader1, 9 Downloader2, 7 SpyGlace loaders, 4 SpyGlace payloads and 3 unresolved PEs).
- network-and-account-iocs.csv: C2s, abused URLs, phishing senders and commit identities, with source separation.
- repository-liveness.json: all 29 public-repository observations.
- ../../cases/: per-sample configuration results.
- ../../../../analysis-framework/malware/spyglace/rules/: Sigma and YARA detections.

## Limits and provenance

Repository status and commit history were observed on 2026-07-15. Public commit metadata can be forged, so an address or username is an investigative pivot rather than proof of attribution. The v3.1.15 samples were statically decoded and decompiled; they were not launched. No live C2, phishing sender, victim system or repository account was modified.

Primary references:

- https://blogs.jpcert.or.jp/en/2026/07/apt-c-60_2026.html
- https://blogs.jpcert.or.jp/en/2025/11/APT-C-60_update.html
- https://blogs.jpcert.or.jp/en/2024/12/APT-C-60.html
