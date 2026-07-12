# ValleyRAT analysis results

Each case directory is named with the submitted sample SHA-256. Only reports, inventories, decoded text/assembly, rules, and evidence metadata belong here. Samples, extracted PE files, decrypted binaries, packet captures, and Ghidra project databases are intentionally excluded.

Every case README distinguishes confirmed, inferred, and unverified findings and states whether local execution or live network contact occurred.

## Cases

| SHA-256 prefix | Campaign / chain | Confirmed or high-confidence C2 |
|---|---|---|
| `8bf54a76` | DLL side-load + vvaS | `202.95.8.27:6666`, `:8888` |
| `b433ecdf` | MSI/CAB side-load | `www.tq8j.com:443` (sandbox IP `103.45.64.246`) |
| `942be7e0` | installer overlay dropper | `150.158.50.175:443` |
| `eab4918e` | direct signed PE | `154.81.37.130:4444`, `:5555` |
| `15015ac7` | DLL side-load + vvaS XOR20 | `134.122.128.66:6666`, `:8888` |
| `5bdcf2d4` | SysCEO/winget-style side-load | `27.124.18.166:63016`, `:63026` |
| `0e4931df` | MSI staged download | `8.210.15.149:28300` |

These are structural/campaign classifications, not operator identities. Builder reuse means matching ValleyRAT family code does not establish a common actor.

Shared candidate rules are under `rules/sigma` and `rules/yara`; validate and tune them against local telemetry before production use.
