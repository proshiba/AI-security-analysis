# ValleyRAT-linked Inno/SilverFox case df603ed55cbf

- SHA-256: df603ed55cbf6f9d74068b956ab966a7b785eb102e1045f343d96255eb2cdc24
- Campaign type: inno_installer_silverfox_unresolved
- Analysis level: static analysis plus public-evidence correlation
- Analysis date: 2026-07-15

## Observed behavior

The artifact is an Inno-style installer associated with a SilverFox delivery pattern. Installer structure, high-entropy overlay content, temporary child execution, and sandbox-observed WriteProcessMemory behavior support a staged loader chain. The final locally created child was quarantined by Defender before its complete payload and configuration could be recovered.

## Behavior and C2 assessment

- Domain: oidng2.duoshit.com
- Resolved or correlated address: 51.79.18.52:443
- Expected role: final RAT or loader-control endpoint
- Confidence: inferred_external
- Evidence: public IOC and sandbox correlation; no locally recovered final config.
- Limitation: domain, address, and port must not be treated as protocol-confirmed C2.

## Detection material

Use the Inno installer ancestry, execution from temporary paths, memory-write behavior, child quarantine event, domain and address, and any subsequently recovered DLL or config hash. Endpoint-only matching has high false-positive risk.

See [family behavior and C2 model](../../BEHAVIOR-C2.md).