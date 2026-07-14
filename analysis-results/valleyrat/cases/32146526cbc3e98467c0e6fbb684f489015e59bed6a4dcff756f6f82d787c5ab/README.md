# ValleyRAT-linked Qt/SilverFox case 32146526cbc3

- SHA-256: 32146526cbc3e98467c0e6fbb684f489015e59bed6a4dcff756f6f82d787c5ab
- Campaign type: qt_static_obfuscated_silverfox
- Analysis level: static analysis plus DNS correlation
- Analysis date: 2026-07-15

## Observed behavior

The artifact is a large x64 Qt-linked application with obfuscated or high-entropy resources and process, injection, and networking API surface. Static review and campaign correlation exposed a domain, but the final protocol and complete configuration were not recovered.

## Behavior and C2 assessment

- Domain: cqbxbkj.cn
- Resolved address: 18.167.91.239
- Port 8880: similar-campaign lead only; unverified for this sample
- Prior bounded TCP result: connection refused
- Confidence: domain and address inferred; port unverified
- Limitation: no protocol response or recovered config ties port 8880 to this artifact.

## Detection material

Use the Qt artifact structure, resource entropy, process or injection API combination, domain resolution, and any child or side-loaded module. Domain or port-only matching has high false-positive risk.

See [family behavior and C2 model](../../BEHAVIOR-C2.md).