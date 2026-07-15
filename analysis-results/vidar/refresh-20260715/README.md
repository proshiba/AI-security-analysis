# Vidar analysis

10 new MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `direct_pe_or_pe_loader`: 10

## Statically observed behavior features

- `wallet_collection`: 7/10

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | packed/encrypted or no literal config |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [71911c8f6eac](cases/71911c8f6eacf5ba5414bc8a66ac83a981aaf4d1141f5117ed6c2ad196c558fc/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [1e13c2c9eac7](cases/1e13c2c9eac72daf63fd00a9946878949e159ae6ec51b54ec64f942d79d61913/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [398c75444639](cases/398c754446396f89ad511e95760c90f9b72e1ce96b105b642b1f853b874f80c5/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [8d90853120d1](cases/8d90853120d18cea4a8a1fa72116fb93db3887f98c330cee9519bc78f87eebf6/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [5bcc428f3765](cases/5bcc428f37655c7bc16110cc2127c510f66827a382cb1c9fa251b15a7d2c214b/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [ee1bddda91c3](cases/ee1bddda91c3a8a3ca8b3fcc077c373dc80da17b94ae6dc7f4219116a49fd7ac/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [0a8f1fa93f96](cases/0a8f1fa93f96182e78f5b95abd940d98bf53f06dc1fbe172bb913f821a3647d3/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [4c958205aa4c](cases/4c958205aa4c56b148377b2bd984a7b3b6525bbc914cf8e5aaa34ce91f71d4cc/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [4992cb5f2959](cases/4992cb5f29594ae1cea78e028a2e6a51d571a610ceeb4442b605953b916dd1c4/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [526efbd526d1](cases/526efbd526d1e0fa9ac6b9def17f1925774e3696595232e8e8d6801a8a302e36/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |

## Detection considerations

- **High false-positive risk:** generic access to browser databases, wallets, `osascript`, Go runtime strings, or high-entropy PE sections. Backup, migration, enterprise inventory, installers, and legitimate Go applications can match.
- **Medium false-positive risk:** script interpreter plus network download plus execution, or an unsigned process reading multiple browser/wallet stores. Administrative automation and software deployment can overlap.
- **Low false-positive risk:** combine family-specific strings, reviewed config path/host, credential-store collection, and unusual parent/child or network context. Builder/version changes can still cause false negatives.

Detection rules under `rules/` are starting points and require environment tuning. Literal C2s should be short-lived IOC matches rather than durable family signatures.

## Safety and limitations

- Samples were never executed and recovered layers are not committed.
- External infrastructure was not contacted.
- Unknown packers and password-protected nested archives remain unresolved.
- MalwareBazaar signature attribution is a lead and was retained separately from static evidence.
