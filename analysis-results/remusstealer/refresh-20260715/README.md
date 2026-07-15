# RemusStealer analysis

10 new MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `direct_pe_or_pe_loader`: 7
- `go_pe_loader`: 3

## Statically observed behavior features

- `archive_delivery`: 7/10
- `go_runtime`: 3/10

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| `http://31.77.168.180:5000/umvbr.bin` | candidate_infrastructure | candidate | embedded_literal |
| `http://31.77.168.180:5000/piva.exe` | payload_or_dependency_url | candidate | embedded_literal |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [d9824b3a6894](cases/d9824b3a6894de0606a03a23417f1c7e780ee0b5655f724dbfa455601e13eb8e/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [0b845b890586](cases/0b845b890586407658a6bfcb1030b32be641760120e304bdf372a835ca5d77a4/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [4049128f0308](cases/4049128f0308d05dcb8d24b668f69238d720199de32ba0d8304cd3c3b3bde1b9/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 1 |
| [746c06f05b8e](cases/746c06f05b8e3bc93d6495a6c447c3c1874bd77011c33b0bcfe74ae27addbfaf/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 1 |
| [ffa78f3d4b1d](cases/ffa78f3d4b1dafb9723e6a68456e42a57c0a109b9b8246196e1a8a6d6d2d6f5a/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 1 |
| [027004739726](cases/027004739726842d8e416672cb7da85c43a75357984f818e27db5eb0dee0b600/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [5e815731f67c](cases/5e815731f67cb070fb1b31272c45bd7f4ecd4a408cbbc68a9545bafc3292d72c/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [7ae44ecd94c5](cases/7ae44ecd94c5e10f560e78539d4dba8b10d2ddcaf551d1321d81f7d97b771d5d/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [5eb378956ee8](cases/5eb378956ee84899b8ec8a59d0b9d5e95bef39cfce2acdfe72b032ea4e704227/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [523dd77b85d0](cases/523dd77b85d0b0cedc99ca23bc7225d4137b9e562a71a2d6d5e163e703680e2e/README.md) | pe | go_pe_loader | true | 0 | 0 |

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
