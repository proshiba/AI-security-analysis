# LummaStealer analysis

Ten recent MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `go_pe_loader`: 10

## Statically observed behavior features

- `loader_or_packer`: 10/10

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | packed/encrypted or no literal config |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [b871f50abbd7](cases/b871f50abbd7e06e6dbede78f499c2efc426d7f8ba08943f06e104f82d8ecc0c/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [b9b7602e0b92](cases/b9b7602e0b929dd2bae9e87b53d5ab1e0a236fe466ea4628c3b8fc32cc2ed899/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [009b2025c432](cases/009b2025c43202f2c643e46d27b30ca5e0f33b7da37841a661838aa07ac34938/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [a8760de45ed2](cases/a8760de45ed2bdda90fea6b136b5a3c5afdfdce4c1b05d3c4ab76e92f308ae36/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [b2930dcb9a59](cases/b2930dcb9a593f79105aa4fecc4f67d3db99273858c42845a553585975307408/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [4e732364c533](cases/4e732364c5335ed8b999528110f954bf88717fbfe865639d8daa4485d9d82410/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [89c66cb60337](cases/89c66cb60337dd2f0901bed8919fe22ad88ae1874e92977cba2f9b37cf79dd5a/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [56970a928b7e](cases/56970a928b7e73504022d0e856ab131d262247b03b3cc082dc950a8e8d2e276b/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [9817c80e1108](cases/9817c80e1108f291efd2eb04a7b5abc8ca5895788b8a3934d1c3dded97d4b124/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [18768e002f6f](cases/18768e002f6f953ad6b9f3265d6e438ec19d0ffa05afaf28a72a04417c35528c/README.md) | pe | go_pe_loader | true | 0 | 0 |

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

## Latest refresh

- [2026-07-15: 10 new MalwareBazaar samples](refresh-20260715/README.md)
