# VenomRAT analysis

10 new MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `direct_pe_or_pe_loader`: 6
- `script_delivery`: 2
- `unknown_or_nested_delivery`: 2

## Statically observed behavior features

- none statically visible

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | packed/encrypted or no literal config |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [579085581348](cases/579085581348296ae88419296edc6a8e91acf4463c7994112b5c3f7f3653710e/README.md) | script | script_delivery | false | 0 | 0 |
| [48b59f27da42](cases/48b59f27da42cfe2d3b806a1c71cc8d8fce0441121a17cd8c1b30bf5e35ea776/README.md) | data | unknown_or_nested_delivery | false | 0 | 0 |
| [d7de7d851061](cases/d7de7d851061a99e6f2ca256aba5badf90778f566fc528db6396a4180901ac26/README.md) | script | script_delivery | false | 0 | 0 |
| [d6d876c73274](cases/d6d876c7327482a6293fb5014393ace99e14aa7e0638bbda9fc602d35b8a72c9/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [9100e92ceb94](cases/9100e92ceb94455d3159c4273b47a4d635f1d6b8add68e7c775e1849d3d1a9da/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [7215cbe8e5df](cases/7215cbe8e5dfed7b22c8bbe8c5f7f35a7848e545d1cdeb60a378baf0be32cb0e/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [e4ea373bf70b](cases/e4ea373bf70b008d51db2d707171a01a40c45e7e01d2ed61eef21199fd30c8dd/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [651859b30c79](cases/651859b30c796cf59166ca018a2b4f18c996af4e688d302466ae56a5712b72a7/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [165b528fb02e](cases/165b528fb02e35b12a59a311102a8bef74ec2f0bf908864fd7fa7ed8f917261e/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [ad6417ba292c](cases/ad6417ba292c504cb7307ca0c520435739f87908f117cc2423cd4b7e81cc1ac8/README.md) | data | unknown_or_nested_delivery | false | 0 | 0 |

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
