# LummaStealer analysis

10 new MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `go_pe_loader`: 8
- `packed_native_pe`: 2

## Statically observed behavior features

- `browser_collection`: 1/10
- `c2_api`: 1/10
- `loader_or_packer`: 9/10
- `wallet_collection`: 1/10

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | packed/encrypted or no literal config |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [c1d067c076f8](cases/c1d067c076f8d0d818aca72cefa32df501a6a887d96e407bdfe08d712b6ff781/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [794a4e96a5f9](cases/794a4e96a5f9590ae52fc0b9fb8cffed73f8b4bdd915a55bb207bfcacb45b92d/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [4e5b2ae91379](cases/4e5b2ae91379b8069c04c6639bb0bca5ddea0dde567bea8cb9bc9822b9cdda0d/README.md) | pe | packed_native_pe | true | 0 | 0 |
| [84fdf69c7381](cases/84fdf69c7381701415d366808450de41e3127d15c497a196bd51cc3ecf3eeaea/README.md) | zip | packed_native_pe | false | 1 | 0 |
| [b435de3e5071](cases/b435de3e50714d774f42cfdefd710519915e7f987f69da8d5fc1963961519844/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [060618b911a7](cases/060618b911a7022394c88e195aa477157d366363f76ed4b86f0cc3b635908cc3/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [817ac7a4ee5b](cases/817ac7a4ee5b546a812b129c9b9cfbb4581988bd95ac3e2a32a83b82f1bf430c/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [3368d54f3063](cases/3368d54f30631c9e305f6df3464e08b6b4f24eebdb605240c44b144deed717fa/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [afa807cee34e](cases/afa807cee34e8b931688ccf2be76b7ea5337af3d64714a348bead839c756643a/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [a6feb3ea4e8d](cases/a6feb3ea4e8dcff0eaea4c8b89b3dc728e0cfe7ea2729c5e25d1f0b6bbfc3453/README.md) | pe | go_pe_loader | true | 0 | 0 |

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
