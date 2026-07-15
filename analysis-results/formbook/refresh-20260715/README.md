# Formbook analysis

10 new MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `direct_pe_or_pe_loader`: 4
- `macro_office_delivery`: 1
- `script_delivery`: 5

## Statically observed behavior features

- `script_loader`: 6/10

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | packed/encrypted or no literal config |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [42255ff19148](cases/42255ff1914882e20ddb9116b521287dccd2bee944e056bc8f1bd1c2970299a6/README.md) | zip | macro_office_delivery | false | 1 | 0 |
| [09a78d4ca618](cases/09a78d4ca618d275809fa2af5f6f1b9b40d5ed2e552ba6ff1ef66b59ccaa1531/README.md) | data | direct_pe_or_pe_loader | false | 0 | 0 |
| [7906d425e122](cases/7906d425e122ae7f4922dbeff8c261be021a921c5f13471a470c60c583280504/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [f913434f31b4](cases/f913434f31b44c0e9df986028468ed3d6d28fd86d6d88aab48f2ef3841609386/README.md) | data | direct_pe_or_pe_loader | false | 0 | 0 |
| [e3ee5d56ae32](cases/e3ee5d56ae3281d15eb73228e5cd94d955b4f664ac73de9651a16d034f32c93b/README.md) | script | script_delivery | false | 1 | 0 |
| [0708ae4eb0d2](cases/0708ae4eb0d2957b40f9162d2fb35cc94a334a6a039860034c27e99b92c8f6e3/README.md) | script | direct_pe_or_pe_loader | false | 0 | 0 |
| [1a3ea22e0c4a](cases/1a3ea22e0c4a68379e164c35d8d5bc438d9624fb575756194c8419121e2d265a/README.md) | script | script_delivery | false | 0 | 0 |
| [5baa58fbd2a9](cases/5baa58fbd2a9309d6853cf1cd5be83adbced95bbdc1a7471c11ee5455f85bfa9/README.md) | script | script_delivery | false | 0 | 0 |
| [7d9512cf29b9](cases/7d9512cf29b9d9792a1018f41eaa156902a16e2f20e4da4f1c308501822b39ad/README.md) | script | script_delivery | false | 1 | 0 |
| [ba8a96319609](cases/ba8a96319609b430e9e976a639ae3af99a28cfbedb965ac67feb7482291b4a54/README.md) | script | script_delivery | false | 0 | 0 |

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
