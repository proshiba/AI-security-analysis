# AgentTesla analysis

10 new MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `script_delivery`: 10

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
| [8a1326b0bee0](cases/8a1326b0bee029dd4470ab53bddc3202de54614ba58a54ee1dc4d60928b812e1/README.md) | script | script_delivery | false | 1 | 0 |
| [58274a188cad](cases/58274a188cad3b137585a3135b5d7044b84996c6e2d656fb533a14d229777959/README.md) | script | script_delivery | false | 0 | 0 |
| [58a54ec5f73f](cases/58a54ec5f73f0c32963ff751050dc2ccb3148a27d8b9c7f1bfe1bf03d1cda13d/README.md) | script | script_delivery | false | 0 | 0 |
| [ec28fa6cc4dc](cases/ec28fa6cc4dc26dc65e882b52dfbf497cd97ce7fe8b2b9438b4647401b38e0b3/README.md) | script | script_delivery | false | 0 | 0 |
| [6be55e959aff](cases/6be55e959aff450d4778e873773ca17ce470e5f1434c75aa1e8603f32fbfa058/README.md) | script | script_delivery | false | 0 | 0 |
| [7388727a3ff7](cases/7388727a3ff77ec25b2b858b7b357032dc543061b6cf8367ca4aa6e77bc3c8d2/README.md) | script | script_delivery | false | 0 | 0 |
| [9fd781d549ae](cases/9fd781d549aec0e884a9d90541e8d7e5802d0de0cc36fc9d3c8533deb44846ed/README.md) | script | script_delivery | false | 0 | 0 |
| [e49a106bc696](cases/e49a106bc6960b958ff9ae49c483ff636d3fdbc817229ef0c8c152c32aa3f611/README.md) | script | script_delivery | false | 0 | 0 |
| [46055195777c](cases/46055195777c8088c7800715c4561af2da0b7dd088cb12f5473af5281aec537c/README.md) | script | script_delivery | false | 0 | 0 |
| [02d99e737239](cases/02d99e737239cc7f05a3988add89ee3672080ca1ddb5e43b4ecf4e8891535ccd/README.md) | script | script_delivery | false | 0 | 0 |

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
