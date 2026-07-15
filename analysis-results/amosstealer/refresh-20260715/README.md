# AmosStealer analysis

10 new MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `direct_macho`: 9
- `script_delivery`: 1

## Statically observed behavior features

- none statically visible

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| `http://91.92.242.30/dx2w5j5bka6qkwxi` | candidate_infrastructure | candidate | embedded_literal |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [998c38b43009](cases/998c38b430097479b015a68d9435dc5b98684119739572a4dff11e085881187e/README.md) | macho | direct_macho | false | 0 | 0 |
| [fe3859f076f3](cases/fe3859f076f3b34efc4155b7d724b024d193dd20ad2e4638985ffbe15992f27d/README.md) | macho | direct_macho | false | 0 | 0 |
| [0e52566ccff4](cases/0e52566ccff4830e30ef45d2ad804eefba4ffe42062919398bf1334aab74dd65/README.md) | macho | direct_macho | false | 0 | 0 |
| [f0a54f2b44e5](cases/f0a54f2b44e557854b0a5001c4e10185884af945814786f78b86539014f78a16/README.md) | macho | direct_macho | false | 0 | 0 |
| [e3b5a5dbbcca](cases/e3b5a5dbbccab4cf36c7abf5cb5ae83062dd1b5dee7db04bddbf53fc9ebdb233/README.md) | data | script_delivery | false | 0 | 1 |
| [a0e66f3067e4](cases/a0e66f3067e4aaf5b83e45b7845cc43b2fc96032a4398cab7cc9d11f4f962e91/README.md) | macho | direct_macho | false | 0 | 0 |
| [77d3ccb2ed3d](cases/77d3ccb2ed3d0dd7cda49a0aed4da7c46278e70995d8e6768b2188fedcb78703/README.md) | macho | direct_macho | false | 0 | 0 |
| [ab267488d2c0](cases/ab267488d2c0a6300b61b5c9046cb86fe4a9ac3fe9a615acd374465b3a4b26c2/README.md) | macho | direct_macho | false | 0 | 0 |
| [d3ad6c9325b7](cases/d3ad6c9325b71044134c77b1e0c97c392a1f8d27f0af041d48325815dc1516db/README.md) | macho | direct_macho | false | 0 | 0 |
| [84a71a9dde6b](cases/84a71a9dde6b087613f3036eefaf8ae53c575e0d067b3b5a8a68896438df3f6b/README.md) | macho | direct_macho | false | 0 | 0 |

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
