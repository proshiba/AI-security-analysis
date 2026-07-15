# Formbook analysis

Ten recent MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `direct_pe_or_pe_loader`: 1
- `macro_office_delivery`: 3
- `script_delivery`: 6

## Statically observed behavior features

- `script_loader`: 4/10

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| `https://misty-cherry-cea3.uploadsimg.workers.dev/EzUaK` | candidate_infrastructure | candidate | embedded_literal |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [9344ddd29069](cases/9344ddd2906925b386bad207e1fb416739a5657a7103feed770d6d6b8d042556/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [f1a1c2a13764](cases/f1a1c2a13764f2621ec0181696fcf7e6f74886ec7bf7f4ef4f56ba986c782b6d/README.md) | script | script_delivery | false | 95 | 0 |
| [e967a7450501](cases/e967a74505018f5a4de19d45bb69634ecdb8524f444f385f3be6957411095229/README.md) | script | script_delivery | false | 0 | 0 |
| [f0ab3929c25a](cases/f0ab3929c25ab32c608a62d39a831f21edcb356cc3b55e3839071c14dacc1ac8/README.md) | script | script_delivery | false | 1 | 1 |
| [55b9b8d561e6](cases/55b9b8d561e6c1a4c099ceb064a97a43bdc222797f732562a1f7afef5d6cfbdb/README.md) | script | script_delivery | false | 1 | 0 |
| [42db32151216](cases/42db32151216db1e67f744c504117de6e133bdbf5619a09544ec198384c9bfa8/README.md) | script | script_delivery | false | 0 | 0 |
| [42cef4aba1a6](cases/42cef4aba1a6bb1d35b4c279664e5586b3f3dc85731598f38e659e33f698e509/README.md) | script | script_delivery | false | 0 | 0 |
| [55ca939df21d](cases/55ca939df21d1486628a2801ea28d0b8e1eb63e624218dbb42348e36cbadfbfd/README.md) | zip | macro_office_delivery | false | 1 | 0 |
| [0bb875dcb216](cases/0bb875dcb216560f3a1d0b8034d290c10e7c15a25a7d5a805152cd3784b9e7b5/README.md) | zip | macro_office_delivery | false | 1 | 0 |
| [2cdedb9e87b1](cases/2cdedb9e87b19f3da82e49563e2f3ca9b1e9f4e195a89b2e60e24e380261e2ef/README.md) | zip | macro_office_delivery | false | 1 | 0 |

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
