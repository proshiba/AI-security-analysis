# RemcosRAT analysis

10 new MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `direct_pe_or_pe_loader`: 1
- `script_delivery`: 7
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
| [99d0eb6047cc](cases/99d0eb6047cc8c9f8cd061a6fcd18bb1fb6a5d4cfb78dd626b7f90a2d90e11b2/README.md) | script | script_delivery | false | 2 | 0 |
| [76aae8a3bf92](cases/76aae8a3bf9207f51b4b0cadb7133e0fddd50306cf7030614c383040e9513721/README.md) | script | script_delivery | false | 0 | 0 |
| [ae41ff70e010](cases/ae41ff70e01087351812394f34575d4f5debac0e76888c16ebaf1c3ed7267bd6/README.md) | script | script_delivery | false | 0 | 0 |
| [2eabe71b1886](cases/2eabe71b18863d2044945eb371da1dbd5d12bc973538755b6177a235712db361/README.md) | script | script_delivery | false | 2 | 0 |
| [6cd42e6eb75c](cases/6cd42e6eb75c0bb98e9846b9faf9bdf66856658bae7209106ed8041d54f6cc2e/README.md) | script | script_delivery | false | 0 | 0 |
| [888625bb2887](cases/888625bb2887f6965cf6d46b7888f73d9d55c0f0caf0abe54221bc455e5534d1/README.md) | script | script_delivery | false | 0 | 0 |
| [55504df33a01](cases/55504df33a0196066494d26d6f8c0533391b220630a9c800c7f1eb0cbc776ce2/README.md) | script | script_delivery | false | 0 | 0 |
| [78b21599a83d](cases/78b21599a83dbfad39c17202d37dd2b6d552c9679755bc199a9826f3dd0e40db/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [ae593f077393](cases/ae593f0773938ade4a4dfdd2f49d47b66482cd4090f269ef39549f12a90ee80c/README.md) | script | unknown_or_nested_delivery | false | 1 | 0 |
| [c478f13eefa7](cases/c478f13eefa74178e585ec29988ab6bc045077b3db9dea930109793716928fad/README.md) | script | unknown_or_nested_delivery | false | 1 | 0 |

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
