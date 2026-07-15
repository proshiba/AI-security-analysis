# RemusStealer analysis

Ten recent MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `direct_pe_or_pe_loader`: 2
- `encrypted_7z_delivery`: 3
- `go_pe_loader`: 5

## Statically observed behavior features

- `archive_delivery`: 8/10
- `go_runtime`: 5/10

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | packed/encrypted or no literal config |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [abc81d4d4b22](cases/abc81d4d4b22d8388e829f3fedeb35cb3d3a7e50a108ba1ac779161b21a5bad3/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [5e5f0122c172](cases/5e5f0122c172b364cb32ddefc79b381113a04ed48bf194a6a975cc7f564fa07b/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [cd362b63aa51](cases/cd362b63aa5130a6290d1326abc883309aa218a5869e82ecd2c106a80de61047/README.md) | pe | direct_pe_or_pe_loader | true | 1 | 0 |
| [fa38f6539af7](cases/fa38f6539af74b5b355c532a3c71c588960d34abd825442fea98c2177375d010/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [aec2007bddf3](cases/aec2007bddf386d7659b60f712334d7f277f65edfd9f11a61c711b7b4b7119e2/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [d5d5465b53f7](cases/d5d5465b53f72727b8218dab4165b954748d29ab8f8de275fbd3a6fac0e08b6d/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [ed38c22c7385](cases/ed38c22c7385998f5182bfae0a235faee616ed19fb34b945b1b8e211e3001e96/README.md) | 7z | encrypted_7z_delivery | false | 0 | 0 |
| [16a1260ae199](cases/16a1260ae199d83c537b65ca558b33c7a783d28c5547b5fcb35dee4cceb5f12e/README.md) | 7z | encrypted_7z_delivery | false | 0 | 0 |
| [d871b4706e64](cases/d871b4706e6410c4170a03a86629822e046d81e15f6a50d905059d7f2383f1de/README.md) | 7z | encrypted_7z_delivery | false | 0 | 0 |
| [c20a551057c1](cases/c20a551057c10e699156ebeb57677cb51625534d8256a3dd3cd8b3efbca5235c/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |

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
