# Vidar analysis

Ten recent MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `direct_pe_or_pe_loader`: 9
- `nested_zip_delivery`: 1

## Statically observed behavior features

- `browser_collection`: 1/10
- `wallet_collection`: 5/10

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | packed/encrypted or no literal config |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [1105c195ea9b](cases/1105c195ea9bf21dcfc8882b1c3887d5056bece5b96170e0ad349cd82a3203a8/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [b59d2b3abdd4](cases/b59d2b3abdd4ddba0f35d200324f1fd55998b76f55e1692c66829b5d49808534/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [52ebf2741148](cases/52ebf27411484098f4643ea8d0d4ca154d66e78de8121d0809ccb437d9f8eeed/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [8aa914b8fa0f](cases/8aa914b8fa0f9cf953f3cd9a9bcbfa27c43a7b7be8ba39d780fb80eaaf3766ff/README.md) | zip | nested_zip_delivery | false | 0 | 0 |
| [5536939f5e28](cases/5536939f5e284524a0ee5f1fe401ac92237e4fb013b8c5adfc5b84d3b6d95017/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [c08d7b0a6a2c](cases/c08d7b0a6a2c416b664182e5715c49ceb62efa0eea3181f684d308a7e1fa3bd1/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [07c295310759](cases/07c295310759ecd7a42fbf3cb96ca1c5b7f45c7e59ac9704b78431000fae5a87/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [3b328b13d692](cases/3b328b13d6925bb86cfa46b58586530dd14e6f0f627ec92a1f14ef162d5712ec/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [bc2297f06dbd](cases/bc2297f06dbddcbfee8fb542ef003f8113932ba8ed40dc2f4da361fb94723956/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [6e42c22a3fc0](cases/6e42c22a3fc0f378992af1bab53101e2a755593cfd9f98429ea64563761854c3/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |

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

## VX-Underground batch, 2026-07-16

The [25-sample static batch](vx-underground-20260716/README.md) includes
recursive container recovery, bounded handling of very large PE files, and
validated repeated-XOR configurations where present.
