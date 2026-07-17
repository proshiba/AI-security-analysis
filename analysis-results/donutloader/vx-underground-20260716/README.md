# DonutLoader analysis

2 `vx-underground` submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Batch outcome

- Cases: 2
- Errors: 0
- Packing suspected: 0
- Cases with recovered artifacts: 2
- Cases with validated static config: 0
- Sample executed: false
- Network contacted: false

## Campaign/delivery shapes

- `direct_shellcode`: 1
- `pe_wrapper_or_loader`: 1

## Statically observed behavior features

- none statically visible

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | packed/encrypted or no literal config |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Validated config values

- `delivery_profile`: `embedded_donut` (1), `unrecognized` (1)

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [119b0994bcf9](cases/119b0994bcf9c9494ce44f896b7ff4a489b62f31706be2cb6e4a9338b63cdfdb/README.md) | data | direct_shellcode | false | 1 | 0 |
| [54a5c82e4c68](cases/54a5c82e4c68c399f56f0af6bde9fb797122239f0ebb8bcdb302e7c4fb02e1de/README.md) | pe | pe_wrapper_or_loader | false | 3 | 0 |

## Detection considerations

- **High false-positive risk:** generic access to browser databases, wallets, `osascript`, Go runtime strings, or high-entropy PE sections. Backup, migration, enterprise inventory, installers, and legitimate Go applications can match.
- **Medium false-positive risk:** script interpreter plus network download plus execution, or an unsigned process reading multiple browser/wallet stores. Administrative automation and software deployment can overlap.
- **Low false-positive risk:** combine family-specific strings, reviewed config path/host, credential-store collection, and unusual parent/child or network context. Builder/version changes can still cause false negatives.

Detection rules under `rules/` are starting points and require environment tuning. Literal C2s should be short-lived IOC matches rather than durable family signatures.

## Safety and limitations

- Samples were never executed and recovered layers are not committed.
- External infrastructure was not contacted.
- Unknown packers and password-protected nested archives remain unresolved.
- Source attribution is retained separately from validated static evidence.
