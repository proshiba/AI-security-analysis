# AMOS analysis

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

- `direct_macho`: 1
- `xz_macho_delivery`: 1

## Statically observed behavior features

- `apple_script`: 1/2
- `browser_collection`: 1/2
- `keychain_collection`: 1/2
- `user_prompt`: 1/2
- `wallet_collection`: 1/2

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | packed/encrypted or no literal config |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Validated config values

- no validated family configuration values recovered

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [6b0bde56810f](cases/6b0bde56810f7c0295d57c41ffa746544a5370cedbe514e874cf2cd04582f4b0/README.md) | xz | xz_macho_delivery | false | 3 | 0 |
| [ce3c57e6c025](cases/ce3c57e6c025911a916a61a716ff32f2699f3e3a84eb0ebbe892a5d4b8fb9c7a/README.md) | macho | direct_macho | false | 2 | 0 |

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
