# AmosStealer analysis

Ten recent MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `direct_macho`: 7
- `script_delivery`: 3

## Statically observed behavior features

- `apple_script`: 3/10
- `browser_collection`: 3/10
- `keychain_collection`: 3/10
- `user_prompt`: 3/10
- `wallet_collection`: 3/10

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| `https://nvoaagent.com/ledger/93ea36a257de15f2fe3f9d5d32fb19ee6e040fa3cd57131dedc33c740d868a89` | c2_or_exfil_candidate | probable | embedded_literal |
| `https://nvoaagent.com/ledger/live/93ea36a257de15f2fe3f9d5d32fb19ee6e040fa3cd57131dedc33c740d868a89` | c2_or_exfil_candidate | probable | embedded_literal |
| `https://flwoagent.com/ledger/484e513fdf967e35d2e21b8b88df0a2867c1abf6045e4ec41974ae927abb2140` | c2_or_exfil_candidate | probable | embedded_literal |
| `https://flwoagent.com/ledger/live/484e513fdf967e35d2e21b8b88df0a2867c1abf6045e4ec41974ae927abb2140` | c2_or_exfil_candidate | probable | embedded_literal |
| `https://northernvirginiapainting.com/ledger/2fc78a36ea00d10a6d4fbba34bd924464f978f9598d97014a4a78a90eb3c6525` | c2_or_exfil_candidate | probable | embedded_literal |
| `https://northernvirginiapainting.com/ledger/live/2fc78a36ea00d10a6d4fbba34bd924464f978f9598d97014a4a78a90eb3c6525` | c2_or_exfil_candidate | probable | embedded_literal |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [4e2c0396e96e](cases/4e2c0396e96e3e5d763fdcba313ace876ca45333c7683a087698768ff2ea277f/README.md) | macho | direct_macho | false | 0 | 0 |
| [f284297b7bf5](cases/f284297b7bf551617553a9c19f101b3aa55f94e3fb60cab2e596e4c287908281/README.md) | macho | direct_macho | false | 0 | 0 |
| [a91d954fa5a9](cases/a91d954fa5a9a1f167625e7ac8314a481e32a9dbee4635533b52be21be4e508b/README.md) | macho | direct_macho | false | 0 | 0 |
| [3aa43ab301b3](cases/3aa43ab301b31b360585f71fd23050fb42311d09cfd406d4b9fb74189ed1cb2d/README.md) | macho | direct_macho | false | 0 | 0 |
| [6f33360d3a3d](cases/6f33360d3a3dc60454a64d74e1ac586f6a184b3886df46471b10e520c5fe0644/README.md) | script | script_delivery | false | 0 | 2 |
| [8809d3421c09](cases/8809d3421c09669f88330adf3007b933abec13bf6ed105a785a97c7df2625301/README.md) | script | script_delivery | false | 0 | 2 |
| [5d52202388cd](cases/5d52202388cde6395fbaaf19bc8119044653f1de8c0dac2325b1da606b9b3bf4/README.md) | macho | direct_macho | false | 0 | 0 |
| [47cd98c6ae43](cases/47cd98c6ae435a1a6aa518e29f9e407ca42c82c9f4b86ceee93cc85d7feeae98/README.md) | script | script_delivery | false | 0 | 2 |
| [c8613819cb49](cases/c8613819cb4978591f4d98edd56bf3fdcc9f52245778416406d5b1e582a7024b/README.md) | macho | direct_macho | false | 0 | 0 |
| [ec6ecebe9d9a](cases/ec6ecebe9d9a6c7df63c6fda709b4bd01b86b2c0f7252c452567a39cf8ac8e26/README.md) | macho | direct_macho | false | 0 | 0 |

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
