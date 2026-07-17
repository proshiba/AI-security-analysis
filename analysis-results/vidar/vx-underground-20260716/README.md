# Vidar analysis

25 `vx-underground` submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Batch outcome

- Cases: 25
- Errors: 0
- Packing suspected: 0
- Cases with recovered artifacts: 15
- Cases with validated static config: 0
- Sample executed: false
- Network contacted: false

## Campaign/delivery shapes

- `direct_pe_or_pe_loader`: 24
- `nested_or_protected_delivery`: 1

## Statically observed behavior features

- `browser_collection`: 8/25
- `dependency_download`: 2/25
- `telegram_dead_drop`: 1/25
- `wallet_collection`: 2/25

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| `http://157.90.113.100:80` | candidate_infrastructure | candidate | embedded_literal |
| `https://steamcommunity.com/profiles/76561199482248283` | candidate_infrastructure | candidate | embedded_literal |
| `https://t.me/dionysus_tg` | candidate_infrastructure | candidate | embedded_literal |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Validated config values

- no validated family configuration values recovered

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [02355d3fee5e](cases/02355d3fee5e217b25f9210ad0f6bacc3807b6ef1a59aa4d428c01017dcbcf28/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [05f9553616bb](cases/05f9553616bb5fdbf37bd4036c210929e08d7181de898c1bea1bdae7afb0766f/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [0c857501e385](cases/0c857501e3851072db666386136929c06bcf4c8d3160b41b7d82a3ce9afca1be/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [0df79273aea7](cases/0df79273aea792b72c2218a616b36324e31aaf7da59271969a23a0c392f58451/README.md) | pe | direct_pe_or_pe_loader | false | 34 | 0 |
| [151247e9379a](cases/151247e9379a755e3bb260cca5c59977e4075d5404db4198f3cec82818412479/README.md) | pe | direct_pe_or_pe_loader | false | 27 | 0 |
| [25f720e9b969](cases/25f720e9b969bdbece357a4704d4575a47ab8230affefbc2bfc467cb317835f1/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [28db05fffe5f](cases/28db05fffe5f32ee8df60a400c97d19270d23327ebb49ae86e455ea14d59f113/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 3 |
| [3418a369486e](cases/3418a369486e9bf2b57023dc0b02cb00f12a5214fca8bae20ff93586cc8c678a/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [363c46dfb252](cases/363c46dfb252d7c40d9c3bb63bdc40c2eff0ce16c0c1b77f507d73058104c6e1/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [3a521823d796](cases/3a521823d79686fad0595f9e90940c8a7451f7343bf64f4dbfcdcbde9115957d/README.md) | data | nested_or_protected_delivery | false | 0 | 0 |
| [416b40630daa](cases/416b40630daa924136b9d10e0faa8c800a7a882416f4e5b7944f9bc2553a414b/README.md) | pe | direct_pe_or_pe_loader | false | 9 | 0 |
| [49a7f82743a0](cases/49a7f82743a038d7a570d5d5d8ecb92f369f0e6dbba6532674c4789f0daf9b31/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [4c17f7ee55f9](cases/4c17f7ee55f9bf6fa9acaeeb9574feab39ba4a3cccd4426dfa85aaf58b90ae73/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [4d4f97f16213](cases/4d4f97f1621334e4075e0229265ac6c5da14754eff1378a7d77ea6d3821e8a33/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [532bc078a686](cases/532bc078a68683ce70cb765191a128fadee2a23180b1a8e8a16b72f1a8ee291a/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [5cd0759c1e56](cases/5cd0759c1e566b6e74ef3f29a49a34a08ded2dc44408fccd41b5a9845573a34c/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [7b217c20a30a](cases/7b217c20a30ab1bdc4534f4adb62df226d128ec4d03c0eb2feb5ab35d2b7dc9f/README.md) | pe | direct_pe_or_pe_loader | false | 8 | 0 |
| [87b92fcd04f6](cases/87b92fcd04f69f9c132c9f350dbb3686888a5e388b1f787f6a658f09582c0da6/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [931ac54db53c](cases/931ac54db53c787f4138e73535db1664fc22cfbd9957b53d4c5135bc8a0dabd5/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [99e733391ac4](cases/99e733391ac499e78e535a98551c4d27408abfad4e56fe4c46956636655df29c/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [b4c9aadd18c1](cases/b4c9aadd18c1b6f613bf9d6db71dcc010bbdfe8b770b4084eeb7d5c77d95f180/README.md) | pe | direct_pe_or_pe_loader | false | 3 | 0 |
| [b67bc7834791](cases/b67bc78347918209973d633287c4e1f514a0917b8678c2cf2066ba80b2004f78/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [b6b6df6abb52](cases/b6b6df6abb52d7d2e2eb8496c04d76e2a01e51703b7ce44aa127d60ce53a0be7/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [e3d16f3f69fa](cases/e3d16f3f69fa0857f966022387ee6f9408385ddf389d09ffe7dc44acc8ac1ad5/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [f1e8f4fba1da](cases/f1e8f4fba1da25cc02d0673f8cc3962c7419d769cb139f818f8f1e4d56a891df/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |

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
