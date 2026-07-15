# ValleyRAT analysis

10 new MalwareBazaar submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Campaign/delivery shapes

- `direct_pe_or_pe_loader`: 7
- `macro_office_delivery`: 3

## Statically observed behavior features

- none statically visible

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| `103.43.11.40:1443` | candidate_c2 | confirmed | decoded_vvas_config |
| `https://xjsjkjdsjjd.s3.ap-southeast-1.amazonaws.com/11100.zip` | config_or_stage_url | inferred | static_string |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [fc397bf8ddae](cases/fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de/README.md) | ole | macro_office_delivery | false | 0 | 0 |
| [74dcd1f64bd3](cases/74dcd1f64bd3b43cf659359bff1f43131d43b4e07f3a3aa2a1f74d6e7970be09/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [1c82635c29f4](cases/1c82635c29f40e971971e150ebee6f36dabdd2a156f51214f20425315abb413f/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [ad4a584f5e62](cases/ad4a584f5e622c10703bca28c58ee8372899edb48cc1ccf28a2cff87d1afbf2d/README.md) | ole | macro_office_delivery | false | 0 | 0 |
| [81f68f61a8f7](cases/81f68f61a8f7cf1accca338fd196051020bf60885aad409332091b759ff818d9/README.md) | ole | macro_office_delivery | false | 0 | 0 |
| [b5af11fcbde5](cases/b5af11fcbde594f47706f4b5a8ee37a20fd4ed1ceb2537c9356ad5f0ff7300a9/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [0fbe935d932c](cases/0fbe935d932ce6849224d77e3f32bdfd49910e5a34741ceab81ca8230d92a9da/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [272747b26622](cases/272747b26622bc9b084b36935efeeae8a63a388db00f94c6359b02368fd52d0d/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [42420ed30965](cases/42420ed30965b2e8cd0abfe59103f9352cf9e8bb9a1c75d340bf13b2660abda5/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 1 |
| [dfacebad09d7](cases/dfacebad09d75d41ee5f477754815ae7e4afd926638d7b72a6a25338cd2479da/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 1 |

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
