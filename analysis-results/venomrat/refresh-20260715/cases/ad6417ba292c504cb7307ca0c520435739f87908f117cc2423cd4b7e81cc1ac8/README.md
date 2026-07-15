# venomrat case ad6417ba292c504cb7307ca0c520435739f87908f117cc2423cd4b7e81cc1ac8

## Overview

- Original name: `ad6417ba292c504cb7307ca0c520435739f87908f117cc2423cd4b7e81cc1ac8.cmd`
- SHA-256: `ad6417ba292c504cb7307ca0c520435739f87908f117cc2423cd4b7e81cc1ac8`
- Campaign shape: `unknown_or_nested_delivery`
- Format: script
- Packing suspected: `false`
- Recovered static layers: 3
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | static extraction incomplete |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Collection/behavior features

```json
{}
```

## Unpacking status

- Root entropy: 5.549
- Root packing assessment: `False`
- Recursive layers analyzed: 0
- 7z status: `not_applicable`
- UPX status: `not_applicable`

## Limitations

- Encrypted resource loaders require a recovered final payload before config can be confirmed.

## 2026-07-15 unpacking reassessment

- Grouped more than 2,000 CMD echo Base64 chunks by redirection target and decoded the completed stream once.
- Terminal PE SHA-256 d6bb84d31d68519e201370f8ccb60d373412573d125f30c5b3090c1ad206d5fd, 1,216,000 bytes, x86 native, not packed.
- The previous 128 recovered entries were fragment noise; structural gating now suppresses those fragments.
- Two bounded opaque PE resources were retained, but neither is an additional packed terminal executable.