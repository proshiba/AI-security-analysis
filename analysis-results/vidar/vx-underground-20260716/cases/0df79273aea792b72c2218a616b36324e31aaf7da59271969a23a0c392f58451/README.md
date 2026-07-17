# vidar case 0df79273aea792b72c2218a616b36324e31aaf7da59271969a23a0c392f58451

## Overview

- Original name: `0df79273aea792b72c2218a616b36324e31aaf7da59271969a23a0c392f58451`
- SHA-256: `0df79273aea792b72c2218a616b36324e31aaf7da59271969a23a0c392f58451`
- Campaign shape: `direct_pe_or_pe_loader`
- Format: `pe`
- Packing suspected: `false`
- Packing classification: `self_extracting_container`
- Unpack status: `artifacts_recovered`
- Recovered static layers: 34
- Sample executed: false
- Network contacted: false

## Config and C2 evidence

| Value | Role | Confidence | Source |
|---|---|---|---|
| none recovered | - | - | static extraction incomplete |

An embedded value is not proof that the server is live or exclusively controlled by this family.

## Static config snapshot

```json
{
  "campaign_shape": "direct_pe_or_pe_loader",
  "features": {
    "browser_collection": false,
    "wallet_collection": false,
    "telegram_dead_drop": false,
    "dependency_download": false
  },
  "static_config_recovered": false,
  "candidate_infrastructure_recovered": false,
  "scan_source": "complete_input",
  "original_size": 867038
}
```

The complete normalized extractor output, including bounded decoded-string evidence, is retained in `analysis.json`.

## Recovered layers

| Depth | Kind | SHA-256 | Size | Format |
|---:|---|---|---:|---|
| 1 | `pe-resource-opaque` | `1d836a138211010a7475c44bda94ff908db402b8afa5f1c668ce0d915823cb2e` | 5593 | `data` |
| 1 | `7z-script` | `e8c81f887906f7e9ac6d28b086770db1fc355635d79b3429ecb2607e50e65647` | 7168 | `script` |
| 1 | `7z-data` | `1acbd25a8056b2c578ac04e276ad9641403d10d8dbc2257db22f8bfbea33ebcd` | 22528 | `data` |
| 1 | `7z-data` | `69c2b3d548a856fc720b433e8745d06f8e1638daa869889b415797d2e72c4e93` | 50176 | `data` |
| 1 | `7z-data` | `59fae68a446f276beea0ee0fc866828b20dd52790ffa5f86fb964a962dd66a4f` | 51200 | `data` |
| 1 | `7z-data` | `22b3e1a7c825c104cc6e4663f983baa48b6209c04eee38b7e5ed24c883595d91` | 34816 | `data` |
| 1 | `7z-data` | `af5a342b23bf7678578753c7aceba58163e4d8bc5a064d57d970a3c306407b81` | 23552 | `data` |
| 1 | `7z-data` | `6bce7bad45476e1ce91fecd6bd648deed5e9b7c23dc327e80ee41e7712ab7bd2` | 61440 | `data` |
| 1 | `7z-data` | `e4da03ef6c2d974042b126c483bc750fc1a6f831b3988e99ec7d82be33c7999a` | 8192 | `data` |
| 1 | `7z-data` | `fdd32ff1bf55cccad61460d636a0fdecf52650584d1a0b70a8d424a167b14f32` | 37888 | `data` |
| 1 | `7z-data` | `d62a0eeee81532cf6d2254abdf5cdeb3c1030f60f3dbe893c6108b8e090a0934` | 165888 | `data` |
| 1 | `7z-data` | `2c3867a30d2d05c0d877059b96f519772cbbbd2a0d7fd7c7f2268f76f41e2107` | 60416 | `data` |
| 1 | `7z-data` | `84fda09356bd13134e107d49e0c4525ab7df713b71ffd75602e8a699e2d0095c` | 19456 | `data` |
| 1 | `7z-data` | `a13c473c321151d9a0a95e835686a599cc8b610cc3100878aaebda99c1032c5c` | 19456 | `data` |
| 1 | `7z-data` | `8268bcda9cb466f90b2bb49c7e2a6a23e85c2cd8c7c63170e3c07839f40b333b` | 24061 | `data` |
| 1 | `7z-data` | `b67fa393883721df42e25346f033ffea20a5775c3ad65b1cad4995a9399ee494` | 32768 | `data` |
| 1 | `7z-data` | `47e13870ce739adf64b33d403d391e14e29371c084cd243a6af8386a9bf48aa3` | 125 | `data` |
| 1 | `7z-data` | `2bd3ab984634ca7092f8c376bc1238d23d1e713fb1614baf5f216c6515420ab4` | 56320 | `data` |
| 1 | `7z-data` | `9c9d3482ee9eb7860b0c69c9d68754a33fc65c52e055e8e787486673ab341c2b` | 35840 | `data` |
| 1 | `7z-data` | `ed896cbf5263298907d8a47fe2b177ad1b1a93927cde77b18fa1fdeb51b52313` | 24576 | `data` |
| 1 | `7z-data` | `e4db4db3b69e13fb052a3fde7f14cdc59bb1619e47bb10c397ae82053a7000e2` | 22528 | `data` |
| 1 | `7z-data` | `c0f4dc26a5ee8028dcd52fd647989611628677b82642fa368e146e21776f6566` | 67584 | `data` |
| 1 | `7z-data` | `d4c38b731d74a94d6840d655f51afe3b845627912d7686bf7203d328dbc3e811` | 64512 | `data` |
| 1 | `7z-data` | `45dfdafebfac3fe00a6dbd7029b3af8d9578d8e70f2ed172f548d4832f987645` | 72704 | `data` |
| 1 | `7z-data` | `1cec9db07dc2944675e16550286a48fee8ea2ff23b2e14c26aef171c3587b001` | 37888 | `data` |
| 1 | `7z-data` | `9957eed2b201572a696317f22c825099e6753e2f6e3b0ef243bd3431294d007b` | 44032 | `data` |
| 1 | `7z-data` | `2405e33214050c56649fd0fab58b486f8cc98c1242ea94ebb1cea897575dcaf5` | 61440 | `data` |
| 1 | `7z-data` | `9e790bc388fb495773fd201a994038ace8df4346d50ee2cdf36ee730acf2279c` | 18432 | `data` |
| 1 | `7z-data` | `a9a08debec110cabedb5521c338e68d427f9a1c201b853623fe8f4a3b94f417e` | 40960 | `data` |
| 1 | `7z-data` | `2efb0040eb9a496cc6a93003c844046efd0f93061ba02c49037e7017f2301ab0` | 34816 | `data` |
| 1 | `7z-data` | `b30240078c64097b4256be548703ac506e1f1243539566558ac6d5a4342ea0c2` | 30720 | `data` |
| 1 | `7z-data` | `b0a17d66f902476be402a90d0341803c35a5bad11862ebffbf142843d7e6a8bd` | 21504 | `data` |
| 1 | `7z-data` | `4ef2df5760049ad16b8860e7befbede0c650b2bf0d797612ba0502b6ca064235` | 13541 | `data` |
| 1 | `7z-data` | `487a4da35ecfa61fbeac8dbd9c9da4819544c870a48ec104817c592bb1c1f37a` | 14025 | `data` |

Recovered bytes are deliberately not committed.

## Unpacking details

- Root entropy: 7.9535
- Root packing assessment: `False`
- Recursive layers analyzed: 34
- 7z status: `extracted`
- UPX status: `not_applicable`

## Limitations

- Vidar may obtain infrastructure from a dead-drop profile rather than a direct embedded C2.
- Packed or loader-stage samples require recursive recovery before a final config can be asserted.
