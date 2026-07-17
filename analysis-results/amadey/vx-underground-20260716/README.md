# Amadey analysis

35 `vx-underground` submissions were analyzed statically. Delivery shape is separated from malware family because loaders, packers, and operators can vary independently.

## Batch outcome

- Cases: 35
- Errors: 0
- Packing suspected: 11
- Cases with recovered artifacts: 9
- Cases with validated static config: 12
- Sample executed: false
- Network contacted: false

## Campaign/delivery shapes

- `direct_pe_or_container`: 24
- `protected_wrapper`: 11

## Statically observed behavior features

- `persistence`: 22/35
- `plugin_download`: 33/35
- `rc4_protected_traffic`: 9/35
- `system_discovery`: 15/35

## C2/config findings

| Value | Role | Confidence | Source |
|---|---|---|---|
| `http://5.42.65.125/k92lsA3dpb/index.php` | c2 | confirmed | amadey_config_decryption |
| `http://212.113.119.255/joomla/index.php` | c2 | confirmed | amadey_config_decryption |
| `http://185.172.128.116/Mb3GvQs8/index.php` | c2 | confirmed | amadey_config_decryption |
| `http://31.41.244.10/Dem7kTu/index.php` | c2 | confirmed | amadey_config_decryption |
| `http://185.172.128.19/ghsdh39s/index.php` | c2 | confirmed | amadey_config_decryption |
| `http://62.204.41.242/9vZbns/index.php` | c2 | confirmed | amadey_config_decryption |
| `http://185.215.113.19/Vi9leo/index.php` | c2 | confirmed | amadey_config_decryption |

No active C2 check-in was performed. Use `analysis-framework/common/c2_candidate_detector.py` for offline assessment and passive-query generation.

## Validated config values

- `c2_urls`: `http://185.172.128.116/Mb3GvQs8/index.php` (1), `http://185.172.128.19/ghsdh39s/index.php` (1), `http://185.215.113.19/Vi9leo/index.php` (1), `http://212.113.119.255/joomla/index.php` (6), `http://31.41.244.10/Dem7kTu/index.php` (1), `http://5.42.65.125/k92lsA3dpb/index.php` (1), `http://62.204.41.242/9vZbns/index.php` (1)
- `campaign_id`: `037208` (1), `0657d1` (1), `4b955f` (1), `5d3738` (6), `62fadb` (1), `810740` (1), `c7817d` (1)
- `install_directory`: `0d8f5eb8a7` (1), `0de90fc5c7` (1), `0e8d0864aa` (1), `4b9a106e76` (1), `5cb6818d6c` (6), `b66a8ae076` (1), `cd1f156d67` (1)
- `install_filename`: `Hkbsse.exe` (1), `Utsysc.exe` (2), `explorti.exe` (1), `nbveek.exe` (1), `oneetx.exe` (6), `svoutse.exe` (1)
- `profile`: `amadey_custom_alphabet_base64` (12)
- `version`: `3.66` (1), `3.70` (6), `4.12` (1), `4.13` (1), `4.30` (1), `4.41` (2)

## Cases

| SHA-256 | Format | Campaign | Packed | Layers | Findings |
|---|---|---|---:|---:|---:|
| [6bd20157eb14](cases/6bd20157eb146f12887ccb49fa09ac5b0c817983edc43ca1b665f17ad3ebfb25/README.md) | pe | direct_pe_or_container | false | 0 | 0 |
| [12e5e5bba84f](cases/12e5e5bba84f2a618310f72a7fbb40e04bf2f221a13145b3a91bb4707d7130c1/README.md) | pe | direct_pe_or_container | false | 0 | 1 |
| [142cbad8b9d4](cases/142cbad8b9d400380c78935e60db104ec080812b1a298f9753a41b2811c856be/README.md) | zip | direct_pe_or_container | false | 0 | 0 |
| [1d8596310e2e](cases/1d8596310e2ea54b1bf5df1f82573c0a8af68ed4da1baf305bcfdeaf7cbf0061/README.md) | zip | direct_pe_or_container | false | 1 | 0 |
| [1dbbf81d6f4b](cases/1dbbf81d6f4b2222b37594e8ff30672bf85fd360f347cbd20b1a5d7b841dd276/README.md) | pe | protected_wrapper | true | 0 | 0 |
| [a1b0074cbd56](cases/a1b0074cbd56956cc94e6161361f8f7407075f2903d14d082c1006f411bec90a/README.md) | pe | direct_pe_or_container | false | 0 | 0 |
| [2b46fc922a0e](cases/2b46fc922a0e16552f09f9b2d1a9cbedfada367fa985e2c0a15b815acc03f806/README.md) | pe | direct_pe_or_container | false | 13 | 1 |
| [43e67fbb1bc6](cases/43e67fbb1bc6ac4549c216476b2aa4e98a89e74ce4d51b8d72380fdd8cc4edb1/README.md) | pe | protected_wrapper | true | 0 | 0 |
| [4506917f5cd8](cases/4506917f5cd8be78ec581d74085c21b75b17c2ede56f0af2dc38bc3f09e96caf/README.md) | pe | direct_pe_or_container | false | 13 | 1 |
| [488385cd54d1](cases/488385cd54d14790b03fa7c7dc997ebea3f7b2a8499e5927eb437a3791102a77/README.md) | pe | direct_pe_or_container | false | 0 | 1 |
| [4c8f8899d027](cases/4c8f8899d02737d9c1c00f8848f73298a2749ff7a1a75a0ca2acd68117d2b515/README.md) | pe | direct_pe_or_container | false | 13 | 1 |
| [572d806c0b56](cases/572d806c0b56d27fe05562301de6a9ed45cda3f36aef2f6e370867d9f3847013/README.md) | pe | protected_wrapper | true | 0 | 0 |
| [5aff860634fa](cases/5aff860634fadee66a6e8220e67f7ebc88bfcde7a905a2753655706c0252afd1/README.md) | pe | direct_pe_or_container | false | 0 | 0 |
| [5bf3ab9c47d8](cases/5bf3ab9c47d8152548db40516ff474a947393de01033b0be2a57409e08d4991c/README.md) | pe | direct_pe_or_container | false | 0 | 1 |
| [42054b960727](cases/42054b960727fbd72bde57e8903881e4239e9500f1160ca298e10a1b438698a8/README.md) | pe | direct_pe_or_container | false | 0 | 0 |
| [6b89cdfe0d3e](cases/6b89cdfe0d3ebc90994ee564aac9c88b0df80f25720aedadff660a0d079ad0c9/README.md) | pe | direct_pe_or_container | false | 1 | 0 |
| [707fc73f8e64](cases/707fc73f8e6494959b1b33c9f7c582335cda88397a0e7e3822f56ad0354996c6/README.md) | pe | direct_pe_or_container | false | 13 | 1 |
| [78305c8b5e8e](cases/78305c8b5e8ead6989a0af09fc6ed8f2ff1b246c0487dfa78fb5b155b554cae9/README.md) | pe | protected_wrapper | true | 0 | 0 |
| [7970613a8bdc](cases/7970613a8bdc95bb97d4996d9302153feef816b64a6b1861045a2aec85dcdb8d/README.md) | pe | direct_pe_or_container | false | 0 | 0 |
| [7d05ae98fea4](cases/7d05ae98fea42630b199a45f26e18a7196a8f3509ed703fc918416780fd1f661/README.md) | pe | protected_wrapper | true | 0 | 0 |
| [8fb3b241a257](cases/8fb3b241a2578c6fbaf43a7c4d1481dc5083d62601edece49d1ce68b0b600197/README.md) | pe | direct_pe_or_container | false | 0 | 0 |
| [919ae827ff59](cases/919ae827ff59fcbe3dbaea9e62855a4d27690818189f696cfb5916a88c823226/README.md) | pe | direct_pe_or_container | false | 0 | 1 |
| [93583dfa872b](cases/93583dfa872b44e13e449cdfbbe20e64851dbe0e615f30b0313d2cb6a9b2309e/README.md) | pe | direct_pe_or_container | false | 1 | 0 |
| [b00302c7a37d](cases/b00302c7a37d30e1d649945bce637c2be5ef5a1055e572df9866ef8281964b65/README.md) | pe | direct_pe_or_container | false | 0 | 1 |
| [ba7570395a1a](cases/ba7570395a1adfa7dd22638402d994c2b36efb559d1a69ddc91503bb0b608839/README.md) | pe | direct_pe_or_container | false | 0 | 1 |
| [c72cbb4b668f](cases/c72cbb4b668f0f56d9df6359e5d391908a9ef5bb21c8f8eb4445be9197c47ef0/README.md) | pe | protected_wrapper | true | 0 | 0 |
| [8babde64a6d3](cases/8babde64a6d3b85c2c4315205ae58884ee01f6364477a777f09d5b9c3ceef2a6/README.md) | pe | direct_pe_or_container | false | 0 | 0 |
| [d04f0d887068](cases/d04f0d88706837f7af27edf86b3c0e3241bad8ab43939ddda29dc6541b20eed2/README.md) | pe | protected_wrapper | true | 0 | 0 |
| [d96239eb6f4f](cases/d96239eb6f4f3af1613dbb8513d97b895dccf7b986adb6d2a94a3bd3064b471b/README.md) | pe | direct_pe_or_container | false | 13 | 1 |
| [e92089c1bcd9](cases/e92089c1bcd9543515ccada144422b83f9f0b39b3fc0762d79d6619138a224cb/README.md) | pe | protected_wrapper | true | 0 | 0 |
| [ea07b2d53fa8](cases/ea07b2d53fa8793d39a63f4f787e3951cf3eb9fab05cc5a2b5cd3e303c241c10/README.md) | pe | direct_pe_or_container | false | 13 | 1 |
| [ea3b2c23df31](cases/ea3b2c23df3162a6fa5c9d22d03f50db30542d7570ef769ded4ef106fb0255f4/README.md) | pe | protected_wrapper | true | 0 | 0 |
| [ee170a14d676](cases/ee170a14d676b69cab768f8a94e482ee9ad6dc1766038d6e26c24fe2cfbd7677/README.md) | pe | protected_wrapper | true | 0 | 0 |
| [fda0fc105ffd](cases/fda0fc105ffd6faae12d08c243fe684be8c69696bd654d733f5caf487b59baae/README.md) | pe | protected_wrapper | true | 0 | 0 |
| [3d4fa915ede8](cases/3d4fa915ede8b3a7d95155694abfe13c3ad26a65545fe1635797ff200ccdcb40/README.md) | pe | direct_pe_or_container | false | 0 | 0 |

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
