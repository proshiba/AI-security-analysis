# ValleyRAT／ACRStealer追加解析（2026-07-23）

MalwareBazaarから各10件を取得し、実行せずに静的解析しました。ACRStealerタグ集合は本体、配布物、デコイ、別payloadを役割分離しています。

| ファミリー | SHA-256 | 役割 | 静的ロジック |
|---|---|---|---|
| `valleyrat` | [`12b920865bc8bd9bad20650a0f7849fe2856de3d72bc5f1a93bb288e8eefaca2`](../../malware/valleyrat/versions/unknown/cases/12b920865bc8bd9bad20650a0f7849fe2856de3d72bc5f1a93bb288e8eefaca2/README.md) | `installer_protected_pe` | `function_logic_review_required` |
| `valleyrat` | [`5876be168613a5e77024f79dad518662e8fd418f01d5839fc7e73ecb0f085a92`](../../malware/valleyrat/versions/unknown/cases/5876be168613a5e77024f79dad518662e8fd418f01d5839fc7e73ecb0f085a92/README.md) | `multi_pe_software_bundle` | `function_logic_review_required` |
| `valleyrat` | [`9a9d372cc821b6d2f7e30abb80aff7cae841703db0fb78bd859e6581420fbc07`](../../malware/valleyrat/versions/unknown/cases/9a9d372cc821b6d2f7e30abb80aff7cae841703db0fb78bd859e6581420fbc07/README.md) | `high_entropy_installer` | `function_logic_review_required` |
| `valleyrat` | [`0f963f03d73f3f874928d744e8188b3f61470f982ab1100a5645d0a3c27ee611`](../../malware/valleyrat/versions/unknown/cases/0f963f03d73f3f874928d744e8188b3f61470f982ab1100a5645d0a3c27ee611/README.md) | `native_dll_rat_worker` | `reviewed_function_logic` |
| `valleyrat` | [`a0eb29beacb4463ed88b579625a1483245dff067697b85d93fd62992c5512489`](../../malware/valleyrat/versions/unknown/cases/a0eb29beacb4463ed88b579625a1483245dff067697b85d93fd62992c5512489/README.md) | `protected_pe_resource_delivery` | `function_logic_review_required` |
| `valleyrat` | [`5f8daf53ef216151a72cb3fbb953886c74488b9d91b3a8afbc9bbf39e8d5eacf`](../../malware/valleyrat/versions/unknown/cases/5f8daf53ef216151a72cb3fbb953886c74488b9d91b3a8afbc9bbf39e8d5eacf/README.md) | `msi_embedded_pe_delivery` | `function_logic_review_required` |
| `valleyrat` | [`b3369a20d7c603b4d1078010b008a9db1b49dccf694a05e6bd49ede2762a8075`](../../malware/valleyrat/versions/unknown/cases/b3369a20d7c603b4d1078010b008a9db1b49dccf694a05e6bd49ede2762a8075/README.md) | `direct_pe_confirmed_vvas_config` | `function_logic_review_required` |
| `valleyrat` | [`8715bb53fad907f12ab1b5ec7bad49d2a4f72bf07f81bb2a6621fd1f9f55ffa1`](../../malware/valleyrat/versions/unknown/cases/8715bb53fad907f12ab1b5ec7bad49d2a4f72bf07f81bb2a6621fd1f9f55ffa1/README.md) | `resource_zip_pe_png_delivery` | `function_logic_review_required` |
| `valleyrat` | [`edb371be39673ca248b4dcb168de0efd90e9d7a39d7cc096c83c435bd6fe260b`](../../malware/valleyrat/versions/unknown/cases/edb371be39673ca248b4dcb168de0efd90e9d7a39d7cc096c83c435bd6fe260b/README.md) | `high_entropy_installer` | `function_logic_review_required` |
| `valleyrat` | [`a0d1e6b471522635bcf7ca0176d6ee8febcf90184078b5e8ce24e0eca970b532`](../../malware/valleyrat/versions/unknown/cases/a0d1e6b471522635bcf7ca0176d6ee8febcf90184078b5e8ce24e0eca970b532/README.md) | `high_entropy_direct_pe` | `function_logic_review_required` |
| `acrstealer` | [`cb336a6e3fc0e9aa62b5768bffc207c09b372546636a5c58057a1b6d0708df06`](../../malware/acrstealer/versions/unknown/cases/cb336a6e3fc0e9aa62b5768bffc207c09b372546636a5c58057a1b6d0708df06/README.md) | `sfx_autoit_delivery` | `function_logic_review_required` |
| `acrstealer` | [`5fbed74e14ac66724e9d88829ade0c3d7f640288d902f7721eca96eab632d165`](../../malware/acrstealer/versions/unknown/cases/5fbed74e14ac66724e9d88829ade0c3d7f640288d902f7721eca96eab632d165/README.md) | `file_pumped_sfx_autoit_delivery` | `function_logic_review_required` |
| `acrstealer` | [`7c9a76145f39a052020aed4eb60927ad678c792c15bdf4f192d36a569e0457f8`](../../malware/acrstealer/versions/unknown/cases/7c9a76145f39a052020aed4eb60927ad678c792c15bdf4f192d36a569e0457f8/README.md) | `file_pumped_pe_delivery` | `function_logic_review_required` |
| `acrstealer` | [`31cf473bb93abef0760d4992d45bafcd936edb7c26193c175f8491f8ffaef0e0`](../../malware/acrstealer/versions/unknown/cases/31cf473bb93abef0760d4992d45bafcd936edb7c26193c175f8491f8ffaef0e0/README.md) | `related_payload_zigclipper_reported` | `function_logic_review_required` |
| `acrstealer` | [`b2ab8825b84e6f0209cf713dcf7156c93ae82f37a6d9f0ca9072e228825c8d63`](../../malware/acrstealer/versions/unknown/cases/b2ab8825b84e6f0209cf713dcf7156c93ae82f37a6d9f0ca9072e228825c8d63/README.md) | `synthetic_go_decoy_or_loader_unconfirmed` | `function_logic_review_required` |
| `acrstealer` | [`b7dacc50bebb59e302a886e3585a521d61c38dd27cfc7de1522bce998cb173f3`](../../malware/acrstealer/versions/unknown/cases/b7dacc50bebb59e302a886e3585a521d61c38dd27cfc7de1522bce998cb173f3/README.md) | `msi_delivery` | `function_logic_review_required` |
| `acrstealer` | [`c4b117f30786d0b328d90c2818e4c454e81d29ed5921d8f8847e80333a12ee86`](../../malware/acrstealer/versions/unknown/cases/c4b117f30786d0b328d90c2818e4c454e81d29ed5921d8f8847e80333a12ee86/README.md) | `file_pumped_pe_delivery` | `function_logic_review_required` |
| `acrstealer` | [`14ac0c55100d957d1b198583461b2605e6e72c2538039b54c538dc7e356ddce3`](../../malware/acrstealer/versions/unknown/cases/14ac0c55100d957d1b198583461b2605e6e72c2538039b54c538dc7e356ddce3/README.md) | `file_pumped_pe_delivery` | `function_logic_review_required` |
| `acrstealer` | [`06f6a0dc417bf0c8d1fa54754f53d37d190a3b9bf66658e00a630ae0bb56dfab`](../../malware/acrstealer/versions/unknown/cases/06f6a0dc417bf0c8d1fa54754f53d37d190a3b9bf66658e00a630ae0bb56dfab/README.md) | `native_loader_shellcode` | `reviewed_function_logic` |
| `acrstealer` | [`1220d2250778f214b8ef2d37cf6c0904fb6080a42ad4e1e9bd253f84c8e7e10e`](../../malware/acrstealer/versions/unknown/cases/1220d2250778f214b8ef2d37cf6c0904fb6080a42ad4e1e9bd253f84c8e7e10e/README.md) | `file_pumped_pe_delivery` | `function_logic_review_required` |

- 検体実行: なし
- C2／外部ホスト接続: なし
- 暗号化受け入れZIPはリポジトリ外で保持
