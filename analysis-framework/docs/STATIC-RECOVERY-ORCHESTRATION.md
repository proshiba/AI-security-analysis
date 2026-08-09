# 静的復元オーケストレーション

複数段の復号、unpack、設定抽出を同じ検体系列へ再適用するための設計です。検体を実行せず、外部通信も行わず、入力の構成がreview済み条件と一致する場合だけ処理を進めます。

## 構成

- [共通engine](../common/static_orchestration.py)は、role manifestの検証、固定DAGの段階実行、成果物hash、process内rollback付き公開、成果物再検証を担当します。
- [GuLoader→XLoader adapter](../malware/guloader/xloader_static_pipeline.py)は、family固有のrole、構造probe、復元段階、段階間の検証条件を定義します。
- [GuLoader one-shot facade](../malware/guloader/extract_config.py)は、単一バイト列から安全な構造probeだけを行い、one-shot解析へ適用状態と復元入口roleを返します。private profileの読み込みや復元処理は行いません。

共通engineへ暗号方式、offset、family markerを直接埋め込みません。family adapterへファイル操作、任意command実行、network取得を持ち込まず、登録済みの静的段階だけを共通engineから呼び出します。

## 適用状態

| 状態 | 意味 | 自動処理 |
|---|---|---|
| `exact_match` | 入力、role、profile、期待出力のhashがreview済みlineageと完全一致する | manifestの全条件を満たす場合だけ可 |
| `structural_match` | 固有marker、配置、個数、親子関係が一致するが、検体hashは異なる | profile portabilityがreview済みの場合だけ可 |
| `candidate` | 一部の特徴は一致するが、familyまたは構成を一意に確定できない | 不可。追加解析へ送る |
| `not_matched` | 必須構造を満たさない | 不可。別adapterまたはgeneric triageへ送る |

`MZ`、有効なPE header、全体Base64、一般的なloader API、ファイル名のいずれか単独ではGuLoaderへ一致させません。Katheco型では、親scriptの固有関数・変数・反復call、または全体Base64 carrierの復号末尾にある複数固有markerを相関させます。

`structural_match`は「同じfamilyまたは似た保護方式」の根拠であり、「同じ鍵・offset・復号結果」の証明ではありません。現在は、構造が一致してもprivate profileの別検体への可搬性がreview済みでなければ停止します。

## Role manifest（役割マニフェスト）

オーケストレーションへ渡す全入力は、用途を示すrole、相対path、size、media type、SHA-256をmanifestで固定します。ファイル名や探索順だけでは対応付けません。次は91関数を復元済みのXLoader像からC2を抽出する最小構成です。

```json
{
  "schema_version": 1,
  "manifest_type": "static_analysis_private_bundle",
  "settings": {
    "pipeline_id": "guloader-xloader-static-v1",
    "family": "xloader",
    "entry_role": "xloader_fully_recovered_image",
    "expected_input_sha256": "<入力の64桁SHA-256>",
    "expected_final_sha256": "<最終像の64桁SHA-256>",
    "expected_final_size": 274432,
    "allow_structural_reuse": false
  },
  "artifacts": [
    {
      "role": "c2_lineage_profile",
      "path": "c2-lineage-profile.json",
      "sha256": "<64桁のSHA-256>",
      "size": 1630,
      "media_type": "application/json"
    },
    {
      "role": "string_builder_base_key",
      "path": "string-builder-base-key.bin",
      "sha256": "<64桁のSHA-256>",
      "size": 20,
      "media_type": "application/octet-stream"
    },
    {
      "role": "primary_layered_key_plan",
      "path": "primary-layered-key-plan.json",
      "sha256": "<64桁のSHA-256>",
      "size": 466,
      "media_type": "application/json"
    },
    {
      "role": "bootstrap_layered_key_plan",
      "path": "bootstrap-layered-key-plan.json",
      "sha256": "<64桁のSHA-256>",
      "size": 599,
      "media_type": "application/json"
    },
    {
      "role": "initial_record_plan",
      "path": "initial-record-plan.json",
      "sha256": "<64桁のSHA-256>",
      "size": 2707,
      "media_type": "application/json"
    }
  ]
}
```

`xloader_protected_mapped_image`から開始する場合は`protected_function_profile`と`nested_static_profile`、`guloader_protected_pe`から開始する場合はさらに`inner_payload_profile`を追加します。91/91/0の既存証拠を併用する場合は、任意roleの`static_recovery_report`を追加できます。

adapterは必要なrole、重複禁止、許容size、親子lineage、profile ID、段階ごとの入力hashと期待出力hashを検証します。未知role、同一roleの重複、path traversal、symlink／junction、hash不一致、曖昧な候補は処理開始前に拒否します。

## Process内rollbackと成果物再検証

1. manifest、全artifact、入力、engine、adapter、復元component、Python／Capstone runtimeから処理契約のfingerprintを作る。
2. 認証済みの単一snapshotを固定DAGへ渡し、probe後に入力やbundleを読み直さない。
3. 公開先と分離した一時directoryで、登録済みの静的段階を順に実行する。
4. 全必須段階とpost gateが成功した場合だけ、`fsync`済み一時fileを置換する。process内の例外では既存成果物をrollbackする。
5. `verify`では最終像をbundleの期待hash／sizeへ再照合し、C2抽出を静的に再実行して公開reportとprivate成果物の一致を確認する。

現行版はstage単位のcacheを再利用せず、`run`ごとに静的stageを再実行します。「出力が存在する」だけでは完了扱いにしません。複数file systemを跨ぐ真のtransactionや、電源断・process強制終了まで含むcrash atomicityは保証しません。異常終了後は`verify`を必須とし、残った一時fileやbackupを人手確認してから再実行します。

## GuLoader→XLoaderの使用例

最初に単一入力をprobeし、対応roleと適用状態を確認します。

```powershell
py -3.13 analysis-framework/malware/guloader/xloader_static_pipeline.py probe `
  --input C:/private/submitted-sample.bin `
  --bundle-manifest C:/private/guloader-xloader-bundle/bundle-manifest.json `
  --private-output-root C:/private/guloader-xloader-bundle `
  --public-report .work/static-recovery/guloader-xloader-probe.json
```

対応する保護PE、保護mapped image、または91関数復元済みimageとreview済みprofileを、検体ごとに分離したrole manifestへ固定した後、静的復元を実行します。

```powershell
py -3.13 analysis-framework/malware/guloader/xloader_static_pipeline.py run `
  --input C:/private/submitted-sample.bin `
  --bundle-manifest C:/private/guloader-xloader-bundle/bundle-manifest.json `
  --private-output-root C:/private/guloader-xloader-bundle `
  --public-report .work/static-recovery/guloader-xloader-static-report.json
```

完了後は、公開reportとprivate成果物を現在の入力・bundleへ再照合し、C2抽出も静的に再生成して検証できます。

```powershell
py -3.13 analysis-framework/malware/guloader/xloader_static_pipeline.py verify `
  --input C:/private/submitted-sample.bin `
  --bundle-manifest C:/private/guloader-xloader-bundle/bundle-manifest.json `
  --private-output-root C:/private/guloader-xloader-bundle `
  --public-report .work/static-recovery/guloader-xloader-static-report.json
```

現在の一括adapterは、GuLoader保護PE、XLoader保護mapped image、91関数を復元済みのXLoader像の3入口を扱います。Katheco親scriptと全体Base64 carrierはone-shot facadeと`katheco_stager.py`で構造判定・shellcode分離できますが、shellcodeから後段PEを静的に導出する汎用stageは未実装です。したがって元の`Ikatath.xtp`だけからC2までを無条件に全段自動復元するものではありません。このgapでは停止理由と必要artifactを返し、前段の成功だけで後段やC2の復元済みを宣言しません。

## 安全性とprivate成果物

- 検体、復元payload、PowerShell、PE、shellcodeを実行しません。
- 外部URL、C2、sandbox API、S3へ接続しません。
- profileの鍵、mix値、復号済みbinary、memory dumpを公開reportやリポジトリへ含めません。
- private rootはlocal drive上のrepository外directoryとし、Windowsでは事前に現在user、SYSTEM、Administratorsへ限定したACLを設定します。`chmod(0o600)`だけをWindowsの秘密保護根拠にしません。
- 公開reportにはhash、size、role、方式、検証状態、blocker、安全フラグ、および無害化した静的IOC候補だけを残します。鍵、復号seed、private path、生の秘密値は残しません。
- S3からのsample、profile、memory dumpの自動取得はorchestratorの責務にしません。入力取得と由来確認を解析者の明示手順として分離します。

リポジトリ外の検体固有データは、解析対象ごとにpassword `infected`のWinZip AES-256 ZIPへ分離し、`analysis-framework/common/archive_analysis_datastore.py`と[解析データ保管手順](ANALYSIS-DATASTORE.md)でS3 bucketへ保存します。upload後のsize、SSE、SHA-256 metadataを確認するまでlocal stagingを削除しません。

## 他familyへの追加手順

1. family固有の構造probeを単一bytes APIとして実装し、一般markerだけのfalse positiveをテストする。
2. 必須role、許容形式、size上限、親子関係、exact／structural条件をadapterへ宣言する。
3. 各復号段階を副作用のない関数へ分離し、入力・出力・profile hashの検証を必須にする。
4. 共通engineへ登録する段階IDを固定し、manifestから任意module、関数、commandを指定できないようにする。
5. fingerprintへ直接依存componentとruntime版を含め、公開report出力先を専用の作業directoryとJSON拡張子へ限定する。
6. 正常系、未知亜種、曖昧role、hash不一致、path逸脱、途中失敗、rollback、成果物改ざん、秘密値非公開をunit testで検証する。
7. 実検体回帰はprivate環境変数で任意実行し、fixtureや復元binaryをリポジトリへ追加しない。

構造差分を吸収するために検証条件を弱めません。新しい構成は新profileまたは新adapter revisionとして追加し、既存profileの回帰テストを残します。




