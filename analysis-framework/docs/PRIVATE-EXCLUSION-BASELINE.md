# private除外baselineの生成

`build_private_exclusion_baseline.py`は、既存のJSON manifest、case directory、bounded JSON treeから検体SHA-256だけを集約し、ValleyRAT cycle evaluatorの`migrate-state`／初回`register`へ渡せるprivate baselineを作ります。API keyは不要で、外部通信、検体展開、検体実行を行いません。

## 生成

単一manifest／case directoryは`--input`で繰返し指定します。JSONでは`sha256`、`sha256_hash`、`sha256:<digest>`形式の`case_id`、`selected_hashes`、`cases`の既知欄だけを読みます。`--input`へdirectoryを渡した場合はJSONを読みません。64桁のSHA-256を名前に持つdirectoryだけをidentityとして扱います。

多数のJSONを含むtreeは`--json-tree`で繰返し指定します。配下の拡張子`.json`の通常fileだけをpath順で再帰的に読みます。こちらはdirectory名をidentityとして扱いません。JSON objectだけでなくtop-level配列、UTF-8、UTF-8 BOMへ対応します。duplicate key、`NaN`／`Infinity`、上限を超える構造は拒否します。どちらの入力方式でも、任意の64桁文字列や`zip_sha256`、token、credential相当の未知欄は収集しません。

```powershell
py -3.13 .\analysis-framework\common\build_private_exclusion_baseline.py `
  --input C:\private-analysis\older-manifest.json `
  --input C:\private-analysis\cases `
  --output C:\private-analysis\valleyrat-baseline.json
```

数千件のJSON pathをcommand lineへ列挙せず、複数treeをまとめる例は次のとおりです。

```powershell
py -3.13 .\analysis-framework\common\build_private_exclusion_baseline.py `
  --json-tree .\analysis-results\collections `
  --json-tree .\analysis-results\research `
  --json-tree .\analysis-results\clickfix `
  --json-tree .\analysis-results\network-traffic `
  --json-tree .\analysis-results\catalog `
  --json-tree .\analysis-results\stix `
  --output C:\private-analysis\valleyrat-baseline.json
```

`--json-tree`には次の明示的な上限があります。1つでも超えた場合は部分結果を保存せずfail-closedで終了します。

- tree全体のentry数: 1,000,000件
- 重複treeを除いたJSON file数: 20,000件
- JSON 1件のsize: 128 MiB
- 全JSONの合計size: 4 GiB
- JSON 1件のnode数: 12,000,000件
- JSONの深さ: 128階層

走査順は絶対path順で固定されます。tree内の全entryについてsymlink／junctionなどのreparse pointを拒否し、通常fileのhardlinkも拒否します。各JSONは単一file handleのbounded snapshotとして読み、tree全体もparse前後でpath、file identity、size、更新時刻を再確認します。解析中の追加、削除、差替え、書換えを検出した場合は出力しません。

出力は次の固定schemaです。

- `schema_version=1`
- `identity_type=sha256`
- `identity_count`と、昇順・重複なしの`identities`
- `excluded_hashes_sha256`: 正規化した`identities`配列のcommitment
- `classification=private`
- `contains_sample_sha256=true`
- `publishable=false`

出力には実際の検体SHA-256が含まれるため、解析repository内へ保存できません。入力／出力の同一pathとdirectory入力配下への出力を拒否します。直接指定したJSON、`--json-tree`のroot／全entry、出力pathにあるreparse pointを拒否し、通常fileと既存出力のhardlinkも拒否します。

`--input`のdirectory modeだけは、rootを非reparseの通常directoryへ固定した上で、配下のreparse entryを開かず、追跡せず、identityにも採用せずskipします。このmodeはfile内容もfile名も読まず、SHA-256名の実directoryだけを収集するため、配下にある通常fileのhardlinkも結果へ影響しないものとして無視します。既存出力がある場合は、strict JSONとして同一内容である場合だけ再利用し、差分があれば上書きしません。

複数入力のうち、SHA-256名directoryが0件の`--input` directoryや、既知identityが0件の`--json-tree`は補助入力として許可します。全入力をunionした最終identity集合が0件の場合は、空baselineを保存せず拒否します。

生成したbaselineは`malwarebazaar_batch.py --exclude-manifest`にも直接指定できます。`manifest_hashes`は、`identity_type=sha256`に加え、`identity_count`、昇順・重複なしのSHA-256配列、`excluded_hashes_sha256` commitmentがすべて一致する`identities`だけを除外集合へ取り込みます。契約外の任意`identities`欄やcredential欄にある64桁値、破損・未整列・重複したidentity集合は取り込みません。

## cycle state移行での利用

生成したbaselineは、そのまま`--baseline-manifest`へ指定できます。

```powershell
py -3.13 .\analysis-framework\common\evaluate_valleyrat_cycles.py migrate-state `
  --state C:\private-analysis\cycle-state.json `
  --selection-manifest C:\private-analysis\cycle-1\ValleyRAT\manifest.json `
  --baseline-manifest C:\private-analysis\valleyrat-baseline.json
```

このCLIはbaseline生成専用です。MalwareBazaarへの照会・取得や、選定済みcycleの評価は行いません。
