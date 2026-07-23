# 代表関数ロジック解析とコード類似性

今後のcase解析では、IOC、挙動要約、YARA／Sigmaとは別に、特徴的な関数の静的ロジックと検体全体の処理像を標準成果物として残します。目的は、同じ復号器、設定parser、通信dispatcher、永続化処理、実行handlerなどを検体横断で比較し、後続解析へ再利用できるようにすることです。

全内部関数の逆コンパイルは完了条件にしません。関数境界のinventoryは保持し、malwareの理解と比較に重要な代表関数を根拠付きで選定します。

## 必須成果物

新規caseと、静的解析を更新した既存caseには次を置きます。

- `static-logic.json`: 発見関数数、代表関数、選定理由、call関係、制御構造、fingerprint、解析状態、制約の機械可読成果物
- `STATIC-LOGIC.md`: 代表関数の役割、処理順、選定理由を日本語で確認する文書
- `OVERALL-LOGIC.md`: 検体全体の処理段階と、静的に観測したcall関係を日本語で確認する文書

`FEATURES.md`は挙動・検体特徴、`STATIC-LOGIC.md`は関数内部、`OVERALL-LOGIC.md`は全体フローを扱います。IOC値、ファミリーOSINT、検知ルールは混在させません。

## 代表関数の選定

まず、GhidraまたはCLR metadataから取得できる全関数／全managed methodをinventory化します。external、thunk、CIL本体なし、opcode hash取得不能も状態付きで残します。

Ghidraが関数本体を1件も認識しないprogramでは、関数recordを推測で作りません。entry point、import、export、string、segmentの完全取得証跡を保持し、`program構造限定解析`として制約を明示します。importから示す内容は限定したAPI patternに一致する能力候補だけとし、実行経路や悪性動作の成立を証明するものではないと併記します。

逆コンパイルまたはCIL本文解析の対象は、次の観点で選びます。

- entrypoint、初期化、loader入口
- 設定、resource、payloadのparser、decoder、復号、展開
- 通信初期化、送受信、endpoint処理
- command dispatcher、task parser、主要handler
- 永続化、anti-analysis、process／thread／memory操作、file操作
- call graphの入次数・出次数が大きい中心関数
- 命令数が多く処理を集約する関数
- 自動名ではなく意味のあるsymbol名を持つ関数

役割ごとの代表を先に確保し、中心性と規模で補完します。小規模programでは内部関数全体を文脈として選んで構いません。既定上限はprogram・解析種別ごとに32件です。各関数へ選定scoreと理由を記録し、選定外件数もcaseとcollectionの集計へ残します。

## 代表関数ごとに残す情報

少なくとも次を記録します。

- 関数名、address／metadata token、entrypointとの関係
- 日本語の役割と要約
- 入力確認、復号、分岐、loop、子関数呼出、結果利用までの処理順
- caller、callee、外部API／managed method
- 条件分岐、loop、例外処理、returnの個数
- 解析tool、明示的なGhidra `program_selector`、根拠、確度
- 選定理由とscore
- 未解決のindirect call、dispatcher、例外flow、packer影響
- 復元不能の場合の理由と次に必要な解析

addressや関数名の列挙だけでは解析済みとしません。選定した代表関数は、すべて逆コンパイル、CIL解析、または静的script構造解析を試行します。

## 全体ロジック文書

`OVERALL-LOGIC.md`は代表関数を次の処理段階へ整理します。

1. 起動・初期化
2. 設定・payload復元
3. 解析回避・環境判定
4. 永続化
5. process・memory操作
6. 通信
7. command分配・処理
8. file操作
9. 補助処理

静的証跡がある段階だけを掲載します。掲載順は解析上の整理順であり、観測call edgeがない段階間の実行順を断定しません。直接解決できた代表関数間のcall edgeは、関数IDと処理段階を併記します。

## 非公開成果物と保持証跡

生の逆コンパイル全文とCIL命令列はリポジトリ外のアクセス制限された解析領域へ保存し、既定では公開しません。公開成果物では具体的なC2、資格情報、token、復号秘密値、string literal、address、数値、Ghidra自動名、local変数名を無害化または正規化します。

方針変更前に取得した全関数の逆コンパイル結果も削除しません。`private-artifact-validation.json`では次を照合します。

- Ghidraの全関数inventoryとopcode hash状態inventory
- 代表関数ID、選定理由、program-resultとraw indexの一致
- 選定したnative関数の逆コンパイル行
- 選定したmanaged methodのCIL命令列
- imports、exports、strings、segmentsの終端page取得証跡
- JSON妥当性、program selector、解析試行状態

取得済み内容は表示上限のために破棄しません。人向け文書を要約しても、取得済み全件は非公開生成果物または機械可読成果物へ残します。

## 公開coverage

主なfieldは次のとおりです。

- `discovered_function_inventory_count`: 発見した関数／method総数
- `characteristic_function_selected_count`: 代表として公開した関数数
- `characteristic_function_analyzed_count`: 解説まで完了した代表関数数
- `unselected_function_count`: 個別解説対象外の関数数
- `all_discovered_functions_inventoried`: 全体inventoryの完了証跡
- `all_characteristic_functions_attempted`: 全代表関数の解析試行証跡
- `all_characteristic_functions_explained`: 全代表関数の解説証跡
- `all_static_analysis_content_retained`: 取得済み静的成果物の保持証跡

完了状態は次の2つです。

- `characteristic_function_static_analysis_complete`: 全代表関数の解析に制約がない
- `characteristic_function_static_analysis_complete_with_documented_limits`: 制約の理由と次の解析方針を記録済み

代表関数に未試行が1件でもある場合、選定理由がない場合、または全体ロジック文書がない場合は完了扱いにしません。

## 類似性fingerprint

公開する各代表関数には次の3種類を生成します。

- `normalized_logic_sha256`: 正規化ロジック全体の完全一致用
- `semantic_sequence_sha256`: 制御構造、演算子、call形状の列による完全一致用
- `semantic_simhash64`: 小さな変更やaddress差を許容する近似比較用

一致はコード共有の手掛かりです。共通library、compiler生成処理、builder共有でも一致するため、fingerprintだけでファミリー、actor、campaignを確定しません。call graph、API、設定形式、配布文脈、IOCなどの独立証拠と相関します。

## Ghidra MCPでの記録手順

1. SHA-256で対象programを確認します。
2. すべてのGhidra MCP呼出しへ明示的なprogram selectorを渡します。HTTP 200でもJSONに`error`がある応答は失敗です。
3. ルートprogramと静的に復元した実行可能layerごとに、全関数／全managed methodをinventory化します。
4. entrypoint、役割pattern、call graph中心性、関数規模、symbol名から代表関数を選定します。
5. 選定した代表関数を逆コンパイルまたはCIL解析し、処理順と制約を記録します。
6. Ghidraのfull call graphと取得済み代表関数のcall式を相関し、内部、import、未解決edgeを根拠付きで残します。
7. imports、exports、strings、segmentsを上限未満の終端pageまで取得します。
8. raw index、代表関数本文、CIL、取得coverageを非公開領域へ保存して検証します。
9. `STATIC-LOGIC.md`、`OVERALL-LOGIC.md`、`static-logic.json`を生成します。
10. collection検証とコード類似性索引を更新します。

任意Ghidra script実行は既定で無効のままにします。MCPが公開していない操作だけをUIで補います。

## 一括解析

`sample-root`と`private-output`はリポジトリ外のアクセス制限された領域を指定します。

```powershell
python .\analysis-framework\common\ghidra_function_batch.py `
  --repository . `
  --collection .\analysis-results\collections\<collection-id> `
  --sample-root C:\path\to\isolated-samples `
  --private-output C:\path\to\private-static-results
```

途中再開時だけ`--reuse-prepared-inputs`を追加します。cacheはcollection IDとcase集合が一致する場合だけ利用します。全programの処理後に、ページング対象の終端取得、opcode hash inventory、call graph補完、代表関数選定、private成果物検証、公開成果物生成、collection検証を実行します。

```powershell
python .\analysis-framework\common\validate_function_analysis.py `
  --repository . `
  --collection .\analysis-results\collections\<collection-id>
```

出力の`complete`が`true`になるまで、binaryの解析完了を宣言しません。

## リポジトリ横断の類似性索引

```powershell
python .\analysis-framework\common\generate_code_similarity_index.py --repository . --write
python .\analysis-framework\common\generate_code_similarity_index.py --repository . --check
```

出力は次の2つです。

- `analysis-results/catalog/code-similarity.json`
- `analysis-results/catalog/CODE-SIMILARITY.md`

同一case内の一致は除外します。同一ファミリーでは0.86、ファミリー横断では0.94を既定の近似閾値とし、横断一致には共有APIも要求します。最終判断は必ず解析者が行います。
JSON索引のschema version 2では、`function_records`に各関数を一度だけ収録し、完全一致group、SimHash group、類似pairは`record_id`を参照します。これにより候補数が増えても関数詳細をpairごとに複製しません。Markdown版は人間による確認用として類似度の高い最大1,000 pairを表示し、全候補はJSON版に保持します。
