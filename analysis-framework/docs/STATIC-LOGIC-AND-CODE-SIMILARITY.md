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

### 静的可視化

`OVERALL-LOGIC.md`には、同じ公開証跡から生成する次のMermaid図を含めます。

- `実行フロー`: `overall_logic.phases`を配置し、`observed_call_edges`で確認した段階間関係だけを実線で結びます。
- `感染チェーン`: `static-layers.json`の提出検体、静的復元層、`parent_sha256`、`transform`を親子関係として描きます。
- `モジュール関係`: `program_evidence`のroot／静的復元programと、hashで対応できる復元layerの親子関係を描きます。

初期侵入、配布経路、後続stage、段階間の順序、復元元が静的に確認できない場合は、点線と`未観測`または`未解決`ノードで示します。処理段階の掲載順だけを矢印へ変換せず、感染経路やmodule依存をファミリー一般論から補完しません。図は静的な要約であり、JavaScriptや対話操作を必要としません。図の順序、共通phase ID、node／edge表現、比較プロファイルは[静的解析図と全体ロジック比較の標準](STATIC-DIAGRAM-AND-LOGIC-COMPARISON-STANDARD.md)に従います。

既存caseは次のコマンドで公開済みの`static-logic.json`と`static-layers.json`から再描画できます。`--write`を省略すると差分検査だけを行います。

```powershell
python .\analysis-framework\common\refresh_overall_logic_diagrams.py `
  --repository . `
  --collection .\analysis-results\collections\<collection-id> `
  --write
```
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
Ghidra MCPのHTTP接続先は、DNS解決を行わないnumeric loopback literal（`127.0.0.0/8`または
`::1`）に限定し、`localhost`などのhost名、資格情報、query、fragmentを受理しません。専用openerは
環境変数のHTTP／HTTPS proxyを使用せず、外部host向けだけでなく別portを含むloopback向けも、すべての
HTTP redirectをdestination request生成前に拒否します。したがって、redirect先へ認証headerやMCP
request bodyを転送しません。応答は64 MiBを上限として1 byteだけ超過確認し、上限を超えた場合は
JSON decode前にfail-closedで終了します。既存のrequest timeoutと公開APIは維持します。

## 一括解析

`collection`は`repository`内部の通常directory、`sample-root`と`private-output`は
リポジトリ外のアクセス制限された領域を指定します。後者2つを含む各rootは同一pathや
親子pathにせず、repositoryとcollection以外の相互包含を双方向で避けます。
collectionとacquisitionの`manifest.json`は上限付きのstrict JSON snapshotとして読み、
reparse point、hardlink、読取中のidentity／size／時刻変更を拒否します。acquisitionの
`zip_path`は絶対path／sample-root相対pathのどちらでも`sample-root`配下に限定し、
親directory参照、root外解決、重複pathを受理しません。ZIPは単一handleから固定したbytesと
任意の`zip_sha256`／`zip_size`を照合し、そのmemory snapshotだけをarchive readerへ渡します。
使用後に元ZIPと両manifestのbindingを再確認するため、差替えを検出したrunは公開しません。
Ghidra MCPへ渡すPE pathは、検証済みlayer bytesから`private-output/import-staging/`へ
O_EXCLで一度だけ作成した専用fileに限定します。既存stagingは単一link、hash、sizeが完全一致する
場合だけ再利用し、不一致fileを削除または上書きしません。MCP import直前と直後にidentity、hash、
sizeを再確認します。private raw index、program result、逆コンパイル／CIL JSONLも上限付きの
strict single-handle snapshotとして読み、atomic update時に既存identityを再照合します。
reparse point、hardlink、過大、破損JSON、競合差替えを検出したrunはfail-closedにします。
逆コンパイル／CIL JSONLには、専用の総量64 MiB、100,000 record、1行8 MiB、JSON深度64の
上限を適用します。single handleから1行ずつstrict parseし、duplicate key、NaN／Infinity、
過大な行・件数・深度を拒否します。parse後のSHA-256再確認も固定chunkで行うため、JSONL全bytesを
再保持しません。追記・全置換は同じdirectoryの一時fileへ既存bytesと新recordをstreaming出力し、
各write前に累積sizeを確認します。既存identity／hashをcommit直前に再照合してからatomic replace
するため、上限超過、破損、または競合を検出した場合も既存fileを変更しません。


```powershell
python .\analysis-framework\common\ghidra_function_batch.py `
  --repository . `
  --collection .\analysis-results\collections\<collection-id> `
  --sample-root C:\path\to\isolated-samples `
  --private-output C:\path\to\private-static-results `
  --minimum-free-bytes 8589934592 `
  --disk-guard-path C:\path\to\ghidra-projects
```

pending checkpointがある途中再開では、同じcommandを再実行すると準備済みinputを
自動利用します。checkpointがない既存cacheを明示的に再利用する場合だけ
`--reuse-prepared-inputs`を追加します。cacheはcollection IDとcase集合が一致し、
固定field集合、件数、停止段階、安全値に加え、`prepared_inventory_sha256`で
`input-relationships.json`の正確なbytesへ束縛できる場合だけ利用します。inventoryと
PE cacheは上限付き単一handle snapshotで読み、reparse point、hardlink、identity、size、
時刻、SHA-256の不一致を拒否します。全programの
処理後に、ページング対象の終端取得、opcode hash inventory、call graph補完、
代表関数選定、private成果物検証、公開成果物生成、collection検証を実行します。

空き容量は既定8 GiBをreserveし、repository、入力copy先の`sample-root`、
private出力、追加指定したGhidra保存先を入力準備前、各input copyの直前と直後、
各programの開始前後、後処理前に監視します。copy予定byte数を含めて判定するため、
現在の空き容量が下限以上でもcopy後にreserveを割るwriteは開始しません。
同一filesystemのroleは1件へ集約し、reserveは加算しません。
別filesystemは個別に下限を満たす必要があります。不足時は完了済み成果物を保持したまま
`ghidra_chunk_pending`で停止し、`run-progress.json`の`pending_programs`、
`postprocessing_pending`、`resume_mode`から再開段階を機械判定します。
入力準備途中ではatomic copy済みfileを保持し、inventory完成後だけ準備済みとして記録します。
後処理中にもcheckpointを先に保存するため、中断後はprogram解析を再実行せず
postprocessing-onlyで再開できます。不足状態のまま下限を無効化して処理を継続しません。
容量下限は256 MiBです。容量確認とatomic checkpointではsymlink／junction／
reparse pointおよびdirectory identityの途中変更を拒否し、進捗へ実local pathを残しません。
CLIは全工程完了時だけ終了code `0`を返し、再実行可能な`ghidra_chunk_pending`では`20`を
返します。自動実行側は`20`を完了として扱わず、容量回復または次chunkへ継続します。

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
JSON索引のschema version 2では、`function_records`に各関数を一度だけ収録し、完全一致group、SimHash group、類似pairは`record_id`を参照します。これにより候補数が増えても関数詳細をpairごとに複製しません。

完全一致groupとSimHash完全一致groupは全memberを保持します。近似pairは類似度、ファミリー横断、共有API数の順に優先し、最終順位付け前と公開後の両方で1関数あたり最大32件、JSON全体で最大100,000件へ制限します。全候補を同時に保持せず、endpoint別の有界heapを使います。`similarity_pairs_total`、`similarity_pairs_retained_for_ranking`、`similarity_pairs_omitted_before_ranking`、`similarity_pairs_omitted`に各段階の総数と省略数を残すため、候補母数の変化を追跡できます。大規模な既存JSONとの`--check`は逐次比較し、`--write`は同一directoryの一時fileから原子的に置換します。Markdown版は保持した候補から類似度の高い最大1,000 pairを表示します。
