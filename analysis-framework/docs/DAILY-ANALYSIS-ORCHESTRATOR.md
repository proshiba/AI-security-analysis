# 日次解析オーケストレータ

analysis-framework/common/daily_analysis_orchestrator.py は、最新の完全な日次sourceの検出、取得前容量確認、日次news取込、MalwareBazaar最新Windows検体の取得と標準静的解析、正規collection公開、Ghidra追加解析、全履歴C2監視、完了検証、非公開dataのS3保管を1つの再開可能なcheckpointへ統合します。

各解析器を置き換えるCLIではありません。既存の安全契約を固定順で呼び出し、途中停止を complete、partial、failed へ分離します。検体、復元payload、Ghidra projectは実行せず、repositoryへ保存しません。

## 自動化する段階

| 順序 | stage | 正本実装 | 主な自動化 |
|---:|---|---|---|
| 1 | news_intake | daily_news_malware_intake.py | IOC正規化、provider cache、取得、非実行静的解析、公開要約 |
| 2 | malwarebazaar_acquisition | malwarebazaar_batch.py | 最新Windows集合の初回固定、暗号化ZIP取得、再利用検証、family hint |
| 3 | static_analysis | analysis_job_runner.py | 分離job root、入力snapshot、決定的job ID、終端payloadとC2契約 |
| 4 | publication | publish_one_shot_collection.py | 解析契約SHA-256を固定したpartial staging、case/catalog更新 |
| 5 | ghidra | ghidra_function_batch.py | 明示的program selector、program単位checkpoint、容量reserve、再開、公開集計再投影 |
| 6 | c2_monitoring | build_all_c2_monitoring_targets.py／run_c2_monitoring_pipeline.py | 全履歴target生成、MaxMind鮮度確認、許可済みNmap NSE限定観測 |
| 7 | validation | validate_daily_analysis.py | 3 lane、C2解析、深掘り繰越、文字品質の完了判定 |
| 8 | private_archive | archive_analysis_datastore.py | 対象別WinZip AES-256、S3 size／SSE／SHA-256検証、source保持 |

stageは常に直列です。公開case、catalog、IOC索引、UIを複数processから同時更新しません。再試行不能なpartialは未解決理由を保持したまま後続へ進めます。一方、再試行可能なpartialは成果物が更新される途中なので、依存するstageを待機させ、待機中はattemptsを消費しません。取得待ちは静的解析・公開・Ghidraを、公開前段とGhidraの処理待ちはC2候補生成・validationを停止します。private_archiveはこの依存待ちから除外し、Ghidra容量停止後も完了済みsourceとjobをS3へ保管できます。

static_analysisの初回復元は6層に限定し、layer_count_limitへ達した検体だけrunner固定hard limitの256層で再試行します。再試行queueはcontainer、PE／ELF／Mach-O／script、設定・payload、opaque data、汎用data、画像・音声・fontの順に解析します。同一tierでは深い復元層を先にし、同じ深さでは発見順を維持するため、末尾で見つかったcontainer内の実行可能fileも浅いterminal siblingより先に確認できます。保留中の同一digestをより高いtierで再発見した場合は、初回の安定順序を保ったまま親とtransformを最良候補へ更新します。最終再試行では保留resourceも含めて検査し、深さ、単体size、合計size、圧縮率、archive member数の上限は緩和しません。

## 実行request

requestは[日次request例](examples/daily-analysis-request.json)の固定fieldだけを受理します。絶対path、任意command、Python module、環境変数、URL、credential、Nmap引数、Ghidra scriptは指定できません。

- tech_memoは --intelligence-root からのPOSIX相対pathです。
- analysis_dateは実行日とMalwareBazaar collectionの日付です。
- news_source_dateはtech-memoの対象公開日です。
- source_manifest_sha256は指定日のnews／IOC CSV／IOC logのpath、size、SHA-256から生成したcommitmentです。schema v2で必須です。
- stagesは8段階を個別に有効化します。
- static_analysisはmalwarebazaar_acquisition、publicationはstatic_analysis、ghidraはpublicationを前提とし、依存stageを無効化したrequestは開始前に拒否します。news_intakeとprivate_archiveだけの保管runは許可します。
- networkはprovider照合、検体取得、C2監視、S3保管を別々に許可します。
- limits.ghidra_max_new_programsを小さくすると、1回のGhidra処理量を固定して同じrequestで反復できます。
- 各Ghidra chunk後は、公開caseの契約を再検証して`manifest.json`と`publication-summary.json`を原子的に再投影してから、未完了静的解析のfollow-up計画を更新します。集計同期に失敗した場合はstaleな計画を生成せず停止します。

schemaは副作用なしで取得できます。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py schema
~~~

### 信頼済み静的toolのoperator固定

CABやinstallerの静的展開にUPXまたは7zzを使う場合、`plan`、`preflight`、`run`、`resume`、`drive`、`verify`へ`--trusted-tools-manifest`と`--trusted-tools-manifest-sha256`を必ず同時指定します。SHA-256はmanifestの正規化後JSONではなくraw bytesに対する小文字64桁です。この設定はoperator CLIだけが保持し、production request schemaへ追加できません。

~~~powershell
$manifest = 'C:\ProgramData\MalwareAnalysisTools\trusted-static-tools.json'
$manifestSha256 = (Get-FileHash -LiteralPath $manifest -Algorithm SHA256).Hash.ToLowerInvariant()
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py preflight --request C:\analysis-lab\daily-request.json --repository C:\analysis-lab\repository --intelligence-root C:\analysis-lab\intelligence --private-root C:\analysis-lab\private --work-root C:\analysis-lab\work --ghidra-project-store C:\analysis-lab\ghidra-projects --trusted-tools-manifest $manifest --trusted-tools-manifest-sha256 $manifestSha256
~~~

片方だけの指定、raw SHA-256不一致、platform不一致、空profile、manifestまたはbinaryの非通常file・複数hardlink・reparse point、size／binary SHA-256不一致はnetwork接触前に拒否します。PATHや既知install先からtoolを自動探索しません。preflightはoperator manifestとtool source identityをread-onlyで検証し、実行時には標準job runnerがjob-private snapshotを作成します。validate、run、完了result、resume／drive／verifyの再照合には同じoperator pinを渡し、異なるpinは別job IDになります。state、plan、preflight、公開stage結果にはmanifestまたはbinaryの絶対pathを保存しません。

### 標準requestの自動生成

draft-requestはtech-memoをnetwork接触なしで有界探索し、空でない通常fileのnews本文、IOC CSV、IOC検証logが1件ずつそろった最新日だけをnews_source_dateへ採用します。日付ごとに重複があれば推測せず停止します。analysis_dateを省略した場合はlocal日付、run_idを省略した場合はdaily-YYYYMMDDを使用します。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py draft-request --intelligence-root C:\analysis-lab\intelligence --tech-memo tech-memo --analysis-date 2026-08-30
~~~

出力はstrict request JSONです。自動生成値でも、実行前にnetwork gateとstageを確認します。credential、絶対出力path、任意commandはrequestへ入りません。

## root分離

pathはrequestではなくoperator CLIで固定します。

    解析repository                 C:\analysis-lab\repository
    intelligence root              C:\analysis-lab\intelligence
      └─ tech-memo                 C:\analysis-lab\intelligence\tech-memo
    private root                   C:\analysis-lab\private
      ├─ 日次ニュース成果物: daily-runs\<run-id>\daily-news-malware\<source-date>\
      ├─ 日次ニュース静的解析ジョブ: daily-runs\<run-id>\daily-news-malware\static-analysis-jobs\
      ├─ MalwareBazaar取得元: daily-runs\<run-id>\malwarebazaar-windows-YYYYMMDD-NNNN\source\
      ├─ Ghidra静的解析結果: daily-runs\<run-id>\malwarebazaar-windows-YYYYMMDD-NNNN\ghidra-static-results\
      └─ maxmind\
    work root                      C:\analysis-lab\work
      ├─ jobs\
      ├─ Ghidra復元input cache: gi\<run-id>\
      ├─ completed-job-verification\
      └─ daily-orchestrations\<run-id>\
    Ghidra project store           C:\analysis-lab\ghidra-projects

解析repository、private root、work root、Ghidra project storeは同一path、親子path、逆向きの包含を禁止します。tech-memoの実体もprivate／work／Ghidra project rootと分離します。既存path componentにsymlink、junction、reparse pointがあれば開始しません。MalwareBazaarの`source`は暗号化archiveと取得manifestだけを保持する不変rootです。Ghidra用の復元済みinputはwork rootの短い`gi\<run-id>`へ分離し、SHA-256検証済みcacheとして再開時にだけ再利用します。復元cacheを`source`の配下へ置く構成は開始前に拒否します。

## 実行計画

planはrootとtech-memoの境界に加え、現在の全filesystem容量とC2二重許可の状態を表示しますが、directory、state、公開成果物を作成しません。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py plan --request C:\analysis-lab\daily-request.json --repository C:\analysis-lab\repository --intelligence-root C:\analysis-lab\intelligence --private-root C:\analysis-lab\private --work-root C:\analysis-lab\work --ghidra-project-store C:\analysis-lab\ghidra-projects
~~~

planで次を確認します。

1. execution.modeが sequential_checkpointed である。
2. automatic_source_deletion、sample_execution、arbitrary_command_executionがfalseである。
3. preflight_before_networkとbounded_drive_supportedがtrueである。
4. 必要なstageだけ network_enabled=trueである。
5. repository書込みstageが想定どおりである。
6. preflight.readyとfilesystem別shortfallが想定どおりである。

## 事前検証（preflight）

preflightはrequest、source、root、C2許可状態、必要credentialの有無、AWS CLI、operator指定のtrusted static tools、全出力先の空き容量をread-onlyで検証します。指定日のnews／IOC三点は各64 MiB以下の単一link通常fileに限定し、単一handleでsize、identity、時刻、SHA-256のsource commitmentへ固定します。欠落、空file、重複、hardlink、reparse point、読取中の差替えをnetwork接触前に拒否します。private root、work root、repository、Ghidra project store、OSのarchive stagingが同一filesystemなら必要量を合算し、別filesystemなら個別に判定します。archive stagingには512 MiBの固定reserveと、逐次作成する対象別archiveのうち最大となる既存tree実測／将来増分を加えます。全archiveのsizeを同時に要求しません。reportへcredential値、絶対path、device IDは出さず、準備可否、filesystem-N、用途、pathを除いたtool identityだけを保存します。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py preflight --request C:\analysis-lab\daily-request.json --repository C:\analysis-lab\repository --intelligence-root C:\analysis-lab\intelligence --private-root C:\analysis-lab\private --work-root C:\analysis-lab\work --ghidra-project-store C:\analysis-lab\ghidra-projects --allow-live-c2
~~~

不足時は終了code 20、十分なら0です。runとdriveも同じpreflightを最初に必ず実行します。容量不足ではprovider照合、sample download、C2監視、S3 uploadを開始せず、全stageのattempts=0の再開可能checkpointだけを作成します。

## 実行・再開・継続（run、resume、drive）

C2ライブ監視はrequestの network.c2_monitoring=true だけでは開始しません。当該実行でも --allow-live-c2 を指定する二重許可です。省略時はC2候補inventoryとtargetをofflineで生成し、外部C2へ接続せず、stageを再開可能なpartialとして保持します。preflightの authorization.live_c2_deferred_for_invocation=true はこの安全な保留状態を表し、後続の静的validationとS3保管を停止させません。`targets_built_live_monitoring_deferred`、非通信・非実行、妥当なtarget件数、エラーなしの固定契約へ一致する許可待ちは、同じ許可なしresumeで再試行せずattemptsを消費しません。契約外のpartialには通常の再試行上限を適用します。明示許可を付けた同じrequestのresumeではライブ監視と、その更新を受けたvalidationを再実行できます。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py run --request C:\analysis-lab\daily-request.json --repository C:\analysis-lab\repository --intelligence-root C:\analysis-lab\intelligence --private-root C:\analysis-lab\private --work-root C:\analysis-lab\work --ghidra-project-store C:\analysis-lab\ghidra-projects --allow-live-c2
~~~

中断、Ghidra chunk上限、容量不足、一時的なS3失敗は、同じrequestとrootで resume します。成功済みstageと再試行不能なpartialは通常再実行しません。ただし上流を再試行するときは、その更新に依存するC2候補生成とvalidationの古い結果をpendingへ戻して再計算します。これにより、後からC2観測等が進んだのに以前の未完了判定だけが残る状態を防ぎます。再計算時も既存attemptsを保持し、上限を緩めません。

driveは新規runまたは既存stateのresumeを自動選択し、Ghidra chunkと再試行可能stageを最大cycle数の範囲で反復します。complete、容量不足、再試行不能partial、最大cycleのいずれかで停止します。容量不足を待機loopで再試行しません。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py drive --request C:\analysis-lab\daily-request.json --repository C:\analysis-lab\repository --intelligence-root C:\analysis-lab\intelligence --private-root C:\analysis-lab\private --work-root C:\analysis-lab\work --ghidra-project-store C:\analysis-lab\ghidra-projects --allow-live-c2 --max-cycles 64
~~~

max-cyclesは1～1,024です。各stage自体の既存上限も維持され、通常stageは5回、Ghidra、追随validation、Ghidra完了待ちのprivate archiveは1,024回を超えません。同じstatus、result、errorへ戻り、意味的進捗がない場合はattempt数やtimestampが変化しても停止します。隣接する同一状態だけでなく、A→B→Aのような循環も検知します。

control planeまたは固定adapterのsource SHA-256が変わった場合、通常のresume／driveは古い成功状態を新実装へ流用せず停止します。解析中断後の修正を同じrunへ限定して引き継ぐ必要がある場合だけ、次の監査付き移行を先に実行します。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py migrate-run-implementation --request C:\analysis-lab\daily-request.json --repository C:\analysis-lab\repository --intelligence-root C:\analysis-lab\intelligence --private-root C:\analysis-lab\private --work-root C:\analysis-lab\work --ghidra-project-store C:\analysis-lab\ghidra-projects --expected-old-implementation-sha256 <旧stateに記録された64桁SHA-256>
~~~

この操作は中断checkpointだけを対象とし、完了済みrunは移行しません。保存request、run ID、collection ID、source commitment、安全値、collection bindingの全fieldが一致し、相違点がoperator指定の旧implementation SHA-256だけである場合に限ってstateとbindingを現在の実装へ更新します。旧実装がライブC2許可待ちを5回の失敗として記録していても、resultが`targets_built_live_monitoring_deferred`、`network_contacted=false`、`sample_executed=false`の固定契約へ完全一致する場合だけ、attemptsを0へ戻した再試行可能partialへ正規化します。この正規化もreceiptへ明記します。更新前・更新後のSHA-256を含むauthorization／completion receiptはprivate collectionの`im` directoryへ保存します。途中停止時は同じ旧pinで再実行でき、片側だけが更新済みでも事前receiptが完全一致する場合に限って完了させます。検体実行、network接触、source削除、公開成果物の変更は行いません。移行後は同じ引数でresumeまたはdriveを実行します。一般的な別解析への転用やrequest変更には新しいrun_idを使用します。

news laneの公開成果物はrun固有のwork stagingへ8種類すべてを書き、consumer終了後にsource commitmentを再検証してから、固定file集合だけをrepositoryへfile単位でatomic昇格します。埋込みCLIのSystemExitもstage failureへ変換するため、stateをrunningのまま残しません。固定Python subprocessのstdout／stderrはpipeで有界captureし、大量logを直接diskへ流しません。実装更新後のGhidra再開とcase別保管は、現在の実装cache keyから別job IDを再計算せず、stateへ記録済みで完全再検証できるone-shot job IDだけを使用します。

news laneが`partial`の場合、8成果物は公開先へ昇格しません。ただし、同じrunのstagingにある`ioc-summary.json`は、source commitment、日付、path、通常file境界を再検証したうえで、当日のC2 handoff入力に限って使用できます。C2 target builderはこの入力を正規の論理source pathへ固定し、stagingの絶対pathを公開成果物へ記録しません。

運用承認がレビュー済み完全一致profileだけに限定される場合、`run_c2_monitoring_pipeline.py --reviewed-profiles-only`を使用します。このモードは`protocol_profile_id`を持たないtargetをnetwork接触前に除外し、未観測の当日targetに対するhandoff bindingも結果へ継承しません。したがって、限定観測結果を全targetの観測完了として扱うことはできません。

公開C2成果物に旧run由来のlocal絶対pathが残った場合は、同じoutput directoryへ`--normalize-existing-output`を指定して修復します。このモードは固定JSONだけを読み、source fieldを`analysis-results/...`へ正規化・重複排除してREADMEを再描画します。`--allow-network`との同時指定は拒否するため、C2を再観測しません。

## statusとverify

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py status --work-root C:\analysis-lab\work --run-id daily-20260829

py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py verify --request C:\analysis-lab\daily-request.json --repository C:\analysis-lab\repository --intelligence-root C:\analysis-lab\intelligence --private-root C:\analysis-lab\private --work-root C:\analysis-lab\work --ghidra-project-store C:\analysis-lab\ghidra-projects --allow-live-c2
~~~

終了codeは0=complete／ready、20=partial／preflight不足、1=failed、2=契約違反です。partialは検体自体の完了を意味しません。

## 容量停止

network接触前のpreflightは、保留stageだけを対象に次の安全側概算をfilesystem単位で合算します。

- newsとMalwareBazaarの暗号化archive: 1検体・laneあたり40 MiB
- 暗号化ZIP取得: 1件256 MiBの絶対上限、lane合計は件数×40 MiB、取得後保持reserveは256 MiB。2026-09-03の実測では35件で約1.26 GiBとなったため、単体上限と後段の2 GiB総入力上限を維持したままbatch budgetを拡張した
- 標準静的解析とGhidra private成果物: 1検体・出力あたり8 MiB
- repository、MaxMind、archive stagingの固定reserveと、S3対象treeの実測／将来増分
- Ghidra project storeのrequest指定reserve。標準requestでは8 GiB

取得済みstageはresume時の概算から外すため、途中完了後は必要量が自動的に減ります。この概算を通過しても、実sizeが大きい場合は各解析器とarchive段階の実測guardが再度停止します。

Ghidraは既定8 GiBのreserveを各program前後でも確認します。下限未満ならrun-progress.jsonと日次stateへ次を保存して停止します。容量回復必要量は現在の空き容量だけでなく、停止判定に使った予定write byte数も含めて算出します。

- 完了program数とpending program数
- 準備済みinput inventoryのSHA-256
- 後処理待ちかどうか
- pathを含まないfilesystem別空き容量
- 回復に必要な最小byte数
- automatic_source_deletion=false

各Ghidra chunkの後には、公開collectionから`STATIC-FOLLOWUP-PLAN.json`／`STATIC-FOLLOWUP-PLAN.md`を自動再生成します。終端payload、family、config、C2 endpoint、protocol、代表関数、再公開の未完了状態を閉じたblocker policyへ変換し、次の最小静的actionを残します。chunk途中は全archiveの反復hash化を避け、Ghidra完了chunkで検証済み取得archiveのsizeと取得時SHA-256を1回だけ照合します。archiveの展開・実行・CPU emulation・外部接続は行いません。詳細は[未完了静的解析follow-upの自動化](STATIC-FOLLOWUP-AUTOMATION.md)を参照してください。

1回のrun／resumeでは各stageを1回だけ実行します。driveだけがcheckpoint境界で有界反復し、同じ容量停止は内部loopで再試行しません。容量整理候補がS3検証済みでも、このCLIは削除しません。削除が必要な場合はS3 report、対象path、source種別を確認し、ユーザーの明示指示を別途得ます。

## Ghidraのタイムアウト回復

Ghidraのauto-analysis待機またはMCP通信がtimeoutになったprogramは未完了のまま保持し、残るprogramを続けて解析します。直後にinventory SHA-256へ束縛したpending checkpointを保存し、停止理由は`program_timeout`、終了codeは`20`とします。タイムアウトしたprogramも`ghidra_max_new_programs`の試行数へ算入します。次回は前回未試行のprogramを先に処理するため、同じ難解析検体だけで各chunkを使い切りません。

日次stageは検証済みpending一覧の順序を`pending_program_order_sha256`、準備済み入力のbindingを`prepared_inventory_sha256`へ保持します。pending件数だけでは見えない順序の前進をdriveへ伝え、後方の未試行programへ到達できるようにします。一方、`program_timeout`では、この2つのSHA-256と完了program数が再び同じ組へ戻ったら、そのdrive呼出しをpartialで停止します。空き容量や保管metadataが変わっても、一巡しただけのqueueを新しい解析進捗とは扱いません。再試行可能flagと既存上限は維持します。

private出力の`program-timeouts.raw.jsonl`には検体SHA-256、inventory SHA-256、UTC時刻、設定上限、固定理由を残します。例外本文やlocal pathは記録しません。auto-analysisの状態確認は通信timeoutとsleepを残り待機時間へ制限しますが、これはHTTP応答全体の厳密な実時間遮断を保証するものではありません。timeout以外の不正MCP応答や整合性違反は従来どおり停止します。保留したprogramを解析完了へ昇格したり、auto-analysisを無断で省略したりしません。

## S3保管

private_archiveは次を別々の解析対象として保管します。

1. news laneのprovider cache、暗号化ZIP、非実行静的解析data
2. MalwareBazaar暗号化ZIPと取得manifest
3. 標準one-shot job
4. Ghidraの進行中checkpointまたは完了済みprivate成果物

全保管対象はsource tree commitmentの先頭16桁を含む世代別targetとして保管します。Ghidraの次chunk、newsの追加取得、jobの進行でtreeが変化した場合は新しいtargetとなるため、前世代の検証済みcheckpointを失いません。targetが128文字を超える場合はtarget全体のSHA-256を保持した決定的短縮名を使います。各target名にはrun IDを含め、同じ日付・件数の別runを混在させません。

各source treeは全fileの相対path、size、SHA-256へ固定します。upload後はS3側のsize、SSE AES256、archive SHA-256、manifest SHA-256、targetを検証し、local report SHA-256とsource tree commitmentを結び付けます。再開時にsourceが変化していれば既存reportを再利用しません。

50検体のcase別保管では、取得manifest、one-shot case集合、Ghidra relationship、完了状態、全program検証manifestをcollection単位で1回検証し、その時点の全入力fileをSHA-256・size・file identityへ固定します。その後もcaseごとにfile集合の追加・削除を確認し、物理copy時に各fileのcommitmentを再照合します。全体検証をcase数だけ繰り返さず、case分離、秘密値scan、差替え拒否、1件ずつの容量判定、remote検証後cleanupは維持します。Windowsではcollection IDと64桁SHA-256を含む深いtreeが通常path上限へ近づかないよう、work root直下のrun専用短縮stagingを使います。

archive stagingの空き容量は、逐次処理する対象の最大圧縮前sizeと512 MiB reserveで事前確認します。不足時はZIP作成を開始しません。解析stageがfailedでもdatastore uploadが明示許可されていれば、後続解析を開始せずprivate_archiveだけへ進み、その時点で存在する対象をcheckpointとして検証保管します。成功後もsource本体は自動削除しません。Ghidra MCP project本体はtarget単位のexport APIがない状態で共有project store全体を混在archiveせず、現時点ではtarget単位に分離済みのGhidra private成果物を保管対象とします。

## 自動化しない判断

- 未復元payload、family、config、C2 protocolを推測で補完しない。
- live C2で任意command、task結果、payload要求を送らない。
- Ghidra任意scriptを有効化しない。
- S3保管済みsourceを自動削除しない。
- Git commit、push、PR作成を解析stageへ混在させない。

Git公開は全validator、文書監査、差分確認後の別工程です。
