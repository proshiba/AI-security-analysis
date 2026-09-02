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
| 5 | ghidra | ghidra_function_batch.py | 明示的program selector、program単位checkpoint、容量reserve、再開 |
| 6 | c2_monitoring | build_all_c2_monitoring_targets.py／run_c2_monitoring_pipeline.py | 全履歴target生成、MaxMind鮮度確認、許可済みNmap NSE限定観測 |
| 7 | validation | validate_daily_analysis.py | 3 lane、C2解析、深掘り繰越、文字品質の完了判定 |
| 8 | private_archive | archive_analysis_datastore.py | 対象別WinZip AES-256、S3 size／SSE／SHA-256検証、source保持 |

stageは常に直列です。公開case、catalog、IOC索引、UIを複数processから同時更新しません。1件のpartialでは後続を止めず、Ghidra容量停止後も完了済みsourceとjobをS3へ保管できます。

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

schemaは副作用なしで取得できます。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py schema
~~~

### 標準requestの自動生成

draft-requestはtech-memoをnetwork接触なしで有界探索し、空でない通常fileのnews本文、IOC CSV、IOC検証logが1件ずつそろった最新日だけをnews_source_dateへ採用します。日付ごとに重複があれば推測せず停止します。analysis_dateを省略した場合はlocal日付、run_idを省略した場合はdaily-YYYYMMDDを使用します。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py draft-request --intelligence-root C:\Users\Administrator --tech-memo tech-memo --analysis-date 2026-08-30
~~~

出力はstrict request JSONです。自動生成値でも、実行前にnetwork gateとstageを確認します。credential、絶対出力path、任意commandはrequestへ入りません。

## root分離

pathはrequestではなくoperator CLIで固定します。

    解析repository                 C:\Users\Administrator\w\a26
    intelligence root              C:\Users\Administrator
      └─ tech-memo                 C:\Users\Administrator\tech-memo
    private root                   C:\Users\Administrator\DailyAnalysisPrivate
      ├─ 日次ニュース成果物: daily-runs\<run-id>\daily-news-malware\<source-date>\
      ├─ 日次ニュース静的解析ジョブ: daily-runs\<run-id>\daily-news-malware\static-analysis-jobs\
      ├─ MalwareBazaar取得元: daily-runs\<run-id>\malwarebazaar-windows-YYYYMMDD-NNNN\source\
      ├─ Ghidra静的解析結果: daily-runs\<run-id>\malwarebazaar-windows-YYYYMMDD-NNNN\ghidra-static-results\
      └─ maxmind\
    work root                      C:\Users\Administrator\DailyAnalysisWork
      ├─ jobs\
      ├─ Ghidra復元input cache: gi\<run-id>\
      ├─ completed-job-verification\
      └─ daily-orchestrations\<run-id>\
    Ghidra project store           C:\Users\Administrator\DailyGhidraProjects

解析repository、private root、work root、Ghidra project storeは同一path、親子path、逆向きの包含を禁止します。tech-memoの実体もprivate／work／Ghidra project rootと分離します。既存path componentにsymlink、junction、reparse pointがあれば開始しません。MalwareBazaarの`source`は暗号化archiveと取得manifestだけを保持する不変rootです。Ghidra用の復元済みinputはwork rootの短い`gi\<run-id>`へ分離し、SHA-256検証済みcacheとして再開時にだけ再利用します。復元cacheを`source`の配下へ置く構成は開始前に拒否します。

## 実行計画

planはrootとtech-memoの境界に加え、現在の全filesystem容量とC2二重許可を検証しますが、directory、state、公開成果物を作成しません。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py plan --request C:\Users\Administrator\daily-request.json --repository C:\Users\Administrator\w\a26 --intelligence-root C:\Users\Administrator --private-root C:\Users\Administrator\DailyAnalysisPrivate --work-root C:\Users\Administrator\DailyAnalysisWork --ghidra-project-store C:\Users\Administrator\DailyGhidraProjects
~~~

planで次を確認します。

1. execution.modeが sequential_checkpointed である。
2. automatic_source_deletion、sample_execution、arbitrary_command_executionがfalseである。
3. preflight_before_networkとbounded_drive_supportedがtrueである。
4. 必要なstageだけ network_enabled=trueである。
5. repository書込みstageが想定どおりである。
6. preflight.readyとfilesystem別shortfallが想定どおりである。

## 事前検証（preflight）

preflightはrequest、source、root、C2許可、必要credentialの有無、AWS CLI、全出力先の空き容量をread-onlyで検証します。指定日のnews／IOC三点は各64 MiB以下の単一link通常fileに限定し、単一handleでsize、identity、時刻、SHA-256のsource commitmentへ固定します。欠落、空file、重複、hardlink、reparse point、読取中の差替えをnetwork接触前に拒否します。private root、work root、repository、Ghidra project store、OSのarchive stagingが同一filesystemなら必要量を合算し、別filesystemなら個別に判定します。archive stagingには512 MiBの固定reserveと、逐次作成する対象別archiveのうち最大となる既存tree実測／将来増分を加えます。全archiveのsizeを同時に要求しません。reportへcredential値、絶対path、device IDは出さず、準備可否、filesystem-N、用途だけを保存します。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py preflight --request C:\Users\Administrator\daily-request.json --repository C:\Users\Administrator\w\a26 --intelligence-root C:\Users\Administrator --private-root C:\Users\Administrator\DailyAnalysisPrivate --work-root C:\Users\Administrator\DailyAnalysisWork --ghidra-project-store C:\Users\Administrator\DailyGhidraProjects --allow-live-c2
~~~

不足時は終了code 20、十分なら0です。runとdriveも同じpreflightを最初に必ず実行します。容量不足ではprovider照合、sample download、C2監視、S3 uploadを開始せず、全stageのattempts=0の再開可能checkpointだけを作成します。

## 実行・再開・継続（run、resume、drive）

C2ライブ監視はrequestの network.c2_monitoring=true だけでは開始しません。当該実行でも --allow-live-c2 を指定する二重許可です。省略時はnetwork接触前に終了code 2で停止します。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py run --request C:\Users\Administrator\daily-request.json --repository C:\Users\Administrator\w\a26 --intelligence-root C:\Users\Administrator --private-root C:\Users\Administrator\DailyAnalysisPrivate --work-root C:\Users\Administrator\DailyAnalysisWork --ghidra-project-store C:\Users\Administrator\DailyGhidraProjects --allow-live-c2
~~~

中断、Ghidra chunk上限、容量不足、一時的なS3失敗は、同じrequestとrootで resume します。成功済みstageと再試行不能なpartialは再実行しません。再試行可能なGhidra、validation、S3保管だけを再開します。

driveは新規runまたは既存stateのresumeを自動選択し、Ghidra chunkと再試行可能stageを最大cycle数の範囲で反復します。complete、容量不足、再試行不能partial、最大cycleのいずれかで停止します。容量不足を待機loopで再試行しません。

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py drive --request C:\Users\Administrator\daily-request.json --repository C:\Users\Administrator\w\a26 --intelligence-root C:\Users\Administrator --private-root C:\Users\Administrator\DailyAnalysisPrivate --work-root C:\Users\Administrator\DailyAnalysisWork --ghidra-project-store C:\Users\Administrator\DailyGhidraProjects --allow-live-c2 --max-cycles 64
~~~

max-cyclesは1～1,024です。各stage自体の既存上限も維持され、通常stageは5回、Ghidra、追随validation、Ghidra完了待ちのprivate archiveは1,024回を超えません。同じstatus、result、errorが連続し、意味的進捗がない場合はattempt数やtimestampが変化しても停止します。

control planeまたは固定adapterのsource SHA-256が変わった場合、古い成功状態を新実装へ流用せず、新しいrun_idを要求します。

news laneの公開成果物はrun固有のwork stagingへ8種類すべてを書き、consumer終了後にsource commitmentを再検証してから、固定file集合だけをrepositoryへfile単位でatomic昇格します。埋込みCLIのSystemExitもstage failureへ変換するため、stateをrunningのまま残しません。固定Python subprocessのstdout／stderrはpipeで有界captureし、大量logを直接diskへ流しません。

news laneが`partial`の場合、8成果物は公開先へ昇格しません。ただし、同じrunのstagingにある`ioc-summary.json`は、source commitment、日付、path、通常file境界を再検証したうえで、当日のC2 handoff入力に限って使用できます。C2 target builderはこの入力を正規の論理source pathへ固定し、stagingの絶対pathを公開成果物へ記録しません。

運用承認がレビュー済み完全一致profileだけに限定される場合、`run_c2_monitoring_pipeline.py --reviewed-profiles-only`を使用します。このモードは`protocol_profile_id`を持たないtargetをnetwork接触前に除外し、未観測の当日targetに対するhandoff bindingも結果へ継承しません。したがって、限定観測結果を全targetの観測完了として扱うことはできません。

公開C2成果物に旧run由来のlocal絶対pathが残った場合は、同じoutput directoryへ`--normalize-existing-output`を指定して修復します。このモードは固定JSONだけを読み、source fieldを`analysis-results/...`へ正規化・重複排除してREADMEを再描画します。`--allow-network`との同時指定は拒否するため、C2を再観測しません。

## statusとverify

~~~powershell
py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py status --work-root C:\Users\Administrator\DailyAnalysisWork --run-id daily-20260829

py -3.13 -B .\analysis-framework\common\daily_analysis_orchestrator.py verify --request C:\Users\Administrator\daily-request.json --repository C:\Users\Administrator\w\a26 --intelligence-root C:\Users\Administrator --private-root C:\Users\Administrator\DailyAnalysisPrivate --work-root C:\Users\Administrator\DailyAnalysisWork --ghidra-project-store C:\Users\Administrator\DailyGhidraProjects --allow-live-c2
~~~

終了codeは0=complete／ready、20=partial／preflight不足、1=failed、2=契約違反です。partialは検体自体の完了を意味しません。

## 容量停止

network接触前のpreflightは、保留stageだけを対象に次の安全側概算をfilesystem単位で合算します。

- newsとMalwareBazaarの暗号化archive: 1検体・laneあたり24 MiB
- 暗号化ZIP取得: 1件256 MiBの絶対上限、lane合計は件数×24 MiB、取得後保持reserveは256 MiB。大きい1件を許可してもlane合計quotaは拡張しない
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

1回のrun／resumeでは各stageを1回だけ実行します。driveだけがcheckpoint境界で有界反復し、同じ容量停止は内部loopで再試行しません。容量整理候補がS3検証済みでも、このCLIは削除しません。削除が必要な場合はS3 report、対象path、source種別を確認し、ユーザーの明示指示を別途得ます。

## S3保管

private_archiveは次を別々の解析対象として保管します。

1. news laneのprovider cache、暗号化ZIP、非実行静的解析data
2. MalwareBazaar暗号化ZIPと取得manifest
3. 標準one-shot job
4. Ghidraの進行中checkpointまたは完了済みprivate成果物

全保管対象はsource tree commitmentの先頭16桁を含む世代別targetとして保管します。Ghidraの次chunk、newsの追加取得、jobの進行でtreeが変化した場合は新しいtargetとなるため、前世代の検証済みcheckpointを失いません。targetが128文字を超える場合はtarget全体のSHA-256を保持した決定的短縮名を使います。各target名にはrun IDを含め、同じ日付・件数の別runを混在させません。

各source treeは全fileの相対path、size、SHA-256へ固定します。upload後はS3側のsize、SSE AES256、archive SHA-256、manifest SHA-256、targetを検証し、local report SHA-256とsource tree commitmentを結び付けます。再開時にsourceが変化していれば既存reportを再利用しません。

archive stagingの空き容量は、逐次処理する対象の最大圧縮前sizeと512 MiB reserveで事前確認します。不足時はZIP作成を開始しません。解析stageがfailedでもdatastore uploadが明示許可されていれば、後続解析を開始せずprivate_archiveだけへ進み、その時点で存在する対象をcheckpointとして検証保管します。成功後もsource本体は自動削除しません。Ghidra MCP project本体はtarget単位のexport APIがない状態で共有project store全体を混在archiveせず、現時点ではtarget単位に分離済みのGhidra private成果物を保管対象とします。

## 自動化しない判断

- 未復元payload、family、config、C2 protocolを推測で補完しない。
- live C2で任意command、task結果、payload要求を送らない。
- Ghidra任意scriptを有効化しない。
- S3保管済みsourceを自動削除しない。
- Git commit、push、PR作成を解析stageへ混在させない。

Git公開は全validator、文書監査、差分確認後の別工程です。
