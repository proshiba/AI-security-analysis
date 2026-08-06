# AI-security-analysis向けAIエージェント指示

このファイルはリポジトリ全体に適用される共通ルールです。より深い階層に `AGENTS.md` がある場合は、そのディレクトリ配下ではより深いファイルの指示も必ず読み、矛盾する場合はより深い指示を優先してください。

## 最初に確認するもの

- ルートの `README.md` を読み、リポジトリ構成、インストール方法、解析結果の読み方、解析履歴サマリの更新方針を確認すること。
- マルウェア別の解析コード、ドキュメント、設定、結果を扱う場合は、対象マルウェア配下の `AGENTS.md` と README/docs を先に確認すること。
  - ValleyRAT 関連の作業では `analysis-framework/malware/valleyrat/AGENTS.md` を必ず読むこと。
  - ValleyRAT のワークフローやパターン判断では `analysis-framework/malware/valleyrat/docs/VALLEYRAT-WORKFLOW.md` と `analysis-framework/malware/valleyrat/docs/PATTERN-DESIGN.md` も参照すること。
- 公開可能な解析結果を扱う場合は `analysis-results/README.md` と対象ファミリーの `analysis-results/malware/<family>/README.md` を確認すること。横断的な調査は `analysis-results/research/`、複数検体をまとめた成果物は `analysis-results/collections/` も確認すること。
- 定期インテリジェンス調査（campaign相関、コード類似、IOC差分、operation仮説）を扱う場合は、`intelligence/README.md`、`intelligence/RECURRING-TASKS.md`、`intelligence/ASSESSMENT-MODEL.md` を先に確認すること。運用ルールは本ファイルの「intelligence/ 継続調査と週次routineのルール」を参照すること。

## リポジトリ構成ルール

- 解析コードは `analysis-framework/` に置くこと。
- マルウェア種別固有のコード、設定、ドキュメント、テストは `analysis-framework/malware/<malware-type>/` に置くこと。
- 公開可能なマルウェア解析結果は `analysis-results/malware/<family>/versions/<version-key>/cases/<sample-sha256>/` に置くこと。ファミリー横断の調査は `analysis-results/research/<topic>/`、複数ファミリーや選定集合の成果物は `analysis-results/collections/<collection>/` に置くこと。
- 新しいマルウェア種を追加するときに、`AAA-analysis/` のような独立トップレベルディレクトリを作らないこと。
- 共通化できる処理は `analysis-framework/common/`、分類器は `analysis-framework/classifiers/`、種別登録は `analysis-framework/registry/` に置くこと。

## 文書の言語ルール

- 人が読む文書は、既定で日本語で新規作成・更新すること。対象には `README.md`、`AGENTS.md`、`docs/`、解析報告、OSINT文書、設計書、手順書、引継ぎ文書、Markdown表の見出しと説明、CLIの人間向けhelp、公開Python APIのdocstring、生成pydocを含む。
- 既存文書を変更する場合も、英語だけの見出しや説明文を新たに残さないこと。変更範囲に日本語と英語の説明が混在している場合は、意味と根拠を保持して日本語へ統一すること。
- マルウェア名、脅威アクター名、製品名、API名、関数名、class名、JSON／YAML key、schema enum、file path、command、hash、domain、URL、IOC、rule identifierなどの技術識別子は、正確性と機械可読性のため原表記を維持してよい。
- 公開情報の原題や短い引用を原文で残す場合は、日本語の題名または要約を併記し、原文だけで説明を完結させないこと。翻訳によって帰属や確度を強めないこと。
- 機械生成文書は、出力だけを手編集せず、generator、template、knowledge dataを日本語対応させること。再生成後も日本語へ収束することを確認すること。
- テキストはUTF-8で読み書きすること。Windows PowerShell 5.1の既定encodingへ依存する`Get-Content`／`Set-Content`／pipelineで日本語を再保存せず、使用時は`-Encoding UTF8`を明示すること。
- 文書を追加・変更した後は、可能な範囲で `localize_result_markdown.py` のdry-run、`audit_japanese_docs.py --fail-on-findings`、local link監査、`git diff --check`を実行すること。公開Python APIのdocstringを変更した場合はpydocも再生成すること。
- 公開前に`analysis-framework/common/validate_text_integrity.py --repository .`を実行し、UTF-8不正、U+FFFD、連続疑問符、典型的な日本語文字化けが0件であることを確認すること。外部providerが原文から疑問符を返した場合は、raw値と「原文復元不能」を分離して記録すること。

## 安全ルール

- 検体本体、抽出した実行可能ファイル、復号バイナリ、PCAP、Ghidra project、資格情報をコミットしないこと。
- 解析結果として保存してよいものは、README、JSON/CSV/YAMLなどのメタデータ、IOC、テキスト化した逆アセンブル、FLOSS等の文字列出力、Sigma/YARAなどの検知ルール候補に限定すること。
- 検体やpayloadを実行しないこと。ローカル実行、デバッガ実行、`rundll32` / `regsvr32` / PowerShell reflection 経由の起動も禁止すること。
- ライブC2確認、JARM収集、HTTP(S) probeなど外部ホストへの通信は、ユーザーが現在のタスクで明示的に許可した場合に限ること。
- ライブC2確認を行う場合も、対象マルウェアの reviewed profile や種別固有AGENTSの制限に従い、送信データ、受信サイズ、リダイレクト、stage取得を最小化すること。
- TCP open、HTTPページ、証明書、banner hash、JARM単独でC2確定としないこと。復号config、process帰属付き通信、malware protocol応答などの相関を要求すること。

## 解析・分類ルール

- 新しい検体では、family名や過去ケースから感染チェーン、復号方式、config形式、C2 protocolを推測で決め打ちしないこと。
- まず `analysis-framework/classifiers/classify_sample.py` と registry/detector の構造判断を確認し、観測された構造に基づいて handler を選ぶこと。
- unknown pattern は generic triage で止め、未対応handlerを無理に流用しないこと。
- 結論は `confirmed`、`inferred`、`unverified` のように信頼度を明示し、根拠と未検証事項を分けて書くこと。
- 配布先、decoy/正規アプリ通信、最終C2を混同しないこと。
- 正規署名付きhostやdecoy installerは、bundle内の同居関係、悪性DLL load、process帰属付き通信などの相関なしに単体で悪性判定しないこと。
## 包括解析・後段payload・C2確認のルール

- 新規検体は最初のdropperまたは表層PEだけで完了扱いにしないこと。静的layer、resource、埋め込みPE、script、memory image、dumped file、配布URL、公開sandboxの完全SHA-256一致を確認し、後段候補の有無と探索範囲をcaseごとに残すこと。
- 後段成果物を取得できる場合は、親検体SHA-256、解析ID／task、成果物名、取得元API pathの分類、成果物SHA-256、size、親と同一か、取得日時、実行有無を記録すること。取得物はリポジトリ外へ暗号化保存し、実行せず同じ静的解析pipelineへ再帰的に渡すこと。
- Triage成果物の取得では`triage_artifact_retrieval.py`を使い、完全SHA-256一致、公開解析、認証なし公開ページの二重確認、redirect禁止、件数・単体size・総size上限を必須とすること。private解析、owner付き解析、hash不一致、404成果物を別経路で迂回取得しないこと。
- 公開sandbox証跡と後段解析結果は`publish_triage_case_evidence.py`で正規化し、`triage-evidence.json`と`TRIAGE.md`へ残すこと。raw command、private path、生API応答、token、artifact binaryを公開しないこと。
- sandboxの`network_context`は正規OSや共有serviceのbackground trafficを含むため`context_only`とすること。config extractor由来endpointだけを`c2_candidate_external_sandbox_config`として候補IOCへ追加できるが、静的config、process帰属、malware protocol応答なしに確認済みC2へ昇格しないこと。
- 新規解析で得たC2／control／exfil候補は、解析回だけの一部targetsではなく`build_all_c2_monitoring_targets.py`で全履歴を再生成してから監視すること。現在のtaskでライブ通信が明示許可されている場合は、MaxMind DB鮮度確認後に`run_c2_monitoring_pipeline.py --allow-network`を実行すること。許可がない場合はライブ確認を実施せず、未実施理由をblockerとして残すこと。
- 後段が得られなかった場合も「なし」と断定せず、候補なし、公開解析なし、404、size上限、復号未解決、時限配布停止などを区別し、次に必要な最小手順を記録すること。
- 取得、正規化、親子関係、IOC統合、C2監視対象生成は再利用可能なscriptへ実装し、成功、拒否、hash不一致、private除外、上限超過、冪等再実行のunit testを追加すること。
- dailyのMalwareBazaar対象は、全検体に`c2-analysis.json`を置くこと。root静的解析、埋め込みlayer、外部payload、公開sandbox、memory、終端payload、family設定、C2 endpoint、C2 protocol、automationの10 phaseをすべて記録し、未実施を空欄にしないこと。
- daily完了と認めるC2結果は、終端payloadまで到達してprotocolレベルでC2を確認した`confirmed`、または終端codeの全通信・設定処理を確認してC2機能なしを立証した`no_c2_capability_verified`だけとすること。`unresolved`、終端未到達、後段未取得、設定未復元、TCP openだけの結果は完了扱いにしないこと。
- C2が取得できない検体を件数合わせの`triaged_unknown`や`complete`へ移さないこと。blocker、試行済み手法、次に必要な最小証拠を残して深掘りqueueへ戻し、`validate_daily_analysis.py`が非0の間はdaily全体を完了と報告しないこと。
- 新しい復号、設定形式、protocol、blocker識別を人手のメモだけで終えず、repository内のhandlerとunit testへ反映し、`c2-analysis.json`の`automation.handlers`と`automation.tests`から参照すること。
- 詳細な完了基準は`analysis-framework/docs/C2-ANALYSIS-COMPLETION-STANDARD.md`に従うこと。

## 関数ロジックとコード類似性の記録ルール

- 新規case、または静的解析を更新した既存caseには、`static-logic.json`、`STATIC-LOGIC.md`、`OVERALL-LOGIC.md` を必ず置くこと。`FEATURES.md` は挙動・検体特徴、`STATIC-LOGIC.md` は特徴的な関数の内部処理、`OVERALL-LOGIC.md` は検体全体の処理段階とcall関係として分離すること。
- binaryと静的に復元した実行可能layerは、Ghidra／CLR metadataから取得できる全関数／全managed methodをinventory化すること。external、thunk、CIL本体なしも分類付きでinventoryへ残すこと。ただし、全内部関数の逆コンパイルを完了条件にはしない。
- Ghidraが関数本体を1件も認識しないprogramでは、架空の関数を作らないこと。entry point、import、export、string、segmentの取得証跡を残し、`program構造限定解析`として制約を明記すること。importから示す挙動は限定patternに一致する能力候補に限り、実行経路や悪性動作の成立と断定しないこと。
- 逆コンパイルまたはCIL本文解析の対象は、entrypoint、設定decoder、復号・展開、通信、command dispatcher、永続化、anti-analysis、process／memory操作、主要handler、call graph中心関数、規模の大きい関数から代表として選定すること。関数ごとに選定理由とscoreを残すこと。
- 小規模programでは内部関数全体を文脈として選定してよい。大規模programでは上限を設け、役割ごとの代表を先に確保してからcall graph中心性、関数規模、symbol名の情報量で補完すること。選定外件数と選定方針を公開成果物へ明示すること。
- 選定した代表関数は、すべて逆コンパイル、CIL解析、または静的script構造解析を試行すること。未試行が1件でもある場合、または制約付き関数に失敗理由と次の解析方針がない場合は解析完了として扱わないこと。
- addressや関数名の列挙だけで解析済みとしないこと。代表関数は処理順、主要分岐、loop、caller、callee、API、結果の利用先、未解決edgeを日本語で記述し、`confirmed`、`inferred`、`unverified`相当の確度を付けること。
- `OVERALL-LOGIC.md`では、起動、設定・payload復元、解析回避、永続化、process・memory操作、通信、command分配、file操作のうち静的証跡がある段階を整理すること。観測call edgeがない段階間の実行順は断定せず、解析上の整理順と明記すること。
- Ghidra MCPを使う場合は、各関数recordにtoolと明示的な `program_selector` を残すこと。複数programが開いている可能性がある状態でactive tabへ依存しないこと。
- Ghidra MCPがHTTP 200で返すJSONに `error` がある場合も失敗として扱うこと。全programにMCP成功証跡が揃い、成功program数と対象program数が一致するまで解析完了として扱わないこと。
- Ghidraのfull call graphが空または不完全な場合は元応答を保存し、取得済みの代表関数逆コンパイル本文のcall式から内部関数、import API、未解決callを補完すること。edgeごとにGhidra由来か逆コンパイル由来かを記録し、未解決edgeを削除しないこと。
- code similarity追跡のため、公開する代表関数には正規化ロジックSHA-256、semantic sequence SHA-256、SimHash64を生成すること。具体的なaddress、数値、string literal、Ghidra自動名、local変数名は比較前に正規化すること。
- fingerprint一致だけでファミリー、actor、campaignを確定しないこと。共通library、compiler生成処理、builder共有を考慮し、call graph、API、設定形式、配布文脈、IOCと相関すること。
- 生の逆コンパイル全文、CIL命令列、具体的なC2 literal、資格情報、token、復号秘密値はリポジトリ外のアクセス制限された解析領域へ保存すること。取得済み成果物を方針変更によって削除せず、公開成果物には無害化した代表関数ロジックだけを記録すること。
- 静的解析で取得または導出した内容は、表示上の都合による件数・文字数上限で破棄しないこと。人向けMarkdownを要約する場合も、取得済み全件を機械可読JSONまたはアクセス制限された生成果物へ残し、参照先と保持件数を明示すること。
- offset／limit型のGhidra MCP endpointは、上限未満の終端pageまで取得すること。imports、exports、strings、segmentsは取得page数、全件数、明示的なprogram selector、終端確認を記録し、保存件数と一致するまで完全取得としないこと。
- 一括解析では、生のGhidra index、全関数inventory、代表関数の逆コンパイル行、選定したmanaged methodのCIL命令列を `private-artifact-validation.json` で照合すること。欠落、不正JSON、program selector不一致、代表関数の未試行、ページング未完了が1件でもある場合は、公開または完了扱いにしないこと。
- binaryの解析完了を宣言する前に `validate_function_analysis.py` を実行し、対象collectionの全caseが `complete: true` であることを確認すること。
- 関数成果物を追加・更新した後は `generate_code_similarity_index.py --repository . --write` と `--check` を実行し、横断索引を同期すること。
- 詳細なschemaと手順は `analysis-framework/docs/STATIC-LOGIC-AND-CODE-SIMILARITY.md` に従うこと。
## 静的解析図の記録ルール

- 新規case、または全体ロジックを更新した既存caseの`OVERALL-LOGIC.md`には、Mermaidの静的な`実行フロー`、`感染チェーン`、`モジュール関係`を必ず含めること。
- 実線はcall edge、復元layerの親子関係、root programなど静的に確認した関係だけに使用すること。段階間の掲載順を実行順として描かないこと。
- 推測、親未特定、配布経路未観測、後続stage未復元は、点線と`未観測`または`未解決`ノードで明示すること。証跡のない感染経路、module依存関係、C2到達を補完しないこと。
- 図は`static-logic.json`、`static-layers.json`、review済み補足情報から機械生成し、検体由来文字列をMermaidへ直接埋め込まないこと。URL、IP、完全hash、private path、制御文字は省略または無害化すること。
- 図は要約であり、関数別根拠、確度、制約、未解決事項の文書記録を置き換えないこと。
- 3図の順序、共通phase ID、node／edge表現は`analysis-framework/docs/STATIC-DIAGRAM-AND-LOGIC-COMPARISON-STANDARD.md`へ統一すること。
- 新規caseの`OVERALL-LOGIC.md`には`比較プロファイル`と`他ケースとの比較`を置き、感染・復元層、実行段階、module構成、機能、代表関数の役割、code fingerprintを独立軸として記録すること。
- 類似候補には最低2つの独立軸を要求すること。同一family名、tag、単一IOC、単一file nameだけで類似、campaign、actorの同一性を判定しないこと。
- 静的ロジック、復元層、featuresを追加・更新した後は`generate_logic_similarity_index.py --write`と`--check`を実行し、`logic-similarity.json`と`LOGIC-SIMILARITY.md`を同期すること。
## README と analysis_history.yaml の更新ルール

- 過去解析の正本はルートの `analysis_history.yaml` とすること。
- 新しい解析ケースを追加・更新した場合は、必要に応じて `analysis_history.yaml` に以下を記録すること。
  - `malware_type`
  - `analyzed_at`
  - `sample_sha256`
  - `analysis_level`
  - `campaign_type`
  - `matched_patterns`
  - `c2`
  - `result_path`
  - `notes`
- `analysis_history.yaml` を変更した場合は、ルート `README.md` の解析履歴サマリも同期すること。
- READMEの履歴サマリには、少なくともマルウェア種、解析回数、最後の解析日、主な解析パターンを含めること。
- ケース別READMEでは、判定とチェーン、ファイルIOC、C2/通信IOC、Sigma/YARA材料、制約を分けて記載すること。
- IOCや検知条件は、IP単独、ファイル名単独、`rundll32.exe` 単独などの高誤検知条件を避け、hash、署名状態、親子関係、image load、process帰属付き通信と組み合わせること。

## IOC-LIST.md の更新ルール

- 個別のcase、campaign、incident解析には、同じディレクトリに機械可読性を意識した `IOC-LIST.md` を必ず置くこと。過去解析も例外にしないこと。
- `IOC-LIST.md` は `python analysis-framework/common/generate_ioc_lists.py --repository . --write` で生成し、原則として手編集しないこと。`--write` を省略した場合は差分確認だけを行い、ファイルを変更しない。
- 内容は `種別`、`値`、`役割`、`確度`、`根拠` の5列表だけとし、挙動説明、検知考察、Shodan/Sigma/YARAクエリ、一般的なコマンド名を混ぜないこと。
- 掲載対象は、証拠に紐づいた検体・payload hash、domain、IP、endpoint、URL、証明書hash、特徴的なfile path/nameとすること。配布先、stage取得先、C2、証明書などの役割を分けること。
- URLのuserinfo、query、fragment、token、password、メールアドレスその他の資格情報を掲載しないこと。必要なURLパスだけを残して秘密値を除去すること。
- 正規署名付きhost、decoy、共有インフラは、単独IOCとして扱える根拠がない限り除外すること。`context_only`、`not_ioc`、`not_c2`、`dual-use` と分類された値も除外すること。
- 公開可能なIOCがない解析でも、空の標準表を持つ `IOC-LIST.md` を置き、「存在しない」ことを明示可能にすること。
- 新規解析、README、`iocs.json`、`config.json`、`analysis_history.yaml` を変更した後は `--write` で一覧を再生成し、`python analysis-framework/common/generate_ioc_lists.py --repository . --check` で同期を検証すること。
- リポジトリ横断の索引は `analysis-results/IOC-INDEX.md` とし、個別一覧と同じgeneratorから更新すること。

## 検証ルール

- YAMLを編集した場合は、利用可能なパーサで構文と期待するトップレベル構造を検証すること。
- Markdownを編集した場合は、少なくとも `git diff --check` で空白・フォーマット問題を確認すること。
- スクリプトや解析コードを変更した場合は、該当READMEまたはドキュメントに書かれたテストを優先して実行すること。
- 依存関係不足や環境制約で検証できない場合は、実行したコマンド、失敗理由、代替検証を明記すること。

## 作業後の報告

- 変更したファイル、実行した検証、未検証事項を簡潔にまとめること。
- ドキュメント変更でも、解析安全ルールや履歴サマリの整合性に影響がある場合はその点を明記すること。
- 作業報告も日本語で記述し、英語のログやerror messageを示す場合は日本語で意味と影響を説明すること。

## ClickFix日次調査のルール

- ClickFix／ClearFake調査は`analysis-framework/clickfix/clickfix_daily_intake.py`を使い、1回あたり最大50件、domain重複なしで選定すること。明示指定case、当日のThreatFox `clickfix`／`clearfake` tag、ClickFix Campaign Monitorの最新記録の順に扱い、情報源の観測日と解析日を区別すること。
- 公開成果物は`analysis-results/clickfix/<domain>/cases/<case-id>/`、実行単位の一覧は`analysis-results/clickfix/collections/clickfix-daily-<YYYYMMDD>/`へ保存すること。各caseに`README.md`、`FEATURES.md`、`OVERALL-LOGIC.md`、`INFECTION-CHAIN.md`、`INFRASTRUCTURE.md`、`TRIAGE.md`、`analysis.json`、`infrastructure.json`、`triage-evidence.json`、`iocs.json`、`IOC-LIST.md`、`live-observation.json`、`rules/sigma.yml`を置くこと。
- 実サイト確認は、上限付きGETと静的本文解析に加え、実ブラウザでJavaScript実行後のDOM、redirect、network request、fake CAPTCHA／verification表示、clipboard書き込みを観測すること。ブラウザ観測前に対象hostがprivate／loopback／link-localへ解決しないことを確認し、該当する場合は接続しないこと。
- clipboardは`navigator.clipboard.writeText`、`ClipboardItem`、legacy copy event等をページ初期化時からinterceptし、書き込み値をGit管理外へ記録すること。可能な限りOS clipboardへの実書き込みを抑止し、取得commandをRun dialog、terminal、PowerShell、cmd、LOLBINへ貼り付けたり実行したりしないこと。copy／verify等の表示操作は再現してよいが、認証情報送信、form送信、POST、WebDAV変更系method、malware protocol、取得script／binaryの実行は行わないこと。
- ブラウザ観測は成功時だけでなく、到達不能、challenge停止、geo-fence、copy操作なし、clipboard interception未対応もcase別の`browser-observation.json`へ記録すること。日次ClickFix解析では50件すべてについてブラウザ観測を試行し、`--require-browser-observations`で欠落を検出すること。
- 感染チェーンはlanding／inject、lure表示、clipboard設定、利用者による貼り付け・実行、shell／LOLBIN、resolver／次段取得、終端payloadの共通phaseへ分解すること。各phaseに`observed`、`provider_reported`、`recovered`、`inferred`、`not_observed`、`not_retrieved`相当の状態、根拠、観測日時を付け、caseの停止位置と未解決edgeを`INFECTION-CHAIN.md`と`analysis.json`へ残すこと。利用者がcommandを実行した事実はsandbox等の根拠がない限り観測済みとしないこと。
- provider生応答、取得本文、生command、token、invite pathは`.work/clickfix/`等の追跡対象外領域へ保存すること。公開側はhash、無害化URL、HTTP status、本文種別、根拠、確度へ正規化すること。ライブDNSの共有基盤IP、Telegram等のdual-use resolver、通常サイト資産は`context_only`としてIOCから除外すること。
- ClickFix／ClearFake tagは手法またはWeb配布clusterであり、終端malware、campaign、actorの確定根拠にしないこと。配布binaryまたは完全hashを取得した場合はClickFix caseだけで完了扱いにせず、`analysis-results/malware/<family>/versions/<version-key>/cases/<sha256>/`へ別caseとして静的解析すること。
- payload取得の成否にかかわらず、`clickfix_infrastructure_enrichment.py`でcurrent DNS（A／AAAA／CNAME／NS／MX）、RDAP、証明書透明性、leaf証明書fingerprint、IP netblock、ASN、Shodan InternetDBを調査し、情報源観測日時と調査日時を分離すること。履歴passive DNSを取得できない場合は未取得と明記し、共有CDN、正規サイト侵害、sinkholeの可能性を残すこと。
- `clickfix_triage_enrichment.py`でHatching Triageを`domain:`、取得済みの完全URLは`url:`、取得済みhashは`sha256:`で照合すること。公開済み解析だけを成果物へ転記し、overviewとbehavioral reportからprocess、raw commandを公開しないcommand hash、通信、dumped file、memory resource、PCAP候補を確認すること。新規sample提出、sample／memory／PCAP downloadは既定で行わず、必要時は対象と保存先を明示して`.work`配下で実施すること。
- TriageやInternetDBの通信先・portはsandbox background trafficを含むため、config extractor、process帰属、malware protocol、複数taskでの再現のいずれかを確認するまでC2へ昇格しないこと。
- RDAP、CT、InternetDB等がHTTP 429または一時的5xxを返した場合は上限付きbackoffを使い、成功済み証跡を保持して部分結果と失敗statusを明記すること。取得失敗を「該当インフラなし」と解釈しないこと。
- 生成後はClickFix単体テスト、Sigma／JSON構文、50件上限、公開秘密値、リンクを検証し、`generate_ioc_lists.py --write`と`--check`で`IOC-INDEX.md`を同期すること。

## daily解析の完了条件

- daily解析は、当日記事・IOCの調査、MalwareBazaarの最新Windows検体50件、ClickFix／ClearFake 50件、当日解析で得たC2候補のライブチェックとMaxMindエンリッチの4系統を同じ日付の実行単位で扱うこと。4系統の成果物検証、終了時安全ゲート、ローカルcommit、GitHubへのpush、PR作成までを完了条件とすること。
- `analysis-framework/common/validate_daily_analysis.py --repository . --analysis-date <YYYY-MM-DD>`が4系統と文字化け品質ゲートのすべてを`complete`と判定するまでdaily解析完了と報告しないこと。候補不足、取得失敗、`partial`、未完了queue、C2ライブチェック未実施、UTF-8不正、日本語文字化けは完了として扱わないこと。
- ユーザーが当該実行で明示的にpush／PRを省略するよう指定しない限り、解析成果を専用branchへpushし、検証内容と未完了項目を記載したdraft PRを作成すること。
- pushまたはPR作成が認証・権限・競合・外部サービス障害で失敗した場合は、解析自体を完了と偽装せず、失敗した段階と再開に必要な操作を報告すること。

## マルウェア解析の開始時・終了時安全ゲート

- マルウェア提出物を開く、抽出する、または解析する前に、検体パス、ハッシュ、特徴的なファイル名をパターンとして、読み取り専用の安全確認を実行すること。
- 解析完了を宣言する前にも同じ確認を実行すること。予期しない一致プロセス、サービス、スケジュールタスク、Runキー値、ネットワーク接続、またはMicrosoft Defenderの有効な脅威を調査すること。
- 安全確認では、検体を実行、ロード、登録したり、検体からネットワーク要求を送信したりしてはならない。
- 安全確認の出力、スナップショット、レポートは一時的な運用データである。このリポジトリ配下へ書き込んだりGitHubへコミットしたりしてはならない。一時保持が必要な場合に限り、標準出力またはリポジトリ外の一時領域を使用すること。
- 説明できない実行または永続化の指標が残っている間は完了を宣言しないこと。破壊的な除去を試みず、観測内容をユーザーへ報告すること。

## ハッシュ限定OSINT補強ルール

- 確度が低いケースや未識別ケースでは、既定で完全一致ハッシュだけを照会すること。代替手段として検体を提出・アップロードせず、検体から抽出したインフラにも接続しないこと。
- APIやプロバイダーの生レスポンスは、無視対象の `.work/` 配下へ保存すること。正規化済み証拠、無害化済み参照、情報源の状態、確度だけを公開すること。
- 集約サービスと、それが明記する基礎プロバイダーを重複して数えないこと。中確度には、相互に独立し一致するプロバイダーを少なくとも2件要求すること。
- 単一プロバイダーのラベルは低確度の手掛かりである。競合するファミリーラベルは競合として保持し、同数の場合はunknownのままにすること。OSINTがないことは無害性の証拠ではない。
- レビュー済みの手動調査は、ハッシュをキーとする精選証拠へ保存すること。完全一致ハッシュの情報源と一般的なファミリー文脈を区別し、両方の来歴を記録すること。
- 公開出力から、URLのユーザー情報、クエリ、フラグメント、資格情報、トークン、メールアドレス、プロバイダーの生フィールド、復元した秘密値を除去すること。
- 公開前に、情報源の正規化、別名、確度、競合処理、秘密値の無害化、オフライン再生、精選証拠を単体テストすること。

## プロファイル定義による複数ファミリー解析ルール

- 共通のファミリーマーカー、設定鍵、通信方式の期待値、別名、確認要件は `extractors/profiles/windows_family_profiles.json` に置くこと。ファミリー検出器は薄いアダプターに保ち、抽出ロジックを重複させないこと。
- MalwareBazaarの完全一致シグネチャとレビュー済みハッシュは、ファミリー選択の証拠として扱うこと。リテラルが復号済み設定または稼働中C2であることの証明にはしないこと。
- ネットワーク所見は役割別に分類すること。配布段階URLはIOCになり得るがC2ではない。公開IP確認サービス、証明書、文書、プレースホルダー、無害なベンダー値は、C2対象でも単独IOCでもない。
- 実際に許可された観測なしに、Shodanのバナー／ハッシュ、HTTPタイトル、証明書ハッシュ、JARM、生存確認の出力を作成しないこと。オフラインの照会文字列には、受動的な計画にすぎないことを明記すること。
- MalwareBazaarからの取得は再開可能に保つこと。回数を使い切った一時的失敗はハッシュをキーとする再試行キューへ保存し、ほかの静的作業後に再実行すること。選定した最新ハッシュを、通知なく古い検体へ置き換えないこと。
- プロファイル対象ファミリーの一括処理後に `validate_family_expansion.py` を実行すること。完了には、ハッシュ、ルーティング、公開成果物、非実行、非接続の各確認が必要である。
- ループバックエミュレーターは合成データ用とし、実際の通信仕様と互換性がないことを明記すること。すべてのバインド先とクライアント対象は、共有のリテラル・ループバック検証を通すこと。

## intelligence/ 継続調査と週次routineのルール

- `intelligence/` は、個別の検体解析を継続的な脅威インテリジェンスへ変換するための定期調査計画の正本である。campaign相関の分析は、Claudeの週次routineとして定期実施する前提で運用すること。
- 定期調査の作業前に次の3文書を読み、その定義に従うこと。
  - `intelligence/README.md`: 目的、差分中心の方針、証拠軸の分離、1回の調査サイクル、成果物構成、成功指標。
  - `intelligence/RECURRING-TASKS.md`: `INT-D01`〜`INT-E01` の定期タスク定義。週次routineの中心は `INT-W01`〜`INT-W05` であり、実行時は前提となる差分確定（`INT-D01`〜`INT-D03` 相当）を先に完了させること。各実行は同文書の「定期実行の共通チェック」を満たして終了すること。
  - `intelligence/ASSESSMENT-MODEL.md`: entity・edge定義、証拠の強さ、確度表現、review queueの優先順位。自動scoreは候補の順位付けにだけ使い、campaign昇格、operation統合、actor帰属の判断は人手レビューを必須とすること。
- 週次実行の成果物は `intelligence/README.md` の「推奨成果物構成」に従うこと。baselineは `intelligence/baselines/YYYY-MM-DD.json`、実行結果は `intelligence/runs/YYYY/YYYY-MM-DD/`（`README.md`、`delta.json`、`review-queue.json`、`metrics.json`）へ保存し、前回baselineとの差分と増減理由を説明できる状態にすること。
- campaign相関の機械可読正本は `analysis-results/research/campaigns/correlated-<YYYYMMDD>/campaigns.json` とすること。既存実行のディレクトリを上書きせず、実行日ごとに新しいディレクトリを作ること。相関には `analysis-framework/common/correlate_campaigns.py`、派生成果物の同期には `analysis-framework/common/refresh_derived_artifacts.py` を用いること。
- 相関・帰属の抑制ルールを毎回守ること。単一のIP、tag、family名、コード類似だけでcampaignやactorを確定しないこと。棄却した候補の理由、否定証拠、代替仮説を保存すること。live C2接続や検体送信を無断で行わないこと。
- 閲覧UI（`ui/`）は、`correlated-*` の最新ディレクトリ（名前の辞書順末尾）、`analysis-results/catalog/code-similarity.json` のexact group、および全case成果物を `ui/data.js` へ取り込む。週次相関の実行後、またはcase・catalog成果物を更新した後は `python3 ui/generate_ui_data.py` で再生成し、`python3 ui/generate_ui_data.py --check` で同期を確認すること。

## 静的深掘りが必要な難解析ケースのルール

- レビュー済みインベントリとして `analysis-framework/inventories/static-hard-cases.yaml` を使用すること。すべてのルートと子要素をSHA-256で認証し、親／変換／子の関係を保持すること。
- このワークフローは静的解析だけに限定すること。検体や復元したレイヤーを実行せず、ネイティブコードやCILをCPUエミュレーションせず、抽出したホストにも接続しないこと。
- 復元したすべての子要素を別レイヤーとして解析すること。パッカー／コンテナの結果は最終ペイロードを説明せず、期待した子要素が見つからない場合は「存在しない」ではなく未解決とすること。
- CFG技法の結果はルーティング証拠として扱うこと。`not_observed` は範囲を限定した到達可能グラフだけに適用し、`suspected` は確認を意味しない。ディスパッチャー状態と再現可能な後続写像を復元した後に限り、CFFを確認済みとすること。
- 通常のCLRエントリサンクでは、ネイティブCFF／VMへの帰属を抑止すること。マネージドイメージはメタデータ、CIL、リソース解析へ送ること。認証済みの子要素を解析するまでは、UPX／MPRESSのローダースタブグラフをパッカーの影響下にあるものとして扱うこと。
- managed PEで高entropy resource、DynamicMethod proxy、ResourceResolve、埋込みassembly loadを確認した場合は、`unpackers/managed_proxy_deobfuscator.py`を含む静的profile解析を実施し、resourceのhash・size・entropy、proxy対応件数、復元経路、未解決変換を記録すること。最終assemblyを復元できない場合も、停止した関数・resource・鍵生成段階と次の静的定数伝播方針を明記すること。
- 新しいprotector変換を手動で復元できた場合は、検体固有の一回限りの処理で終わらせず、size上限と出力形式検証を持つfail-closedなunpacker／profileとして実装し、`unpackers/static_unpacker.py`へ統合して正常系・誤検知抑止・破損入力のテストを追加すること。
- 静的検証にはGhidra MCPを優先し、必ず明示的なプログラムセレクターを使用すること。localhostだけで運用し、任意スクリプト実行は無効のままにすること。
- ハッシュ、サイズ、関係、指標、証拠、明示的な制約だけを公開すること。復元した生バイナリや、開始時・終了時のホスト安全確認出力を公開してはならない。

## C2監視とMaxMindエンリッチのルール

- malware固有のactive protocol C2検出器またはレビュー済みprofileを追加・更新した場合は、Nmapで再現可能な範囲を`analysis-framework/nmap/scripts/`のNSEにも反映し、`analysis-framework/nmap/profiles.json`の対応表と`verify_nse.py`のloopback模擬C2試験を同時に更新すること。Nmapでは固有応答を確認できずtransport確認に留まるfamilyはC2確定用NSEを作らず、除外理由を対応表へ記録すること。完了前に`python analysis-framework/nmap/verify_nse.py`と`python -m pytest analysis-framework/tests/test_nmap_c2_scripts.py -q`を実行すること。
## 終端ペイロード未取得ケースの優先取得ルール

- 新規検体を外部sourceから選定する前に、`analysis-framework/common/build_terminal_payload_gap_inventory.py --repository . --check`を実行し、`intelligence/terminal-payload-recovery/README.md`のP0から順にfamilyを選ぶこと。台帳が不一致なら`--write`で更新してから選定すること。
- 「最新版」は固定hashではなく、取得時点のfirst seen降順で照会すること。既存SHA-256を除外し、leaf DLL／loader単体より、親archive、sidecar、resource、script、decoyを含む完全な配布chainを優先すること。
- `source_material_absent`のケースは同じrootへ復号処理を繰り返さず、同familyの新しい完全配布物、exact sampleの公開sandbox artifact、memory dump、dumped file、親子relationを優先して探すこと。
- ローカルでは検体を実行しないこと。静的復元で不足する場合は、公開sandboxの既存実行または別途承認された隔離環境から、完全一致hashを検証できるdump／memory artifactを取得して静的pipelineへ戻すこと。
- 外層やpackerだけの解析、`partial`解除、family tagだけで終端到達としないこと。終端artifactのSHA-256、親子関係、復元方法、終端family・version・config・C2の確認結果、または追加stageがない根拠を残すこと。
- gapを閉じる場合は、case `report.json`の`classification.terminal_family_confirmed`と`case_state.complete`をともに`true`とし、終端artifactの根拠をcase文書へ記録すること。古い難解析台帳の記録は履歴として残してよいが、構造化された完了証拠なしに自動除外しないこと。
- 新規解析または再解析後は同生成器を`--write`、続けて`--check`で実行し、台帳、ケース一覧、CSV、family優先表を同期すること。


- C2監視結果を作成または更新するときは、観測時に得たglobal IPをGeoLite2 City/ASNで照合し、Geo・AS情報とDB provenanceを結果へ付与すること。
- 標準経路として`analysis-framework/common/run_c2_monitoring_pipeline.py`を使い、限定観測、MaxMind照合、JSON／Markdown生成を一括実行すること。
- daily解析では、`build_all_c2_monitoring_targets.py`で`analysis-results`全体のIOC履歴のC2／control／exfil候補を再収集し、`.onion`を除く通常のglobal IP／FQDNを100% `targets.json`へ反映してから、統合ランナーを`--allow-network`付きで実行すること。既知portは完全一致endpointへ限定接続し、port不明hostはDNS-onlyとしてC2稼働と区別すること。`candidate-inventory.json`へ走査数、カバレッジ、除外理由を残すこと。ライブチェック未実施のままdaily解析を完了扱い、commit、pushまたはPR更新してはならない。
- 静的解析または過去の限定観測でmalware固有heartbeat、check-in、server-first handshakeを復元済みのC2は、単純な`tcp_connect`へ降格させず、`c2_protocol_probe_profiles.json`のレビュー済み完全一致profileを適用すること。profile ID、host、port、protocol、methodが一致しない場合はfail-closedとし、未知または未レビュー対象へmalware protocolを送信しないこと。
- active protocolの送信値、期待応答長、SNI、IP pinningは`targets.json`へ直接記述せず、レビュー済みregistryだけを正本とすること。1対象1回の限定観測、最大3秒とし、Winos／vvaS／AsyncRAT／VenomRATは最大64 byte、N520 server-firstは44 byte、AgentTesla FTP replyは1024 byteに限定すること。StealC／Lumma／Remusだけは後述の例外で最大2 HTTP要求を許可する。明示した例外以外ではvictim metadata、stage要求、command polling、任意commandを送信しないこと。結果にはprofile適用数、実送信数、protocol確認数を残すこと。
- AsyncRAT／VenomRATのTLS MessagePack probeは、`--allow-network`に加えて`--allow-reviewed-application-probes`がある場合だけ、空の`Message`を持つ匿名Ping 1 frameを送ること。AsyncRATの`Packet`／`pong`とVenomRATの`Pac_ket`／`Po_ng`を別profileとして扱い、field名を推測で相互流用しないこと。
- AsyncRAT／VenomRATの観測証明書が検体内蔵証明書と不一致でも、それだけで非C2または停止と判定しないこと。`certificate_mismatch_excludes_c2=false`と`mismatch_inconclusive`を記録し、改変build、fork、再build、証明書rotationの可能性を残すこと。完全一致は強い加点、MessagePack応答一致はprotocol確認として扱うこと。
- AgentTesla FTP認証は、完全一致review済みprofile、リポジトリ外`private_credential_vault`、`--allow-network`、`--allow-authentication`が揃う場合だけ行うこと。送信は`USER`、必要時の`PASS`、`QUIT`に限定し、資格情報、raw reply、秘密値を公開成果物へ残さないこと。`LIST`、`PWD`、`RETR`、`STOR`、upload、directory操作は行わないこと。
- FormBook／XLoaderは`passive_only`のままとし、campaign path／account推測を監視目的で送信しないこと。StealC、Lumma v6、Remusは、復号済みの検体固有値、完全一致host／port、単一global IP pin、最大3秒、`--allow-network`と`--allow-malware-registration-tasking`の両方を満たすreview済みprofileだけを例外的に許可する。StealCは合成hwidの`create`と`loader`、Lumma v6は`uid/cid`と合成hwid付きtask要求、Remusは合成hwid登録と取得tokenによる`step=1`の計2要求までとする。実端末情報、`debug`、upload、`done`、task実行、task内URL追跡、payload取得を行わず、task本文、token、合成ID、raw応答を公開しないこと。応答上限はStealC 16,384 byte、Lumma 65,536 byte、Remus 8,192 byteとし、超過時はtask段へ進まずfail-closedにすること。Lumma v5以前の`act=life`はexact versionと復号済み設定を静的に確認したreview済みprofileなしに送信しないこと。
- 4系統の公開PCAPは`stealer_protocol_evidence.py`で正規化し、socket接続先、DNS名、HTTP Host、URI path、Content-Type、フォームkey名、multipart name、要求順序を分離すること。本文値、query、token、filename、victim metadataを公開成果物へ残さず、HTTP status、404、Host、port、domain単独をprotocol確認へ昇格しないこと。
- StealCでは最深PEを自動的にC2 coreと扱わず、collection／C2 coreとChrome App-Bound Encryption helperのmodule役割を分離すること。親coreへhelperが内包される場合は、ASCII／UTF-16のJSON、transport、credential collectionという独立marker群を優先し、`builder_vN`単独で製品versionを確定しないこと。
- ライブチェック前にGeoLite2 City/ASN両DBのbuild時刻を確認し、いずれかが24時間以上前なら両DBを更新して公式checksumを検証すること。鮮度確認または取得に失敗した場合は、先にC2へ接続せずfail-closedで終了すること。
- `MAXMIND_LICENSE_KEY`、Authorization header、署名付きdownload URL、MMDB本体をリポジトリや公開成果物へ保存しないこと。DBはリポジトリ外のprivate cacheへ保存すること。
- GeoLite2は概略位置情報であり、個人・住所・攻撃者所在地・C2稼働を確定する根拠として扱わないこと。
- C2のdomainは日次観測ごとのA／AAAA解決先、ASN、organization、観測日時を履歴化すること。生IPの変化は保持し、同一Cloudflare、Akamai、Fastly等の共有CDN provider内のedge IPローテーションはC2インフラ変化件数から除外すること。CDN provider変更または非CDN IP変更は別に記録すること。
- DNS/IP履歴の各IPにはAS番号・AS組織、国・地域・都市、インフラタグ、防弾ホスティング評価を保存すること。IP集合が変わった場合は、旧側、新側、追加、消失の各集合に完全なIP詳細を保持し、単純なIP文字列だけの遷移を作らないこと。
- インフラタグは根拠と確度を持たせ、`DNS解決先`、`ホスティング`、`CDN`、`Anycast／共有エッジ`、`VPN／Proxy`、`Tor関連`、`ドメイン事業者`、`C2候補インフラ`を区別すること。service種別タグはproviderの悪性、攻撃者、C2所有を意味しない。
- `防弾ホスティング`はprovider自身の明示、政府措置、または信頼できる脅威インテリジェンスの明示評価がある場合だけ付与すること。高密度かつ継続的なC2悪用等の状況証拠に基づく場合は`防弾ホスティング - 疑い`に限定し、単一の悪性IP観測だけでは付与しないこと。共有CDN edgeからoriginを推定しないこと。
- 防弾ホスティングとインフラ分類のregistryには、根拠URL、公開日または観測期間、取得日、確度、判断理由を保存すること。根拠の更新時は過去履歴を消さず、評価変更が追跡できる形にすること。
- 全履歴から再生成した対象へ直近の`active-targets.json`を統合し、ON、7日未満のOFF、未観測の対象を継続監視すること。`.onion`は監視対象へ再追加しないこと。最新観測がOFFで、最後のON以後または初回OFFから7日以上経過し、2回以上のOFF実観測がある対象だけを`retired_stopped`として停止履歴へ移し、次回active対象から外すこと。単発timeout、DNS解決失敗、DNS-only観測だけで停止しないこと。
- 停止と再開の状態遷移は`monitoring-history.json`へ残すこと。停止済み対象が後日ONになった場合は再開履歴を付け、active監視へ戻すこと。

## 新規解析の全体反映ルール

- caseディレクトリを作成した時点で、解析状態が`complete`、`partial`、`triaged_unknown`のいずれでもcase identityを`analysis-results/catalog/cases.json`へ登録すること。catalog登録は解析完了の宣言ではなく、存在・格納先・帰属状態の正本化である。
- `partial`をcatalogから除外してはならない。解析完了状態とblockerはcase `report.json`およびcollection `manifest.json`の`publication_stage`で保持し、identity登録と混同しないこと。
- 新規caseまたは既存caseの解析結果を変更した後は、リポジトリルートで次を必ず実行すること。

```powershell
py -3.13 .\analysis-framework\common\refresh_case_inventory.py --repository . --write
py -3.13 .\analysis-framework\common\refresh_case_inventory.py --repository . --check
```

- 一括反映の対象は、case `metadata.json`、`analysis-results/catalog/cases.json`、ルートおよび成果物READMEの全case件数、`IOC-LIST.md`と`IOC-INDEX.md`、コード類似性索引、`manifest.sha256`、`ui/data.js`、`ui/api/v1/*.json`である。これらの生成物を個別に手編集して終了しないこと。
- collectionに属するcaseは、公開処理の時点でcollection `manifest.json`の`cases`と`family_sources`、case `metadata.json`の`collections`を同時に更新すること。一括反映スクリプトは、欠落した収集文脈を推測して補わない。
- `analysis_history.yaml`、新規ファミリのOSINT文書、検知ルール、campaign相関は解析内容に応じて別途更新すること。campaign相関を更新した場合は`refresh_derived_artifacts.py`も実行してから全体反映を再検証すること。
- `refresh_case_inventory.py --check`が1件でも不一致を報告した状態でcommit、push、PR作成、daily解析完了を行わないこと。詳細な対象ファイルと確認順は`analysis-framework/docs/CASE-PUBLICATION-CHECKLIST.md`に従うこと。
