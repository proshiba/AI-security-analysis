# AI-security-analysis向けAIエージェント指示

このファイルはリポジトリ全体に適用される共通ルールです。より深い階層に `AGENTS.md` がある場合は、そのディレクトリ配下ではより深いファイルの指示も必ず読み、矛盾する場合はより深い指示を優先してください。

## 最初に確認するもの

- ルートの `README.md` を読み、リポジトリ構成、インストール方法、解析結果の読み方、解析履歴サマリの更新方針を確認すること。
- マルウェア別の解析コード、ドキュメント、設定、結果を扱う場合は、対象マルウェア配下の `AGENTS.md` と README/docs を先に確認すること。
  - ValleyRAT 関連の作業では `analysis-framework/malware/valleyrat/AGENTS.md` を必ず読むこと。
  - ValleyRAT のワークフローやパターン判断では `analysis-framework/malware/valleyrat/docs/VALLEYRAT-WORKFLOW.md` と `analysis-framework/malware/valleyrat/docs/PATTERN-DESIGN.md` も参照すること。
- 公開可能な解析結果を扱う場合は `analysis-results/README.md` と対象ファミリーの `analysis-results/malware/<family>/README.md` を確認すること。横断的な調査は `analysis-results/research/`、複数検体をまとめた成果物は `analysis-results/collections/` も確認すること。

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
- 文書を追加・変更した後は、可能な範囲で `localize_result_markdown.py` のdry-run、`audit_japanese_docs.py --fail-on-findings`、local link監査、`git diff --check`を実行すること。公開Python APIのdocstringを変更した場合はpydocも再生成すること。

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
- `IOC-LIST.md` は `python analysis-framework/common/generate_ioc_lists.py --repository .` で生成し、原則として手編集しないこと。
- 内容は `種別`、`値`、`役割`、`確度`、`根拠` の5列表だけとし、挙動説明、検知考察、Shodan/Sigma/YARAクエリ、一般的なコマンド名を混ぜないこと。
- 掲載対象は、証拠に紐づいた検体・payload hash、domain、IP、endpoint、URL、証明書hash、特徴的なfile path/nameとすること。配布先、stage取得先、C2、証明書などの役割を分けること。
- URLのuserinfo、query、fragment、token、password、メールアドレスその他の資格情報を掲載しないこと。必要なURLパスだけを残して秘密値を除去すること。
- 正規署名付きhost、decoy、共有インフラは、単独IOCとして扱える根拠がない限り除外すること。`context_only`、`not_ioc`、`not_c2`、`dual-use` と分類された値も除外すること。
- 公開可能なIOCがない解析でも、空の標準表を持つ `IOC-LIST.md` を置き、「存在しない」ことを明示可能にすること。
- 新規解析、README、`iocs.json`、`config.json`、`analysis_history.yaml` を変更した後は一覧を再生成し、`python analysis-framework/common/generate_ioc_lists.py --repository . --check` で同期を検証すること。
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

## 静的深掘りが必要な難解析ケースのルール

- レビュー済みインベントリとして `analysis-framework/inventories/static-hard-cases.yaml` を使用すること。すべてのルートと子要素をSHA-256で認証し、親／変換／子の関係を保持すること。
- このワークフローは静的解析だけに限定すること。検体や復元したレイヤーを実行せず、ネイティブコードやCILをCPUエミュレーションせず、抽出したホストにも接続しないこと。
- 復元したすべての子要素を別レイヤーとして解析すること。パッカー／コンテナの結果は最終ペイロードを説明せず、期待した子要素が見つからない場合は「存在しない」ではなく未解決とすること。
- CFG技法の結果はルーティング証拠として扱うこと。`not_observed` は範囲を限定した到達可能グラフだけに適用し、`suspected` は確認を意味しない。ディスパッチャー状態と再現可能な後続写像を復元した後に限り、CFFを確認済みとすること。
- 通常のCLRエントリサンクでは、ネイティブCFF／VMへの帰属を抑止すること。マネージドイメージはメタデータ、CIL、リソース解析へ送ること。認証済みの子要素を解析するまでは、UPX／MPRESSのローダースタブグラフをパッカーの影響下にあるものとして扱うこと。
- 静的検証にはGhidra MCPを優先し、必ず明示的なプログラムセレクターを使用すること。localhostだけで運用し、任意スクリプト実行は無効のままにすること。
- ハッシュ、サイズ、関係、指標、証拠、明示的な制約だけを公開すること。復元した生バイナリや、開始時・終了時のホスト安全確認出力を公開してはならない。
