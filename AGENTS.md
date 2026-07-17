# AI agent instructions for AI-security-analysis

このファイルはリポジトリ全体に適用される共通ルールです。より深い階層に `AGENTS.md` がある場合は、そのディレクトリ配下ではより深いファイルの指示も必ず読み、矛盾する場合はより深い指示を優先してください。

## 最初に確認するもの

- ルートの `README.md` を読み、リポジトリ構成、インストール方法、解析結果の読み方、解析履歴サマリの更新方針を確認すること。
- マルウェア別の解析コード、ドキュメント、設定、結果を扱う場合は、対象マルウェア配下の `AGENTS.md` と README/docs を先に確認すること。
  - ValleyRAT 関連の作業では `analysis-framework/malware/valleyrat/AGENTS.md` を必ず読むこと。
  - ValleyRAT のワークフローやパターン判断では `analysis-framework/malware/valleyrat/docs/VALLEYRAT-WORKFLOW.md` と `analysis-framework/malware/valleyrat/docs/PATTERN-DESIGN.md` も参照すること。
- 公開可能な解析結果を扱う場合は `analysis-results/README.md` と対象種別の `analysis-results/<malware-type>/README.md` を確認すること。

## リポジトリ構成ルール

- 解析コードは `analysis-framework/` に置くこと。
- マルウェア種別固有のコード、設定、ドキュメント、テストは `analysis-framework/malware/<malware-type>/` に置くこと。
- 公開可能な解析結果は `analysis-results/<malware-type>/cases/<sample-sha256>/` に置くこと。
- 新しいマルウェア種を追加するときに、`AAA-analysis/` のような独立トップレベルディレクトリを作らないこと。
- 共通化できる処理は `analysis-framework/common/`、分類器は `analysis-framework/classifiers/`、種別登録は `analysis-framework/registry/` に置くこと。

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
- 内容は `Type`、`Value`、`Role`、`Confidence`、`Source` の表だけとし、挙動説明、検知考察、Shodan/Sigma/YARAクエリ、一般的なコマンド名を混ぜないこと。
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

## Malware-analysis start/end safety gate

- Before opening, extracting, or analyzing a malware submission, run the read-only
  safety check with sample paths, hashes, and distinctive filenames as patterns.
- Run the same check again before declaring the analysis complete. Investigate any
  unexpected matching process, service, scheduled task, Run-key value, network
  connection, or active Microsoft Defender threat.
- The check must not execute, load, register, or make a network request from a sample.
- Safety-check output, snapshots, and reports are ephemeral operational data. They
  MUST NOT be written under this repository or committed to GitHub. Use stdout, or
  an outside-repository temporary location only when transient retention is required.
- Do not declare completion while an unexplained execution or persistence indicator
  remains. Escalate the observation to the user without attempting destructive cleanup.

## Hash-only OSINT enrichment rules

- For low-confidence and unidentified cases, query exact hashes only by
  default. Never submit or upload a sample as a fallback, and never contact
  infrastructure extracted from a sample.
- Keep raw API/provider responses under ignored `.work/` storage. Publish only
  normalized evidence, sanitized references, source status, and confidence.
- Do not count an aggregator in addition to its named underlying providers.
  Require at least two independent agreeing providers for medium confidence.
- A one-provider label is a low-confidence lead. Preserve competing family
  labels as conflicts; a tie remains unknown. Missing OSINT is not benign
  evidence.
- Store reviewed manual research in hash-keyed curated evidence. Distinguish an
  exact-hash source from general family context and record provenance for both.
- Strip URL user information, queries, fragments, credentials, tokens, email
  addresses, raw provider fields, and recovered secrets from public output.
- Unit-test source normalization, aliases, confidence, conflict handling,
  secret sanitation, offline replay, and curated evidence before publication.

## Profile-defined multi-family analysis rules

- Put shared family markers, config keys, transport expectations, aliases, and
  confirmation requirements in `extractors/profiles/windows_family_profiles.json`.
  Keep family detector files as thin adapters; do not duplicate extraction logic.
- Treat a MalwareBazaar exact signature and reviewed hash as family-selection
  evidence, not proof that a literal is a decoded config or live C2.
- Classify network findings by role. Delivery-stage URLs may be IOCs but are not
  C2; public-IP discovery, certificate, documentation, placeholder, and benign
  vendor values are neither C2 targets nor standalone IOCs.
- Never create Shodan banner/hash, HTTP title, certificate hash, JARM, or liveness
  output without an actual authorized observation. Offline query strings must be
  labelled as passive plans only.
- MalwareBazaar acquisition must remain resumable. Persist exhausted transient
  failures in a hash-keyed retry queue and rerun them after other static work;
  never silently substitute an older sample for a selected newest hash.
- After a profile-family batch, run `validate_family_expansion.py`. Completion
  requires hash, routing, public-artifact, non-execution, and non-contact checks.
- Keep loopback emulators synthetic and explicitly non-wire-compatible. All bind
  and client targets must pass the shared literal-loopback validator.

## Deep static hard-case rules

- Use `analysis-framework/inventories/static-hard-cases.yaml` as the reviewed
  inventory. Authenticate every root and child by SHA-256 and preserve the
  parent/transform/child relationship.
- Keep this workflow static-only: do not execute samples or recovered layers,
  do not CPU-emulate native code or CIL, and do not contact extracted hosts.
- Analyze every recovered child as a separate layer. A packer/container result
  does not describe the terminal payload, and a missing expected child remains
  unresolved rather than absent.
- Treat CFG technique results as routing evidence. `not_observed` applies only
  to the bounded reachable graph; `suspected` is not confirmation. Confirm CFF
  only after recovering the dispatcher state and reproducible successor map.
- Suppress native CFF/VM attribution for a normal CLR entry thunk. Route managed
  images to metadata, CIL, and resource analysis. Treat UPX/MPRESS loader-stub
  graphs as packer-confounded until an authenticated child is analyzed.
- Prefer Ghidra MCP for static validation, always with an explicit program
  selector. Keep it localhost-only and leave arbitrary scripts disabled.
- Publish hashes, sizes, relationships, metrics, evidence, and explicit limits
  only. Never publish recovered raw binaries or the start/end host safety-check
  output.
