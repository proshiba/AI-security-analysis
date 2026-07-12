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

## 検証ルール

- YAMLを編集した場合は、利用可能なパーサで構文と期待するトップレベル構造を検証すること。
- Markdownを編集した場合は、少なくとも `git diff --check` で空白・フォーマット問題を確認すること。
- スクリプトや解析コードを変更した場合は、該当READMEまたはドキュメントに書かれたテストを優先して実行すること。
- 依存関係不足や環境制約で検証できない場合は、実行したコマンド、失敗理由、代替検証を明記すること。

## 作業後の報告

- 変更したファイル、実行した検証、未検証事項を簡潔にまとめること。
- ドキュメント変更でも、解析安全ルールや履歴サマリの整合性に影響がある場合はその点を明記すること。
