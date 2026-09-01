# 解析フレームワーク文書

## 次期宣言型基盤の設計

- [宣言型マルウェア解析基盤 設計](DECLARATIVE-ANALYSIS-ARCHITECTURE.md)
- [宣言型解析定義 スキーマ案](DECLARATIVE-SCHEMA-REFERENCE.md)
- [宣言型解析基盤への移行計画](DECLARATIVE-MIGRATION-PLAN.md)
- [宣言型エンジンのフェーズ1実装](DECLARATIVE-ENGINE-IMPLEMENTATION.md)

上記文書は設計段階の仕様であり、`asa/v1alpha1` の実装前にスキーマとモデルテストで固定する。

## 現行基盤

- [AI非依存の一括静的解析オーケストレーション](AI-FREE-STATIC-ANALYSIS-ORCHESTRATION.md)
- [識別・解析・公開・保管を接続する解析lifecycleの自動化](ANALYSIS-LIFECYCLE-AUTOMATION.md)
- [複数の解析lifecycleを統括する解析全体オーケストレータ](ANALYSIS-ORCHESTRATOR.md)
- [WebUI／ローカルAPI向け静的解析ジョブ契約](LOCAL-ANALYSIS-JOB-CONTRACT.md)
- [dailyマルウェア解析の3系統取込](DAILY-NEWS-MALWARE-INTAKE.md)
- [ClickFix／ClearFake 50件の収集・インフラ・Triage照合](../clickfix/README.md)
- [一括静的解析と解析器適用可否判定](ONE-SHOT-ANALYSIS.md)
- [静的復元オーケストレーション](STATIC-RECOVERY-ORCHESTRATION.md)
- [MalwareBazaar最新Windows検体の一括静的解析](MALWAREBAZAAR-WINDOWS-BATCH.md)
- [終端ペイロード・設定・C2解析の完了基準](C2-ANALYSIS-COMPLETION-STANDARD.md)
- [静的ロジック記録とコード類似性](STATIC-LOGIC-AND-CODE-SIMILARITY.md)
- [検体特徴、解析充足度、攻撃キャンペーン相関](CASE-KNOWLEDGE-CAMPAIGNS.md)
- [安全な提出物I/Oと一括処理ワークフロー](SAFE-SUBMISSION-IO.md)
- [ValleyRAT感染チェーンのパターン設計](../malware/valleyrat/docs/PATTERN-DESIGN.md)
- [ValleyRAT通信プロトコル解析とコード根拠](../malware/valleyrat/docs/COMMUNICATION-PROTOCOL-ANALYSIS.md)
- [プロファイル定義による10ファミリー拡張と構成要素の関係](PROFILED-FAMILY-EXPANSION.md)
- [難解析検体の静的深掘り解析](DEEP-STATIC-ANALYSIS.md)
- [ValleyRATワークフロー](../malware/valleyrat/docs/VALLEYRAT-WORKFLOW.md)
- [Nmap NSEによるC2稼働確認](../common/C2-LIVENESS.md)
- [Nmap C2 adapter、method対応、loopback検証](../nmap/README.md)
- [Stealer 6系統のC2 detectorとloopback emulator](STEALER-C2-DETECTION-EMULATION.md)
- [ValleyRAT／PureRATエミュレーターの実装状況](VALLEYRAT-PURERAT-EMULATOR-STATUS.md)
- [マルウェア外部通信の初期data要件](EXTERNAL-COMMUNICATION-DATA-REQUIREMENTS.md)
