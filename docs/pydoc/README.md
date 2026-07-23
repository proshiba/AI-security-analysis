# Python API文書

このディレクトリには、宣言的engineとルート `extractors/` の公開APIを標準libraryの `pydoc` で生成したHTMLとして収録します。

主な入口は次のとおりです。

- `asa.cli.html`：定義検証とplan compile
- `asa.runtime_cli.html`：offlineのend-to-end解析
- `asa.discovery.html`：安全な受付と正規化済みdiscovery
- `asa.runner.html`：allowlistに限定したoffline step実行
- `analyze_stealer_set.html`：認証済みmanifest SHA-256、封じ込めたarchive受付、family batchの静的解析
- `extractors.config_extractor.html`：統一family extractor API
- family固有の `extractors.*.extractor.html`

再生成は次のように行います。

```powershell
$env:PYTHONPATH = '<repo-root>\analysis-framework\src;<repo-root>\analysis-framework\common;<repo-root>'
cd <repo-root>\docs\pydoc
python -m pydoc -w asa asa.models asa.conditions asa.loader asa.catalog asa.compiler asa.cli `
  asa.discovery asa.runner asa.runtime_cli `
  malwarebazaar_batch analyze_stealer_set c2_candidate_detector generate_stealer_reports `
  generate_ioc_lists deep_static_triage `
  unpackers.static_unpacker unpackers.static_control_flow unpackers.managed_il_triage `
  unpackers.javascript_obfuscator unpackers.javascript_dropper_unpacker unpackers.nsis_unpacker `
  emulators.stealers.lab `
  extractors extractors.common extractors.config_extractor extractors.stealer_common `
  extractors.formbook.extractor extractors.vidar.extractor `
  extractors.lummastealer.extractor extractors.remusstealer.extractor `
  extractors.amosstealer.extractor `
  extractors.valleyrat.extractor extractors.agenttesla.extractor `
  extractors.remcosrat.extractor extractors.venomrat.extractor `
  extractors.unclassified.mx_go.extractor
```

実装変更後に再生成してください。testでは、公開functionのdocstringと、各対象moduleに対応するHTML artifactを検証します。

## 深層静的解析module

- `deep_static_triage.html`：範囲限定のinventory orchestration、memory内layer復元、公開可能なreport
- `unpackers.static_control_flow.html`：範囲限定のnative PE／raw x86 control-flow triage
- `unpackers.managed_il_triage.html`：範囲限定の.NET metadata、IL、managed obfuscation triage
- `audit_analysis_coverage.html`：repository内だけで行う完全性とartifact contractの監査
- `sanitize_public_results.html`：fail-closedの公開provider metadata／email sanitizer

## 静的ロジックmodule

- `static_logic.html`：関数、補完処理単位、Ghidra program構造の正規化と日本語成果物生成
- `record_static_logic.html`：レビュー済み関数recordのcase成果物化
- `generate_code_similarity_index.html`：意味fingerprintとGhidra opcode hashのcase横断相関
- `backfill_static_logic.html`：既存公開成果物と無害化済みGhidra構造による過去caseの一括補完
- `ghidra_function_batch.html`：Ghidra MCPとCIL parserによる代表関数一括静的解析と全体ロジック生成
- `validate_function_analysis.html`：全関数inventory、代表関数解析、全体ロジック、MCP成功証跡の完了条件検証
## 解析成果物レイアウトmodule

- `result_layout.html`：family／version／caseの固定構成、保守的な版根拠、collection／catalog、衝突・参照・rollback計画
- `normalize_result_layout.html`：既定read-onlyの計画CLIと、明示的な `--write` 適用入口
- `result_publication.html`：生成器から固定case配置、catalog、collection membershipを同期する共通公開処理

両moduleは公開済み成果物だけを読み、検体実行、CPU／CILエミュレーション、外部通信を行いません。詳細は [成果物レイアウト仕様](../../analysis-framework/docs/RESULT-LAYOUT.md) を参照してください。

これらのpageは、repository root、framework source、common moduleを `PYTHONPATH` に設定し、`docs/pydoc` から再生成します。

```powershell
python -m pydoc -w deep_static_triage unpackers.static_control_flow unpackers.managed_il_triage
```

## ShadowPadモジュール

- `extractors.shadowpad.extractor.html`：ScatterBeeとlegacy Casperの統一config抽出
- `extractors.shadowpad.legacy.html`：offline stream復号、QuickLZ展開、config parse

いずれも静的解析専用APIで、検体の実行や抽出endpointへの接続は行いません。

## PureHVNC／DonutLoaderモジュール

`unpackers.donut_unpacker`、`unpackers.purehvnc_unpacker`、`unpackers.chrd_donut_unpacker`、`extractors.purehvnc.extractor`、`extractors.donutloader.extractor`、`emulators.purehvnc.lab`、`c2_detector`、`chain` も生成対象です。

## APT-C-60／SpyGlaceモジュール

`repository_history_collector.html`、`unpackers.spyglace_unpacker.html`、`unpackers.apt_c60_delivery.html`、`extractors.spyglace.extractor.html`、`emulators.spyglace.lab.html` を含みます。

## 2026-04-01ニュース調査module

- `supply_chain_audit.html`
- `extractors.npm_supply_chain.extractor.html`
- `extractors.atlascross.extractor.html`
- `generate_ioc_lists.html`

## StealCモジュール

- `extractors.stealc.extractor.html`：v1 RC4 skip-keyとpaired-buffer XORによる設定抽出

## 現行family／復元module

- `extractors.amadey.extractor.html`
- `extractors.latrodectus.extractor.html`
- `unpackers.container_recovery.html`
- `unpackers.donut_wrapper_unpacker.html`
- `unpackers.index_xor_pe_unpacker.html`

生成APIは `analyze_stealer_set.html` と `generate_stealer_reports.html` にあるraw-directory batch modeと、公開可能な詳細report rendererも対象にします。

## 未分類batch／Electron復元module

- `malwarebazaar_unknown_batch.html`：newest-first tag収集、除外、再開、公開可能な取得metadata
- `analyze_unknown_set.html`：較正済みの静的family帰属、IOC sanitize、clustering、選択的cache refresh、report生成
- `update_unknown_analysis_history.html`：batch caseに対する冪等かつ保守的なhistory entry
- `unpackers.asar_unpacker.html`：範囲限定のASAR検証と復元
- `unpackers.electron_nsis_unpacker.html`：NSIS／Electron ASARに限定した復元

## profile定義型family拡張module

- `extractors.profiled_family.html`：共有の範囲限定config／IOC抽出とrole分類
- `profiled_family_detector.html`：exact hashと構造的family routing
- `scaffold_family_expansion.html`：薄いmoduleと宣言的定義の生成
- `generate_family_expansion_reports.html`：公開可能なcase、IOC、YARA生成
- `validate_family_expansion.html`：100 caseの整合性と安全性検証
- `emulators.common.html`：共有のliteral-loopback強制と範囲限定collector
- `emulators.families.lab.html`：wire互換ではないsynthetic family lab
- `unpackers.path_safety.html`：未信頼member pathの共有検証

公開functionを変更した場合は生成pageを更新します。pydoc testは各moduleをimportし、公開functionのdocstringと対応HTML anchorを検証します。

これらのmoduleは検体を実行せず、抽出インフラにも接続しません。

## Hash OSINTモジュール

- `osint_hash_enricher.html`：exact-hash収集、provider正規化、確度／競合処理、精査済み根拠、公開可能なreport

## 日本語化・OSINT・レイアウト監査module

- `audit_japanese_docs.html`：Markdownの日本語化監査
- `localize_result_markdown.html`：保護値を維持するtransactionalな成果物日本語化
- `render_malware_family_docs.html`：精査済みknowledgeからfamily README／OSINT／版一覧を決定的に生成
