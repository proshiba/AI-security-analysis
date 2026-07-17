# 宣言型解析定義 スキーマ案

本書は `asa/v1alpha1` の設計用リファレンスである。実装前に JSON Schema と model tests で固定する。

## 1. マルウェア定義

```yaml
api_version: asa/v1alpha1
kind: MalwareAnalysisDefinition
metadata:
  id: valleyrat
  display_name: ValleyRAT
  definition_version: 1.0.0
  owners: [malware-research]
  status: proposed

classification:
  family:
    threshold: 70
    tie_policy: unknown
    rules:
      - id: reviewed_outer_hash
        weight: 100
        when:
          fact: submission.sha256
          in_ref: cases.reviewed_outer_hashes
      - id: family_marker
        weight: 35
        when:
          fact: static.strings.normalized
          contains_any: [ValleyRAT, vvaS.bin]
  campaigns:
    - id: dll_sideload_vvas_bundle
      threshold: 80
      rules:
        - id: required_members
          weight: 100
          when:
            fact: container.member_names_ci
            contains_all: [chgport.exe, loggercollector.dll, vvas.bin]
      pipeline: valleyrat.dll_sideload_vvas_bundle
    - id: msi_embedded_cab_custom_actions
      threshold: 80
      rules:
        - id: msi_cab_pe
          weight: 100
          when:
            all:
              - {fact: container.has_msi_ole, equals: true}
              - {fact: container.ole_stream_types, contains_all: [cab, pe]}
      pipeline: valleyrat.msi_embedded_cab_custom_actions

fallback_pipeline: unknown.family_static
```

## 2. パイプライン定義

```yaml
api_version: asa/v1alpha1
kind: AnalysisPipeline
metadata:
  id: valleyrat.dll_sideload_vvas_bundle
  version: 1.0.0

requires:
  tools:
    - {id: floss, version: ">=3,<4", optional: true}
    - {id: ghidra-mcp, version: ">=1", optional: true}
  capabilities:
    - filesystem.sample.read
    - filesystem.quarantine.write

steps:
  - id: intake
    uses: intake.submission@^1
    with:
      password_ref: runtime.archive_password
    outputs:
      graph: artifact_graph

  - id: inventory
    uses: containers.inventory@^1
    needs: [intake]
    inputs:
      graph: steps.intake.outputs.graph

  - id: strings
    uses: static.strings.extract@^1
    needs: [inventory]
    foreach:
      items: facts.container.pe_artifacts
      as: artifact
    inputs:
      artifact: foreach.artifact

  - id: floss
    uses: external.floss.analyze@^1
    needs: [inventory]
    when:
      fact: tools.floss.available
      equals: true
    foreach:
      items: facts.campaign.floss_targets
      as: artifact
    inputs:
      artifact: foreach.artifact
    on_error: partial

  - id: ghidra_import
    uses: external.ghidra_mcp.import_analyze@^1
    needs: [inventory]
    when:
      all:
        - {fact: tools.ghidra-mcp.available, equals: true}
        - {fact: tools.ghidra-mcp.bound_to_loopback, equals: true}
    foreach:
      items: facts.campaign.ghidra_targets
      as: artifact
    inputs:
      artifact: foreach.artifact
    with:
      selector_template: "sha256:{artifact.sha256}"
      allow_scripts: false
    on_error: partial

  - id: decrypt_vvas
    uses: family.valleyrat.vvas_xor@^1
    needs: [inventory]
    inputs:
      artifact: facts.campaign.vvas_artifact
    with:
      key_ref: case.vvas.xor_key
      expected_sha256_ref: case.vvas.expected_plain_sha256
    outputs:
      plaintext: vvas_plaintext

  - id: decode_vvas
    uses: family.valleyrat.vvas_decode@^1
    needs: [decrypt_vvas]
    inputs:
      artifact: steps.decrypt_vvas.outputs.plaintext
    with:
      marker_ref: case.vvas.marker

  - id: report
    uses: reporting.case_report@^1
    needs: [strings, floss, ghidra_import, decode_vvas]
    run_if: always
```

## 3. 条件DSL

条件 node は次のいずれか一つだけを持つ。

- leaf: `fact` と operator 一つ
- `all`: 条件リスト
- `any`: 条件リスト
- `not`: 否定する条件

operator:

| 演算子 | 入力 | 意味 |
|---|---|---|
| `exists` | bool | fact path の存在 |
| `equals` | scalar | 型を含む完全一致 |
| `in` | list | scalar が list 内に存在 |
| `in_ref` | reference | 外部 data set 内に存在 |
| `contains` | scalar | list/string に存在 |
| `contains_any` | list | 一つ以上を含む |
| `contains_all` | list | 全てを含む |
| `matches` | bounded regex | 正規表現一致 |
| `gt/gte/lt/lte` | number | 数値比較 |

fact path は model で宣言済みの namespace のみ参照可能とし、存在しない path は compile error にする。

## 4. ステップのフィールド

| フィールド | 必須 | 内容 |
|---|---:|---|
| `id` | yes | pipeline 内で一意 |
| `uses` | yes | allowlisted step ID と version constraint |
| `needs` | no | 依存 step。artifact reference からも補完 |
| `when` | no | 実行条件。既定 true |
| `inputs` | step依存 | artifact/fact reference |
| `with` | no | step model が許可する非機密 parameter |
| `foreach` | no | bounded artifact list に対する fan-out |
| `outputs` | no | 論理出力の別名 |
| `on_error` | no | `fail`、`partial`、`block`。既定 `fail` |
| `timeout` | no | step spec 上限以下のみ指定可能 |
| `run_if` | no | `success` または `always`。report/cleanup 用 |

`foreach` の最大件数は policy で制限する。definition が無制限 fan-out を作れないようにする。

## 5. ツール定義

```yaml
api_version: asa/v1alpha1
kind: ToolDefinition
metadata:
  id: floss
  version: 1
adapter: floss
discovery:
  windows:
    commands: [floss.exe, floss]
  linux:
    commands: [floss]
version_probe:
  operation: version
accepted_versions: ">=3,<4"
operations:
  analyze:
    timeout_seconds: 300
    max_input_bytes: 268435456
    output_media_types:
      - application/json
      - text/plain
capabilities:
  - external.floss
network: denied
sample_execution: denied
```

`commands` は tool adapter が理解する論理候補であり、pipeline YAML から任意引数を追加できない。

### Ghidra MCP definition の必須制約

```yaml
connection:
  transport: mcp
  host_policy: loopback_only
operations:
  import_analyze:
    require_explicit_program_selector: true
    arbitrary_scripts: denied
filesystem_scope:
  root: runtime.analyst_workspace
```

## 6. ポリシー定義

```yaml
api_version: asa/v1alpha1
kind: ExecutionPolicy
metadata:
  id: offline-default
capabilities:
  allow:
    - filesystem.sample.read
    - filesystem.quarantine.write
    - external.floss
    - external.ghidra_mcp
  deny:
    - network.passive_api
    - network.active_target
    - sample.execute
    - ghidra.arbitrary_scripts
    - sensitive.config.publish
limits:
  max_artifact_bytes: 268435456
  max_total_materialized_bytes: 1073741824
  max_foreach_items: 256
  max_parallel_steps: 4
  default_timeout_seconds: 300
```

deny は allow より優先する。runtime flag だけで deny を解除できない。別 policy と明示 approval record が必要。

## 7. ケース定義

```yaml
api_version: asa/v1alpha1
kind: ReviewedCase
metadata:
  sample_sha256: 8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6
review:
  reviewed_at: 2026-07-12
  reviewer: analyst
expected:
  inner_sha256: 8bf54a76924ad62e3b5562826f0e491c4c498f166276b071c177b694762199f6
classification:
  family: valleyrat
  campaign: dll_sideload_vvas_bundle
values:
  vvas:
    artifact_selector:
      basename_ci: vvas.bin
    xor_key: 20
    expected_plain_sha256: b2586edb216bdb27ffbf5be5c091c94c62df8d87500ceacdc519e3016f7d7e2a
    marker: odaktomk
live_targets:
  - host: 202.95.8.27
    port: 6666
    protocol: vvas
    reviewed: true
```

この `live_targets` は contact permission ではない。active-network policy、当該実行の approval、bounded
protocol step の三つが揃った時だけ plan に入る。

## 8. 出力レイアウト

```text
<run-root>/
  run.json
  plan.json
  facts.jsonl
  findings.jsonl
  artifacts/
    index.json
    evidence/
    publishable/
  steps/
    <step-id>/
      result.json
      stderr.txt
      stdout.txt
  report/
    README.md
    indicators.json
    detection-material.json
    manifest.sha256
```

`stdout/stderr` は secret redaction 後に保存する。quarantine artifact bytes は run-root 外の専用 store に置き、
`artifacts/index.json` から content-addressed reference だけを持つ。

## 9. 終了コード

| 終了コード | 状態 | 意味 |
|---:|---|---|
| 0 | succeeded | 必須 step 成功 |
| 10 | partial | 任意 tool/step が一部失敗 |
| 20 | needs_review | family/campaign unknown、analyst review が必要 |
| 30 | blocked | policy、approval、tool、reviewed value 不足 |
| 40 | invalid_input | hash/path/archive/schema 不正 |
| 50 | failed | 必須解析 step 失敗 |

## 10. 定義の作成ルール

1. family label 単独で campaign、decryptor、C2 protocol を選ばない。
2. hash rule と structural rule を別 reason として記録する。
3. generic step で表現できる処理に family-specific step を作らない。
4. family-specific step は一つの狭い変換だけを行い、I/O model と test vector を持つ。
5. 必須外部ツールは最小化し、欠如時の `partial`/`blocked` を定義する。
6. `network.active_target` は通常の family pipeline に入れず、明示 opt-in enrichment とする。
7. output artifact の publishability を必ず宣言する。
8. failure checks と analyst next action を metadata に持たせ、ドキュメント生成に利用する。
