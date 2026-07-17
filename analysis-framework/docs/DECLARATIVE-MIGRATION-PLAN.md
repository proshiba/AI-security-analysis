# 宣言型解析基盤への移行計画

## 1. 方針

全面書き換えは行わず、現行 CLI の外側に次期 engine を置き、機能単位で置換する。
各段階で既知検体の classification、主要 artifact hash、C2/config finding、safety marker を比較し、
同等性を確認してから旧経路を縮小する。

## 2. 移行前 baseline

実装開始前に、現行コードで次を固定する。

- 全 unit test の結果
- 既知検体ごとの classification JSON
- batch run summary と completed stages
- 公開済み case の file/network IOC
- 復号 artifact の期待 SHA-256（bytes は commit しない）
- Sigma/YARA validator の結果
- `executed=false`、`network_contacted=false` の safety assertions

baseline は機密値と検体を含まない golden JSON として `tests/golden/legacy/` に置く。

## 3. フェーズ1: エンジンの骨格

実装:

- `src/asa` package、CLI、definition loader
- JSON Schema/Pydantic models
- condition DSL
- step/tool catalog
- policy compiler
- DAG compiler と dry-run `plan`
- run/artifact/finding model

完了条件:

- すべての definition を実行せず compile できる。
- 未登録 step、未知 fact path、循環 DAG、禁止 capability を CI が拒否する。
- YAML から任意 command/module path を指定できない。

## 4. フェーズ2: 汎用静的解析ステップ

最初に重複の多い処理を移す。

| 現行 | 次期 step |
|---|---|
| `malware_io.py` | `intake.submission`、成果物ストアの基本処理 |
| `analyze_submission.py` | `containers.inventory` + `static.pe.inspect` |
| `analyze_family_sample.py` | inventory、strings、IOC、script、PE に分割 |
| entropy 実装群 | `static.bytes.metrics` |
| strings/IOC 実装群 | `static.strings.extract`, `static.ioc.extract` |
| PE/resource 実装群 | `static.pe.inspect`, `static.pe.resources` |
| script tools | `scripts.layers`, `scripts.logic`, `scripts.vbs_trace` |
| ISO/MSI/CAB tools | `containers.iso`, `containers.msi`, `containers.cab` |

旧 CLI は同名の wrapper とし、引数を次期 CLI/context へ変換する。

完了条件:

- 同一 test vector に対して hash、member graph、PE metadata、IOC が baseline と一致する。
- すべての step が共通 safety/provenance metadata を返す。

## 5. フェーズ3: AgentTesla／RemcosRAT

この二つは現在同じ batch runner と多くの汎用 script 処理を共有しているため、最初の family 移行対象とする。

実装:

- `agenttesla.yaml`、`remcosrat.yaml`
- 既知 hash mapping を detector Python から case/index data へ移す。
- loader campaign rules を YAML 化する。
- AgentTesla 固有 payload recovery/config extraction を狭い family step として catalog 登録する。
- sensitive config は別 storage class と redaction policy を維持する。

完了条件:

- 各10検体の family/campaign が baseline と一致する。
- script、ISO、direct PE の分岐が compiled plan で説明できる。
- 回収不能 case は誤って成功扱いにせず `partial` または `needs_review` になる。

## 6. フェーズ4: ValleyRAT

ValleyRAT は campaign variant と reviewed profile が多いため、generic step の安定後に移す。

移行順:

1. `dll_sideload_vvas_bundle`
2. `msi_embedded_cab_custom_actions`
3. generic `single_pe`
4. N520 managed config
5. SilverFox/UPX/Qt 等の追加 variant

実装:

- campaign 判定規則を構造 facts へ変換する。
- profile の `default_stages`、FLOSS/Ghidra target、vvaS values を case YAML へ移す。
- XOR、vvaS decode、N520 config、SilverFox recovery を step catalog へ移す。
- active C2 は family pipeline から分離し、approved enrichment workflow とする。

完了条件:

- 既知11検体で、campaign、復号 hash、主要 C2/config finding が baseline と一致する。
- MSI/CAB の sideload relation と process-attributed evidence の相関が失われない。
- unknown variant が generic analysis 後に停止する。

## 7. フェーズ5: VenomRAT／MX-Go／unknown

実装:

- VenomRAT resource/.NET/native inspection を generic resource/PE/.NET steps と family marker rules に分ける。
- MX-Go の Go build info、embedded JSON、symbol marker を generic Go/static steps と cluster definition に分ける。
- `unclassified/<cluster>.yaml` を正式に registry へ参加させる。
- unknown pipeline と analyst review bundle を実装する。

完了条件:

- VenomRAT 7 case と MX-Go case の report material が baseline と一致する。
- MX-Go の detector callable 形式のような family ごとの interface 差がなくなる。
- unknown sample は既知 family に強制分類されない。

## 8. フェーズ6: ツール連携とレポート生成

実装:

- FLOSS、Ghidra MCP、JARM、YARA／Sigmaの検証アダプター
- tool preflight と version capture
- finding normalizer
- README、IOC、検知材料、マニフェスト、履歴候補の生成器
- publish allowlist/denylist と secret/binary scan

完了条件:

- tool 欠如時の plan と report に理由、影響、確認点が表示される。
- Ghidra MCP は loopback と explicit selector を強制する。
- report は confirmed/inferred/unverified と delivery/C2 role を分離する。

## 9. フェーズ7: 切り替え

1. `Invoke-Analysis.ps1` と `Invoke-FamilyBatch.ps1` を新 CLI の wrapper にする。
2. README の実行例を `asa analyze` と `asa plan` へ切り替える。
3. 2リリース相当の互換期間を置く。
4. CI と既知検体回帰が安定後、旧 family CLI を deprecated にする。
5. 旧コード削除は別 PR とし、移行対応表を残す。

## 10. テスト戦略

### スキーマテスト

- 正常な全 YAML を parse/validate
- unknown field、重複 ID、無効 version、秘密 literal を拒否
- campaign pipeline reference と case reference の整合性

### コンパイラーテスト

- family/campaign score と tie
- `all/any/not` 条件
- artifact dependency と DAG order
- cycle、missing output、unknown fact の拒否
- policy ceiling が case/runtime override より優先されること

### ステップ契約テスト

- input/output model
- deterministic output
- ハッシュ不一致時の即時停止
- 危険なアーカイブパス、サイズ上限、エンコーディングの境界事例
- timeout、partial、blocked、failed の状態変換

### ゴールデンプランテスト

実検体 bytes を repository に置かず、公開可能な discovery facts fixture から plan を compile し、
family/campaign、step order、required tools、capability を snapshot 比較する。

### 結合テスト

- 合成 ZIP/PE/script fixture
- fake FLOSS/Ghidra/tool adapters
- fake passive API
- loopback-only protocol emulator
- resume/cache と implementation version invalidation

### 安全性テスト

- offline policy で socket/subprocess network を拒否
- active target step は reviewed target + policy + approval の三条件を要求
- executable/decrypted bytes/Ghidra project を publish できない
- sensitive fields が stdout、run JSON、report に漏れない
- YAML に command/module path を書いても schema が拒否

## 11. CIゲート

各 PR で最低限次を実行する。

```text
format/lint
unit tests
schema validation
definition compile --all --offline
golden plan comparison
safety tests
Sigma parse + YARA compile
git diff --check
publishable tree binary/secret scan
```

## 12. リスクと対策

| リスク | 対策 |
|---|---|
| YAML が巨大化する | base workflow、pipeline include、共通 step defaults。継承は一段に制限 |
| 条件規則が読みにくい | reason ID、generated decision table、plan explain |
| plugin が再び巨大化する | 一つの変換/観測に限定し、typed I/O と cyclomatic complexity gate |
| 出力互換性が崩れる | normalized model と legacy export adapter、golden comparison |
| 外部ツール版差 | version constraint、tool metadata、optional/required の区別 |
| case override が安全制約を迂回 | policy ceiling と schema-level deny |
| cache が古い結果を返す | input hash + definition digest + step implementation version |
| family label に引きずられる | two-stage routing、unknown threshold、negative evidence |

## 13. 実装PRの分割案

1. Models/schema/definition validator
2. Condition DSL/DAG compiler/dry-run
3. Artifact store/policy/runner
4. Generic intake/container/static steps
5. AgentTesla／Remcosの定義と互換ラッパー
6. ValleyRATの定義とファミリー固有ステップ
7. VenomRAT/MX-Go/unknown definitions
8. Tool adapters
9. Reporting/publish/history generation
10. Legacy removal

各 PR は単独で testable にし、family の一部だけが新 engine を使う期間を許容する。

## 14. 最終受入条件

- 解析の実行順、分岐理由、必要ツールを Python/PowerShell を読まずに YAML と generated docs から説明できる。
- ファミリー追加時の標準作業が definition、必要最小限の step plugin、fixture、docs 追加になる。
- 既知全 case の分類と主要 finding が baseline 以上の品質で再現される。
- 同じ共通処理が family ごとに複製されていない。
- offline-default で検体実行と外部通信が技術的に拒否される。
- すべての公開 finding に provenance、confidence、limitations がある。
