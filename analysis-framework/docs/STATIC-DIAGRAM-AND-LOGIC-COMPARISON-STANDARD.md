# 静的解析図と全体ロジック比較の標準

## 目的

検体ごとの実行フロー、感染チェーン、モジュール関係を同じ粒度で記録し、別検体との共通点と相違点を目視・機械処理の両方で比較できるようにします。

図は静的証跡の要約です。動的実行の再現、ファミリー帰属、campaign帰属、actor帰属を図だけで確定しません。

## 必須の3図

`OVERALL-LOGIC.md`の`## 静的可視化`には、次の順序と見出しで3図を置きます。

1. `### 実行フロー`
2. `### 感染チェーン`
3. `### モジュール関係`

図の役割は次のとおりです。

| 図 | 表現するもの | 正本 |
|---|---|---|
| 実行フロー | 入口、復号、展開、解析回避、収集、送信などの処理段階と観測call edge | `static-logic.json`の`overall_logic` |
| 感染チェーン | 提出物、静的復元層、親子関係、復元変換 | `static-layers.json` |
| モジュール関係 | loader、runtime、payload、collector、senderなどの役割と依存関係 | `program_evidence`とreview済み補足証跡 |

## 共通表現

### ノードID

Mermaid内部のノードIDは、検体固有名ではなく次のprefixを使用します。

- `exec_`: 実行段階
- `chain_`: 提出物と復元層
- `module_`: programまたは論理モジュール
- `unknown_`: 未観測または未解決

表示ラベルには、可能な範囲で`役割 / 技術・形式 / 確度`を記載します。完全hash、C2、資格情報、private pathは図へ直接埋め込みません。

### 線

| 表現 | 意味 |
|---|---|
| `-->` | 静的に確認したcall、親子、復元、依存関係 |
| `-.->` | 未観測、親未特定、順序未解決、review中の関係 |

段階の掲載順だけを実線へ変換しません。動的観測だけに基づく関係は、静的図へ混在させず説明文で区別します。

### 色

- 緑: 静的証跡で確認済み
- 黄: 未観測、未解決、追加レビューが必要

色だけに意味を依存させず、線種と日本語ラベルも併用します。

## 共通の実行段階ID

`overall_logic.phases[].phase_id`は、該当する場合に次のIDを優先します。

| phase ID | 内容 |
|---|---|
| `delivery` | 配布物、添付、ダウンロード、初期侵入 |
| `script_execution` | JScript、PowerShell、VBS等の起動 |
| `payload_decoding` | 復号、復元、展開、resource抽出 |
| `loader_execution` | loader、runtime、entrypoint、初期化 |
| `defense_evasion` | sandbox、VM、debugger、AMSI／ETW回避 |
| `persistence` | Run key、service、scheduled task等 |
| `process_memory` | process生成、injection、memory確保・保護変更 |
| `credential_collection` | browser、mail、password等の収集 |
| `input_capture` | キー入力記録、clipboard、screenshot |
| `host_discovery` | host識別、OS、hardware、user情報 |
| `staging` | report生成、圧縮、一時保存 |
| `command_control` | C2初期化、送受信、command処理 |
| `exfiltration` | FTP、SMTP、HTTP等による送信 |
| `file_operations` | file作成、移動、列挙、読み書き |
| `cleanup` | 一時file削除、self-delete、痕跡整理 |

複数の役割を持つ関数は、主目的の段階へ置き、副作用を説明文に残します。証跡に合わないIDへ無理に正規化しません。

## 比較プロファイル

機械比較では次の独立軸を使用します。

| 軸 | 比較対象 |
|---|---|
| 実行段階 | 共通phase ID |
| 感染・復元層 | 親形式、変換方式、子形式 |
| モジュール構成 | root、runtime、recovered payload等の関係と形式 |
| 機能・挙動 | `features.json`の構造化ID |
| 代表関数の役割 | `static-logic.json`の`role` |
| コードfingerprint | 十分なsemantic tokenを持つ関数fingerprint |

同一ファミリー名、同一tag、単一IP、単一domain、単一file nameは比較軸に数えません。最低2つの独立軸が一致した場合だけ類似候補として保持します。

比較索引は次のコマンドで更新します。

```powershell
py -3.13 .\analysis-framework\common\generate_logic_similarity_index.py --repository . --write
py -3.13 .\analysis-framework\common\generate_logic_similarity_index.py --repository . --check
```

出力は次の2ファイルです。

- `analysis-results/catalog/logic-similarity.json`
- `analysis-results/catalog/LOGIC-SIMILARITY.md`

## `OVERALL-LOGIC.md`の比較節

新規caseでは、3図の後に次を記録します。

### 比較プロファイル

- 共通phase ID
- 復元層の形式と変換方式
- moduleの役割
- 特徴的な機能・挙動
- 比較可能なコードfingerprintの有無

### 他ケースとの比較

候補ごとに次を記録します。

- 相手caseのSHA-256短縮表記と参照先
- `高`、`中`、`参考候補`のreview優先度
- score
- 一致した独立軸
- 顕著な相違点
- campaign／actor同一性を確定しない旨

候補がない場合も「比較可能な候補なし」と記録し、構造化成果物不足なのか、本当に一致がないのかを区別します。

## 判定の扱い

- `高`: 3軸以上が一致し、コードまたは強い層構造の一致を含む。
- `中`: 2軸以上が一致し、追加レビューに十分な候補。
- `参考候補`: 2軸以上は一致するが、共通runtimeやbuilderの影響を強く受け得る。

これらはレビューの優先度です。コード共有、builder共有、packer共有、共通libraryでも一致するため、最終判断では配布文脈、時系列、設定形式、通信、署名、IOCを追加相関します。
