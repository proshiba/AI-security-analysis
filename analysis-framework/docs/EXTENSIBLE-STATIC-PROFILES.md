# 拡張可能な静的解析プロファイル

## 目的

新しい検体で見つかったbyte変換やPEローダーの構造を、ファミリー専用Pythonへ毎回複製せず、安全な許可リストと宣言型JSONへ追加できるようにします。検体、復元レイヤー、CLR、CILは実行せず、外部インフラにも接続しません。

## 1. byte変換プロファイル

正本は `unpackers/profiles/byte_transforms.json`、実装は `unpackers/profiled_transform.py` です。`static_unpacker.py` は入力形式に合うプロファイルだけを評価します。

形式によるfilterを共通hookで行うため、`data`だけでなくPE、ELF等のcanonical形式を対象とする宣言も通常の静的pipelineから評価できます。既存の早期拒否された破損containerとISO9660候補へは適用しません。既定のDonut宣言は従来通り`data`専用であり、他形式へ自動的に拡大しません。宣言の追加はレビュー済みの変換根拠と否定試験を必須とします。

共通hookは現在layerの原本bytesへ適用します。容量膨張PEをcompact化した場合、そのbyte列は`pe-inflated-gap-removed`の独立childです。profileはchildの再帰stepで評価し、原本→compact→profile出力という二段階のSHA-256親子関係を保持します。compactの変換結果を、原本に直接適用した結果として記録しません。

利用できる操作は次の許可リストに限定されます。

- byte列の反転
- 左または右ローテート
- 単一byte XOR
- 繰り返し鍵XOR
- 上限付きslice

復元結果は、次のいずれかの構造検証に成功した場合だけ子レイヤーになります。

- 厳格なDonut call-over-instance構造
- 指定offsetのmagic
- 構造的に有効なPE
- 構造的に有効なZIP

未知のoperation、validator、範囲外の鍵、空の変換結果、上限超過は拒否します。任意Python、式評価、subprocess、ネットワーク処理をプロファイルから呼び出すことはできません。

複数プロファイルの処理量・保持量・経過時間は共有予算で制限します。設定JSONは重複keyと未知keyを拒否し、cacheは検証した文書bytesへ束縛します。予算超過時は既存候補と未評価を分離し、解析完了にはしません。詳細は[宣言型byte変換の共有予算と設定検証](DECLARATIVE-TRANSFORM-BOUNDS.md)を参照してください。

### 追加手順

1. 変換順、鍵、offsetを逆コンパイル結果から確定します。
2. `byte_transforms.json` に一意なID、対象形式、上限、operation、validator、artifact kindを追加します。
3. 正例、ノイズ、境界超過、壊れたプロファイルのテストを追加します。
4. `static_unpacker.py` と `common/analyze_sample.py` の一括解析で、復元SHA-256と親子関係を検証します。
5. 復元できたことと最終ペイロードを識別できたことを分離して記録します。

## 2. PE構造プロファイル

正本は `analysis-framework/registry/pe_structural_profiles.json`、実装は `analysis-framework/common/pe_structural_profile.py` です。ファミリーの `detect.py` は薄い互換アダプターに保ちます。

一つのプロファイルは、必要に応じて次の証拠軸を組み合わせます。

- レビュー済みSHA-256完全一致
- 必須エクスポート集合
- import、ASCII、UTF-16LEから得たAPIマーカー
- type、ID、XOR鍵、magicを固定したリソース検証

完全一致ハッシュは `high`、構造一致は最大でも `medium` です。構造一致では、宣言したエクスポート、API最小件数、すべてのリソース条件を満たす必要があります。一つでも欠ける場合は未一致です。

### 追加手順

1. ファイル名や単一文字列ではなく、独立した構造証拠を最低2軸選びます。
2. 復号リソースを使う場合はtype、必要ならID、鍵、plaintext magicを固定します。
3. `pe_structural_profiles.json` へ追加し、ファミリー `detect.py` からプロファイルIDを指定します。
4. 正例、証拠軸が一つ欠ける負例、一般的な正規PE、壊れたPEをテストします。
5. classifierが受理する `high`、`medium`、`low` だけを一致時のconfidenceに使います。

## 3. 静的レイヤーパイプライン

`analysis-framework/common/static_layer_pipeline.py` は、unpackerの `(report, artifacts)` 共通契約を、SHA-256で認証した親子レイヤーへ変換します。one-shot CLI以外の一括解析やGhidra準備処理でも同じ実装を再利用できます。

`StaticLayerPolicy` で次をまとめて指定します。

- 最大レイヤー数
- 最大深度
- レイヤー単体の最大サイズ
- 復元総量
- アーカイブ圧縮率

レイヤー重複、非bytes、壊れたartifact tuple、単体・総量・件数の上限超過は理由付きで拒否します。公開レポートにはバイト列を含めず、親SHA-256、変換名、深度、形式、制限イベントだけを残します。

managed PEでは、参照metadataとmethod bodyのlexical参照走査が明示的に完了していない場合、PE summaryの`analysis_coverage`を`partial`へ伝播します。`managed_lexical_references_complete`はこの静的走査範囲だけの判定です。全命令を走査しても、未解決参照や`calli`の実行時targetは別に残り、runtime dispatch、到達性、ファミリー、設定C2の確定を意味しません。native PEでは同条件を適用せず、この値は`null`です。

## 検証

```powershell
$Python = 'C:\Users\Administrator\Tools\Python313\python.exe'

& $Python -m pytest .\unpackers\tests -q
Push-Location .\analysis-framework
& $Python -m pytest .\tests\test_pe_structural_profile.py .\tests\test_static_layer_pipeline.py .\tests\test_one_shot_hardening.py -q
Pop-Location
```

実検体を使う統合確認では、隔離済み入力を読み取るだけにし、復元byteをリポジトリへ保存しません。期待SHA-256、`executed_sample: false`、`network_contacted: false` を必ず確認します。

## 過去の失敗から改善対象を選ぶ

[全履歴metadata監査](AUTOMATION-FAILURE-INVENTORY.md)は、公開catalogの記録だけを読み、設定・family・終端・静的layer等の不足と、旧形式・欠落した記録を分けます。[人間レビュー専用の再解析計画](AUTOMATION-REANALYSIS-PLAN.md)は、そのsnapshotと現在の証拠を照合し、追加解析候補と記録修復を有界に列挙します。検体の探索、jobの起動、同じworkflowのresume、C2通信は行いません。

この集計は記録状態の監査であり、実検体の抽出成功率を新たに測定するものではありません。新しい復元・抽出profileは、この不足理由を再現する合成fixtureと境界試験で検証し、実検体に適用した成果とは区別して報告します。

## managed解析の共通境界

[有界managed metadata参照](../../docs/MANAGED-METADATA-REFERENCE.md)は、token、署名、MethodSpec、参照coverageと限定framework APIの宣言照合を共通化します。[managed RAT設定の静的回収](MANAGED-RAT-CONFIG-STATIC-SAFETY.md)では、直列literal代入を通常の成功mapと部分観測に分けます。[TripleDES／GZIP resource復元](../../docs/MANAGED-TRIPLEDES-GZIP-REFERENCE.md)はclassic .NETの型別identityを照合し、既存の限定復元レシピを維持します。

宣言一致は実行時assembly真正性、virtual dispatch、無例外性、副作用なしの証明ではありません。未知の初期化効果を無視して設定を確定したり、復元した候補だけでファミリーや終端を確定したりしません。
