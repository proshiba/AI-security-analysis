# 拡張可能な静的解析プロファイル

## 目的

新しい検体で見つかったbyte変換やPEローダーの構造を、ファミリー専用Pythonへ毎回複製せず、安全な許可リストと宣言型JSONへ追加できるようにします。検体、復元レイヤー、CLR、CILは実行せず、外部インフラにも接続しません。

## 1. byte変換プロファイル

正本は `unpackers/profiles/byte_transforms.json`、実装は `unpackers/profiled_transform.py` です。`static_unpacker.py` は入力形式に合うプロファイルだけを評価します。

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

## 検証

```powershell
$Python = 'C:\Users\Administrator\Tools\Python313\python.exe'

& $Python -m pytest .\unpackers\tests -q
Push-Location .\analysis-framework
& $Python -m pytest .\tests\test_pe_structural_profile.py .\tests\test_static_layer_pipeline.py .\tests\test_one_shot_hardening.py -q
Pop-Location
```

実検体を使う統合確認では、隔離済み入力を読み取るだけにし、復元byteをリポジトリへ保存しません。期待SHA-256、`executed_sample: false`、`network_contacted: false` を必ず確認します。
