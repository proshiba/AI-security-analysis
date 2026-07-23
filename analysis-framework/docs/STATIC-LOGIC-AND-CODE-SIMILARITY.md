# 関数ロジック解析とコード類似性

今後のcase解析では、IOC、挙動要約、YARA／Sigmaとは別に、関数・処理単位の
静的ロジックを標準成果物として残します。目的は、後から同じ復号器、設定parser、
通信dispatcher、永続化処理、攻撃handlerなどを検体横断で比較できるようにすることです。

## 必須成果物

新規caseと、静的解析を更新した既存caseには次を置きます。

- `static-logic.json`: 関数、call graph、制御構造、API列、正規化fingerprintの機械可読成果物
- `STATIC-LOGIC.md`: 関数の役割と処理順を日本語で確認できる人向け成果物

`FEATURES.md` は挙動・検体特徴だけ、`STATIC-LOGIC.md` は関数内部の処理だけを扱います。
IOC値、ファミリーOSINT、検知ルールを関数ロジック成果物へ混在させません。

## 関数単位で残す情報

少なくとも次を記録します。

- 関数名、address／metadata token、entrypointとの関係
- 日本語の役割と要約
- 入力確認、復号、分岐、loop、子関数呼出、結果利用までの処理順
- caller、callee、外部API／managed method
- 条件分岐、loop、例外処理、returnの個数
- 定数の役割。資格情報、token、具体的なC2値は除外する
- 解析tool、根拠、確度
- Ghidraの場合は明示的な `program_selector`
- 未解決のindirect call、dispatcher、例外flow、packer影響

生の逆コンパイル全文は既定で公開しません。比較用には、string literal、address、数値、
Ghidraの自動関数名、local変数名を正規化したロジックだけを保持します。

## 類似性fingerprint

各関数には次の3種類を生成します。

- `normalized_logic_sha256`: 正規化ロジック全体の完全一致用
- `semantic_sequence_sha256`: 制御構造、演算子、call形状の列による完全一致用
- `semantic_simhash64`: 小さな変更やaddress差を許容する近似比較用

一致はコード共有の手掛かりです。共通library、compiler生成処理、builder共有でも一致するため、
fingerprintだけでファミリー、actor、campaignを確定しません。call graph、API、設定形式、
配布文脈、IOCなどの独立証拠と相関します。

## Ghidra MCPでの記録手順

1. SHA-256で対象programを確認します。
2. すべてのGhidra MCP呼出しへ明示的なprogram selectorを渡します。
3. entrypoint、設定decoder、通信初期化、dispatcher、永続化、anti-analysis、主要handlerを優先します。
4. 各関数のdecompile、caller／callee、参照、型、主要分岐を確認します。
5. addressだけでなく、処理順と未解決edgeを日本語で記録します。
6. レビュー済み関数recordをJSONへ保存し、標準成果物へ変換します。

任意Ghidra script実行は既定で無効のままにします。MCPが公開していない操作だけをUIで補います。

review済みsource JSONの例です。

```json
{
  "functions": [
    {
      "name": "decode_config",
      "address": "0x00401230",
      "role": "config_decoder",
      "summary_ja": "resource内の設定blobを復号して設定項目へ分割します。",
      "logic_steps_ja": [
        "入力長とmagicを確認します。",
        "鍵導出後に復号処理を呼び出します。",
        "復元bufferを設定項目へ分割します。"
      ],
      "pseudocode": "レビュー対象関数のpseudocode",
      "callees": ["derive_key", "decrypt_blob", "parse_fields"],
      "api_calls": ["CryptDecrypt"],
      "source": "ghidra-mcp",
      "tool": "ghidra-mcp",
      "program_selector": "sha256:<対象SHA-256>",
      "confidence": "confirmed_static_decompilation"
    }
  ]
}
```

標準成果物への変換例です。

```powershell
python .\analysis-framework\common\record_static_logic.py `
  --repository . `
  --case-dir .\analysis-results\malware\<family>\versions\<version>\cases\<sha256> `
  --source-json .\.work\<sha256>-reviewed-functions.json `
  --write
```

公開成果物へ変換するsource JSONを `.work/` に置く場合は、`record_static_logic.py` の入力制約に
合わせてリポジトリ内の無視対象領域を使います。生のGhidra projectや検体はコミットしません。

## 一括解析での扱い

`common/analyze_sample.py` は今後、すべてのcaseに `static-logic.json` と
`STATIC-LOGIC.md` を生成します。

- scriptは実行せず、関数定義またはtop-level処理を上限付きで抽出する
- string literalや具体的なIOCを除外してfingerprintを作る
- binaryで関数解析をまだ実施できない場合は `function_analysis_required` を明示する
- binaryの解析完了条件には、Ghidra等でレビューした関数recordへの更新を含める

状態は次のように区別します。

- `function_analysis_required`: 関数境界や逆コンパイル結果が未記録
- `automated_script_structure`: script構文からの自動抽出で、意味レビューは未完了
- `function_logic_review_required`: 関数recordはあるが、役割、処理順、tool、program selector、確度のいずれかが不足
- `reviewed_function_logic`: 必須証拠を持つレビュー済み関数record

空のplaceholderや証拠不足の関数recordを「関数解析完了」とは扱いません。

## リポジトリ横断の類似性索引

```powershell
python .\analysis-framework\common\generate_code_similarity_index.py --repository . --write
python .\analysis-framework\common\generate_code_similarity_index.py --repository . --check
```

出力は次の2つです。

- `analysis-results/catalog/code-similarity.json`
- `analysis-results/catalog/CODE-SIMILARITY.md`

同一case内の関数一致は除外します。同一ファミリーでは0.86、ファミリー横断では0.94を
既定の近似閾値とし、横断一致には共有APIも要求します。最終判断は必ず解析者が行います。
