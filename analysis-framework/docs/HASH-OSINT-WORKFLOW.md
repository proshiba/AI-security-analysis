# ハッシュ OSINT 補強ワークフロー

## 目的と安全境界

`common/osint_hash_enricher.py` は、信頼度が低い、または未識別の静的解析 case に対して、完全一致する SHA-256 のメタデータを照会し、監査可能な family 候補へ変換します。ファイルのアップロード、検体の実行、検体から抽出したインフラへの接続は行いません。provider の生応答は Git 管理対象外の `.work/` cache にだけ保持し、リポジトリへ出力するのは正規化した根拠だけです。

このワークフローは意図的に保守的です。

- family 固有の根拠を示す provider が 1 つだけの場合は、信頼度の低い候補とします。
- 信頼度を中にするには、互いに独立し、同じ family を示す provider が 2 つ必要です。
- aggregator と、その aggregator が明示した基礎 provider を重複して数えません。
- 競合する family 候補が 1 つでもあれば、結果の信頼度を低へ降格します。
- 同点は status を `conflicting`、family を `unknown` のままにします。
- 信頼度を高にするには、レビュー済みのローカル family 根拠も必要です。

## 入力と情報管理

情報源と安全ポリシーは `osint/hash_sources.yaml` で定義します。現在の adapter は次の情報源に対応しています。

| 情報源 | 保持する根拠 | 解釈 |
|---|---|---|
| MalwareBazaar | catalog/YARA label と、正規化した名前付き provider label | MalwareBazaar は転送元として扱い、名前付き provider はそれぞれ独立した情報源として扱う |
| OTX | pulse 名と tag | 全 pulse をまとめて community provider 1 票として扱う |
| CIRCL hashlookup | 既知ファイルの文脈 | malware family の票には使用しない |
| VirusTotal | popular classification と sandbox family label | 参照だけを行い、upload への fallback は行わない |

API から取得できない analyst 調査は、公開可能でハッシュを key とする YAML に保存し、`--curated-evidence` で指定します。各 record は `reviewed: true` でなければなりません。family に関する各観測には、provider、根拠の種類、長さを制限した label、強度、任意の query を含まない参照先を記録します。文脈用の参照先は保持しますが、family の票には変換しません。

```yaml
schema_version: 1
policy:
  sample_submission: prohibited
records:
  <sha256>:
    reviewed: true
    reviewed_at: YYYY-MM-DD
    evidence:
      - provider: external_researcher
        transport: external_research
        family: ExampleFamily
        label: Exact-hash report and distinctive static structure agree.
        strength: 4
        reference: https://example.org/report
      - provider: local_reviewed_static
        transport: local_static_review
        family: ExampleFamily
        label: Static review confirmed the distinctive structure.
        strength: 4
    context_references:
      - https://vendor.example/advisory
```

password、token、API key、URL の user information・query string・fragment、email address、復元した攻撃者の secret は含めません。検知に実値が不要な特徴的定数は、その値を公開せず特徴だけを記述します。

## 実行順序

検体 archive を読む前に開始時の安全 gate を実行します。静的 batch が `summary.json` を生成したら、未解決 case を補強します。batch の集約情報は `collections`、公開する case 単位の情報は固定深さの `malware/unclassified/versions/unknown/cases`、手動調査根拠は `research/osint` に分離します。

```powershell
python common/osint_hash_enricher.py `
  --summary ..\analysis-results\collections\<batch>\sources\unclassified\summary.json `
  --output ..\analysis-results\malware\unclassified\versions\unknown `
  --registry osint\hash_sources.yaml `
  --cache ..\.work\<batch>\osint-cache `
  --private-manifest ..\.work\<batch>\manifest.json `
  --history ..\analysis_history.yaml `
  --curated-evidence ..\analysis-results\research\osint\<batch>\research-evidence.yaml `
  --allow-network
```

1 つの情報源だけを更新する場合は `--source malwarebazaar --refresh` を使用します。cache にある他の情報源の応答は保持されます。API 応答の cache と curated evidence だけを使って network 接続なしで再生する場合は、`--allow-network` を省略します。任意の VirusTotal adapter は、設定済みの環境 credential を必要とします。credential がなければ利用不能として報告し、ファイル送信へ切り替えることはありません。

## 出力

- `analysis-results/malware/unclassified/versions/unknown/cases/<sha256>/osint-evidence.json`: 正規化した根拠、情報源の status、信頼度、競合、安全性 assertion。
- `analysis-results/malware/unclassified/versions/unknown/cases/<sha256>/README.md`: 生成した「ハッシュ OSINT 補強」section。
- `analysis-results/collections/<batch>/sources/unclassified/osint-summary.json`: 機械可読な集約値と case 別 record。
- `analysis-results/collections/<batch>/sources/unclassified/OSINT.md`: 件数、情報源の coverage、case 表を人が読める形にした文書。
- `summary.json`、`README.md`、対応する `analysis_history.yaml` block: 統合した帰属根拠への参照。
- `.work/<batch>/osint-cache/<sha256>.json`: 非公開の API 生応答 cache。この directory は commit しません。

現行 CLI で aggregate を canonical collection に移す場合は、case tree を複製せず、`analysis-results/collections/<batch>/manifest.json` の membership と `sources/unclassified/` の集約 artifact だけを更新します。

## 未識別 case の手動 escalation

1. 完全一致する SHA-256 を検索し、派生 IOC list よりも原典の技術 report を優先します。
2. 情報源がその完全一致 hash を実際に識別しているか記録します。一般的な family 記事は文脈であり、family の票ではありません。
3. protocol 定数、validation flow、service/port の分離、config layout、import、難読化解除済み code など、特徴的なローカル静的構造を比較します。ファイルは実行しません。
4. provenance を伴うレビュー済み根拠を curated YAML に追加し、batch を offline で再生します。
5. 情報源が 1 つだけの label は低信頼のままにし、競合を明示的に保持します。

YARA だけの一致、一般的な AV 用語、filename、file type、entropy、TCP port が open であること、URL 1 つだけでは、根拠ある family 帰属には不十分です。

## 失敗時の確認

| 症状 | 確認事項 |
|---|---|
| 401/403 | 設定された環境 credential が存在し、有効であることを確認する。command history や report へ credential を記録しない |
| 404/not found | benign の根拠ではなく、その情報源に結果がないものとして扱う |
| OTX pulse が空 | `pulse_count: 0` を保持し、他の情報源を継続する |
| rate limit/timeout | 後で該当情報源だけを更新する。cache 済み情報源は merge される |
| label が競合 | provider の provenance を確認し、`conflicting` を保持する。vendor 数だけで選択しない |
| 公開出力に生 field がある | 公開を中止し、`response`、provider の生 metadata、URL query、token、環境変数名がないか確認する |
| family alias がない | レビュー済み alias と unit test を追加する。名前が似ているだけの無関係な family を推測しない |

report 生成後は、IOC list を再生成して検査し、unit/pydoc suite を実行し、secret や生 field が repository 出力へ混入していないか走査してから、終了時の安全 gate を実行します。安全 gate の出力は stdout だけに表示し、commit しません。

## 2026-07-17 batch の結果

新しい順に選んだ 100 case の batch には、信頼度が低い、または未識別の対象が 93 case ありました。hash OSINT により 69 case で family 候補を得て、そのうち 6 case は中信頼度の裏付けを得ました。24 case は未識別のままで、1 case は family の競合を保持しています。これらの件数は監査時点の snapshot であり、未解決の検体が benign であることを意味しません。
