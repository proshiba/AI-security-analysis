# 継続的マルウェアインテリジェンス調査計画

## 目的

このディレクトリは、個々の検体解析を継続的な脅威インテリジェンスへ変換するための定期調査案を管理します。主な目的は次の4点です。

1. マルウェアの実装、設定、配布方法、通信方式の変化を早期に把握する。
2. 新旧IOCを突合し、再利用、移行、失効、役割変更を時系列で追跡する。
3. 関数ロジックや構成部品の類似性から、ファミリー名をまたぐコード共有を整理する。
4. コード、設定、インフラ、配布、時間、標的、OSINTを組み合わせ、同一運用者による可能性があるoperationを保守的に抽出する。

ここでいう`campaign`は、共有証拠を持つ検体や配布活動の候補集合です。`operation`は、複数campaign、複数マルウェア、配布基盤、C2基盤などを一定期間にわたって運用した主体の活動仮説です。どちらも脅威アクターへの帰属と同義ではありません。

## 現在の出発点

2026年7月25日時点の生成済み成果物には、次の規模の相関対象があります。

| 項目 | 現在値 | 調査上の意味 |
|---|---:|---|
| campaign相関の評価case | 1,125 | IOCと非汎用特徴による横断相関の母集団 |
| campaign候補 | 26 | 人手で代替仮説を確認すべき候補集合 |
| campaign label付与case | 125 | 強いfingerprintを再観測したcase |
| `static-logic.json` | 1,124 | 関数単位の類似性を評価できるcase |
| fingerprint対象関数 | 5,558 | コード共有を調べる関数集合 |
| コード類似候補pair | 226,643 | 全件を同等に扱わず、情報量で順位付けすべき候補 |
| ValleyRAT canonical case | 68 | OSINT campaignとの帰属試行対象 |
| ValleyRAT未解決case | 53 | 新しい完全一致IOCや複合証拠で再評価すべき集合 |

これらは固定値ではありません。定期実行ごとにbaselineを保存し、増減理由を説明できるようにします。

現在利用できる主な正本と処理は次のとおりです。

- [IOC横断索引](../analysis-results/IOC-INDEX.md)
- [コード類似性索引](../analysis-results/catalog/CODE-SIMILARITY.md)
- [campaign相関結果](../analysis-results/research/campaigns/correlated-20260724/README.md)
- [ValleyRAT campaign帰属結果](../analysis-results/research/campaigns/valleyrat-20260725/README.md)
- [IOC生成処理](../analysis-framework/common/generate_ioc_lists.py)
- [コード類似性索引生成処理](../analysis-framework/common/generate_code_similarity_index.py)
- [campaign相関処理](../analysis-framework/common/correlate_campaigns.py)
- [ハッシュ限定OSINT補強処理](../analysis-framework/common/osint_hash_enricher.py)
- [派生成果物一括更新処理](../analysis-framework/common/refresh_derived_artifacts.py)

## 調査の基本方針

### 差分を中心にする

毎回すべてを読み直すのではなく、前回baselineから追加、消失、変更したentityとedgeを先に抽出します。新規検体だけでなく、既存検体のfamily再分類、config復元、IOC役割変更、OSINT追加、類似度変化も差分として扱います。

### 証拠軸を分離する

次の証拠を混ぜずに記録し、最後に相関します。

- 検体同一性: SHA-256、埋込payload hash、署名、親子artifact関係
- コード: 正規化ロジックhash、semantic sequence、SimHash、opcode hash、call graph
- 設定・protocol: config schema、暗号・圧縮方式、command ID、URI形式、mutexやcampaign ID
- インフラ: domain、IP、endpoint、証明書、ASN、hosting、登録・観測期間
- 配布・実行: archive構成、side-loading組合せ、installer、decoy、file path、親子process
- 時間・標的: first seen、campaign期間、言語、地域、業種、テーマ
- OSINT: 完全一致hash、報告されたcampaign、actor、別名、公開根拠

単一の軸だけでoperationやactorを確定しません。

### 自動生成と分析判断を分ける

自動処理は、差分抽出、正規化、候補生成、score計算、過去結果の再現までを担当します。campaign昇格、operation統合、actor帰属、誤相関の除外は人手レビューを必須にします。

### 否定証拠と代替仮説を残す

一致点だけでなく、時期の不整合、異なるconfig形式、共通library、builder共有、bulletproof hostingの再利用、公開サービスの共有なども保存します。候補を棄却した理由は、同じ誤相関を繰り返さないための知識として扱います。

## 推奨する調査周期

| 周期 | 主なタスク | 目的 |
|---|---|---|
| 毎日 | `INT-D01`～`INT-D03` | 新規検体、IOC差分、強い既知一致の即時把握 |
| 毎週 | `INT-W01`～`INT-W05` | 実装変化、コード共有、インフラ再利用、未解決case、検知不足の整理 |
| 毎月 | `INT-M01`～`INT-M03` | operation仮説、actor帰属仮説、相関閾値のレビュー |
| 四半期 | `INT-Q01` | データ品質、schema、解析coverage、調査負債の見直し |
| 事象発生時 | `INT-E01` | 重大報告、新しいcampaign、CVE悪用、情報窃取などへの緊急再相関 |

詳細な入力、処理、成果物、完了条件は[定期調査タスク一覧](RECURRING-TASKS.md)を参照してください。候補の昇格条件と確度は[相関・評価モデル](ASSESSMENT-MODEL.md)に定義します。

## 1回の調査サイクル

1. 前回baselineと今回の正本を固定し、対象期間と対象caseを記録する。
2. 新規・更新・削除されたcase、IOC、関数fingerprint、campaign labelを抽出する。
3. IOC、コード、config、配布、時間、OSINTの各軸で候補edgeを生成する。
4. generic値、共有library、公開サービス、収集バッチだけの一致を除外する。
5. 新規候補と既存候補の変化を、人手レビュー用queueへ順位付けする。
6. campaign候補、operation候補、actor帰属仮説を別々に評価する。
7. 採用、保留、棄却とその根拠を保存し、fingerprintと検知材料へ還元する。
8. 次回比較用baseline、件数、coverage、誤相関率、未解決queueを確定する。

## 推奨成果物構成

現時点では計画文書だけを置きます。運用開始後は、次の構成へ拡張します。

```text
intelligence/
  README.md
  RECURRING-TASKS.md
  ASSESSMENT-MODEL.md
  baselines/
    YYYY-MM-DD.json
  runs/
    YYYY/
      YYYY-MM-DD/
        README.md
        delta.json
        review-queue.json
        metrics.json
  hypotheses/
    campaigns/
    operations/
    actors/
  watchlists/
    malware-drift.json
    infrastructure.json
    unresolved-cases.json
  schemas/
```

raw OSINT応答、資格情報、検体、復号binary、PCAP、Ghidra projectはここへ保存しません。生データが必要な場合は、リポジトリ外のアクセス制限領域または無視対象の`.work/`へ保存し、公開成果物には正規化・無害化した根拠だけを残します。

## 最初の90日で優先すること

### 第1段階: baselineと差分の再現性

- `INT-D01`、`INT-D02`、`INT-W04`を先に運用し、前回との差分を毎回同じ入力から再生成できるようにする。
- case数、IOC数、関数fingerprint数、未分類数、未解決campaign数をbaseline化する。
- 生成物の日時と収集日時を分け、遅れて追加されたOSINTを過去の観測時刻と混同しない。

### 第2段階: 候補の順位付け

- 22万件を超えるコード類似候補を、異なるfamily、希少関数、通信・config・loaderに関係する関数から優先する。
- IOCは完全一致だけでなく、役割、初回・最終観測、共有度、同時出現を評価する。
- ValleyRAT未解決53件を、OSINTの完全一致hash、親子artifact、希少config、配布chainの追加時だけ再評価する。

### 第3段階: operation graph

- review済みcampaignだけをoperation候補の入力とする。
- コード、インフラ、配布、時間のうち複数軸で結ばれた候補だけを昇格する。
- actor名は最後に付与し、actor名が先に決まることで証拠の解釈が歪まないようにする。

## 成功指標

| 指標 | 望ましい方向 |
|---|---|
| 新規caseがbaselineへ反映されるまでの時間 | 短縮 |
| 未分類・未解決caseのうち追加証拠で再評価できた割合 | 増加 |
| コード類似候補のうち人手レビュー対象へ絞り込めた割合 | 増加 |
| campaign候補の根拠軸数 | 増加 |
| 単一IP、単一tag、family名だけによる候補 | 0を維持 |
| 採用後に誤相関として取り消した割合 | 測定し、閾値調整へ反映 |
| operation仮説に代替説明と否定証拠が記録された割合 | 100% |
| 定期実行の再現率 | 100% |

件数を増やすこと自体は成功指標にしません。根拠の再現性、誤相関の抑制、未解決事項の明示を優先します。
