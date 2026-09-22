# ファミリー別STIX 2.1の生成と判定境界

## 目的

個別検体ではなくマルウェアファミリーごとに、公開済みの静的解析と出典付きOSINTを一つのSTIX Bundleへ整理します。成果物は[ファミリー別STIX一覧](../../analysis-results/stix/README.md)に置きます。攻撃者が実際に用いた配布・侵入・展開経路を扱い、MalwareBazaar、Triage、VirusTotalなどで検体を発見・収集した経路は攻撃経路へ含めません。

## 入力とSTIXへの対応

| 入力 | STIX 2.1での表現 | 判定境界 |
|---|---|---|
| ファミリー別の公開解析 | malwareとreport | 版や個別検体の運用者はファミリー名から推定しない |
| 静的比較プロファイル | note | 個別case報告で高確度の独立したファミリー根拠を確認できたcaseだけを集計し、全版共通の性質と断定しない |
| 正規化関数の完全一致 | note | 同じ強根拠caseの元静的関数まで遡り、汎用runtime・SDK・生成コードを除外する。derived-fromや同一開発者関係にしない |
| 出典付き開発者 | threat-actorとmalware authored-by threat-actor | 開発の明示的な一次資料がある場合だけ |
| 出典付き利用主体 | threat-actorとthreat-actor uses malware | 名前のある主体による利用が明記された場合だけ。未特定の購入者などはnoteのみ |
| 出典付き攻撃キャンペーン | campaignとcampaign uses malware | 審査済みの具体的な攻撃活動だけ。自動相関の候補は昇格しない |
| 出典付きキャンペーン帰属 | campaign attributed-to threat-actor | 当該活動と主体の直接的な根拠がある場合だけ。ファミリーの全利用者へ拡張しない |
| 販売・提供形態、MaaS、専用性、利用史 | malware.labelsとnote | 不明なら不明と記録し、単一利用報告から専用性を推定しない |

出典は各objectのexternal_referencesに付けます。利用者と開発者を混同せず、公開資料の帰属表現を超えて断定しません。攻撃に使われた正規RMM、暗号通貨miner、無害なデコイ、認証情報フィッシングHTML、汎用reverse shell／downloader技法、単独のアンチフォレンジック用toolはMalware SDOの対象から除外しています。

confidenceは本整理内の高・中・低をそれぞれ80・50・20へ写像した評価値で、引用元が提示した数値ではありません。元資料がcampaign名を付けていない場合は記述名と明示します。

ファミリー横断のコード類似候補は、正規化した関数のsemantic sequence SHA-256だけでなく、元の`static-logic.json`にある正規化ロジックSHA-256も一致し、双方の役割が一致するものに限ります。各関数の意味tokenは16以上、同一groupのmemberは2〜12件、異なるgroupで2件以上の一致を必要とします。元の関数名と静的解析の根拠を照合し、Go標準ライブラリ、.NET標準部品、既知の共通SDK、DelayLoad関数、UI designer生成関数、名前未解決の汎用関数などを除外します。これらを除いても共通ライブラリの可能性は残るため、同じ作者や派生版とは判定しません。

caseのディレクトリ名はファミリー確定の根拠ではありません。静的特徴とコード類似の母集団には、個別の`report.json`で`classification.family`が一致し、`confidence=high`で、既知ハッシュまたはレビュー済みの終端コード・設定などの具体的な`selection_basis`があるcaseだけを含めます。`low`、単なる作業者選択、固有検出器の閾値未達、分類根拠未記録のcaseは含めません。これはOSINT上で存在するファミリーの否定ではなく、ローカル検体の帰属とコード類似性を過大評価しないための境界です。索引には全case数と、この強根拠を満たすcase数を分けて記録します。
関数索引のSHA-256は復元した内部layerを示す場合があるため、case分類の照合とcase数集計には、元`static-logic.json`が置かれた公開caseディレクトリのroot SHA-256を用います。内部layer hashとroot case hashを混同しません。

`.NET resource loader`、難読化NSIS loader、PNG/registry loader、カスタム保護PE loader、Windows Script Stagerは暫定的な技術クラスタであり、固有のマルウェアファミリーと確認できていません。STIX 2.1の`malware.is_family=false`は個別malware instanceを意味し、複数検体の暫定クラスタの代用にはできません。そのため、これらはファミリー別Bundleから除外し、索引の`excluded_technical_clusters`に記録します。元の解析成果物は維持します。

## 更新手順

出典付きの知識はanalysis-framework/knowledge/malware_families/とanalysis-framework/knowledge/stix_curated.jsonを編集します。後者のcampaignsとdevelopersは、出典IDと説明を明示した審査済み項目です。既存のfamily知識と重複したfamily定義は拒否します。

    py -3.13 analysis-framework/common/generate_family_stix.py --repository . --as-of 2026-09-21 --write
    py -3.13 analysis-framework/common/generate_family_stix.py --repository . --as-of 2026-09-21 --check
    py -3.13 -m pytest analysis-framework/tests/test_generate_family_stix.py -q

--as-ofには成果物の更新日を指定します。既存の同一STIX object IDでは初出時刻を維持し、内容が変わらない場合はmodifiedも維持します。同日内の作業中の再生成は未公開snapshotの更新として扱い、公開後の意味的変更には新しい日付を指定します。外部への通信、検体実行、C2接触は発生しません。

## 制約

OSINT未登録ファミリーには公開済みローカル概要と、強根拠caseがある場合に限る静的比較情報だけを出力し、出典未登録の開発者・攻撃者関係は生成しません。コード類似は厳格な根拠ゲートを通した比較候補で、開発者、アクター、キャンペーン、派生系譜を示しません。ファミリー全体への帰属は個別caseへの帰属を意味しません。公開資料のURLが消えた場合は、当該根拠の再確認と知識の更新が必要です。
