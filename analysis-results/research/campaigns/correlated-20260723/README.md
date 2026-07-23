# 過去caseの攻撃キャンペーン相関

公開済みcaseの共有インフラ、共有子要素、非汎用の配布・挙動特徴を相関し、
同一攻撃キャンペーンの可能性がある集合だけを候補として切り出しました。
ファミリー名、ファイル名、収集バッチ、IP単独では相関していません。

## 集計

| 項目 | 件数 |
|---|---:|
| 評価case | 1025 |
| 共有指標を持つ候補pair | 1247 |
| 閾値を満たした相関pair | 760 |
| campaign候補 | 37 |
| campaign label付与case | 201 |

## campaign候補

| campaign ID | ファミリー | case数 | 確度 | 分類 |
|---|---|---:|---|---|
| [`correlated-acrstealer-agenttesla-formbook-4ceaf9e4071a`](correlated-acrstealer-agenttesla-formbook-4ceaf9e4071a/README.md) | acrstealer, agenttesla, formbook, guloader, snakekeylogger, unclassified, valleyrat, venomrat, vidar | 24 | high | cross_family_campaign_candidate |
| [`correlated-acrstealer-blazetrack-3fa63f35a009`](correlated-acrstealer-blazetrack-3fa63f35a009/README.md) | acrstealer, blazetrack | 3 | high | cross_family_campaign_candidate |
| [`correlated-acrstealer-hijackloader-remusstealer-44a2a70e87e4`](correlated-acrstealer-hijackloader-remusstealer-44a2a70e87e4/README.md) | acrstealer, hijackloader, remusstealer, unclassified, vidar | 10 | high | cross_family_campaign_candidate |
| [`correlated-agenttesla-4721f7464834`](correlated-agenttesla-4721f7464834/README.md) | agenttesla | 3 | medium | same_family_campaign_candidate |
| [`correlated-agenttesla-aa662ac5b0ef`](correlated-agenttesla-aa662ac5b0ef/README.md) | agenttesla | 2 | medium | same_family_campaign_candidate |
| [`correlated-amadey-d27a1eebf320`](correlated-amadey-d27a1eebf320/README.md) | amadey | 6 | medium | same_family_campaign_candidate |
| [`correlated-condi-0c21a99db5d6`](correlated-condi-0c21a99db5d6/README.md) | condi | 2 | medium | same_family_campaign_candidate |
| [`correlated-condi-43b54d6f7682`](correlated-condi-43b54d6f7682/README.md) | condi | 2 | medium | same_family_campaign_candidate |
| [`correlated-dotnet-resource-loader-c1881c6000c2`](correlated-dotnet-resource-loader-c1881c6000c2/README.md) | dotnet-resource-loader | 2 | medium | same_family_campaign_candidate |
| [`correlated-eclipse-ddos-bot-97449ff85f19`](correlated-eclipse-ddos-bot-97449ff85f19/README.md) | eclipse-ddos-bot | 2 | medium | same_family_campaign_candidate |
| [`correlated-eclipse-ddos-bot-97a264ac07f5`](correlated-eclipse-ddos-bot-97a264ac07f5/README.md) | eclipse-ddos-bot | 2 | medium | same_family_campaign_candidate |
| [`correlated-efimer-5bebcc52c2ef`](correlated-efimer-5bebcc52c2ef/README.md) | efimer | 13 | high | same_family_campaign_candidate |
| [`correlated-efimer-unclassified-b09640a89712`](correlated-efimer-unclassified-b09640a89712/README.md) | efimer, unclassified | 25 | high | cross_family_campaign_candidate |
| [`correlated-freepbx-k-php-jomangy-eb89229e7b5d`](correlated-freepbx-k-php-jomangy-eb89229e7b5d/README.md) | freepbx-k-php, jomangy | 16 | high | cross_family_campaign_candidate |
| [`correlated-genddos-bot-a74d6b3d1370`](correlated-genddos-bot-a74d6b3d1370/README.md) | genddos-bot | 15 | high | same_family_campaign_candidate |
| [`correlated-hijackloader-unclassified-valleyrat-a18f3baa7fdc`](correlated-hijackloader-unclassified-valleyrat-a18f3baa7fdc/README.md) | hijackloader, unclassified, valleyrat | 7 | high | cross_family_campaign_candidate |
| [`correlated-jackskid-52bbfd994f2b`](correlated-jackskid-52bbfd994f2b/README.md) | jackskid | 6 | high | same_family_campaign_candidate |
| [`correlated-latrodectus-07f25a0194ab`](correlated-latrodectus-07f25a0194ab/README.md) | latrodectus | 4 | medium | same_family_campaign_candidate |
| [`correlated-latrodectus-119609fcd1f4`](correlated-latrodectus-119609fcd1f4/README.md) | latrodectus | 4 | medium | same_family_campaign_candidate |
| [`correlated-latrodectus-16adde821df9`](correlated-latrodectus-16adde821df9/README.md) | latrodectus | 3 | medium | same_family_campaign_candidate |
| [`correlated-latrodectus-48ccbbb41b6f`](correlated-latrodectus-48ccbbb41b6f/README.md) | latrodectus | 2 | medium | same_family_campaign_candidate |
| [`correlated-latrodectus-4d1f92bd239b`](correlated-latrodectus-4d1f92bd239b/README.md) | latrodectus | 4 | medium | same_family_campaign_candidate |
| [`correlated-latrodectus-529ef014e1b4`](correlated-latrodectus-529ef014e1b4/README.md) | latrodectus | 3 | medium | same_family_campaign_candidate |
| [`correlated-latrodectus-5650492dc465`](correlated-latrodectus-5650492dc465/README.md) | latrodectus | 3 | medium | same_family_campaign_candidate |
| [`correlated-latrodectus-90dd888eada9`](correlated-latrodectus-90dd888eada9/README.md) | latrodectus | 2 | medium | same_family_campaign_candidate |
| [`correlated-latrodectus-d90e452386a7`](correlated-latrodectus-d90e452386a7/README.md) | latrodectus | 2 | medium | same_family_campaign_candidate |
| [`correlated-mirai-derived-ens-doh-bot-f390f335f534`](correlated-mirai-derived-ens-doh-bot-f390f335f534/README.md) | mirai-derived-ens-doh-bot | 3 | medium | same_family_campaign_candidate |
| [`correlated-remcosrat-9856d4a51265`](correlated-remcosrat-9856d4a51265/README.md) | remcosrat | 2 | high | same_family_campaign_candidate |
| [`correlated-remusstealer-8d56fe990dd4`](correlated-remusstealer-8d56fe990dd4/README.md) | remusstealer | 2 | medium | same_family_campaign_candidate |
| [`correlated-signed-dht-bot-59446980ef66`](correlated-signed-dht-bot-59446980ef66/README.md) | signed-dht-bot | 6 | high | same_family_campaign_candidate |
| [`correlated-unclassified-140dc63f6cf6`](correlated-unclassified-140dc63f6cf6/README.md) | unclassified | 2 | high | same_family_campaign_candidate |
| [`correlated-unclassified-18d330f0907e`](correlated-unclassified-18d330f0907e/README.md) | unclassified | 2 | medium | same_family_campaign_candidate |
| [`correlated-unclassified-70f6c8da86de`](correlated-unclassified-70f6c8da86de/README.md) | unclassified | 2 | high | same_family_campaign_candidate |
| [`correlated-unclassified-90d978be19ce`](correlated-unclassified-90d978be19ce/README.md) | unclassified | 5 | high | same_family_campaign_candidate |
| [`correlated-valleyrat-570f481c0f42`](correlated-valleyrat-570f481c0f42/README.md) | valleyrat | 2 | medium | same_family_campaign_candidate |
| [`correlated-venomrat-b8be79d70868`](correlated-venomrat-b8be79d70868/README.md) | venomrat | 3 | medium | same_family_campaign_candidate |
| [`correlated-wannacry-63b40cc27704`](correlated-wannacry-63b40cc27704/README.md) | wannacry | 5 | high | same_family_campaign_candidate |

## 判定上の注意

- campaign候補は同一アクターへの帰属を意味しません。
- 共有インフラの再利用、ホスティング転売、builder共有は別の説明になり得ます。
- 新規caseへの自動labelは、生成したfingerprintの強い指標を再観測した場合だけ行います。
- 検体の読込み・実行と外部通信は行っていません。
