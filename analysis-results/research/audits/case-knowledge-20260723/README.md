# 過去caseの解析充足度監査

全公開caseを同じ基準で再評価し、挙動、検体特徴、静的復元、設定、通信役割、
制約、IOC一覧、根拠の追跡可能性を確認しました。詳細なcase一覧は `audit.json` にあります。
検体や復元バイナリは開かず、公開済みのREADMEとJSONだけを使用しています。

## 集計

| 状態 | 件数 | 意味 |
|---|---:|---|
| complete | 302 | 挙動と検体特徴を含む主要項目が揃っている |
| partial | 723 | 根拠はあるが追加静的解析または文書化が必要 |
| insufficient | 0 | 現行成果物だけでは主要項目を説明できない |

## 主な未解決理由

| 理由 | case数 |
|---|---:|
| `behavior_not_documented` | 723 |
| `static_config_not_recovered` | 349 |
| `packed_or_protected_inner_payload_not_recovered` | 112 |
| `declarative_analysis_needs_review` | 58 |
| `sample_characteristics_insufficient` | 1 |

## ファミリー別状態

| ファミリー | complete | partial | insufficient |
|---|---:|---:|---:|
| `acrstealer` | 4 | 6 | 0 |
| `agenttesla` | 8 | 21 | 0 |
| `amadey` | 0 | 35 | 0 |
| `amosstealer` | 20 | 2 | 0 |
| `asyncrat` | 2 | 27 | 0 |
| `blackhorse-miner-agent` | 1 | 0 | 0 |
| `blazetrack` | 1 | 1 | 0 |
| `catddos` | 0 | 2 | 0 |
| `chud-bot` | 0 | 6 | 0 |
| `condi` | 2 | 7 | 0 |
| `credential-phishing-html` | 0 | 1 | 0 |
| `darkcomet` | 10 | 0 | 0 |
| `dcrat` | 6 | 4 | 0 |
| `donutloader` | 1 | 2 | 0 |
| `dotnet-resource-loader` | 0 | 4 | 0 |
| `eclipse-ddos-bot` | 0 | 11 | 0 |
| `efimer` | 30 | 6 | 0 |
| `formbook` | 20 | 20 | 0 |
| `freepbx-k-php` | 1 | 9 | 0 |
| `genddos-bot` | 6 | 10 | 0 |
| `gh0strat` | 0 | 19 | 0 |
| `guloader` | 1 | 10 | 0 |
| `hijackloader` | 1 | 15 | 0 |
| `infectedslurs-tbot` | 0 | 1 | 0 |
| `infrastructure-decoy-hta` | 0 | 1 | 0 |
| `jackskid` | 5 | 4 | 0 |
| `jiproxy-relay` | 0 | 1 | 0 |
| `jomangy` | 0 | 7 | 0 |
| `latrodectus` | 0 | 54 | 0 |
| `linux-downloader` | 0 | 1 | 0 |
| `linux-reverse-shell` | 0 | 1 | 0 |
| `lummastealer` | 20 | 18 | 0 |
| `macos-stealer-v2` | 0 | 1 | 0 |
| `manageengine-endpoint-central-abuse` | 0 | 1 | 0 |
| `maskgram-stealer` | 2 | 0 | 0 |
| `mig-logcleaner` | 0 | 1 | 0 |
| `mirai` | 3 | 1 | 0 |
| `mirai-derived-ens-doh-bot` | 1 | 3 | 0 |
| `nanocore` | 1 | 0 | 0 |
| `njrat` | 0 | 10 | 0 |
| `npm-supply-chain` | 0 | 1 | 0 |
| `nsis-obfuscated-loader` | 0 | 1 | 0 |
| `panchan` | 0 | 1 | 0 |
| `phorpiex-downloader` | 0 | 1 | 0 |
| `phorpiex-spam` | 0 | 1 | 0 |
| `png-registry-loader` | 2 | 0 | 0 |
| `prometei` | 2 | 1 | 0 |
| `protected-pe-loader` | 1 | 2 | 0 |
| `protection-agent-loader` | 0 | 1 | 0 |
| `proxyrack-pop-deployer` | 0 | 1 | 0 |
| `purehvnc` | 0 | 1 | 0 |
| `putita-v3` | 4 | 9 | 0 |
| `quasarrat` | 4 | 6 | 0 |
| `redlinestealer` | 0 | 10 | 0 |
| `remcosrat` | 2 | 20 | 0 |
| `remusstealer` | 20 | 20 | 0 |
| `screenconnect-rmm` | 0 | 1 | 0 |
| `shadowpad` | 1 | 7 | 0 |
| `signed-dht-bot` | 0 | 8 | 0 |
| `snakekeylogger` | 10 | 1 | 0 |
| `sobfox-launcher` | 0 | 1 | 0 |
| `softbot` | 0 | 3 | 0 |
| `spyglace` | 0 | 4 | 0 |
| `stealc` | 43 | 16 | 0 |
| `suomi-agent` | 1 | 0 | 0 |
| `traffmonetizer-deployer` | 0 | 1 | 0 |
| `unclassified` | 29 | 140 | 0 |
| `valleyrat` | 4 | 60 | 0 |
| `venomrat` | 2 | 35 | 0 |
| `vidar` | 20 | 28 | 0 |
| `wannacry` | 5 | 4 | 0 |
| `windows-script-stager` | 6 | 4 | 0 |
| `xmrig` | 0 | 1 | 0 |
| `xworm` | 0 | 10 | 0 |

## 優先して追加解析するcase

- insufficient判定のcaseはありません。

## 追加解析の原則

- `static_config_not_recovered` は、ファミリー名から設定やC2を補完せず、終端payloadの静的復元を優先します。
- `packed_or_protected_inner_payload_not_recovered` は、外層のpacker所見と終端payload解析を分離します。
- `behavior_not_documented` は、control flowまたはscript処理順の直接根拠を追加します。
- `sample_characteristics_insufficient` は、形式、保護、resource、import、script構造を追加します。
- 外部接続や検体実行を、文書不足の代替手段として行いません。
