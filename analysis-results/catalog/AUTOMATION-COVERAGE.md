# 既知マルウェア自動解析カバレッジ

本表はdetectorと静的handlerの実装状況から自動生成しています。検体実行、外部通信、生成AIは使用しません。

- 対象family: 86件
- detector＋安全handler＋品質policyで解析完結可能: 24件（27.91%）
- detector＋安全handlerでfamily自動選択可能: 53件
- automatic宣言済みfamily: 84件（97.67%）
- 安全preflight済みscript-only handler利用可能: 84件（97.67%）
- 品質policy宣言済み: 33件 / 安全handler＋品質policy: 33件
- 安全handlerはあるが品質policy未宣言: 51件
- handler実装: 宣言95件 / 安全95件 / 停止0件
- automatic handlerが安全preflightで停止: 0件
- handlerによる候補検証のみ: 9件
- 実行したformat別preflight: 1059件（上限2048件）

| family | 状態 | detector | 品質policy | 宣言handler | 安全handler | blocker |
|---|---|---:|---:|---:|---:|---|
| acrstealer | fully_routable | あり | あり | 1 | 1 | なし |
| agenttesla | fully_routable | あり | あり | 2 | 2 | なし |
| amadey | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| amosstealer | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| asyncrat | fully_routable | あり | あり | 1 | 1 | なし |
| atlascross | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| blackhorse_miner_agent | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| blazetrack | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| catddos | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| chud_bot | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| clickfix_booking | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| condi | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| credential_phishing_html | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| darkcomet | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| dcrat | fully_routable | あり | あり | 1 | 1 | なし |
| donutloader | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| dotnet_resource_loader | fully_routable | あり | あり | 1 | 1 | なし |
| dysphoria | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| eclipse_ddos_bot | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| efimer | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| electron_payload_loader | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| formbook | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| formbook_loader | fully_routable | あり | あり | 1 | 1 | なし |
| freepbx_k_php | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| genddos_bot | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| gh0strat | fully_routable | あり | あり | 1 | 1 | なし |
| go_synthetic_workload | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| guloader | fully_routable | あり | あり | 1 | 1 | なし |
| hijackloader | fully_routable | あり | あり | 1 | 1 | なし |
| infrastructure_decoy_hta | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| jackskid | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| jiproxy_relay | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| jomangy | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| latrodectus | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| linux_downloader | fully_routable | あり | あり | 1 | 1 | なし |
| linux_ens_sns_bot | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| linux_reverse_shell | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| lummastealer | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| macos_stealer_v2 | fully_routable | あり | あり | 1 | 1 | なし |
| manageengine_endpoint_central_abuse | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| maskgram_stealer | fully_routable | あり | あり | 2 | 2 | なし |
| mig_logcleaner | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| mirai | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| mirai_ens_doh_bot | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| mx-go | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| nanocore | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| njrat | fully_routable | あり | あり | 1 | 1 | なし |
| npm_supply_chain | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| nsis_obfuscated_loader | fully_routable | あり | あり | 1 | 1 | なし |
| owareaper | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| panchan | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| phorpiex_downloader | fully_routable | あり | あり | 1 | 1 | なし |
| phorpiex_spam | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| png_registry_loader | fully_routable | あり | あり | 1 | 1 | なし |
| pony | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| prometei | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| protected_pe_loader | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| protection_agent_loader | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| proxyrack_pop_deployer | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| purehvnc | fully_routable | あり | あり | 2 | 2 | なし |
| purelogs | fully_routable | あり | あり | 1 | 1 | なし |
| putita_v3 | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| quasarrat | fully_routable | あり | あり | 1 | 1 | なし |
| redlinestealer | fully_routable | あり | あり | 1 | 1 | なし |
| remcosrat | fully_routable | あり | あり | 1 | 1 | なし |
| remusstealer | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| screenconnect_rmm | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| shadowpad | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| signed_dht_bot | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| snakekeylogger | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| sobfox_launcher | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| softbot | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| spyglace | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| stealc | fully_routable | あり | あり | 1 | 1 | なし |
| suomi_agent | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| tbot_iot_bot | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| tor_openssh_backdoor | manual_only_without_detector | なし | なし | 0 | 0 | detector_and_automatic_handler_missing |
| traffmonetizer_deployer | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| unclassified | manual_only_without_detector | なし | なし | 0 | 0 | detector_and_automatic_handler_missing |
| valleyrat | fully_routable | あり | あり | 9 | 9 | なし |
| venomrat | fully_routable | あり | あり | 1 | 1 | なし |
| vidar | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| wannacry | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| windows_script_stager | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |
| xmrig | quality_policy_missing | なし | なし | 1 | 1 | detector_and_quality_policy_missing |
| xworm | quality_policy_missing | あり | なし | 1 | 1 | quality_policy_missing |

## 判定の意味

- `fully_routable`: detectorで候補を選び、安全な静的handlerを実行でき、family別品質policyも宣言済みです。
- `candidate_verification_only`: 外部metadataなどから候補化できますが、family確定には強いhandler証拠が必要です。
- `quality_policy_missing`: 安全handlerはありますが、解析完結に必要な成果物条件が未宣言です。
- `automatic_handler_blocked`: automatic宣言はありますが、安全preflightを通過するformatがありません。
- `classification_only`: family判定後のconfig・C2・ロジック抽出が未自動化です。
- `manual_handler_only`: handlerは存在しますが共通の安全契約へ未適合です。

blocked handlerのID、format別阻害理由、sourceとlocal dependencyから算出したSHA-256指紋はJSON正本に記録します。
安全handlerがあることだけでは解析完結とは判定しません。family別品質policyの宣言と全品質gateの充足が別途必要です。
