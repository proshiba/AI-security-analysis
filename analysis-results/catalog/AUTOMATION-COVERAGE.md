# 既知マルウェア自動解析カバレッジ

本表はdetectorと静的handlerの実装状況から自動生成しています。検体実行、外部通信、生成AIは使用しません。

- 対象family: 86件
- detector＋handlerで自動選択可能: 53件（61.63%）
- script-only handler利用可能: 84件（97.67%）
- handlerによる候補検証のみ: 31件

| family | 状態 | detector | 自動handler | blocker |
|---|---|---:|---:|---|
| acrstealer | fully_routable | あり | 1 | なし |
| agenttesla | fully_routable | あり | 2 | なし |
| amadey | fully_routable | あり | 1 | なし |
| amosstealer | candidate_verification_only | なし | 1 | detector_missing |
| asyncrat | fully_routable | あり | 1 | なし |
| atlascross | fully_routable | あり | 1 | なし |
| blackhorse_miner_agent | fully_routable | あり | 1 | なし |
| blazetrack | fully_routable | あり | 1 | なし |
| catddos | fully_routable | あり | 1 | なし |
| chud_bot | candidate_verification_only | なし | 1 | detector_missing |
| clickfix_booking | candidate_verification_only | なし | 1 | detector_missing |
| condi | candidate_verification_only | なし | 1 | detector_missing |
| credential_phishing_html | candidate_verification_only | なし | 1 | detector_missing |
| darkcomet | fully_routable | あり | 1 | なし |
| dcrat | fully_routable | あり | 1 | なし |
| donutloader | candidate_verification_only | なし | 1 | detector_missing |
| dotnet_resource_loader | fully_routable | あり | 1 | なし |
| dysphoria | fully_routable | あり | 1 | なし |
| eclipse_ddos_bot | candidate_verification_only | なし | 1 | detector_missing |
| efimer | fully_routable | あり | 1 | なし |
| electron_payload_loader | candidate_verification_only | なし | 1 | detector_missing |
| formbook | candidate_verification_only | なし | 1 | detector_missing |
| formbook_loader | fully_routable | あり | 1 | なし |
| freepbx_k_php | fully_routable | あり | 1 | なし |
| genddos_bot | candidate_verification_only | なし | 1 | detector_missing |
| gh0strat | fully_routable | あり | 1 | なし |
| go_synthetic_workload | candidate_verification_only | なし | 1 | detector_missing |
| guloader | fully_routable | あり | 1 | なし |
| hijackloader | fully_routable | あり | 1 | なし |
| infrastructure_decoy_hta | candidate_verification_only | なし | 1 | detector_missing |
| jackskid | fully_routable | あり | 1 | なし |
| jiproxy_relay | candidate_verification_only | なし | 1 | detector_missing |
| jomangy | candidate_verification_only | なし | 1 | detector_missing |
| latrodectus | fully_routable | あり | 1 | なし |
| linux_downloader | fully_routable | あり | 1 | なし |
| linux_ens_sns_bot | candidate_verification_only | なし | 1 | detector_missing |
| linux_reverse_shell | fully_routable | あり | 1 | なし |
| lummastealer | candidate_verification_only | なし | 1 | detector_missing |
| macos_stealer_v2 | fully_routable | あり | 1 | なし |
| manageengine_endpoint_central_abuse | fully_routable | あり | 1 | なし |
| maskgram_stealer | fully_routable | あり | 2 | なし |
| mig_logcleaner | candidate_verification_only | なし | 1 | detector_missing |
| mirai | fully_routable | あり | 1 | なし |
| mirai_ens_doh_bot | fully_routable | あり | 1 | なし |
| mx-go | candidate_verification_only | なし | 1 | detector_missing |
| nanocore | candidate_verification_only | なし | 1 | detector_missing |
| njrat | fully_routable | あり | 1 | なし |
| npm_supply_chain | fully_routable | あり | 1 | なし |
| nsis_obfuscated_loader | fully_routable | あり | 1 | なし |
| owareaper | fully_routable | あり | 1 | なし |
| panchan | fully_routable | あり | 1 | なし |
| phorpiex_downloader | fully_routable | あり | 1 | なし |
| phorpiex_spam | candidate_verification_only | なし | 1 | detector_missing |
| png_registry_loader | fully_routable | あり | 1 | なし |
| pony | candidate_verification_only | なし | 1 | detector_missing |
| prometei | fully_routable | あり | 1 | なし |
| protected_pe_loader | candidate_verification_only | なし | 1 | detector_missing |
| protection_agent_loader | candidate_verification_only | なし | 1 | detector_missing |
| proxyrack_pop_deployer | candidate_verification_only | なし | 1 | detector_missing |
| purehvnc | fully_routable | あり | 2 | なし |
| purelogs | fully_routable | あり | 1 | なし |
| putita_v3 | fully_routable | あり | 1 | なし |
| quasarrat | fully_routable | あり | 1 | なし |
| redlinestealer | fully_routable | あり | 1 | なし |
| remcosrat | fully_routable | あり | 1 | なし |
| remusstealer | candidate_verification_only | なし | 1 | detector_missing |
| screenconnect_rmm | fully_routable | あり | 1 | なし |
| shadowpad | fully_routable | あり | 1 | なし |
| signed_dht_bot | fully_routable | あり | 1 | なし |
| snakekeylogger | fully_routable | あり | 1 | なし |
| sobfox_launcher | candidate_verification_only | なし | 1 | detector_missing |
| softbot | candidate_verification_only | なし | 1 | detector_missing |
| spyglace | fully_routable | あり | 1 | なし |
| stealc | fully_routable | あり | 1 | なし |
| suomi_agent | fully_routable | あり | 1 | なし |
| tbot_iot_bot | fully_routable | あり | 1 | なし |
| tor_openssh_backdoor | manual_only_without_detector | なし | 0 | detector_and_automatic_handler_missing |
| traffmonetizer_deployer | candidate_verification_only | なし | 1 | detector_missing |
| unclassified | manual_only_without_detector | なし | 0 | detector_and_automatic_handler_missing |
| valleyrat | fully_routable | あり | 9 | なし |
| venomrat | fully_routable | あり | 1 | なし |
| vidar | candidate_verification_only | なし | 1 | detector_missing |
| wannacry | candidate_verification_only | なし | 1 | detector_missing |
| windows_script_stager | fully_routable | あり | 1 | なし |
| xmrig | candidate_verification_only | なし | 1 | detector_missing |
| xworm | fully_routable | あり | 1 | なし |

## 判定の意味

- `fully_routable`: detectorで候補を選び、静的handlerまで自動実行できます。
- `candidate_verification_only`: 外部metadataなどから候補化できますが、family確定には強いhandler証拠が必要です。
- `classification_only`: family判定後のconfig・C2・ロジック抽出が未自動化です。
- `manual_handler_only`: handlerは存在しますが共通の安全契約へ未適合です。
