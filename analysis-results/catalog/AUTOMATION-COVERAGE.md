# 既知マルウェア自動解析カバレッジ

本表はdetector、静的handler、品質policyの実装構造と、無害なprobe入力によるformat別preflightから自動生成しています。検体実行、外部通信、生成AIは使用しません。
この割合は実検体を解析して測定した成功率ではなく、解析完了率、config／C2抽出成功率、終端payload到達率、誤検知率を示しません。

- 対象family: 86件
- detector＋安全handler＋品質policyで構造上ルーティング可能: 76件（88.37%）
- 代表fixtureで自動解析完了を実証済み: 0件
- detector＋安全handlerでfamily自動選択可能: 76件
- automatic宣言済みfamily: 84件（97.67%）
- 安全preflight済みscript-only handler利用可能: 84件（97.67%）
- 品質policy宣言済み: 84件 / 安全handler＋品質policy: 84件
- 安全handlerはあるが品質policy未宣言: 0件
- handler実装: 宣言96件 / 安全96件 / 停止0件
- automatic handlerが安全preflightで停止: 0件
- handlerによる候補検証のみ: 8件
- 実行したformat別preflight: 1043件（上限2048件）

| family | 状態 | detector | 品質policy | 宣言handler | 安全handler | blocker |
|---|---|---:|---:|---:|---:|---|
| acrstealer | fully_routable | あり | あり | 1 | 1 | なし |
| agenttesla | fully_routable | あり | あり | 2 | 2 | なし |
| amadey | fully_routable | あり | あり | 1 | 1 | なし |
| amosstealer | fully_routable | あり | あり | 1 | 1 | なし |
| asyncrat | fully_routable | あり | あり | 1 | 1 | なし |
| atlascross | fully_routable | あり | あり | 1 | 1 | なし |
| blackhorse_miner_agent | fully_routable | あり | あり | 1 | 1 | なし |
| blazetrack | fully_routable | あり | あり | 1 | 1 | なし |
| catddos | fully_routable | あり | あり | 1 | 1 | なし |
| chud_bot | fully_routable | あり | あり | 1 | 1 | なし |
| clickfix_booking | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| condi | fully_routable | あり | あり | 1 | 1 | なし |
| credential_phishing_html | fully_routable | あり | あり | 1 | 1 | なし |
| darkcomet | fully_routable | あり | あり | 1 | 1 | なし |
| dcrat | fully_routable | あり | あり | 1 | 1 | なし |
| donutloader | fully_routable | あり | あり | 1 | 1 | なし |
| dotnet_resource_loader | fully_routable | あり | あり | 1 | 1 | なし |
| dysphoria | fully_routable | あり | あり | 1 | 1 | なし |
| eclipse_ddos_bot | fully_routable | あり | あり | 1 | 1 | なし |
| efimer | fully_routable | あり | あり | 1 | 1 | なし |
| electron_payload_loader | fully_routable | あり | あり | 1 | 1 | なし |
| formbook | fully_routable | あり | あり | 1 | 1 | なし |
| formbook_loader | fully_routable | あり | あり | 1 | 1 | なし |
| freepbx_k_php | fully_routable | あり | あり | 1 | 1 | なし |
| genddos_bot | fully_routable | あり | あり | 1 | 1 | なし |
| gh0strat | fully_routable | あり | あり | 1 | 1 | なし |
| go_synthetic_workload | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| guloader | fully_routable | あり | あり | 1 | 1 | なし |
| hijackloader | fully_routable | あり | あり | 1 | 1 | なし |
| infrastructure_decoy_hta | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| jackskid | fully_routable | あり | あり | 1 | 1 | なし |
| jiproxy_relay | fully_routable | あり | あり | 1 | 1 | なし |
| jomangy | fully_routable | あり | あり | 1 | 1 | なし |
| latrodectus | fully_routable | あり | あり | 1 | 1 | なし |
| linux_downloader | fully_routable | あり | あり | 1 | 1 | なし |
| linux_ens_sns_bot | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| linux_reverse_shell | fully_routable | あり | あり | 1 | 1 | なし |
| lummastealer | fully_routable | あり | あり | 1 | 1 | なし |
| macos_stealer_v2 | fully_routable | あり | あり | 1 | 1 | なし |
| manageengine_endpoint_central_abuse | fully_routable | あり | あり | 1 | 1 | なし |
| maskgram_stealer | fully_routable | あり | あり | 2 | 2 | なし |
| mig_logcleaner | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| mirai | fully_routable | あり | あり | 1 | 1 | なし |
| mirai_ens_doh_bot | fully_routable | あり | あり | 1 | 1 | なし |
| mx-go | fully_routable | あり | あり | 1 | 1 | なし |
| nanocore | fully_routable | あり | あり | 1 | 1 | なし |
| njrat | fully_routable | あり | あり | 1 | 1 | なし |
| npm_supply_chain | fully_routable | あり | あり | 1 | 1 | なし |
| nsis_obfuscated_loader | fully_routable | あり | あり | 1 | 1 | なし |
| owareaper | fully_routable | あり | あり | 1 | 1 | なし |
| panchan | fully_routable | あり | あり | 1 | 1 | なし |
| phorpiex_downloader | fully_routable | あり | あり | 1 | 1 | なし |
| phorpiex_spam | fully_routable | あり | あり | 1 | 1 | なし |
| png_registry_loader | fully_routable | あり | あり | 1 | 1 | なし |
| pony | fully_routable | あり | あり | 1 | 1 | なし |
| prometei | fully_routable | あり | あり | 1 | 1 | なし |
| protected_pe_loader | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| protection_agent_loader | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| proxyrack_pop_deployer | fully_routable | あり | あり | 1 | 1 | なし |
| purehvnc | fully_routable | あり | あり | 2 | 2 | なし |
| purelogs | fully_routable | あり | あり | 1 | 1 | なし |
| putita_v3 | fully_routable | あり | あり | 1 | 1 | なし |
| quasarrat | fully_routable | あり | あり | 1 | 1 | なし |
| redlinestealer | fully_routable | あり | あり | 1 | 1 | なし |
| remcosrat | fully_routable | あり | あり | 1 | 1 | なし |
| remusstealer | fully_routable | あり | あり | 1 | 1 | なし |
| screenconnect_rmm | fully_routable | あり | あり | 1 | 1 | なし |
| shadowpad | fully_routable | あり | あり | 1 | 1 | なし |
| signed_dht_bot | fully_routable | あり | あり | 1 | 1 | なし |
| snakekeylogger | fully_routable | あり | あり | 1 | 1 | なし |
| sobfox_launcher | candidate_verification_only | なし | あり | 1 | 1 | detector_missing |
| softbot | fully_routable | あり | あり | 1 | 1 | なし |
| spyglace | fully_routable | あり | あり | 1 | 1 | なし |
| stealc | fully_routable | あり | あり | 1 | 1 | なし |
| suomi_agent | fully_routable | あり | あり | 1 | 1 | なし |
| tbot_iot_bot | fully_routable | あり | あり | 1 | 1 | なし |
| tor_openssh_backdoor | manual_only_without_detector | なし | なし | 0 | 0 | detector_and_automatic_handler_missing |
| traffmonetizer_deployer | fully_routable | あり | あり | 1 | 1 | なし |
| unclassified | manual_only_without_detector | なし | なし | 0 | 0 | detector_and_automatic_handler_missing |
| valleyrat | fully_routable | あり | あり | 10 | 10 | なし |
| venomrat | fully_routable | あり | あり | 1 | 1 | なし |
| vidar | fully_routable | あり | あり | 1 | 1 | なし |
| wannacry | fully_routable | あり | あり | 1 | 1 | なし |
| windows_script_stager | fully_routable | あり | あり | 1 | 1 | なし |
| xmrig | fully_routable | あり | あり | 1 | 1 | なし |
| xworm | fully_routable | あり | あり | 1 | 1 | なし |

## 判定の意味

- `fully_routable`: detectorで候補を選び、安全な静的handlerを実行でき、family別品質policyも宣言済みです。構造上の到達可能性であり、自動完了の実測値ではありません。
- `candidate_verification_only`: 外部metadataなどから候補化できますが、family確定には強いhandler証拠が必要です。
- `quality_policy_missing`: 安全handlerはありますが、解析完結に必要な成果物条件が未宣言です。
- `automatic_handler_blocked`: automatic宣言はありますが、安全preflightを通過するformatがありません。
- `classification_only`: family判定後のconfig・C2・ロジック抽出が未自動化です。
- `manual_handler_only`: handlerは存在しますが共通の安全契約へ未適合です。

blocked handlerのID、format別阻害理由、sourceとlocal dependencyから算出したSHA-256指紋はJSON正本に記録します。
`automated_analysis_completion_possible`は後方互換用のdeprecated aliasで、`structurally_routable`と同値です。名前に反して実検体の完了実績を表しません。
この表は構造・preflight上で経路と品質gateを構成できるかを示し、実検体での完了を保証しません。
安全handlerがあることだけでは解析完結とは判定せず、caseごとにfamily別品質policyと全品質gateの充足を検証します。
