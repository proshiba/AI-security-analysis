# RedLine／XLoader能動C2判定の共通統合契約

## 目的

RedLine Stealerと、GuLoaderが配送したXLoader／FormBook系後段について、マルウェア固有の最小通信を使ったC2判定を共通監視、レビュー済みprofile registry、Nmap NSEへ安全に統合するための契約を定義する。

ここでいう「能動C2判定」は、単なるDNS解決、TCP port open、HTTP status、汎用SOAP endpointへの到達ではない。検体へ完全一致で結び付いたendpointと通信材料を使い、レビュー済みの要求を上限内で送信し、マルウェア固有の応答構造または暗号学的整合性を確認することを指す。

## ファミリー境界

- RedLineは`BasicHttpBinding`上のSOAP 1.1 `CheckConnect`を初期の最小probeとする。
- GuLoaderは配送・復号loaderであり、最終C2 protocolの所有者ではない。能動probeのfamilyは`xloader`とし、GuLoader parent hashは由来情報として保持する。
- Google DriveなどのGuLoader配布先はXLoader C2へ昇格しない。
- XLoaderの候補domain群はreal C2とdecoyを含み得る。候補形式、HTTP 404、候補indexの推測だけでは能動probe対象へ昇格しない。

## 共通profileに必要な証拠

| 項目 | RedLine | XLoader |
|---|---|---|
| endpoint | 静的に復元したscheme、host、port、path | real C2として選択されたscheme、host、port、path |
| sample binding | terminal RedLine SHA-256とconfig artifact | terminal XLoader core SHA-256。必要に応じてGuLoader parent SHA-256も由来として保持 |
| protocol binding | `Endpoint/CheckConnect`、SOAP namespace、引数なし、boolean応答 | request builder、候補選択、暗号／encoding、応答検証までの同一variant dataflow |
| review binding | config artifactのSHA-256とJSON pointer | candidate table、real-C2選択根拠、鍵材料、pathのreview record |
| endpoint固定 | 完全一致。domainの場合は単一review済みIP pinを推奨 | 完全一致かつ単一review済みIP pinを必須 |
| request budget | 1 | 1。候補総当たりは禁止 |
| redirect | 追跡しない | 追跡しない |
| response上限 | 4 KiB以下を推奨 | variantのreview値。最大64 KiB |
| timeout | 3秒以下を推奨、上限5秒 | 3秒以下を推奨、上限5秒 |

profile registryへ登録する前に、source artifactの実体、artifact SHA-256、sample SHA-256、endpoint、protocol variantがすべて一致することを再検証する。いずれかを欠くendpointは`protocol_profile_required`としてDNS観測だけに留める。

## RedLine最小probe

許可するapplication requestは次の1件だけである。

- `POST /`またはreview済み完全一致path
- `Content-Type: text/xml; charset=utf-8`
- 引用符付き`SOAPAction: "http://tempuri.org/Endpoint/CheckConnect"`
- SOAP 1.1 envelope内の空`CheckConnect`要素
- victim ID、build ID、端末情報、資格情報を送らない

C2確定には、2xx応答だけではなく、次のすべてを要求する。

- SOAP 1.1 namespaceの完全一致
- `CheckConnectResponse`直下に単一`CheckConnectResult`
- resultが単純な`xsd:boolean`相当の`true`、`false`、`1`、`0`
- DTD、entity、未知要素、未知属性、余分なtextを拒否
- `Content-Length`と実body長の一致

`false`もRedLine contractへ適合する応答であるため、protocol同定には使用できる。ただし、server側が後続処理を受け入れる状態であることまでは意味しない。結果にはprotocol確認と後続task可用性を分離して残す。

安全gateは`allow_network`と専用の`allow_reviewed_checkconnect`の両方とし、さらに対象profile IDの完全一致acknowledgementを要求する。`CheckConnect`は端末登録や認証ではないため、資格情報用gateやtask取得用gateへ混在させない。

## XLoader最小probe

XLoaderは候補domainの存在だけではprobeを構築できない。次の証拠がそろったvariantだけを実装対象とする。

1. real C2をdecoyから選択するdataflowまたは同一flowのreview済み動的証跡
2. request pathとHTTP method
3. request bodyのfield、encoding、暗号化順序、検体固有鍵
4. 応答の復号、認証、command envelope検証

能動送信は合成端末値を使用し、候補1件へ1要求だけ送る。64件または65件の候補総当たり、fallback、redirect追跡、追加payload取得、返却commandの実行は禁止する。応答にtaskやcommandが含まれていても、公開結果へ本文を残さず、存在、長さ、cryptographic validationの成否だけを記録する。

HTTP 404はXLoader／FormBook系で偽装やdecoyに利用されるため、単独では肯定根拠にも否定根拠にもならない。`c2_confirmed=true`は、review済み鍵で応答を復号・認証し、期待するenvelopeまで一致した場合だけ許可する。

安全gateは`allow_network`と専用の`allow_xloader_registration`の両方とする。初期bootstrap候補を例外的に扱うfamily APIでは、さらに候補専用gateを要求する。real C2選択、runtime URL seed、review済み合成PKT2平文のいずれかが未確定の現在のGuLoader caseは、probe能力のloopback検証とは分離し、実endpoint profileを登録しない。

現在検体の要求側はGhidraで復元した`PKT2`／`XLNG`、URL SHA-1、URL seed派生鍵、RC4、Base64のdataflowを根拠とする。応答側は現在検体でbuffer保存まで確認したもののconsumer xrefを確定できていないため、XLoader v8.7の一次調査と参照検体に基づくcross-version contractとして明示する。現在検体の直接根拠とcross-version根拠を同じ強度で扱わない。

## 共通monitorへの統合点

新しいmethodごとに、次の全箇所を同時に更新する。

1. `c2_protocol_probe_profiles.py`のhandler／protocol／method対応
2. profile固有の型、上限、evidence pin、sample集合、endpoint一致の検証
3. `monitor_recent_c2.py`の許可method、active method、confidence ceiling、日本語label
4. `validate_plan`のexpected protocolと追加evidence pin検証
5. application gate付きdispatch
6. observationのサニタイズとfail-closed評価
7. policy集計のcheck-in数、登録数、task取得数
8. `build_all_c2_monitoring_targets.py`の完全一致overlayと未登録時の`protocol_profile_required`

共通観測結果には少なくとも次を含める。

- `target_contact_attempted`
- `target_connection_established`
- `application_data_sent`
- `sent_bytes`と`received_bytes`
- `request_budget_used`
- `protocol_response_received`
- `c2_confirmed`
- `synthetic_identity_sent`
- `victim_metadata_sent`
- `task_poll_attempted`
- `task_content_published=false`
- `task_executed=false`
- `payload_download_attempted=false`
- 生のrequest、response、鍵、token、cookieを公開していないことを示すflag

`status`とboolean flagが矛盾した場合はC2確定を禁止する。socket error、timeout、HTTP mismatch、復号失敗は「その観測で未確認」であり、直ちに非C2または恒久停止とは扱わない。

## Nmap NSEによる観測

RedLineとXLoaderは、既存の汎用HTTP GET判定へ混ぜず、familyごとのmodeまたは専用NSEとして登録する。

- loopback模擬C2でpositive、mismatch、malformed、overlong、timeoutを検証する。
- 必須の検体固有引数がない場合は送信せず終了する。
- 1 host、1 port、1 requestに限定する。
- redirect、候補fallback、task取得、payload取得を行わない。
- script出力へ鍵、合成端末値、token、復号本文を出さない。
- XLoaderの鍵をCLIへ渡す設計では、process listやscan logへの露出を避けるため、private fileまたは環境依存の安全な参照方式を優先する。
- `profiles.json`には最大confidenceと、そのconfidenceへ到達する厳密な条件を書く。

NmapのRedLine肯定条件は、完全なSOAP response構造とboolean resultの一致です。XLoader NSEは検体固有private materialを安全に扱えないためtransport-onlyとし、application dataを送らず、`c2_confirmed=false`とconfidence 0.15を固定します。XLoaderの旧Python active probeへfallbackせず、暗号応答を安全に検証できるreview済みNSE profileが完成するまではtransport観測だけに限定します。

## オフラインテストマトリクス

| 層 | 肯定系 | 否定・安全系 |
|---|---|---|
| profile registry | exact endpoint、sample、artifact pin | endpoint差替え、sample差替え、hash差替え、上限超過を拒否 |
| RedLine request | byte単位のreview済みSOAP fixture | path、SOAPAction、namespace、引数追加を拒否 |
| RedLine response | `true`／`false`の完全構造 | 2xxだけ、HTML、DTD、entity、未知要素、trailing bytesを拒否 |
| XLoader request | review済み既知vector | 鍵、候補index、path、encodingの1 byte差を拒否 |
| XLoader response | 復号・認証・envelope一致 | 404だけ、decoy HTML、tamper、overlong、未知commandをC2確定にしない |
| monitor gate | 明示gate有効時だけloopback probeを呼ぶ | 既定値、片方のgateだけ、profileなしではsocketを呼ばない |
| monitor評価 | statusとflagsの完全一致 | 矛盾するstatus／flagをfail-closedにする |
| target builder | exact profileを1件overlay | candidateだけのendpointをactive化しない |
| Nmap | localhost模擬C2で一致 | mismatch、malformed、timeoutで非一致。外部hostをtestへ含めない |
| 情報管理 | hash、長さ、booleanのみ出力 | request／response本文、鍵、token、cookieがreportへ出ない |

## 現在の適用判断

- RedLineは静的config、終端MVID、CIL意味hash、`CheckConnect` contractを固定したexact endpoint profileへ昇格済みである。2026-08-09の1回限定実確認はTCP接続前の3秒timeoutで、application dataは送信されず、稼働状態は未確認のままである。
- 対象GuLoader caseのXLoaderは、65候補、初期16 selector／path、slot 12のbootstrap置換、第1PKT2鍵、要求生成dataflowまで静的復元した。一方、runtime URL seed、review済み合成PKT2平文、real C2／decoyの確定、common active profileが未解決である。この状態で実endpointへ送信するprofileは作らない。protocol実装はreview済みloopback vectorで検証し、実profileは追加証拠を得た時点で別途承認する。

この区別により、「probe実装が存在する」ことと「特定の実C2へ送信してよい」ことを分離する。
