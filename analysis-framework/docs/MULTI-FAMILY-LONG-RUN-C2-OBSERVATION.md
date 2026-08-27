# 6 familyの長期・防御的command観測

## 目的と現在の到達点

本書は、Vidar、StealC、RemusStealer、VenomRAT、RemcosRAT、QuasarRATについて、静的解析および保存済み証跡から得た情報を、安全な反復観測へ接続するための実装境界と将来設計を記録します。

現在実装されているのは、`long_running_command_observer.py`によるrepository外spoolのoffline／loopback観測です。このobservatory自身はsocket、HTTP client、DNS、C2 session、schedulerを持たず、外部endpointへ接続しません。復号済みobjectまたは既に取得済みframeを分類し、commandを実行せず、replyを返さず、追加payloadを取得しません。24時間を超える連続processは許可せず、さらに長い期間の比較は外部schedulerがbounded processを反復して行う想定です。

StealCのreview済み旧検体には別の有限active probe helperが存在しますが、observatoryには統合されておらず、今回external networkで実行していません。長期live C2観測は本書後半の将来設計であり、未実装です。

関連する既存境界は、[Stealer C2 detectorとemulator](STEALER-C2-DETECTION-EMULATION.md)、[防御的RATホストエミュレーター](RAT-C2-HOST-EMULATOR.md)、[AsyncRAT／VenomRATのC2検出と防御的エミュレーション](ASYNCRAT-VENOMRAT-C2-EMULATION.md)、[C2解析の完了基準](C2-ANALYSIS-COMPLETION-STANDARD.md)を参照してください。

## 共通の安全境界

実装済み観測器では、次を不変条件とします。

- `source_scope`は`offline_capture`または`loopback`だけを受理する。
- 受信command、task、script、shell、process／file／registry操作を実行しない。
- 成功・失敗reply、heartbeat、synthetic resultを送信しない。
- file、plugin、stage、config、追加payloadを要求・追跡・保存・実行しない。
- victim由来の端末名、利用者名、credential、token、path、raw commandを公開しない。
- 未知opcode、message type、packet名へ推測で意味を割り当てない。

公開eventでは`operation_executed=false`、`payload_download_attempted=false`、`plugin_retained_by_observer=false`、`raw_content_published=false`を固定し、observer actionは`observe_only_no_response`です。

## 検体とevidence scope

表のbindingはfamily全体への一般化を意味しません。同じfamily名、version候補、code類似、provider labelだけで、鍵、endpoint、certificate、packet ID、serializer mappingを継承しません。

| family | 現在の根拠 | 実装で許可する範囲 | 未解決または禁止する一般化 |
|---|---|---|---|
| Vidar | [`0c307efa...ddc36`](../../analysis-results/malware/vidar/versions/unknown/cases/0c307efa752ca4d412aee733c3d4c3453942b44a22ec2b0d405156003beddc36/README.md)、[`0cad181b...3ddc2`](../../analysis-results/malware/vidar/versions/unknown/cases/0cad181b2a0c10c287173b15efa7bf92d387987a41a49ad9be3c486e43e3ddc2/README.md)、[`3d2cea3e...0e323`](../../analysis-results/malware/vidar/versions/unknown/cases/3d2cea3eaa43053ae0efa20de8544387d7cabeb70c89980f4241f3b6efa0e323/README.md) | 3 SHA-256を、同じoffline resolver-result分類schemaへ束縛した3個の独立bindingとして扱う | 3検体が同じendpoint、config、最終C2 wireを共有するとは解釈しない。interactive command C2ではなくbootstrap候補の相関だけ |
| StealC | 現行[`8a7e7071...18c7b`](../../analysis-results/malware/stealc/versions/unknown/cases/8a7e70710748b10cec4c9f0653c55a0439a7f5f8f51b1e60284ace75a2118c7b/README.md)と、別のreview済み旧検体`47854afb...` | 旧検体の復号済みJSONをoffline分類する。別helperは旧検体、build、host、IP、registry hashへ完全pinした最大2 POSTだけを構成できる | 現行`8a7`へのexact bindingは未解決。response schema適合はconfigured acceptance policyであり、version確認ではない |
| RemusStealer | 現行[`75d199a7...95bef`](../../analysis-results/malware/remusstealer/versions/unknown/cases/75d199a793b8f5ba7d15d2665a9abc0a80489250393af7bc9f9e832c2e495bef/README.md)、[`0e5424f3...3bf7b`](../../analysis-results/malware/remusstealer/versions/unknown/cases/0e5424f3c4c5459f3fcb3c8b0cd121c4799f5274af8d01af1cbff78118c3bf7b/README.md)、および別のreview済み旧検体`2b3a23db...` | 旧検体のChaCha20復号後`{type,name,data}` objectをserver-to-clientのopaque task envelopeとして分類する | `name`／`data`の意味、現行2検体とのexact binding、完全なresponse flowは未解決 |
| VenomRAT | 旧6.0.3検体[`6a24ba25...a1073`](../../analysis-results/malware/venomrat/versions/v6.0.3/cases/6a24ba25482c73d193fcc208d8ae267236b870b9ab30c44cabe2dc8bfb7a1073/STATIC-DEEP-DIVE.md)と現行[`2b0af18b...94f6a`](../../analysis-results/malware/venomrat/versions/unknown/cases/2b0af18bdd10782cf72a985b2f49564aa9058c34645205afb4fcc27724794f6a/README.md) | 旧検体はreview済みwire profile。現行は[専用evidence](../malware/venomrat/current-2b0af18b-exact-profile-evidence.json)に基づくcode-lineage candidateのdecode-only profileで、直接確認した`Pac_ket`、`Po_ng`、`plu_gin`、`save_Plugin` markerだけを扱う | 現行profileはregistration無効、heartbeat要求未確認。旧検体の`ClientInfo`や送信literalを継承せず、live互換を主張しない |
| RemcosRAT | 現行[`61321510...d8a19`](../../analysis-results/malware/remcosrat/versions/unknown/cases/61321510045ef68e4e20672cb1b130a2632d7b3cb1c3c8348c4c5e300d0d8a19/README.md)、保存済みplaintext framing、公開3.4.0 taxonomy | magic `24 04 ff 00`、LE32 size／IDを復号済みstreamから復元する。公開taxonomyは明示opt-inの`remcos-published-340-taxonomy-v1`だけ | 現行`613`のversion、transport、登録、heartbeat、command mappingは未解決。公開taxonomyにexact sample bindingはない |
| QuasarRAT | 現行[`a63cffc7...fc743`](../../analysis-results/malware/quasarrat/versions/unknown/cases/a63cffc78eea1c004b2e56ef5ae6573662376b5c6ec8ebbaef27cac7344fc743/README.md)とupstream v1.3知識 | upstream taxonomyの復号済みmessage objectをoffline分類する。v1.3 protocol metadataは認証済み静的configが復元できた場合だけ付与する | 現行`a63`のversionはunknown。旧[`handler-results.json`](../../analysis-results/malware/quasarrat/versions/unknown/cases/a63cffc78eea1c004b2e56ef5ae6573662376b5c6ec8ebbaef27cac7344fc743/handler-results.json)のgeneric TLS表現はsupersededで、現行証拠に使わない |

## 実装済みoffline／loopback observatory

### profile registry

`rat_command_observer.py`の現在のprofileは次のとおりです。

| profile ID | 方向と入力 | sample binding | 境界 |
|---|---|---|---|
| `vidar-dead-drop-snapshot-v1` | `internal`、decoded JSON | 上記3 SHA-256を個別に許可 | resolver snapshot結果だけ。interactive commandではない |
| `stealc-v2-1backs-decoded-json-v1` | 双方向、RC4／Base64復号後JSON | `47854afb...` | create、config、status、loader shapeの有限分類だけ |
| `remus-ba0044e8-decoded-task-v1` | server-to-client、ChaCha20復号後JSON | `2b3a23db...` | envelopeだけ。task意味は未解決 |
| `venomrat-603-6a24ba25-messagepack-v1` | server-to-client、LE32／gzip／MessagePack frame | `6a24ba25...` | 旧検体review済みprofileの1 inbound frame |
| `venomrat-603-2b0af18b-messagepack-v1` | server-to-client、LE32／gzip／MessagePack frame | `2b0af18b...` | 現行code-lineage candidateの1 inbound frameをdecode-only分類 |
| `remcos-decrypted-plaintext-framing-v1` | 双方向、復号済みplaintext frame | なし | command IDの意味を`unknown`のまま保持 |
| `remcos-published-340-taxonomy-v1` | server-to-client、復号済みplaintext frame | なし | Fortinet 3.4.0公開taxonomyの明示opt-in。`exact_sample_binding=false` |
| `quasar-upstream-decoded-message-v1` | 双方向、decoded object | なし | upstream type taxonomyだけ。serializer、type ID、current wireを再実装していない |

`long_running_command_observer.py`は、`PROFILES`の全dataclass公開fieldと分類taxonomy定数をcanonical JSON化し、`frozenset`をsortした`profile_registry_sha256`をmanifestへpinします。起動時に現在のregistry hashと一致しない既存observatoryは拒否します。

### 初期化と実行

observatory rootは新規の絶対pathで、実行moduleから求めた実repositoryおよび任意のGit worktree外に置く必要があります。`--repository-root`は、その実repositoryと一致しなければ拒否されます。

```powershell
py -3 .\analysis-framework\common\long_running_command_observer.py init `
  --root C:\analysis-private\command-observatory-20260827 `
  --repository-root C:\path\to\repository

py -3 .\analysis-framework\common\long_running_command_observer.py once `
  --root C:\analysis-private\command-observatory-20260827 `
  --repository-root C:\path\to\repository

py -3 .\analysis-framework\common\long_running_command_observer.py run `
  --root C:\analysis-private\command-observatory-20260827 `
  --repository-root C:\path\to\repository

py -3 .\analysis-framework\common\long_running_command_observer.py verify `
  --root C:\analysis-private\command-observatory-20260827 `
  --repository-root C:\path\to\repository

py -3 .\analysis-framework\common\long_running_command_observer.py summary `
  --root C:\analysis-private\command-observatory-20260827 `
  --repository-root C:\path\to\repository
```

private decoded projectionが必要な場合だけ、`init`時に`--retain-private-fields`を付けます。この選択はmanifestへ固定され、後から自動的に有効化されません。

### spool入力とprovenance

`incoming`へ置くJSONは、`schema_version=1`、`profile_id`、`sample_sha256`、`source_scope`、`direction`、UTC秒精度の`captured_at`、`encoding`を持ちます。VenomRAT／RemcosRATは`encoding=frame_base64`と`frame_base64`、それ以外は`encoding=decoded_json`と`message`を使用します。exact sample profileでは対応SHA-256が必須です。未知key、duplicate key、不正Base64、過大入力、profile／direction／sample不一致はfail-closedで拒否します。

`source_scope=loopback`はproducer／callerのprovenance契約です。特にVenomの下位frame decoderは、byte列が本当にloopback由来かを技術的に検証しません。callerが由来を確認して完全なframe envelopeをspoolへ渡す必要があり、このlabelは送信許可ではありません。Remcos stream decoderのchunk出力もobservatoryへ自動接続されず、callerが完全frameを明示的に渡します。

### bounded process、backoff、容量停止

`once`と`run`は排他claimを使用し、stale claimを自動回収しません。1 cycleのfile数、1 event、segment event数／bytes、ledger event総数、storage総量には固定上限があります。eventまたはstorage上限へ達すると未処理inputを残して停止し、自動削除で容量を空けません。

`run`のprocess runtimeは最大24時間です。poll、backoff、cooldownのsleepは最大1秒単位に分割され、`kill.switch`とruntime deadlineを確認します。通常errorは指数backoffとjitterを使います。設定名`circuit_breaker_failures`の閾値へ達するとcooldown後に失敗数とbackoffをresetして再試行しますが、永続的な`circuit_open`状態やprofile別breakerは実装していません。長期live設計でいうcircuit breakerとは区別します。

storage計測はincoming／control surfaceのcacheと定期的な全tree再照合を組み合わせ、既定では256 cycleごとに全体を再確認します。ledger segment名は連続したcanonical番号だけを許可し、6桁zero-padから最大9桁までに制限します。

### ledger、checkpoint、receipt

eventはcanonical JSONのSHA-256でglobal chain化し、sequence、previous hash、source size／SHA-256、sample、source scope、direction、公開分類、dedupe fingerprintを保存します。dedupe fingerprintはprofile、sample、family、direction、category、normalized command、message SHA-256を含むため、逆方向の観測を同一視しません。

eventをdurable化した後に`ledger-head.json`をatomic更新します。起動、`verify`、summary生成では全chainとlocal durable checkpointを照合し、tail削除またはevent追加後のcheckpoint更新失敗をfail-closedで検出します。ただし外部anchorは未実装です。eventとcheckpointを同じ過去状態へ同時rollbackした場合は検出できないため、manifest、summary、verifyは`external_anchor_present=false`と`coordinated_checkpoint_rollback_detectable=false`を明示します。

ledger eventのcommitまたはcheckpoint更新に失敗した場合、runはそのprocess内で再試行を継続せず、ledger_commit_failed_restart_requiredで直ちに停止します。operatorはstorageとchainをverifyし、原因を解消してから新しいbounded processとして再開します。

`processed`と`rejected`にはraw spoolを複製せず、source size／SHA-256、status、時刻だけのsanitized receiptを置きます。拒否理由の生文字列も保存しません。正常処理または拒否receiptの固定後、identityが変わっていないincoming sourceを削除します。

### public／private出力

既定の`retain_private_fields=false`ではledgerの`private_fields`は空で、decoded command、URL、token、path等を保持しません。`--retain-private-fields`を明示したrootだけがbounded decoded projectionをprivate ledgerへ保持します。その場合でもplugin raw bytesは保持せず、公開summaryへprivate fieldを出しません。

public summaryは検証済みledger snapshotから、profile ID、sample SHA-256、family、direction、category、normalized command、message SHA-256、初回／最終sequence、sighting数を集約します。session ID、外部endpoint、raw frame、実command line、archive参照、実時刻ベースのfirst／last seenは現在のsummary schemaにありません。

## 分離されている有限active probe

StealC旧検体の`stealc-v2-1backs-31-77-228-62-80`は、observatoryとは別のhelperです。`allow_network`と`allow_registration_tasking`の両方、profile registry source／SHA-256 pin、完全sample／build／host／port／単一global IP pinが一致した場合だけ最大2 POSTを構成します。安定したUUIDv5合成HWIDを使い、create responseとloader responseをconfigured acceptance policyで検証します。loader entryは`{url}`だけ、schemeはHTTP(S)、userinfoは禁止し、URLをfollowせず、payloadをdownload／実行せず、task replyを送りません。

結果fieldの`configuration_schema_confirmed`は`configuration_schema_scope=configured_acceptance_policy_not_version_confirmation`の判定です。`version_confirmed_by_response_schema=false`であり、応答shapeだけからStealC versionを確定しません。profile根拠は[`analysis-summary.json`の`samples[0]`](../../analysis-results/research/stealer-protocol-profiles/2026-08-04/analysis-summary.json)です。

## 将来のlong-running live設計（未実装）

次は設計上の要件であり、現行observatoryの機能ではありません。

- endpoint／DNS／certificate／credentialを完全evidenceへ束縛する期限付きlease。
- OSまたはnetwork layerのegress allowlist、同時接続1、sessionごとの送受信byte／frame／時間上限。
- session manifest、profile別状態遷移、明示的なno-reply disconnect。
- profile別に永続するcircuit-open状態、operator reset、外部schedulerとのlease連携。
- 外部anchorへledger headを固定し、coordinated rollbackを検出する仕組み。
- observatoryとS3 archiveの検証済みhandoff、archive manifest参照のpublic summary統合。

live観測を実装・開始するには、少なくとも次をすべて満たす必要があります。

1. 対象sampleとendpointへexact bindingしたprofile、profile hash、証拠sourceが揃う。
2. offline fixtureとloopbackでpositive、negative、truncate、oversize、duplicate、認証失敗を検証する。
3. command実行、reply、download、payload保存をcode上でfail-closedにし、未知frame testを持つ。
4. repository外storage、private／public分離、hash chain、quota、kill switchを一体で試験する。
5. 期限付きlease、egress allowlist、session上限、profile別circuit breaker、operator resetを実装する。
6. 対象endpointと期間を限定した別途の明示承認を得る。

これらが揃っても、受信commandの実行、reply、payload取得へ範囲を広げません。current exact wireが未完成のprofileはoffline研究に留め、互換性を推測して外部へbyte列を送りません。

## S3 datastoreへの保管

observatoryはS3 uploadやlocal staging削除を実装していません。`--retain-private-fields`で保持したprivate ledger、PCAP、復号済みpayload等を別工程で保管する場合だけ、[解析データストア運用手順](ANALYSIS-DATASTORE.md)と`analysis-framework/common/archive_analysis_datastore.py`を使用します。解析対象ごとにpassword `infected`のWinZip AES-256 ZIPへ分離し、AWS CLIとhost IAM roleで`malware-analysis-datastore-720232834682`へuploadします。token、API key、AWS credential、`.env`、`creds.txt`、SSH秘密鍵を含めません。

upload後はS3側のsize、SSE、SHA-256 metadataを検証し、成功前にlocal stagingを削除しません。source本体は自動削除せず、observerのlocal checkpointを外部anchorとして扱いません。

## family別の残課題

- Vidar: 3つの独立sample bindingごとのdead-drop時点、最終C2 exact request／response、server responseの意味。
- StealC: 現行`8a7`の鍵、path、finite flow、review済み`47854afb` profileとの関係。
- RemusStealer: `type`、`name`、`data`の方向別意味、現行2検体と旧exact profileのbinding。
- VenomRAT: 現行`2b0`のregistration／keepalive evidence、current wireの独立確認。semantic lineageだけでは送信を許可しない。
- RemcosRAT: 現行`613`のversion、transport復号、登録frame、heartbeat方向、version別command／result mapping。
- QuasarRAT: 現行`a63`のversion、認証済み静的config、endpoint、鍵、serializer type ID、登録frame。upstream v1.3知識をcurrentへ自動bindingしない。
