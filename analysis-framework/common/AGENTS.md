# `analysis-framework/common` のAI非依存解析runner規則

- WebUI／API向けproduction入口は`analysis_job_runner.py`とし、request JSONから`upx`、`sevenzip`、`diec`、任意command、任意環境変数を受理しない。
- productionで外部静的toolが必要な場合は、service operatorが管理するmanifest pathとmanifest raw SHA-256 pinをrunner CLIへpairで固定する。client値、`PATH`探索、起動時downloadへ置き換えない。
- 現在許可するtoolはself-containedなUPXと7zzだけとし、DIECはproduction契約では無効のままにする。追加toolを有効にするときはmanifest exact schema、platform pin、binary size／SHA-256 pin、job-private snapshot、root／child契約、result provenance、process／一時tree上限を同じ変更で実装する。
- operator tool sourceはinput root、job root、repositoryの外へ分離し、通常file、単一link、非reparseを単一handleで検証する。analyzerへは`contract-inputs/static-tools/`内のsnapshotだけを渡し、worker前後に再検証する。
- full analyzerと内側workerの`TEMP`、`TMP`、`TMPDIR`は`analysis/.private-temp/`へ固定する。終了時にtree quota、link、identity、空directoryを検証し、残存物を再帰削除して成功扱いしない。
- 外部tool processは共通containment、有界stdout／stderr、明示timeout、active process／memory上限、一時tree件数／size上限、安全な単一handle出力読込を必須とする。これらをkernel sandboxと説明せず、本番では低権限account、ACL、outbound deny、global quota、container／VMを併用する。

# `analysis-framework/common` の防御的RATエミュレーター規則

この文書は`analysis-framework/common/`配下のRATホストエミュレーター、session evidence、C2監視統合に適用します。リポジトリルートの`AGENTS.md`にある静的解析、ライブC2、秘密情報、MaxMind、履歴管理の規則も併せて守ります。

## live通信の許可

- RATの遠隔操作channelを継続観測する処理は、通常の1回限定C2監視から分離し、`run_defensive_rat_emulator.py`を標準入口とします。
- 現在のtaskでユーザーが実C2通信を明示的に許可していない場合は、offline replayまたはloopback試験だけを行います。
- live sessionには`--allow-network`、`--allow-live-c2-emulation`、`--acknowledge-profile <完全一致profile ID>`、存在するkill-switch fileをすべて要求します。host／portの任意指定、profile外IP、複数IP試行、redirect、reconnect、別endpointへの接続を許可しません。
- `rat_emulator_live_leases.json`の短期leaseが現在時刻に有効であり、その`profile_registry` source／SHA-256 pinが検証済みprofile registryと一致することをDNS、MaxMind、TCPより前に要求します。CLIから検証時刻やlease pathを上書きできるようにしてはいけません。
- 接続前にMaxMind GeoLite2 City／ASNのbuild時刻を確認し、24時間以上前なら更新します。鮮度確認に失敗した場合は接続しません。

## 短期live leaseの再レビュー

- leaseは`reviewed_at_utc <= 現在時刻 < expires_at_utc`の半開区間だけ有効とし、1件の有効期間を24時間以内に限定します。期限前、期限到達、profile欠落、未知profile、重複、registry pin不一致はfail-closedです。
- 再レビューでは3 profileそれぞれの検体SHA-256、endpoint、単一pinned IP、SNI、証明書SHA-256、protocol／evidence SHA-256を再確認します。既存`rat_emulator_profiles.json`をlease更新だけの目的で変更せず、そのraw SHA-256を新しいlease registryからpinします。
- 再確認後に`reviewed_at_utc`、`expires_at_utc`、`review_owner`を更新し、lease validator、preflight、期限境界testを実行します。過去のlive summary、sidecar、静的evidenceは再生成しません。
- live開始時の残lease秒をmonotonic deadlineへ変換し、profileのsession期限との短い方を使います。MaxMind後、DNS後、TLS後、各send／recv直前に期限を再確認し、transport timeoutも残時間以下へ再設定します。kill-switchはleaseとは独立して継続利用します。

## 送受信と実処理の禁止

- 現行実装で送信できるapplication frameは、profileへ固定したN520の空command 1 registration、Winosの固定heartbeat、AsyncRAT／VenomRATの合成`ClientInfo`とprivacy-safeな固定Ping requestだけです。固定した合成端末情報を使い、実端末のhost名、user名、process、file、画面、camera、clipboard、credentialを読みません。
- exact ILの`KeepAlivePacket`は、AsyncRATではtoken `0x06000024`、VenomRATではtoken `0x06000056`で、`Ping.Message`へ`GetActiveWindowTitle`結果を入れます。エミュレーターはこのAPIを呼ばず、`Message`を空文字へsanitizeして送信します。
- AsyncRAT／VenomRATは合成`ClientInfo`、固定Ping requestの順に送信し、C2からの`pong`／`Po_ng`またはtaskを最大1 frameだけ受信します。heartbeat応答にもtaskにも返信せず、分類後にsessionを終了します。
- command本文、path、URL、引数を実行、反射、別通信へ転送しません。shell、process、filesystem、registry、service、画面、camera、音声、proxy、scan、DDoS、payload／plugin／stage取得を実装しません。
- file-transfer、未知command、未reviewのresult serializerを受信した場合は、fingerprintを記録して無応答でsessionを終了します。
- 任意操作結果のfake replyは現行実装にありません。result serializerが未解決の間はlive C2へのwire送信を禁止し、offline／loopbackではwire bytesを持たない抽象判断だけを扱い、公開要約は`synthetic_reply_sent=false`を必須とします。将来実装する場合も、command ID、sequence、result serializer、固定templateを静的解析とloopback試験で確認し、証拠SHA-256を専用profileへ固定するまでは有効化しません。

## 上限と記録

- 初期版は1 session、単一接続、短時間、固定frame数・command数・送受信byte数に制限し、上限超過時はfail-closedで終了します。
- private transcriptはevent sequence、直前event SHA-256、frame SHA-256、最終root SHA-256で改ざんを検知できる形式にします。生command、raw frame、token、鍵、合成IDをgitへ追加しません。
- private transcriptは解析対象別に`archive_analysis_datastore.py`でS3へAES-256 ZIP保管します。通常の公開live要約にはsession要約、root hash、archive／manifest SHA-256だけを残します。監視sidecarに限り、validatorがbucket／解析対象とのbinding、SSE、archive size／SHA-256、manifest SHA-256、archive report SHA-256を検証した`object_uri`をallowlist公開できます。credential、ETag、IAM role、local path、raw transcriptは公開しません。
- command受信はC2稼働の強い肯定証拠として扱えますが、短時間にcommandを受信しなかったことは停止の根拠にしません。通常の到達性・DNS履歴とprotocol activity履歴を分離します。

## 将来の常時稼働

常時稼働へ移行する場合は、専用VM／service account、OSレベルegress allowlist、同時接続1、現行の短期live leaseに加えたprocess間のatomic claim、cooldown、log rotationを追加し、別の明示承認を得ます。既存の短時間runnerを単純な無限loopへ変更しません。
