# 防御的RATエミュレーターのDocker実行

## 対象

この構成はKali Linux上に設置した次のloopback限定エミュレーターを、互いに独立したDocker imageとして実行します。

- PureRAT／PureHVNCの観測エミュレーター: `/home/kali/purerat-emulator-20260824`
- ValleyRAT N520のhost adapter: `/home/kali/valleyrat-n520-emulator-20260824`

既定commandは、実socketを使うloopback統合テストです。検体、受信command、plugin、stageを実行しません。外部C2へ接続せず、コンテナのnetwork namespaceも`none`にします。

## Kaliへの導入

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose
sudo systemctl enable --now docker
```

`docker` groupはDocker daemonを介してroot相当の操作が可能になるため、解析用userを追加しません。Compose操作は`sudo docker-compose`を使用します。

## buildと実行

```bash
cd /home/kali/rat-emulator-docker-20260824
sudo docker-compose build --pull
sudo docker-compose up --abort-on-container-exit
```

両サービスが`exited with code 0`となり、PureRATが`10 passed`、ValleyRAT N520が`23 passed`となることを確認します。

## 安全境界

- runtime userはUID／GID `10001`で、rootを使用しない。
- `network_mode: none`により外部通信とcontainer間通信を無効化する。
- root filesystemはread-onlyとし、`/tmp`だけを`noexec,nosuid,nodev`で一時利用する。
- Linux capabilityをすべて削除し、`no-new-privileges`を設定する。
- process、memory、CPUに上限を設け、自動再起動しない。
- host directory、Docker socket、device、秘密情報をmountしない。
- command実行、plugin／stage保存、任意result送信を追加しない。

PureRAT observerを長時間待機させる運用は、loopback模擬C2とkill-switch／log volumeを同一の隔離構成へ追加した別profileで扱います。この既定Composeのnetwork制限を外部C2向けに緩和しません。

## 外部C2 observer

`docker-compose.external.yml`は既定構成から分離した明示profileです。現在、外部live証拠と完全一致する短期lease対象はValleyRAT N520だけです。PureRATはreview済み証拠が`live_registration_allowed=false`を固定しているため、外部接続対象へ追加していません。

外部observerは任意host／portを受け取りません。次の完全一致profileだけを使用します。

```text
valleyrat-n520-host-d11e793-9999
118.107.21.88:9999/TCP
container address: 172.30.52.10
```

受信commandはcommand番号、分類、方向、frame size、SHA-256、処理判断として改ざん検知付きtranscriptへ記録します。raw command本文、plugin、stage、fileは保存せず、応答、実行、別通信を行わずsessionを終了します。

### Kali側の準備

```bash
sudo install -d -o 10001 -g 10001 -m 0700 \
  /home/kali/rat-emulator-external-20260824/transcripts
sudo install -d -o root -g root -m 0755 \
  /home/kali/rat-emulator-external-20260824/arm
sudo install -d -o 10001 -g 10001 -m 0700 \
  /home/kali/rat-emulator-external-20260824/maxmind
sudo install -o root -g root -m 0444 /dev/null \
  /home/kali/rat-emulator-external-20260824/arm/valleyrat-n520.arm
```

MaxMind GeoLite2のlicense keyは、管理serverの環境変数から暗号化SSHの標準入力でKaliへ渡し、tmpfsである`/run/rat-emulator-secrets/maxmind-license-key`へ実行中だけ配置します。Kaliの永続file、`.env`、serviceの通常環境変数には保存しません。処理終了後は一時fileとdirectoryを削除します。secretをchatやshell履歴へ記載しないでください。

observer起動前に、C2機能を持たない一回限りのsetup serviceでGeoLite2 City／ASNを取得します。接続先URLはrepositoryのMaxMind取得処理へ固定され、公式checksumを検証します。

Kaliに直接secretを入力するのではなく、管理serverの実行wrapperがtmpfs secretの作成、Compose実行、削除を一つの処理として行います。Kali上でComposeだけを直接起動すると、一時secretが存在しないためfail-closedで停止します。

observerは取得済みcacheをread-only mountします。公式再取得から24時間以上経過している、cacheがない、hash不一致、checksum未検証、secretが空の場合はC2接続前に停止します。MaxMind側の最新DB build自体が24時間より古い場合でも、setup serviceによる公式再取得とchecksum検証を24時間以内に完了していれば利用できます。

### egress固定と起動

Kaliの`DOCKER-USER` chainで、固定container addressからreview済みC2の単一port以外をdropします。

```bash
cd /home/kali/rat-emulator-docker-20260824
sudo ./kali-egress-policy.sh apply
sudo ./kali-egress-policy.sh check
sudo docker-compose -f docker-compose.external.yml \
  --profile external-observer build --pull
sudo docker-compose -f docker-compose.external.yml \
  --profile external-observer up --abort-on-container-exit \
  valleyrat-n520-external-observer
```

起動には、profile registryと完全一致する24時間以内のlive lease、存在するkill-switch、freshなMaxMind DB、証明書pin一致が必要です。単一接続・単一registration・最大300秒の有界sessionで、reconnectや自動再起動は行いません。

停止する場合はhost側でkill-switchのmtimeを変更します。

```bash
sudo touch /home/kali/rat-emulator-external-20260824/arm/valleyrat-n520.arm
```

停止後の公開要約とprivate transcriptは次へ残ります。

```text
/home/kali/rat-emulator-external-20260824/transcripts
```

## Winos最新C2の8時間external observer

`docker-compose.winos-external.yml`は2026-08-10検体の`64.81.30.192:6666`だけに固定した別構成です。container addressは`172.30.54.10`で、`kali-winos-egress-policy.sh`が対象TCP/6666以外をdropします。送信は接続ごとに15-byte C9 heartbeat 1 frameだけです。最初の応答後もclient側から切断せず、8時間、受信256 frame、合計16,384 byteのいずれかへ達するまで同じTCP接続を維持します。受信フレームはprivate transcriptへ保存し、command byte、size、SHA-256を記録して破棄します。返信、stage取得、plugin／file取得、command実行は行いません。

peer close、reset、接続拒否時だけ初回接続後に最大3回まで再接続します。4回目の失敗、frame／byte上限、lease／kill-switch違反では停止します。`valleyrat-winos-wire-capture` sidecarは対象IP／portだけを8時間PCAPへ記録します。

```bash
sudo install -d -o 10001 -g 10001 -m 0700 \
  /home/kali/valleyrat-winos-external-20260829-8h/transcripts \
  /home/kali/valleyrat-winos-external-20260829-8h/captures
sudo install -d -o root -g root -m 0755 \
  /home/kali/valleyrat-winos-external-20260829-8h/arm
sudo install -o root -g root -m 0444 /dev/null \
  /home/kali/valleyrat-winos-external-20260829-8h/arm/observer.arm

sudo ./kali-winos-egress-policy.sh apply
sudo ./kali-winos-egress-policy.sh check
sudo docker compose -f docker-compose.winos-external.yml build --pull
sudo docker compose -p winos8h -f docker-compose.winos-external.yml up -d \
  valleyrat-winos-external-observer valleyrat-winos-wire-capture
```

MaxMind keyは起動時だけCompose secretからprocess環境へ渡します。コンテナが読み取った後はKali側の一時secretを削除できます。完了後は`docker compose -p winos8h ... down`と`kali-winos-egress-policy.sh remove`でcontainer、network、専用chainを削除します。transcriptとPCAPは自動削除しません。

## PureRAT長期観測profile

`docker-compose.purerat-long-running.yml`は、単発runnerを無限loopへ変更せず、完全一致PureRAT sessionを安全なcooldownで直列実行する専用構成です。通常の`docker-compose.external.yml`およびcanonical offline profileとは分離されています。

固定値は次のとおりです。

```text
profile: purerat-441-d025a296-direct-tls10-empty-gclass4
endpoint: 45.192.211.77:56001/TCP
container address: 172.30.53.10
registration: 匿名固定GClass4、26 byte、sessionごとに最大1回
receive: sessionごとに最大1 frame／65,536 byte
cooldown: 30秒、連続失敗時は最大900秒まで指数backoff
retry: 初回失敗後の再接続は最大3回。同じlease registry identityで4回連続失敗すると永続circuitをopen
```

受信command、plugin、configurationは分類後に終了し、実行、適用、返信、別通信を行いません。外部profileのprivate transcriptに限り、受信application frameを`frames/*.inbound.bin`へ保存します。保存先はrepository外であり、公開summaryにはsizeとSHA-256だけを残します。

`purerat-wire-capture` sidecarはobserverのnetwork namespaceだけを監視し、対象IP／portのTCP packetをpcapへ保存します。SYN／FIN、peerまたはobserverが送信したRST、TLS handshake、暗号化済みwire dataを含みます。sidecarは非root UID `10001`で実行し、追加するcapabilityは`NET_RAW`だけです。`tcpdump`のfile capabilityを有効化するため、このsidecarに限り`no-new-privileges`を設定しません。その代わり、image内のsetuid／setgid bitをbuild時にすべて除去し、root filesystemをread-onlyにします。observer本体の`no-new-privileges`は維持します。pcapは64 MBごとに256 fileまで循環し、最大約16 GiBです。JSONL supervisor logは8 MiB、16世代でrotationし、Docker logも10 MB、5世代へ制限します。pcapとprivate frameは検体同様に信頼しないデータとして扱い、Gitへ追加しないでください。

### Kaliの永続directory

```bash
sudo install -d -o 10001 -g 10001 -m 0700 \
  /home/kali/purerat-observer/observations \
  /home/kali/purerat-observer/captures
sudo install -d -o root -g root -m 0755 \
  /home/kali/purerat-observer/arm
sudo install -o root -g root -m 0444 /dev/null \
  /home/kali/purerat-observer/arm/purerat.arm
```

MaxMind cacheは既存の`/home/kali/rat-emulator-external-20260824/maxmind`を使用します。license keyはsetup時だけ`/run/rat-emulator-secrets/maxmind-license-key`へ配置し、`maxmind-refresh`完了後に削除します。observer本体へlicense keyをmountしません。

### build、事前確認、起動

```bash
cd analysis-framework/docker/rat-emulators
sudo ./kali-purerat-egress-policy.sh apply
sudo ./kali-purerat-egress-policy.sh check
sudo docker compose -f docker-compose.purerat-long-running.yml build --pull

# networkなしでprofile、evidence、leaseを確認
sudo docker run --rm --network none --read-only --cap-drop ALL \
  local/defensive-purerat-observer:20260826 \
  python -B /opt/rat-external-observer/purerat_external_observer_entrypoint.py \
  preflight --profile-id purerat-441-d025a296-direct-tls10-empty-gclass4

sudo docker compose -f docker-compose.purerat-long-running.yml up -d \
  purerat-observer purerat-wire-capture
```

24時間以内のlive leaseとMaxMind公式取得記録を各接続前に再検証します。期限切れ、peer reset、timeout、接続拒否等でsessionを完了できない場合は、初回失敗後に最大3回だけ再試行します。4回連続失敗すると`retry_limit_reached`を記録し、`/home/kali/purerat-observer/observations/retry-circuit.json`へcircuit-open状態を永続化して、以後の接続を停止します。Docker／host再起動でも同じlease registry identityでは再試行しません。再レビュー済みlease registryのraw SHA-256が変化した場合だけcounterを0へ戻し、接続前の全gateを改めて検証します。lease更新でendpoint、証明書pin、protocol／evidence hashを緩和してはいけません。

稼働確認と緊急停止は次のとおりです。

```bash
sudo docker compose -f docker-compose.purerat-long-running.yml ps
sudo docker compose -f docker-compose.purerat-long-running.yml logs --tail 100

# active sessionとsupervisorの両方を停止させるkill-switch
sudo touch /home/kali/purerat-observer/arm/purerat.arm
sudo docker compose -f docker-compose.purerat-long-running.yml stop
```

停止後に`kali-purerat-egress-policy.sh remove`を実行できます。`observations`と`captures`は自動削除されません。解析・archive・retention確認後にだけ明示的に整理してください。
