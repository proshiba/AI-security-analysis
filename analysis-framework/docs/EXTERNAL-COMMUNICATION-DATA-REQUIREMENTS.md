# マルウェア外部通信の初期data要件

## 結論

外部C2へTCP接続できることと、マルウェアとしてsession登録できることは別です。現在のrepositoryでreview済みの22 protocol profile／13 handlerと5 host profile／4 adapterを横断すると、初期通信は次の4種類に分かれます。

1. 固定probeだけで応答を確認できる: Winos C9、vvaS bootstrap、RedLine CheckConnect。
2. 空または合成registrationを送れる: N520、PureRAT、AsyncRAT、VenomRAT、StealC、Lumma、Remus。
3. 認証情報が必要: AgentTesla FTP。
4. server-first／passive／current wire未解決: DarkComet、FormBook／XLoader、Vidar、Remcos、Quasar、Onyx。

機械可読な正本は[`external_communication_requirements.json`](../common/external_communication_requirements.json)です。registryへhandler／adapterが追加されたのに要件がcatalogへない場合、[`audit_external_communication_requirements.py`](../common/audit_external_communication_requirements.py)はfail-closedで失敗します。また、`analysis-framework/malware`以下の全`*emulator*.py`をinventory化します。catalogにないoffline emulatorを外部通信対応とは扱いません。

```powershell
py -3.13 -B analysis-framework/common/audit_external_communication_requirements.py `
  --repository . `
  --check
```

この監査はsourceとJSONを読むだけです。DNS、socket、HTTP、TLS、検体実行は行いません。

## family別の要件

| family／protocol | 最初のclient data | C2から必要になるdata | 端末情報 | 現在の安全な実装範囲 |
|---|---|---|---|---|
| ValleyRAT Winos | 固定`C9` heartbeat | `C9 01`登録challenge、以後のcommand frame | 完全登録では26固定長field | 外部はheartbeatだけ。登録はoffline参照layoutのみ |
| ValleyRAT N520 | server-first 44 byte後、空command 1 | handshakeと認証済みcommand | 現行登録では不要。station identityは別command | exact空registrationを期限付きlease下で送信可能 |
| ValleyRAT vvaS | 固定`33 32 00` | 14-byte headerと宣言stage | 不要 | stage bodyを取得しない固定probe |
| PureRAT 4.4.1 | TLS 1.0後、GClass4 | protobuf-net subtype frame | GClass4にHWID等20 member | 空GClass4だけ。C2受理に必要なmember部分集合は未解決 |
| AsyncRAT 0.5.8 | 合成`ClientInfo`、空`Message`のPing | `pong`またはtask | 12 field | exact旧検体profileだけ送信可能 |
| VenomRAT 6.0.3 | 合成`ClientInfo`、空`Message`のPing | `Po_ng`またはtask | 22 field | exact旧検体profileだけ。現行検体へ継承しない |
| StealC v2 | `type=create,build,hwid`、次にtoken付き`type=loader` | access token、config、loader list | HWID | 固定buildとUUIDv5合成HWIDの最大2 POST |
| Lumma v6 | `uid,cid`、次に`uid,cid,hwid` | 暗号化task応答 | HWID | 合成UUID、最大2 POST。task schema未確定 |
| Remus | `tag,exp,hwid`、次にtokenと`step=1` | token、`vm`、`ss`、task envelope | HWID | 合成UUID、最大2 POST。`name/data`意味は未確定 |
| AgentTesla FTP | `USER`、必要時`PASS`、`QUIT` | banner、認証状態 | profile由来credential | 認証だけ。file／directory操作なし |
| RedLine | 引数なしSOAP `CheckConnect` | boolean result | 不要 | 固定1 request。登録・task pollなし |
| DarkComet | application dataを送らず受信 | RC4で`IDTYPE`となるserver-first challenge | 後続登録は未解決 | receive-only |
| FormBook／XLoader | 未実装 | passive responseだけ | variant依存、未確定 | passive-only |
| Vidar | 静的configへ束縛した共有serviceを明示opt-inで1回GET | 2サービスで一致したresolver候補 | 最終C2 wireでは未確定 | DNS pin付き限定取得とoffline相関。復元endpointへは接続しない |
| Remcos | 未実装 | 復号済みframe taxonomy | registration全体が未確定 | offline decodeだけ |
| Quasar | 未実装 | upstream message taxonomy | current sampleでは未確定 | offline classificationだけ |
| ValleyRAT Onyx | loopback sinkへ固定長POST | 空HTTP 204／400 | bodyの意味を保持しない | passive loopbackだけ |

## Winos registration解析

外部観測で返った`C9 01`は、現在のclassifierでは`registration_challenge_observed`、session statusでは`registration_requested_but_not_sent`として記録します。従来の`C9 00` heartbeat応答と区別できますが、自動返信は増えていません。

公開Winos実装のwide-character `LOGININFO`は、1-byte `Btoken`、alignment padding、26個の固定長`TCHAR`配列、4-byte `BOOL backdoor`からなります。復元したfieldは次のとおりです。

- network／identity: 内部IP一覧、public IP、address、activity、computer name、group、remark、HWID
- OS／hardware: OS名、OS version、CPU、disk／memory、GPU、architecture、monitor、system directory
- process／desktop: foreground window、process integrity／user、process path、PID
- security／locale／user surface: camera、chat identity、antivirus、locale
- client state: version、local time、backdoor flag

UTF-16LE、MSVC既定alignmentの参照layoutは4,688 byteです。[`winos_registration.py`](../malware/valleyrat/winos_registration.py)はRFC 5737の文書用IPと固定合成値だけでこのlayoutを生成し、実hostname、user、IP、process、window、camera、AV、hardware、localeを読みません。生成にはcallerがtoken値と`allow_offline_fixture=True`を必ず指定します。

```python
payload = build_synthetic_logininfo(
    login_token=fixture_token,
    allow_offline_fixture=True,
)
```

`build_synthetic_logininfo_frame`は同じ明示gateの下で既存Winos codecの1 frameへ包めるため、loopback serverとのserializer試験に使用できます。どちらの関数もsocket APIは持ちません。

ただし、公開実装のsymbolic `TOKEN_LOGIN`に対応する数値、対象検体の実serializer、header suffix、registration完了までのsequenceはrepository内のexact sample evidenceだけでは確定していません。classic Gh0stで知られる`0x66`もWinos対象検体へ自動継承しません。このためcodecは`sample_bound=false`、`external_send_allowed=false`です。共通runnerや8時間observerから呼び出さず、外部C2へ送信しません。

## PureRAT registration解析

PureRAT 4.4.1のexact managed metadataでは、client→server登録型`GClass4`に20 memberがあります。意味が回収できたものはHWID、camera、antivirus、OS、version、privilege、user/domain、remote port/address、wallet application inventory、campaign ID、process path、idle duration、screenshot JPEG、foreground windowです。

protobuf-netでは全memberがdefaultなら、ProtoInclude tag 1の空submessage `0a 00`がschema上有効です。現在のhost emulatorが送るのはこの2 byteだけであり、実端末情報はありません。一方、schema上validであることはC2が登録を受理することを保証しません。外部でcommand待受けへ進むために必要なpopulated member部分集合とheartbeat requestは未解決なので、空GClass4 profileを合成実端末登録へ自動昇格しません。

## 合成値の方針

- 実hostname、user、domain、IP、process、window、path、screen、camera、AV、hardware、localeを読み取らない。
- 合成HWIDはprofileが規定する固定値、UUIDv5、またはsession UUIDだけを使用する。
- sample固有build、campaign、uid、tag、exp、暗号鍵、credentialはprofile／vaultへ固定し、catalogには秘密値を複製しない。
- C2が発行したtokenは同じ有界sessionの次requestだけで使用し、公開結果へ出さない。
- current sampleで確認できないfieldを旧versionや公開実装から自動継承しない。
- 登録後に受けたcommand、task、plugin、file、stageは実行・保存・追跡・返信しない。

## 未解決事項の優先順位

1. Winosのexact sampleごとのlogin token、client serializer、`C9 01`後のsequence。
2. PureRATのC2受理に必要なGClass4 member部分集合とheartbeat。
3. 現行VenomRATの独立したregistration／keepalive evidence。
4. Remcos／Quasar／FormBook／XLoaderのcurrent wireとregistration。
5. StealC／Remusの現行検体binding、Lumma／Remus task response schema。

これらが未解決のままでも受信分類の改善はできますが、外部送信byteを増やす根拠にはしません。
