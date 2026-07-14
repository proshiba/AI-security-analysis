# 260713-kdg5eafz7v / MX-Go cluster

## 結論

本検体は既知の汎用RATではなく、**日本向けの遠隔制御型大量メール送信（spam）ボット**である可能性が高い。暫定クラスタ名を `MX-Go` とする。新しい独立ファミリーか、非公開ツールの改変版かは1検体だけでは確定できない。

- 分類: unclassified / MX-Go cluster
- 種別: remotely controlled bulk-email spam bot
- 分類確度: 高
- RAT判定: 汎用RATを支持する証拠なし
- 解析: 実検体の静的解析 + 公開Triage 2環境の挙動比較
- ローカル実行: なし
- ライブC2接触: なし

## ファイル

| 役割 | 名前 | SHA-256 | サイズ |
|---|---|---|---:|
| Triage submission | `vpass-co.zip` | `462ae2f56a5f3a961be8bdee03497c65cad61ab04c2482ddcb14e6bf6cdd70fb` | 4,833,677 |
| payload | `mx-go.exe` | `e25053585ac5e4f411f954fe7bedc8cb62672a3f9ae96b6022a7b7116700228e` | 11,910,656 |

外側のTriageダウンロード用暗号化ZIPは配布コンテナであり、上記submissionとは別ハッシュになる。

## 静的解析

`mx-go.exe`は署名なしのnative x64 PE（GUI subsystem）で、Go build infoは `go1.26.1`、module pathは `mx-go`。PE timestampは0。Go関数名と型情報が残っているため、機能を高い確度で復元できた。

主な独自package:

- `mx-go/internal/mail`: MIME/日本語携帯向け本文、ISO-2022-JP、送信者生成、SMTP/MX直送、DKIM署名
- `mx-go/internal/dnsmx`: 宛先domainのMX解決とSQLite/memory cache
- `mx-go/internal/remote`: 受信者、HTML本文、送信domain、DKIM関連設定の取得
- `mx-go/internal/control`: heartbeat、command polling、activate/shutdown/restart等
- `mx-go/internal/aliyun`: Aliyun DNS APIによるTXT/SPF/DKIM操作
- `mx-go/internal/dnshealth`: DKIM公開鍵、SPF、MX健全性確認
- `mx-go/internal/sysenv`: 日本語locale/timezoneの実行条件

確認できたメール送信機能:

- 日本語環境判定（`MX_GO_SKIP_JP_CHECK`で迂回可能）
- 宛先リストとHTMLテンプレートの遠隔取得
- 宛先domainごとのMX direct delivery
- 日本語件名・本文、ISO-2022-JP、携帯メール向け整形
- randomized sender、Message-ID、EHLO、送信domain
- DKIM key生成/署名、SPF/DKIM TXTのAliyun DNS自動設定
- Spamhaus ZENチェック、public IPv4確認
- 並列worker、domain単位concurrency、送信成功/失敗・再開状態管理

汎用RATに一般的な画面取得、keylogging、任意shell、file manager、資格情報窃取の実装は静的symbolから確認できない。Triageの`WriteProcessMemory`シグネチャは観測事実だが、これだけでprocess injectionやRAT機能とは断定しない。

## 埋め込み設定

| Key | Value / meaning |
|---|---|
| `control_server` | `http://43.165.179.173:5000`（HTTP control/C2候補） |
| `app_version` | `2.0.0-go-portable` |
| `license_key` | `MX_TRIAL` |
| `use_remote` | true |
| `startup_remote_gate_enabled` | true |
| `memory_only_mode` | true |
| `standby_mode` | true |
| `domain_source` | `dimk` |
| `url_recipients` | `https://www.iainglespa.com/jp01.txt` |
| `url_html` | `https://www.iainglespa.com/html-a.txt` |
| `url_fscs` | `https://www.iainglespa.com/fscs-a.txt` |
| `url_yuming` | `https://www.iainglespa.com/yuming.txt` |
| `url_dimk` | `https://www.iainglespa.com/dimk.txt` |

control APIの静的文字列には `/api/heartbeat`, `/api/v1/heartbeat_direct`, `/api/client_command/`, `/api/v1/activate`, `/api/v1/shutdown`, `/api/v1/selftest_result` がある。command構造にはpause/activate、restart、exit/shutdown、UI表示制御に対応するfieldが見える。任意OS command実行を示すcontrol actionは確認していない。

## 動的挙動（Triage公開テレメトリ）

Windows 10/11の日本語環境で同一の流れを確認した。

1. `%TEMP%\mx-go.exe`を起動。
2. `cmd /c cls`を生成。
3. `C:\Users\Admin\Documents\mx\mx-go.exe.tmp`へ自己コピーし、`mx-go.exe`へrename。
4. コピー先を子processとして起動。
5. 固有mutex `Local\MX_Go_SingleInstance_v1`を作成。
6. `cmd /c pause`を生成。
7. `www.iainglespa.com`を解決しCloudflare edge `104.21.4.118` / `172.67.132.11`へTLS接続。

TLSは両環境で約90秒、SNIとfingerprintが一致した。

- JA3: `e69402f870ecf542b4f017b0ed32936a`
- JA3S: `eb1d94daa7e0344597e756a1fb6e7054`

Cloudflare IPは共有edgeであり、専用C2 IPとしてblockしない。`ctldl.windowsupdate.com`も同process telemetryに出るが、証明書/Windows関連の補助通信としてC2候補から除外した。

## インフラの役割と確度

| Indicator | Role | Evidence | Confidence |
|---|---|---|---|
| `43.165.179.173:5000` | control/C2 | embedded `control_server`、heartbeat/command API | 高（静的設定 + live API route一致） |
| `www.iainglespa.com` | content/config distribution、control補助の可能性 | 5つのURL + 2 sandboxでTLS接続 | 高 |
| `104.21.4.118`, `172.67.132.11` | Cloudflare edge | DNS/TLS telemetry | 高、block IOCとしては低品質 |
| `https://alidns.aliyuncs.com` | legitimate Aliyun DNS API | static function/string | 高、悪性IOCではない |
| public-IP/Spamhaus URL | environment/reputation check | static function/string | 高、悪性IOCではない |

## 既知ファミリーとの比較

- Sliver / Merlin / Mythic / SparkRAT / ChaosRAT: GoとHTTP(S) controlという表面的共通点のみ。各framework固有protocol/config、remote shell、post-exploitation機能がない。
- VenomRAT / Quasar / Remcos: .NET/native RATのconfig/namespace/protocolと一致しない。
- AgentTesla: メール関連機能は共通するが、AgentTeslaはcredential stealerのexfiltrationであり、本検体はSMTP配送エンジン自体を実装する。
- spam bot / bulk mailer: recipient/template配布、MX直送、sender randomization、DKIM/SPF自動化、blocklist確認、remote campaign controlが強く一致する。

公開検索ではhash、mutex、C2文字列、cluster固有APIの既知報告を確認できなかった。したがって「既知RATの亜種」より「独自または非公開のspam bot」が妥当。ただし、新ファミリー確定には追加検体とcode/config clusteringが必要。

## 検知と誤検知

- 高: payload SHA-256、mutex + `mx-go/internal/*` + control API/固有URLを組み合わせたYARA。誤検知は同一toolの正規研究copy程度。
- 高: `www.iainglespa.com`へのDNS/TLS。domainが侵害・再利用された場合は無関係通信を過検知し得る。
- 中: `43.165.179.173:5000`。control backendとの関連性は高いが、IP再割当や別service併設で誤検知し得る。
- 中: `Documents\mx\mx-go.exe`への自己配置と`cmd /c pause`。同名の内部toolが存在すれば誤検知。
- 低: JA3単独。Go標準TLS clientと共有される可能性が高く、domain/process条件との併用が必須。
- 検知に不適: Cloudflare edge IP、Aliyun/API IP確認/Spamhaus URL。正常利用が非常に多い。

## 限定ライブ確認（2026-07-15 JST）

状態変更を伴わないTCP、HTTP root、既知routeへのOPTIONS、TLS、content pathへのHEADだけを実施した。

### `43.165.179.173:5000`

- TCP: open
- HTTP root: `404 Not Found`
- Server: `Werkzeug/3.1.8 Python/3.14.3`
- root banner SHA-256: `b31ad76cca159ac5782beb3c33799c28eae70e191f1d853c329e9bfb7960c6cc`
- Shodan mmh3: `-1999552396`
- 検体内と完全一致するrouteを確認:
  - `/api/v1/heartbeat_direct`: `POST, OPTIONS`
  - `/api/v1/activate`: `POST, OPTIONS`
  - `/api/v1/shutdown`: `POST, OPTIONS`
  - `/api/v1/selftest_result`: `POST, OPTIONS`
- `/api/heartbeat`と`/api/client_command/`は404。legacy route、別path parameter、またはserver/client version差の可能性がある。

単なるopen portより強く、**MX-Goに関連するcontrol backendが現在稼働している可能性は高い**。ただしPOST/check-inは送っていないため、client認証、task format、campaign状態は未確認。

### `www.iainglespa.com:443`

- TLS 1.3 / `TLS_AES_256_GCM_SHA384`
- 証明書SHA-256: `66c472500a03b1e27f672e13d6c81053f2e584ae13b48aa5cc1b13327a965deb`
- Subject: `CN=iainglespa.com`
- Issuer: Google Trust Services WE1
- 有効期間: 2026-06-23～2026-09-21 UTC
- JARM: `27d40d40d00040d1dc42d43d00041d6183ff1bfae51ebd88d70384363d525c`
- rootはHTTP 200だが本文titleは`403 Forbidden`
- 5つの既知`.txt` pathはHEAD 200。ただし不存在pathも同じstatus、Content-Type、Last-Modifiedを返す。

したがってhost/TLSは生きているが、既知pathは現在、Cloudflare配下の共通403/placeholderへ置き換えられたか、条件付きでgateされている可能性が高い。受信者リストやtemplate本文は取得していない。

Shodan条件は`ip:43.165.179.173 port:5000`を主軸にし、`hash:-1999552396`を補助条件とする。domain側の証明書/JARM/Cloudflare IPは共有されやすく、単独検知には使わない。

## ローカルprotocol lab

再現可能なlocalhost限定C2/content server、合成check-in client、合成受信者fixtureを`emulators/unclassified/mx_go/`に追加した。`c2_detector.py --protocol mxgo`はoffline previewが既定で、active modeはloopbackに強制される。実C2への登録や実受信者データの取得には使用できない。 CLI往復試験では合成check-in成功、合成受信者2件の件数・SHA-256取得、値のredactionを確認した。

## 制約

実検体は静的にのみ解析した。限定ライブ確認ではTCP/TLS/HTTP root/OPTIONS/HEADだけを実施した。malware check-in、POST、command取得、recipient/template本文取得、メール送信、sample実行は行っていない。

Source: https://tria.ge/260713-kdg5eafz7v/behavioral1
