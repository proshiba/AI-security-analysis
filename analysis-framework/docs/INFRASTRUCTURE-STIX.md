# 攻撃インフラのSTIX整理と証拠境界

## 目的と範囲

ファミリー別の[STIX整理](FAMILY-STIX.md)に、攻撃で使われたC2、配布先、dead drop、証明書、履歴DNSと、それらを結ぶキャンペーン・攻撃主体を追加するための基準です。検体をMalwareBazaar、Triage、VirusTotalなどで発見した経路は攻撃経路ではないため収録しません。公開資料と既存の解析結果を受動的に照合し、検体実行、実C2への接続、ポート探索は行いません。

IOCの値だけでなく、`役割`、`対象検体または感染系統`、`観測期間`、`出典`、`根拠の強さ`、`未確認事項`を一緒に扱います。同一IPの別時期の利用、共有CDN、合法サービス、証明書の再利用を、同一運営者の証明として扱いません。以下のクラスタは、同じファミリーであっても独立した攻撃活動を混ぜないための調査単位です。

## 出典で確認した攻撃クラスタ

### Operation FishMedley：FishMongerとShadowPad

[ESETの一次調査](https://www.welivesecurity.com/en/eset-research/operation-fishmedley/)は、2022年の複数侵害をOperation FishMedleyとしてまとめ、FishMongerへの帰属を高い確度と評価しています。ShadowPadの復号設定には`api.googleauthenticatoronline.com:443`がTCPとUDPのC2として記録されています。このドメインが`213.59.118.124`へ解決していたとESETが示す期間は2022-03-20～2022-11-02です。後者は履歴DNSであり、現在の解決先ではありません。

同じキャンペーンでは別ファミリーのSpyderも使われ、ESETはそのC2を`61.238.103.165`、2022年に同IPへ解決していた`junlper.com`の複数サブドメインを報告しています。`61.238.103.165:443`で2022年5～12月に観測した自己署名証明書のSHA-1は`89EDCFFC66EDA3AEB75E140816702F9AC73A75F0`です。これはSpyder／FishMonger側の証明書根拠であり、ShadowPadの証明書として転記しません。ShadowPadとSpyderは、証明書一致ではなくESETが同じ攻撃活動での利用を確認したことによって関連します。

### FamousSparrowによる2024年のShadowPad利用

[ESETの別の一次調査](https://www.welivesecurity.com/en/eset-research/you-will-always-remember-this-as-the-day-you-finally-caught-famoussparrow/)は、米国とメキシコでの2024年の侵害をFamousSparrowへ帰属し、同グループによるShadowPad利用を初めて確認したと記載しています。感染端末で確認されたShadowPad C2は`216.238.106.150`で、ESETのIOC表にある初観測日は2024-03-11です。このサーバーの自己署名TLS証明書にはSHA-1 `BAED2895C80EB6E827A6D47C3DD7B8EFB61ED70B`が記録されています。

同じ攻撃ではSparrowDoorのC2 `45.131.179.24:80`とドメイン`amelicen.com`も観測され、ESETの初観測日は2024-07-05です。`45.131.179.24:443`の証明書はShadowPad C2の証明書とCommon Nameが一致しますが、証明書全体のfingerprintが一致したとは資料に書かれていません。ShadowPadとSparrowDoorの関係は当該キャンペーン内に限定し、両ファミリーの全運用を同一主体へ拡張しません。

### TA4922が使用したValleyRAT／Winos4.0変種

[Proofpointの一次調査](https://www.proofpoint.com/us/blog/threat-insight/ta4922-suspected-chinese-crime-group-going-global)は、TA4922がValleyRAT／Winos4.0を使用したことを報告し、2026年初頭の変種の復号設定に`aeya388.club:7880`と`aeya388.club:7881`を掲載しています。これは検体設定に裏付けられたC2候補です。設定の19文字のRC4接頭辞`A16A6736FB5DC030EF3`はProofpointが「campaign識別子の可能性」としており、確定したcampaign IDとは記録しません。証明書のhashや履歴DNSは同資料に示されていません。

同資料にあるAtlas RATの`206.238.115.58:886`（2026-03-06）と`154.211.86.110:886`（2026-04-02および04-07）は、TA4922による別キャンペーンのC2です。共通の利用主体は資料で示されますが、ValleyRATの`aeya388.club`と共通のC2基盤だったという証拠はありません。単一の巨大な「TA4922インフラクラスタ」へ結合しません。

[Joe Sandboxの2025-11-25提出検体レポート](https://www.joesandbox.com/analysis/1820852)は、ValleyRATタグのSHA-256 `42da42715b4a5fcdb7f8188b63138a4e8fef1e82e1447467e8efa2d5e9246fc2`と、`aeya388.club`から`121.127.233.111`への対応を掲載しています。これは同じドメインの過去利用を調べる手掛かりですが、Proofpointの2026年初頭の検体と同一であることや、そのIPをTA4922が運用したことは示しません。STIXでは別Groupingと履歴DNSの出典として記録します。

### 2026年8月の日本語マルスパム：ValleyRATの独立した3系統

[精査済みの3件比較](../../analysis-results/research/campaigns/valleyrat-japanese-malspam-20260820/README.md)は、2026-08-20～08-24の日本語メールからZIP→IMG→正規EXEによる悪性DLL side-loadingに至る配布経路を示します。共通のファミリーと近接する日付だけでは、同一運営者または一つのキャンペーンとは判定できません。STIX上では各攻撃の`Grouping`を分け、共通のValleyRATファミリーへ関連付けるに留めます。

| 配布テーマと悪性DLL | C2の役割・確認水準 | 系統を分ける根拠 |
|---|---|---|
| 請求書／`nW_Elf.dLL` | `121.127.253.206:8856`と`:8868`を公開sandbox／PCAPで観測 | `ms-settings`／`ComputerDefaults.exe`によるUAC bypass、`NvDLISR.NVX.exe`、Winos `CA00`の後段 |
| 情報更新／`vulkan-1.dll` | `170.62.130.47:449`を公開sandbox／PCAPで観測。`:443`は静的設定のみで通信未観測 | `OpenraVPN`偽装の配置とRun key、Winos `CA01`の後段 |
| 見積・取引／`MSOCF.dll` 3変種 | `202.61.140.222:448`を静的設定とPCAPで確認 | RC4＋XORで復元する同一後段、`99\0` bootstrap、`svchostsr.exe`とdriverの展開 |

3件目のDLLは外見のresource／overlayとhashが違っても、復号されたstageと主要コードが一致します。この3ファイルを別の攻撃活動3件と数えません。上記endpointに関するTLS証明書、履歴DNS、現在の稼働状態、攻撃者の名称は、この比較資料からは確認できません。後日の証明書ピボットやTA4922の`aeya388.club`を、同一ファミリーという理由だけでこれら3件へ接続しません。

### ValleyRATと報告された証明書ピボット：未帰属

[既存の証明書ピボット調査](../../analysis-results/research/c2-monitoring/2026-09-14-valleyrat-cert-pivot/README.md)の観測では、2026-09-14に`107.155.109.150:443`と`110.173.48.35:443`～`110.173.48.38:443`の5台で、TLS証明書のSHA-1 `7f1ed4a13d8a2ba6e690ecaf66a9dfa42dd8d9d1`、SHA-256 `ff887bedc2a83426ee1febcafe193f6601f263aca1f8fb137033173af00dc7c0`、server-firstの`TIMEOUT`応答が一致しました。これは同一サービス構成を示す強いクラスタ証拠です。

一方、[ThreatFoxの185.9.17.250:443の登録](https://threatfox.abuse.ch/ioc/1892367/)と[43.154.230.182:443の登録](https://threatfox.abuse.ch/ioc/1892371/)はValleyRAT／Winos、confidence 75と報告していますが、両レコードに紐付く検体や一次解析参照はありません。両IPは当日の観測ではfilteredで証明書一致を再確認できず、`45.64.52.195:443`はclosedでした。既知のN520型ValleyRAT応答とも一致しません。したがって5台の証明書クラスタ、2件のThreatFox報告、TA4922の実C2を同じ攻撃として結合せず、ValleyRAT C2・campaign・intrusion setの帰属は未確定のままにします。ThreatFoxの75は提供元の数値であり、本調査のconfidenceではありません。

### PureRAT：三つの異なる根拠系列

[Huntressの一次調査](https://www.huntress.com/blog/purerat-threat-actor-evolution)では、著作権侵害通知を装うメールからPXA StealerとPureRATへ至る攻撃で、復号設定の`157.66.26.209:56001`、`:56002`、`:56003`を確認しています。埋込X.509によるTLS pinningも解析していますが、記事に証明書fingerprintは掲載されていません。[MicrosoftのPXA Stealer Campaign 1調査](https://www.microsoft.com/en-us/security/blog/2026/02/02/infostealers-without-borders-macos-python-stealers-and-platform-abuse/)のPureRAT C2 `157.66.27.11`、PureRAT配布URL、PXA側のC2 `bagumedios.cloud`は別資料の別活動として保持します。PureRATの開発者と個々の攻撃実行者も混同しません。

[ローカル検体の設定](../../analysis-results/malware/purehvnc/versions/v4.4.1/cases/e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0/config.json)にある`tirakian.com:56001`～`:56003`はさらに別の系列です。[観測計画](../../analysis-results/malware/purehvnc/versions/v4.4.1/cases/e55412555b4699c6d3ce2ac60df81eb1ee0d5aa412a303555c8f64037d5633d0/c2-observation-plan.json)の証明書SHA-256 `67260a713ab105197098882f6d126f89fe4f48df8013f8bba1d2c9307b17410b`は**検体内の期待値**であり、実サーバーが提示したleafではありません。2026-09-21の既存監視では当該3接続先は到達できず、稼働確認として扱いません。STIXでは期待証明書をC2 Infrastructureの構成要素や`Observed Data`へ昇格させません。

### ValleyRAT／Winos：Silver Fox評価の範囲

[Fortinetの2024年調査](https://www.fortinet.com/blog/threat-research/valleyrat-campaign-targeting-chinese-speakers)では、検体設定にある`154.82.85.12:5689`と、IOC表のみの`154.92.19.81`を別の根拠水準で記録しました。Silver Fox関与は記事の疑いに留まり、確定帰属を付けません。一方、[Check Pointの2025年BYOVD調査](https://research.checkpoint.com/2025/silver-fox-apt-vulnerable-drivers/)はSilver Foxが使ったValleyRAT／Winosの5 IP・9 endpointを明示し、`156.234.58.194:52110`と`:52111`はdownloader設定でも確認しています。[Fortinetの2026年台湾向け調査](https://www.fortinet.com/blog/threat-research/massive-winos-40-campaigns-target-taiwan)は、`47.76.86.151`を当該活動のC2とし、別の関連operationの移行先`154.91.64.246`を区別します。両後者の資料が直接支持する範囲のみSilver Foxへ接続し、先述の未帰属TLS証明書5台やThreatFox報告2台へ帰属を波及させません。

### Nood RAT：同一設定内の二つのC2と別検体

[AhnLab ASECの復号設定](https://asec.ahnlab.com/jp/62078/)から7 endpointを収録しました。`x.uu`検体は`update.kworker.net:443`と`check.snapupdate.org:80`を**同一設定内**に持ちます。ほかに`43.156.118.72:443`、`b.niupilao.vip:80`、`42.51.40.184:56`、`13.214.222.35:443`、`bo.appleupcheck.com:443`は別検体の設定です。元資料の検体採取日はネットワーク観測日ではありません。またport 443だけをTLS証明書の存在や共通actorの根拠にしません。

### Remcos：Censysの共通証明書と動的DNS

[Censysの一次調査](https://censys.com/blog/unmasking-the-infrastructure-of-a-spearphishing-campaign/)は5種類のRemcos設定先を示しています。`rem25rem.duckdns.org:1515`と`sosten38999.duckdns.org:38999`では共通TLS leafのピボットを報告し、`gotemburgoxm.duckdns.org:8090`では別のRemcos listenerと日替わりの履歴DNSを確認しました。`trabajonuevos.duckdns.org:3010`と`remc21.duckdns.org:3010`は設定に存在する一方、報告時点でlistenerが未観測のため`configured-only`とします。後者の履歴IPで別portのAsyncRATが見えても、同一運営者とは断定しません。

共通leafのSHA-256 `95f61fba6418c812c4c62d0c7ee4c8e5c369fc76e044cab6de3b6ddf787db2ed`は記事中のCensys検索リンクの値で、こちらで証明書を独立に再取得したものではありません。関連する6 endpointは証明書のみのピボットとし、Remcos C2と断定しません。`gotemburgoxm`の8090番で共有されたTLS fingerprintは本文に値がなく、前記共通leafと同一としません。各DDNSのIP履歴は時点の異なる解決先であり、現在のC2ではありません。記事のBlind Eagleとの関連は推測に留まるため、Intrusion Set関係を生成しません。

### QuickFox改ざん・FDMTP：登録先と直接C2ノードを分離

[Fortinetの一次調査](https://www.fortinet.com/blog/threat-research/quickfox-supply-chain-attack-used-to-deploy-fdmtp-implant)のTable 4にある`www.wangmeng66.top`、`www.yahoo-cdn.it.com`、`www.google-apis.net`、`www.icloud-cdn.net`、`www.wangmeng.xyz`、`www.wangmengsb.com`、`www.techcheck1.com`はFDMTPの登録・ノード取得に関わる7つのstaging domainです。直接のsocket C2ノード10 IPとは別です。ノード表のIPに、記事が示す一般的port範囲を根拠なく個別割当しません。Fortinetは特定actorへの確信をもった帰属をしていません。

同資料の2026年6～7月の履歴DNS先25 IPについて、[過去の限定的な能動TLS観測](../../analysis-results/research/daily-news-malware/2026-08-06/infrastructure-summary.json)では2026-08-05 UTCに各IPへ**SNIなし**で接続し、443番で同じleaf SHA-256 `ffe0435800af23ac24e6ab0b4b6f44de63de578138ad6db5f459049d572537e8`が記録されています。一方、`www.wangmeng66.top`を**SNI指定**したドメイン接続では別のleaf SHA-256 `f3aa1b05947d9434e3bd46ab323c070db4adde159a018b5386593d310aab7dfb`を観測しました。同時のDNS A結果は10 IPで、そのうち8 IPは前記25 IPに含まれますが、ドメイン接続で実際に選択したIPは記録されていません。よってこの別leafを10 IP全件へ割り当てません。DNS履歴と証明書実測は時期が異なり、25 IPをFDMTPの直接C2、同日に同ドメインを提供したIP、または同一運営者の証拠とはしません。STIXではIP直指定の25件とSNI指定の1件を別の証明書ピボット、DNSを期間付きの履歴、10件を直接C2ノードとして別々に表現します。

### PATCHCORD／SHEETCORD：14回のTLS観測は単一IP

[Acronisの一次調査](https://www.acronis.com/en/tru/posts/patchcord-new-malware-cluster-targets-afghan-telecom-and-south-asian-critical-infrastructure/)はAfghan Telecomを装うinstallerからPATCHCORDが配布され、`appstoore.solutions:8080`をhardcoded C2として使用すると報告しています。基盤IPは報告時点で`46.30.188.13`（AS199959、Gwy IT Pty Ltd）です。`nic-support.site`は別のSHEETCORD installer配布先であり、SHEETCORDのGoogle Sheets C2自体ではありません。AcronisはAPT36との重複を中程度の確度と評価しているため、確定したIntrusion Set関係は付けません。

[既存の観測記録](../../analysis-results/research/daily-news-malware/2026-08-15/infrastructure-summary.json)では、2026-08-16 UTCに`46.30.188.13:443`と同IPへ解決した13ドメインで同じleaf SHA-256 `b22c77c7f99555480b5be2e605d4f1ef2ab956182388f87388e4cdad40a7b61a`を確認しています。14回のhandshakeは14台の独立したC2ではありません。この443番の証明書を8080番でPATCHCORDが実際に受け取る証明書とも見なしません。関連ドメインは当時のDNS対応で整理し、各ドメインのC2機能を一括推定しません。

### AsyncRAT：検体設定と横断証明書調査を分離

[NCC Groupの一次調査](https://www.nccgroup.com/research/asyncing-feeling-when-your-download-comes-with-something-extra/)では、SEO偽サイト→ScreenConnect→AsyncRATの後段を確認し、検体から`hone32.work.gd`、`mora1987.work.gd`とport `1800`～`1803`を復号しました。実装はhostとportを独立に選ぶため、STIXの8 endpointは**設定上の候補組合せ**であり、8サービスの同時稼働実測ではありません。ScreenConnect relayをAsyncRAT C2へ昇格しません。NCCはCN=`AsyncRAT Server`の埋込証明書と共通hashによる追加ホスト探索を説明しますが、fingerprintの値を記事に公開していません。

NCCの本文は共通証明書から「追加18 host」を発見したと書く一方、IOC表には「Additional AsyncRAT C2」のIPが19件並びます。数値の不一致を修正推定せず、表の19 IPを`reported-c2`として別Groupingに収録しました。各IPのport、証明書hash、検体設定や実通信による個別の裏付けは公開されていません。これら19 IPを8通りの設定値やCampaignの確定C2へ混ぜません。

[Censysの別の横断調査](https://censys.com/blog/asyncrat-c2-activity-at-internet-scale/)が示すSHA-256 `136fbfd2d255a7fc69c16fe115138d7a53ed0a7db8302017ee0e692b42d82ffe`は独立したハント指標として収録します。NCC検体の証明書と同一とする証拠はありません。Censysは`AsyncRAT Server`のCNが調査対象の98%に見られるとし、このCNや一般的portだけで個別actor・campaignを特定できません。

### Amateraの`pf.ch`／ClearFake系

[Cisco Talosの一次調査](https://blog.talosintelligence.com/clearfake-webdav-infection-chain/)は、偽CAPTCHAのClickFixからWebDAV上の`pf.ch`へ誘導する系統を報告しています。配布段階の`leaguejazire.com`は無作為サブドメインが使われた親ドメインで、親ドメインの全サブドメインが悪性という意味ではありません。Amateraが参照したdead dropは`https://telegra.ph/Functions-04-03`という特定ページであり、Talosの解析時にはそこから`145.249.109.147:443`をC2として復元しました。`telegra.ph`全体を悪性IOCとして扱いません。

この系統の後段ZigCryptoStealerは、BNB Smart Chain契約`0x7CC3cFC1Ac007B8c6566fD2C7419b15a75473468`から次のC2値を取得したとTalosが報告しています。期間はいずれも2026年のUTCです。

| 期間 | ZigCryptoStealerのC2ドメイン |
|---|---|
| 06-30～07-05 | `fd.gstats-api-contact.cc` |
| 07-05～07-09 | `pkg.vogueatelier.cc` |
| 07-09～07-12 | `kffd3.vogueatelier.cc` |
| 07-12～07-18 | `kffd3.vexlatech.cc` |
| 07-18～07-26 | `static.quorashift.cc` |
| 07-26～07-30 | `lb.propertyfind.cc` |

この6件は契約値の履歴であり、Amatera本体のC2ではありません。契約を照会する正規のRPCサービスも、それ自体を悪性インフラへ分類しません。契約値の変更は同じ後段インフラ運用を追跡する根拠になりますが、別のAmatera利用者や別系統の攻撃者まで特定しません。

### Amateraの`verification.google`／UAT-10820系

[同じTalos調査](https://blog.talosintelligence.com/clearfake-webdav-infection-chain/)では、2026年4月にウクライナの組織で確認された別のWebDAV系統をUAT-10820として追跡しています。この系統のAmateraは暗号化設定から`45.150.34.2:443`を復元し、TLS SNIとHTTP Hostには`github.com`を提示します。`github.com`は偽装に使用された正規ドメインであり、悪性IOCにしません。後段には不正なNetSupport Managerの導入が確認されています。

Talosは`pf.ch`系と`verification.google`系の感染チェーンの一致を低～中程度の確度とし、両系統の運営者が同一であるとは確定していません。したがって、Amateraという共通ファミリーだけを理由に2つのC2やUAT-10820帰属を統合しません。現時点でこの2系統に対する証明書fingerprintは引用資料から確認できません。

## 証明書ハントとSTIXでの表現

証明書は`x509-certificate` SCOに、確認できたhash、自己署名の有無、subjectなどを記録します。完全な証明書を取得していない場合、issuer、serial number、SAN、有効期限、公開鍵を補完しません。観測したIP・portと証明書の対応には、観測時刻と出典を付けます。SHA-1とSHA-256の両方が分かる場合は両方を残します。

IOCの出典に日付だけがある場合、便宜的な真夜中の時刻をSTIXの`first_observed`や`Indicator.valid_from`に代入しません。正確な時刻を持たない履歴IOCは出典付きSCO・Note・Infrastructure等として記録し、即時ブロック用Indicatorは生成しません。現行稼働を確認したという意味でもありません。

[Hunt.ioの一次調査](https://hunt.io/blog/tracking-shadowpad-infrastructure-via-non-standard-certificates)は、Dellを装うShadowPad候補証明書の一群について、subjectを`C=US, ST=Texas, L=Round Rock, O=Dell Technologies Inc., OU=Dell Data Vault, CN=Dell Technologies Inc.`と報告しています。これはハントの候補条件であり、ESETが報告した`BAED2895C80EB6E827A6D47C3DD7B8EFB61ED70B`証明書のsubjectを独立に証明するものではありません。Hunt.ioもこの一群の運営者を未特定とし、クラスタ内の部分集合が別の攻撃主体である可能性を残しています。Dell風のsubject、共通CN、自己署名、IP単独、ASN単独ではmalwareやactorを確定しません。

[STIX 2.1仕様](https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html)に沿い、通信実測に基づくC2だけを`malware beacons-to infrastructure`、検体の静的設定や一次解析記事だけに基づくC2を`malware uses infrastructure`として表現します。どちらも根拠の種類をNoteで明示します。攻撃活動で使用した基盤には`campaign uses infrastructure`、直接の一次資料による帰属には`campaign attributed-to intrusion-set`を使います。証明書だけの未帰属ピボットは候補と注記に留め、`malware beacons-to`やactor所有関係を付けません。証明書条件はハンティング候補であり、全一致ホストを自動的に悪性とするブロックリストではありません。

## 網羅性と不足

2026-09-21時点のリポジトリ横断の読み取り専用棚卸しでは、マルウェア別`iocs.json`が3,163ファイル、ネットワーク関連recordが1,166件あります。このうち静的config根拠のC2は505 record／異なる値151件、未確認候補は111件、公開sandbox由来の候補は65件でした。ほかにClickFixインフラrecord 401件、当該棚卸し経路のTLS実測証明書2件、CT観測25件、現行DNS成果物227ファイル、RDAP成果物56件があります。これらは種類・粒度・確認水準が異なる在庫数であり、合算してIOC総数や確認済みC2件数にはできません。本書の優先調査クラスタと日本語マルスパム3系統、生成されるSTIXの収録分は、この全件の完全調査を意味しません。

審査済み入力から生成した2026-09-21時点の横断Bundleは、164 endpointのうち68件を根拠付きC2、3件を設定のみ、12件を攻撃補助基盤、25件を報告のみのC2、56件をピボットのみとして扱います。11 Campaign、26 Grouping、4 Intrusion Set、9 X.509証明書を収録します。68件には同一検体が設定した複数portや、AsyncRATのhost×portの候補組合せが含まれるため、68台の稼働サーバーを意味しません。`Observed Data`45件はすべて証明書・TLSなどの付帯観測であり、C2チェックイン時刻ではありません。本作業中に45件のライブ接続を行ったという意味でもありません。自動的な即時ブロック用Indicatorは0件です。

[全件C2監査](../../analysis-results/research/stix-audit/2026-09-21/README.md)では、検体別静的設定のC2 505 record／151種類と、審査済みSTIXのC2値が**値・host単位とも重複0**と確認しました。表記差ではなく、ローカル自動解析コーパスと手編纂したOSINTクラスタの対象検体・活動が異なるためです。別形式8種の監査では、明示endpointを持つ213 case中65 caseで同caseの`iocs.network`が空または欠落していました。設定・候補・監視計画が混在するため65件を確定C2と数えません。したがって、この横断Bundleをリポジトリ内の全C2の一覧として利用しないでください。個別IOCの根拠不足やファミリー確定の限界も監査資料へ記録しています。

ClickFixの実測証明書2件は個別精査しました。`determinedresults.com`側はCNが別ドメインの共有Bluehost証明書で、攻撃専用の証明書ピボットとしては採用しません。`fingerprint-verification.info`側は配布URLの観測と結び付くものの、既存解析で証明書とIPが`context_only`と評価され、C2や別キャンペーンとの再利用も確認できません。いずれも証明書単独の悪性Indicatorやcampaign接続へ昇格しません。

静的configは通信先候補を示しても現在のサービス稼働を証明しません。公開sandboxのnetwork contextは正規通信と混在し、CT証明書やDNS／RDAPには時期、共有ホスティング、IP再割当の問題があります。STIXの9証明書には公開資料、検体内の期待値、異なる日のローカル実測が混在し、どれも全C2候補を現在の証明書で網羅するものではありません。大部分のC2候補へcertificate hash、subject、SAN、有効期限を無根拠に付けず、付帯情報がない項目は空欄または未確認として保持します。

再評価では、まず検体SHA-256と復号config／通信先の完全一致、endpointのportと役割、証明書とIPの同時期観測、履歴DNSの有効期間、独立した一次資料の攻撃・主体帰属を突合します。別ファミリーや別キャンペーンとの結合には、単一の証明書・IP・ASNを超える独立した証拠を要求します。候補数の多さを補うためだけに帰属を昇格させず、ライブ確認が必要な場合はそのタスクで明示された許可とリポジトリの安全手順へ別途従います。

## 再生成と検証

追加のIOCやキャンペーンは、値・役割・時期・一次資料URL・根拠の境界を[審査済み知識](../knowledge/stix_infrastructure_curated.json)へ登録してから生成します。全体の根拠充足度は次の読み取り専用集計で確認できます。個別IOCの生値は標準出力へ出しません。

```powershell
python .\analysis-framework\common\inventory_infrastructure_evidence.py --repository .
python .\analysis-framework\common\audit_c2_inventory.py --repository . --as-of 2026-09-21 --check .\analysis-results\research\stix-audit\2026-09-21\c2-inventory-audit.json
python .\analysis-framework\common\audit_c2_artifact_coverage.py --repository . --as-of 2026-09-21 --check .\analysis-results\research\stix-audit\2026-09-21\c2-artifact-coverage.json
python .\analysis-framework\common\generate_infrastructure_stix.py --repository . --as-of 2026-09-21 --write
python .\analysis-framework\common\generate_infrastructure_stix.py --repository . --as-of 2026-09-21 --check
```

出力は[横断Bundle](../../analysis-results/stix/infrastructure/bundle.json)と[件数・安全境界索引](../../analysis-results/stix/infrastructure/index.json)です。既存のファミリー別Bundleと横断インフラ成果物を更新した後、生成器の`--check`、STIX参照整合性、重複ID、出典URL、日本語文書、テキスト整合性を確認します。既存のファミリー別STIXだけを再生成する手順は[別文書](FAMILY-STIX.md#更新手順)を参照してください。

本資料は公開済み一次資料と過去の観測結果の整理です。2026-09-21現在のC2稼働、DNSの現行解決先、証明書の現行提供、ピボット先全IPの網羅性は確認していません。失効・再割当・正規利用を考慮し、ハンティング時には時間帯と複数の独立証拠を突合してください。
