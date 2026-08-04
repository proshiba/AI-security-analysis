# インフラ調査

## 時点と役割

- domain: `lexingtoncancerfoundation.org`
- 情報源観測日時: `2026-08-04 00:15:03 UTC`
- インフラ調査日時: `2026-08-04T01:58:06.258895+00:00`
- ライブ到達: `到達` / HTTP `[200]`
- WebDAV 207: `未観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| DNS種別 | 解析時の応答 |
|---|---|
| `A` | 162.241.4.116（DNS応答） |
| `AAAA` | 未取得（DNS応答） |
| `CNAME` | 未取得（DNS応答） |
| `NS` | salvador.ns.porkbun.com, curitiba.ns.porkbun.com, maceio.ns.porkbun.com, fortaleza.ns.porkbun.com（DNS応答） |
| `MX` | 0 lexingtoncancerfoundation-org.mail.protection.outlook.com（DNS応答） |

## 登録・ホスティング

- RDAP handle（登録識別子）: `未取得`
- registrar handle（レジストラ識別子）: `1861`
- nameserver（権威DNS）: `curitiba.ns.porkbun.com, fortaleza.ns.porkbun.com, maceio.ns.porkbun.com, salvador.ns.porkbun.com`
- 登録status: `client delete prohibited, client transfer prohibited`
- IP pivot（調査対象）: `162.241.4.116`
- netblock（割当範囲）: `UNIFIEDLAYER-NETWORK-16` / `162.240.0.0 - 162.241.255.255`
- ASN: `AS19871` / `Unified Layer` / 国コード `US`

## 証明書とCT

- ライブleaf証明書: `0`件
- CT行数: `0`
- CT names（証明書名）: `未取得`
- issuer（発行者）: `未取得`

## Shodan InternetDBの公開サービス情報

- ports（公開port）: `[53, 80, 110, 143, 443, 993, 995, 2082, 2083, 2086, 2222]`
- hostnames（観測名）: `['4934096.pivt.me', 'hrmech.com', 'pivt.me']`
- CPE（製品識別子）: `['cpe:/a:apache:http_server', 'cpe:/a:openbsd:openssh:7.4']`
- CVE（脆弱性識別子）: `['CVE-2007-2768', 'CVE-2008-3844', 'CVE-2016-20012', 'CVE-2017-15906', 'CVE-2018-15473', 'CVE-2018-15919', 'CVE-2018-20685', 'CVE-2019-6109', 'CVE-2019-6110', 'CVE-2019-6111', 'CVE-2020-14145', 'CVE-2020-15778', 'CVE-2021-36368', 'CVE-2021-41617', 'CVE-2023-38408', 'CVE-2023-48795', 'CVE-2023-51385', 'CVE-2023-51767', 'CVE-2025-26465', 'CVE-2025-32728', 'CVE-2026-35385', 'CVE-2026-35387', 'CVE-2026-35388', 'CVE-2026-35414', 'CVE-2026-59995', 'CVE-2026-59996', 'CVE-2026-59997', 'CVE-2026-59998', 'CVE-2026-59999', 'CVE-2026-60000', 'CVE-2026-60001', 'CVE-2026-60002']`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`1`件でした。
