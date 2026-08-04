# インフラ調査

## 時点と役割

- domain: `muhammedmuheisen.com`
- 情報源観測日時: `2026-08-04 01:15:04 UTC`
- インフラ調査日時: `2026-08-04T01:56:28.524303+00:00`
- ライブ到達: `到達` / HTTP `[200]`
- WebDAV 207: `未観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| DNS種別 | 解析時の応答 |
|---|---|
| `A` | 192.185.224.35（DNS応答） |
| `AAAA` | 未取得（DNS応答） |
| `CNAME` | 未取得（DNS応答） |
| `NS` | ns6589.hostgator.com, ns6590.hostgator.com（DNS応答） |
| `MX` | 5 alt1.aspmx.l.google.com, 10 alt3.aspmx.l.google.com, 1 aspmx.l.google.com, 10 alt4.aspmx.l.google.com, 5 alt2.aspmx.l.google.com（DNS応答） |

## 登録・ホスティング

- RDAP handle（登録識別子）: `2125499186_DOMAIN_COM-VRSN`
- registrar handle（レジストラ識別子）: `146`
- nameserver（権威DNS）: `ns6589.hostgator.com, ns6590.hostgator.com`
- 登録status: `client delete prohibited, client renew prohibited, client transfer prohibited, client update prohibited`
- IP pivot（調査対象）: `192.185.224.35`
- netblock（割当範囲）: `HGBLOCK-10` / `192.185.0.0 - 192.185.255.255`
- ASN: `AS31898` / `Hostgator.com LLC` / 国コード `US`

## 証明書とCT

- ライブleaf証明書: `0`件
- CT行数: `0`
- CT names（証明書名）: `未取得`
- issuer（発行者）: `未取得`

## Shodan InternetDBの公開サービス情報

- ports（公開port）: `[22, 53, 80, 110, 143, 443, 465, 587, 995, 2086, 2087, 2222, 3306]`
- hostnames（観測名）: `['autodiscover.themannlab.org', 'cpanel.themannlab.org', 'cpcalendars.themannlab.org', 'cpcontacts.themannlab.org', 'mail.themannlab.org', 'mail.wegocine.com', 'themannlab.org', 'webdisk.themannlab.org', 'webmail.themannlab.org', 'www.themannlab.org']`
- CPE（製品識別子）: `['cpe:/a:apache:http_server', 'cpe:/a:exim:exim:4.99.2', 'cpe:/a:openbsd:openssh:9.9', 'cpe:/a:oracle:mysql:5.7.44-48']`
- CVE（脆弱性識別子）: `['CVE-2007-2768', 'CVE-2008-3844', 'CVE-2023-51767', 'CVE-2025-26465', 'CVE-2025-26466', 'CVE-2025-32728', 'CVE-2026-35385', 'CVE-2026-35387', 'CVE-2026-35388', 'CVE-2026-35414', 'CVE-2026-45185', 'CVE-2026-48840', 'CVE-2026-59995', 'CVE-2026-59996', 'CVE-2026-59997', 'CVE-2026-59998', 'CVE-2026-59999', 'CVE-2026-60000', 'CVE-2026-60001', 'CVE-2026-60002']`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`1`件でした。
