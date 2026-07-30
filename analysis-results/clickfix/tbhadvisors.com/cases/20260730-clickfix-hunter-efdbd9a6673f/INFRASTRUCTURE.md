# インフラ調査

## 時点と役割

- domain: `tbhadvisors.com`
- 情報源観測日時: `2026-07-27T22:22:02.212Z`
- インフラ調査日時: `2026-07-30T07:41:07.315670+00:00`
- ライブ到達: `到達` / HTTP `[200]`
- WebDAV 207: `未観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| type | 解析時の応答 |
|---|---|
| `A` | 162.159.135.42 |
| `AAAA` | 未取得 |
| `CNAME` | 未取得 |
| `NS` | ns21.domaincontrol.com, ns22.domaincontrol.com |
| `MX` | 20 tbhadvisors-com.mx2.arsmtp.com, 10 tbhadvisors-com.mx1.arsmtp.com |

## 登録・ホスティング

- RDAP handle: `1897756975_DOMAIN_COM-VRSN`
- registrar handle: `146`
- nameserver: `ns21.domaincontrol.com, ns22.domaincontrol.com`
- status: `client delete prohibited, client renew prohibited, client transfer prohibited, client update prohibited`
- IP pivot: `162.159.135.42`
- netblock: `CLOUDFLARENET` / `162.158.0.0 - 162.159.255.255`
- ASN: `AS13335` / `Cloudflare, Inc.` / 国コード `US`

## 証明書とCT

- ライブleaf証明書: `0`件
- CT行数: `0`
- CT names: `未取得`
- issuer: `未取得`

## Shodan InternetDB

- ports: `[80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880]`
- hostnames: `['kinsta.cloud', 'proreni.kinsta.cloud', 'southbayjam.kinsta.cloud']`
- CPE: `['cpe:/a:cloudflare:cloudflare', 'cpe:/a:mysql:mysql', 'cpe:/a:php:php', 'cpe:/a:wordpress:wordpress']`
- CVE: `[]`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`2`件でした。
