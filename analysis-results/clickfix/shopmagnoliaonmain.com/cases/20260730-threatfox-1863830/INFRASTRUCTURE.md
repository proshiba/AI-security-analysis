# インフラ調査

## 時点と役割

- domain: `shopmagnoliaonmain.com`
- 情報源観測日時: `2026-07-30 00:16:00 UTC`
- インフラ調査日時: `2026-07-30T07:41:43.560581+00:00`
- ライブ到達: `到達` / HTTP `[206]`
- WebDAV 207: `未観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| type | 解析時の応答 |
|---|---|
| `A` | 104.21.5.116, 172.67.133.95 |
| `AAAA` | 未取得 |
| `CNAME` | 未取得 |
| `NS` | mimi.ns.cloudflare.com, dante.ns.cloudflare.com |
| `MX` | 未取得 |

## 登録・ホスティング

- RDAP handle: `3099700153_DOMAIN_COM-VRSN`
- registrar handle: `1923`
- nameserver: `dante.ns.cloudflare.com, mimi.ns.cloudflare.com`
- status: `client transfer prohibited`
- IP pivot: `104.21.5.116`
- netblock: `未取得` / `? - ?`
- ASN: `AS13335` / `Cloudflare, Inc.` / 国コード `US`

## 証明書とCT

- ライブleaf証明書: `0`件
- CT行数: `0`
- CT names: `未取得`
- issuer: `未取得`

## Shodan InternetDB

- ports: `[80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880]`
- hostnames: `['evgl.herzogmeier.com']`
- CPE: `['cpe:/a:cloudflare:cloudflare']`
- CVE: `[]`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`2`件でした。
