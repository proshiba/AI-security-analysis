# インフラ調査

## 時点と役割

- domain: `subterranean-mineral-map.garden`
- 情報源観測日時: `2026-07-22T10:57:03.485Z`
- インフラ調査日時: `2026-07-30T23:16:25.305858+00:00`
- ライブ到達: `到達` / HTTP `[207]`
- WebDAV 207: `観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| type | 解析時の応答 |
|---|---|
| `A` | 172.67.206.225, 104.21.22.195 |
| `AAAA` | 未取得 |
| `CNAME` | 未取得 |
| `NS` | gannon.ns.cloudflare.com, adele.ns.cloudflare.com |
| `MX` | 未取得 |

## 登録・ホスティング

- RDAP handle: `未取得`
- registrar handle: `未取得`
- nameserver: `未取得`
- status: `未取得`
- IP pivot: `104.21.22.195`
- netblock: `未取得` / `? - ?`
- ASN: `AS13335` / `Cloudflare, Inc.` / 国コード `US`

## 証明書とCT

- ライブleaf証明書: `0`件
- CT行数: `6`
- CT names: `*.subterranean-mineral-map.garden, subterranean-mineral-map.garden`
- issuer: `C=US, O=Google Trust Services, CN=WE1, C=US, O=Let's Encrypt, CN=E7, C=US, O=Let's Encrypt, CN=YE1`

## Shodan InternetDB

- ports: `[80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880]`
- hostnames: `['jens-place.org', 'lvchs.org', 'www.jens-place.org']`
- CPE: `['cpe:/a:cloudflare:cloudflare']`
- CVE: `[]`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`2`件でした。
