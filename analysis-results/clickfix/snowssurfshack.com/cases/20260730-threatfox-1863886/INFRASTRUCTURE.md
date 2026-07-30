# インフラ調査

## 時点と役割

- domain: `snowssurfshack.com`
- 情報源観測日時: `2026-07-30 05:37:52 UTC`
- インフラ調査日時: `2026-07-30T07:40:54.984933+00:00`
- ライブ到達: `到達` / HTTP `[301]`
- WebDAV 207: `未観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| type | 解析時の応答 |
|---|---|
| `A` | 172.67.159.204, 104.21.89.135 |
| `AAAA` | 未取得 |
| `CNAME` | 未取得 |
| `NS` | dante.ns.cloudflare.com, mimi.ns.cloudflare.com |
| `MX` | 未取得 |

## 登録・ホスティング

- RDAP handle: `3101214894_DOMAIN_COM-VRSN`
- registrar handle: `1923`
- nameserver: `dante.ns.cloudflare.com, mimi.ns.cloudflare.com`
- status: `client transfer prohibited`
- IP pivot: `104.21.38.211`
- netblock: `CLOUDFLARENET` / `104.16.0.0 - 104.31.255.255`
- ASN: `AS13335` / `Cloudflare, Inc.` / 国コード `US`

## 証明書とCT

- ライブleaf証明書: `0`件
- CT行数: `0`
- CT names: `未取得`
- issuer: `未取得`

## Shodan InternetDB

- ports: `[80, 443, 2082, 2083, 2086, 2087, 8080, 8443, 8880]`
- hostnames: `['inphase-technologies.com']`
- CPE: `['cpe:/a:cloudflare:cloudflare']`
- CVE: `[]`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`1`件でした。
