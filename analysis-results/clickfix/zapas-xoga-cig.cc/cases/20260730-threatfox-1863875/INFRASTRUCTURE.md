# インフラ調査

## 時点と役割

- domain: `zapas-xoga-cig.cc`
- 情報源観測日時: `2026-07-30 04:11:30 UTC`
- インフラ調査日時: `2026-07-30T07:41:30.761213+00:00`
- ライブ到達: `到達` / HTTP `[403]`
- WebDAV 207: `未観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| type | 解析時の応答 |
|---|---|
| `A` | 87.58.206.75 |
| `AAAA` | 未取得 |
| `CNAME` | 未取得 |
| `NS` | summer.ns.cloudflare.com, damian.ns.cloudflare.com |
| `MX` | 未取得 |

## 登録・ホスティング

- RDAP handle: `209582128_DOMAIN_CC-VRSN`
- registrar handle: `472`
- nameserver: `damian.ns.cloudflare.com, summer.ns.cloudflare.com`
- status: `client transfer prohibited`
- IP pivot: `87.58.206.75`
- netblock: `DEDIK-IO-NETHERLANDS-NETWORK-87-58-206-0-24` / `87.58.206.0 - 87.58.206.255`
- ASN: `AS207043` / `DEDIK SERVICES LIMITED` / 国コード `NL`

## 証明書とCT

- ライブleaf証明書: `0`件
- CT行数: `0`
- CT names: `未取得`
- issuer: `未取得`

## Shodan InternetDB

- ports: `[80, 443, 444, 3001]`
- hostnames: `['max.ru']`
- CPE: `['cpe:/a:caddyserver:caddy', 'cpe:/a:golang:go']`
- CVE: `[]`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`1`件でした。
