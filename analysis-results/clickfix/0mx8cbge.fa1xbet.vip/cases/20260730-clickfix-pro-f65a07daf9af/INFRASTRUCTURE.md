# インフラ調査

## 時点と役割

- domain: `0mx8cbge.fa1xbet.vip`
- 情報源観測日時: `2026-07-25T20:00:16.749Z`
- インフラ調査日時: `2026-07-30T07:41:45.799459+00:00`
- ライブ到達: `到達` / HTTP `[206]`
- WebDAV 207: `未観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| type | 解析時の応答 |
|---|---|
| `A` | 72.251.7.23, 72.251.7.22 |
| `AAAA` | 未取得 |
| `CNAME` | 未取得 |
| `NS` | ns2.lander.d.parity.domains, ns1.lander.d.parity.domains |
| `MX` | 未取得 |

## 登録・ホスティング

- RDAP handle: `未取得`
- registrar handle: `未取得`
- nameserver: `未取得`
- status: `未取得`
- IP pivot: `72.251.7.22`
- netblock: `OVH-DEDICATED-FO` / `72.251.7.0 - 72.251.7.31`
- ASN: `AS16276` / `OVH Infrastructures Canada INC` / 国コード `CA`

## 証明書とCT

- ライブleaf証明書: `0`件
- CT行数: `0`
- CT names: `未取得`
- issuer: `未取得`

## Shodan InternetDB

- ports: `[53, 80, 443]`
- hostnames: `['ip22.ip-72-251-7.net']`
- CPE: `[]`
- CVE: `[]`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`3`件でした。
