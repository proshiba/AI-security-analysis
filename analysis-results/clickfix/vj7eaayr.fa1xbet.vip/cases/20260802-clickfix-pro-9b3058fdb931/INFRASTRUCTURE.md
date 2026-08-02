# インフラ調査

## 時点と役割

- domain: `vj7eaayr.fa1xbet.vip`
- 情報源観測日時: `2026-07-31T07:24:21.469Z`
- インフラ調査日時: `2026-08-01T23:45:58.002381+00:00`
- ライブ到達: `到達` / HTTP `[206]`
- WebDAV 207: `未観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| type | 解析時の応答 |
|---|---|
| `A` | 72.251.7.22, 72.251.7.23 |
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
- hostnames: `['ip22.ip-72-251-7.net', 'ozon.pay.blablacar.sbermarket.nalozhka.royalenfield-mkt-prod1-res.campaign.carlaskitchenmb.com', 'www.crypto-earnup.caddsolutions.org']`
- CPE: `['cpe:/a:f5:nginx:1.28.3', 'cpe:/o:canonical:ubuntu_linux', 'cpe:/o:linux:linux_kernel']`
- CVE: `[]`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`2`件でした。
