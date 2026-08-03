# インフラ調査

## 時点と役割

- domain: `hdz7omr1.nextbahis.blog`
- 情報源観測日時: `2026-07-22T11:53:07.658Z`
- インフラ調査日時: `2026-08-02T22:40:56.852484+00:00`
- ライブ到達: `未到達` / HTTP `[]`
- WebDAV 207: `未観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| type | 解析時の応答 |
|---|---|
| `A` | 未取得 |
| `AAAA` | 未取得 |
| `CNAME` | 未取得 |
| `NS` | 未取得 |
| `MX` | 未取得 |

## 登録・ホスティング

- RDAP handle: `未取得`
- registrar handle: `未取得`
- nameserver: `未取得`
- status: `未取得`
- IP pivot: `未設定`
- netblock: `未取得` / `? - ?`
- ASN: `AS未取得` / `未取得` / 国コード `未取得`

## 証明書とCT

- ライブleaf証明書: `0`件
- CT行数: `0`
- CT names: `未取得`
- issuer: `未取得`

## Shodan InternetDB

- ports: `[]`
- hostnames: `[]`
- CPE: `[]`
- CVE: `[]`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`2`件でした。
