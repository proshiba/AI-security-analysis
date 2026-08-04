# インフラ調査

## 時点と役割

- domain: `a7r6cxyd.lacavamexicancocina.com`
- 情報源観測日時: `2026-08-04 00:21:27 UTC`
- インフラ調査日時: `2026-08-04T01:57:50.166726+00:00`
- ライブ到達: `到達` / HTTP `[403]`
- WebDAV 207: `未観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| DNS種別 | 解析時の応答 |
|---|---|
| `A` | 104.21.82.202, 172.67.162.221（DNS応答） |
| `AAAA` | 未取得（DNS応答） |
| `CNAME` | 未取得（DNS応答） |
| `NS` | 未取得（DNS応答） |
| `MX` | 未取得（DNS応答） |

## 登録・ホスティング

- RDAP handle（登録識別子）: `未取得`
- registrar handle（レジストラ識別子）: `未取得`
- nameserver（権威DNS）: `未取得`
- 登録status: `未取得`
- IP pivot（調査対象）: `104.21.82.202`
- netblock（割当範囲）: `CLOUDFLARENET` / `104.16.0.0 - 104.31.255.255`
- ASN: `AS13335` / `Cloudflare, Inc.` / 国コード `US`

## 証明書とCT

- ライブleaf証明書: `0`件
- CT行数: `0`
- CT names（証明書名）: `未取得`
- issuer（発行者）: `未取得`

## Shodan InternetDBの公開サービス情報

- ports（公開port）: `[80, 443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8080, 8443, 8880]`
- hostnames（観測名）: `['larroc.com']`
- CPE（製品識別子）: `['cpe:/a:cloudflare:cloudflare']`
- CVE（脆弱性識別子）: `[]`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`2`件でした。
