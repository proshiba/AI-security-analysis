# インフラ調査

## 時点と役割

- domain: `betensured-tips.com`
- 情報源観測日時: `2026-08-04 01:15:03 UTC`
- インフラ調査日時: `2026-08-04T01:57:18.777494+00:00`
- ライブ到達: `到達` / HTTP `[206]`
- WebDAV 207: `未観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| DNS種別 | 解析時の応答 |
|---|---|
| `A` | 72.249.68.244（DNS応答） |
| `AAAA` | 未取得（DNS応答） |
| `CNAME` | 未取得（DNS応答） |
| `NS` | ns2.web-sites-solutions.com, ns1.web-sites-solutions.com（DNS応答） |
| `MX` | 0 mail.betensured-tips.com（DNS応答） |

## 登録・ホスティング

- RDAP handle（登録識別子）: `未取得`
- registrar handle（レジストラ識別子）: `未取得`
- nameserver（権威DNS）: `未取得`
- 登録status: `未取得`
- IP pivot（調査対象）: `72.249.68.244`
- netblock（割当範囲）: `COLO4-BLK2` / `72.249.0.0 - 72.249.191.255`
- ASN: `AS17378` / `TierPoint, LLC` / 国コード `US`

## 証明書とCT

- ライブleaf証明書: `0`件
- CT行数: `109`
- CT names（証明書名）: `*.betensured-tips.com, betensured-tips.com`
- issuer（発行者）: `C=US, O="Cloudflare, Inc.", CN=Cloudflare Inc ECC CA-3, C=US, O=Google Trust Services LLC, CN=GTS CA 1P5, C=US, O=Let's Encrypt, CN=E1, C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3, C=US, O=Let's Encrypt, CN=R10, C=US, O=Let's Encrypt, CN=R11, C=US, O=Let's Encrypt, CN=R12, C=US, O=Let's Encrypt, CN=R13, C=US, O=Let's Encrypt, CN=R3, C=US, O=Let's Encrypt, CN=YR1`

## Shodan InternetDBの公開サービス情報

- ports（公開port）: `[21, 53, 80, 110, 443, 993]`
- hostnames（観測名）: `['cloud.web-sites-solutions.com']`
- CPE（製品識別子）: `['cpe:/a:apache:http_server', 'cpe:/a:pureftpd:pure-ftpd']`
- CVE（脆弱性識別子）: `[]`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`1`件でした。
