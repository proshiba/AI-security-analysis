# インフラ調査

## 時点と役割

- domain: `makeverizyjar.info`
- 情報源観測日時: `2026-08-04 01:22:54 UTC`
- インフラ調査日時: `2026-08-04T01:56:03.401248+00:00`
- ライブ到達: `到達` / HTTP `[403]`
- WebDAV 207: `未観測`

配布domain、stage取得先、resolver、終端C2を分離します。以下のDNS、RDAP、証明書、port情報は
pivot候補であり、単独では悪性またはC2の根拠にしません。

## 現行DNS

| DNS種別 | 解析時の応答 |
|---|---|
| `A` | 158.94.208.87（DNS応答） |
| `AAAA` | 未取得（DNS応答） |
| `CNAME` | 未取得（DNS応答） |
| `NS` | kolton.ns.cloudflare.com, amy.ns.cloudflare.com（DNS応答） |
| `MX` | 未取得（DNS応答） |

## 登録・ホスティング

- RDAP handle（登録識別子）: `未取得`
- registrar handle（レジストラ識別子）: `472`
- nameserver（権威DNS）: `amy.ns.cloudflare.com, kolton.ns.cloudflare.com`
- 登録status: `add period, client transfer prohibited`
- IP pivot（調査対象）: `158.94.208.87`
- netblock（割当範囲）: `OMEGATECH` / `158.94.208.0 - 158.94.208.255`
- ASN: `AS202412` / `OMEGATECH` / 国コード `DE`

## 証明書とCT

- ライブleaf証明書: `0`件
- CT行数: `0`
- CT names（証明書名）: `未取得`
- issuer（発行者）: `未取得`

## Shodan InternetDBの公開サービス情報

- ports（公開port）: `[22, 80, 443]`
- hostnames（観測名）: `['verifyrecapcha.info']`
- CPE（製品識別子）: `['cpe:/a:f5:nginx', 'cpe:/a:openbsd:openssh:9.6p1', 'cpe:/o:canonical:ubuntu_linux']`
- CVE（脆弱性識別子）: `[]`

port openはサービス存在の観測にすぎません。malware protocol、URI、証明書再利用、process帰属の
いずれかを追加確認してからC2候補へ昇格します。

## 時系列上の制約

履歴passive DNS providerは未設定です。情報源の観測日時、今回のcurrent DNS、RDAP event、CTの
not-before／not-afterを混同せず、同一IP・証明書・nameserverの再利用はcampaign候補としてのみ扱います。
API errorは`1`件でした。
