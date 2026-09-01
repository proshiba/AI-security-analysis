# インフラ調査

## 解析時点

- 配布domain: `fingerprint-verification.info`
- 情報源観測日時: `2026-08-31T14:45:06Z`
- 調査日時: `2026-08-31T23:14:00Z`
- current A: `178.16.52[.]101`
- NS: `justin.ns.cloudflare[.]com`, `melody.ns.cloudflare[.]com`
- レジストラ: `Spaceship, Inc.` / IANA `3862`
- 登録: `2026-08-24T03:35:39.909Z`
- 失効予定: `2027-08-24T03:35:39.909Z`

配布本文の再取得は行わなかった。HTTP statusを到達証跡として記録せず、DNS、RDAP、CT、
InternetDBと、HTTP requestを送らないTLS handshakeだけを実施した。

## IPの調査軸

| 項目 | 観測値 |
|---|---|
| IP | `178.16.52[.]101` |
| netblock | `178.16.52.0/24`相当（`178.16.52.0` - `178.16.52.255`） |
| allocation | `OMEGATECH`, `ASSIGNED PA`, `DE` |
| ASN | `AS202412`, `OMEGATECH` / `Omegatech LTD` |
| InternetDB ports | `80`, `443` |
| InternetDB CPE | `cpe:/a:f5:nginx` |
| InternetDB CVE | なし |

## 証明書

- leaf証明書SHA-256: `638a0743830403481a753f46f0167f03e0d5fb6fa03a29177b627098e0e0522d`
- subject: `CN=fingerprint-verification.info`
- issuer: `Let's Encrypt YR2`
- validity: `2026-08-24T04:11:33Z` - `2026-11-22T04:11:32Z`
- CT行数: `2`

IP、open port、Cloudflare nameserver、証明書だけではC2やcampaignを確定しない。IPとleaf証明書は
時点付き`context_only`であり、IOC一覧から除外する。
