# ClickFixインフラ調査サマリー: 2026-08-03

- case: `50`件
- ライブHTTP到達: `26`件
- domain RDAP取得: `6`件
- CT取得: `7`件
- Shodan InternetDB取得: `26`件
- ASN取得: `26`件
- provider別error: `94`件

DNS・証明書・RDAP・netblock・InternetDBを同一caseへ束ねました。共有CDNや侵害された正規サイトを
含むため、IP／証明書／portの一致だけでcampaignやC2を確定しません。
