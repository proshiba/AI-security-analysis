# ClickFixインフラ調査サマリー: 2026-08-04

- case: `50`件
- ライブHTTP到達: `35`件
- domain RDAP取得: `9`件
- CT取得: `1`件
- Shodan InternetDB取得: `35`件
- ASN取得: `35`件
- provider別error: `94`件

DNS・証明書・RDAP・netblock・InternetDBを同一caseへ束ねました。共有CDNや侵害された正規サイトを
含むため、IP／証明書／portの一致だけでcampaignやC2を確定しません。
