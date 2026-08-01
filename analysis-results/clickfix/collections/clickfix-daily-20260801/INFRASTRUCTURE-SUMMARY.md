# ClickFixインフラ調査サマリー: 2026-08-01

- case: `50`件
- ライブHTTP到達: `30`件
- domain RDAP取得: `4`件
- CT取得: `0`件
- Shodan InternetDB取得: `30`件
- ASN取得: `30`件
- provider別error: `114`件

DNS・証明書・RDAP・netblock・InternetDBを同一caseへ束ねました。共有CDNや侵害された正規サイトを
含むため、IP／証明書／portの一致だけでcampaignやC2を確定しません。
