# ClickFixインフラ調査サマリー: 2026-07-30

- case: `50`件
- ライブHTTP到達: `30`件
- domain RDAP取得: `14`件
- CT取得: `1`件
- Shodan InternetDB取得: `30`件
- ASN取得: 30件
- provider別error: `106`件

DNS・証明書・RDAP・netblock・InternetDBを同一caseへ束ねました。共有CDNや侵害された正規サイトを
含むため、IP／証明書／portの一致だけでcampaignやC2を確定しません。
