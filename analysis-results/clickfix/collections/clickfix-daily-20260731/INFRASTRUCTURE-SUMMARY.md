# ClickFixインフラ調査サマリー: 2026-07-31

- case: `50`件
- ライブHTTP到達: `25`件
- domain RDAP取得: `4`件
- CT取得: `9`件
- Shodan InternetDB取得: `25`件
- ASN取得: `25`件
- provider別error: `95`件

DNS・証明書・RDAP・netblock・InternetDBを同一caseへ束ねました。共有CDNや侵害された正規サイトを
含むため、IP／証明書／portの一致だけでcampaignやC2を確定しません。
