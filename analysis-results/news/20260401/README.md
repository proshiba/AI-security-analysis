# Security news analysis: 2026-04-01

`tech-memo/daily-news/news/2026_04-06/20260401.md` に列挙された9件を、2026-07-16時点の一次情報と静的解析結果で再評価した。公開情報だけで確認できない攻撃者・マルウェア・被害範囲は補完せず、`confirmed`（一次情報または検体で確認）、`inferred`（複数証拠から推定）、`unverified`（報道のみ、または現物未取得）を区別する。

## 結果一覧

| # | 活動 | 判定 | 実施内容 |
|---|---|---|---|
| 1 | 日本語賞与通知を装う ValleyRAT | 配布チェーン confirmed、最終設定 unverified | [ケース解析](../../valleyrat/cases/f543dcf4f178e464c7b4dc24b463272417d8ada2a7d3a832e177f37e64f10cbd/README.md)、誤帰属を避ける検出器改修 |
| 2 | Trivy/TeamPCP と Cisco 開発環境侵害報道 | Trivy confirmed、Cisco範囲は報道ベース | [供給網解析](../../supply-chain/trivy-teampcp-2026/README.md)、オフライン監査器 |
| 3 | Uranium Finance 約5,300万ドル窃取 | 起訴内容 confirmed、マルウェアなし | スマートコントラクト悪用として整理。検体解析対象外 |
| 4 | オランダ財務省ポータル侵害 | 侵害 confirmed、侵入経路詳細非公開 | 6月の政府追補を優先。公開IOC・検体なし |
| 5 | NetScaler CVE-2026-3055 | 脆弱性・悪用 confirmed | [防御的評価](../../vulnerabilities/cve-2026-3055/README.md)。PoC再現は行わない |
| 6 | CareCloud EHR環境侵害 | SEC提出内容 confirmed | 公開IOC・マルウェアなし。1/6環境が約8時間影響 |
| 7 | axios npm供給網侵害 | setup.jsを静的に confirmed | [実検体解析](../../npm-supply-chain/cases/e10b1fa84f1d6481625f741b69892780140d4e0e7769e7491e5f4d894c2e0e09/README.md)、復号器・監査器 |
| 8 | Silver Foxによる AtlasCross/Atlas RAT配布 | 公開技術解析で confirmed | [キャンペーン解析](../../atlascross/campaigns/silver-fox-vpn-2026/README.md)、設定復号器（合成fixtureで検証） |
| 9 | コタ株式会社のシステム障害 | サイバー攻撃 confirmed、手法非公開 | 第1報の事実だけを保持。公開IOC・検体なし |

## 3. Uranium Finance

米司法省の起訴発表では、2021年のスマートコントラクト操作で26の流動性プールから約5,330万ドル相当を取得し、Tornado Cash等を使って資金洗浄した疑いが示されている。これはオンチェーン／コントラクトロジック悪用であり、エンドポイントマルウェアの存在を示す証拠ではない。検知はトランザクション時系列、異常なプール残高変化、ブリッジ・ミキサーへの資金移動を中心とし、YARA/Sigmaの適用対象ではない。

## 4. オランダ財務省

初報だけでなく2026-06-18の政府追補を確認した。特定サプライヤのソフトウェアに存在した当時未知の脆弱性を介した不正アクセスと、データ窃取の可能性が公表されている。一方、正確にどのファイルが取得されたかは再構成できず、マルウェア名・ハッシュ・C2は公開されていない。したがって特定ファミリへの帰属やIOC生成は行わない。

## 6. CareCloud

2026-03-27のSEC Form 8-Kでは、3月16日にCareCloud Healthの6つのEHR環境のうち1つが不正な第三者アクセスを受け、機能とデータアクセスが約8時間部分的に影響した。提出時点でアクセス／持ち出しの範囲を調査中としており、攻撃者、初期侵入、マルウェア、C2は非公開である。EHR監査ログ、特権操作、異常エクスポート、同時間帯のIdP／VPN／EDR相関が優先で、公開情報だけからルールを狭く固定するのは危険である。

## 9. コタ株式会社

2026-03-30の第1報は、3月27日のサイバー攻撃によるシステム障害と、外部専門家・警察等と連携した調査を確認している。個人情報・顧客データ流出を含む影響範囲、攻撃手法、マルウェアは当時調査中である。`KOTA`ではなく上場会社のコタ株式会社（COTA）であり、追加情報なしにランサムウェア等へ分類しない。

## Sources

- Source memo: https://github.com/proshiba/tech-memo/blob/main/daily-news/news/2026_04-06/20260401.md
- ITOCHU Cyber & Intelligence ValleyRAT analysis: https://blog.itochuci.co.jp/entry/2026/04/03/133000
- Aqua Trivy advisory: https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23
- U.S. DOJ Uranium Finance release: https://www.justice.gov/usao-sdny/pr/maryland-man-charged-defrauding-crypto-exchange-over-50-million-hacks
- Dutch government incident retrospective: https://www.rijksoverheid.nl/actueel/nieuws/2026/06/18/terugblik-cyberincident
- Citrix bulletin: https://support.citrix.com/external/article/CTX696300/netscaler-adc-and-netscaler-gateway-secu.html
- CareCloud SEC Form 8-K: https://www.sec.gov/Archives/edgar/data/1582982/000149315226013239/form8-k.htm
- axios post-mortem: https://github.com/axios/axios/issues/10636
- StepSecurity axios analysis: https://www.stepsecurity.io/blog/axios-compromised-on-npm-malicious-versions-drop-remote-access-trojan
- Hexastrike AtlasCross analysis: https://hexastrike.com/resources/blog/threat-intelligence/trust-the-tunnel-get-the-trojan-silver-fox-delivers-atlas-rat-via-weaponized-vpn-installers/
- COTA first report: https://www.kabutec.jp/pdf/202603/140120260330592911.pdf

No malware was executed and no live infrastructure was contacted during this work.
