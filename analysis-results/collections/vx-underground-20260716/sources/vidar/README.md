# Vidar 解析

`vx-underground` の提出検体25件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。

## バッチ解析結果

- ケースs：25
- Errors：0
- パッキングの可能性：0
- ケースs を伴う から回収した値:rtifacts：15
- ケースs を伴う validated 静的 設定：0
- 検体の実行：false
- ネットワーク接続：false

## キャンペーン／配送形態

- `direct_pe_or_pe_loader`：24
- `nested_or_protected_delivery`：1

## 静的解析で確認した挙動

- `browser_collection`：8/25
- `dependency_download`：2/25
- `telegram_dead_drop`：1/25
- `wallet_collection`：2/25

## C2／設定の確認事項

| 値 (値) | 役割 (役割) | 確度 (確度) | 情報源 (情報源) |
|---|---|---|---|
| `http://157.90.113.100:80` | candidate_infrastructure | 候補 | embedded_literal |
| `https://steamcommunity.com/profiles/76561199482248283` | candidate_infrastructure | 候補 | embedded_literal |
| `https://t.me/dionysus_tg` | candidate_infrastructure | 候補 | embedded_literal |

能動的なC2チェックインは行っていない。オフライン評価と受動照会の生成には `analysis-framework/common/c2_candidate_detector.py` を使用する。

## 検証済み設定値

- なし validated ファミリー 設定 値 回収済み

## ケース一覧

| SHA-256 | 形式 (Format) | 配送形態 (キャンペーン) | パッキング (パック済み) | レイヤー数 (Layers) | 確認事項 (確認事項) |
|---|---|---|---:|---:|---:|
| [02355d3fee5e](../../../../malware/vidar/versions/unknown/cases/02355d3fee5e217b25f9210ad0f6bacc3807b6ef1a59aa4d428c01017dcbcf28/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [05f9553616bb](../../../../malware/vidar/versions/unknown/cases/05f9553616bb5fdbf37bd4036c210929e08d7181de898c1bea1bdae7afb0766f/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [0c857501e385](../../../../malware/vidar/versions/unknown/cases/0c857501e3851072db666386136929c06bcf4c8d3160b41b7d82a3ce9afca1be/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [0df79273aea7](../../../../malware/vidar/versions/unknown/cases/0df79273aea792b72c2218a616b36324e31aaf7da59271969a23a0c392f58451/README.md) | pe | direct_pe_or_pe_loader | false | 34 | 0 |
| [151247e9379a](../../../../malware/vidar/versions/unknown/cases/151247e9379a755e3bb260cca5c59977e4075d5404db4198f3cec82818412479/README.md) | pe | direct_pe_or_pe_loader | false | 27 | 0 |
| [25f720e9b969](../../../../malware/vidar/versions/unknown/cases/25f720e9b969bdbece357a4704d4575a47ab8230affefbc2bfc467cb317835f1/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [28db05fffe5f](../../../../malware/vidar/versions/unknown/cases/28db05fffe5f32ee8df60a400c97d19270d23327ebb49ae86e455ea14d59f113/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 3 |
| [3418a369486e](../../../../malware/vidar/versions/unknown/cases/3418a369486e9bf2b57023dc0b02cb00f12a5214fca8bae20ff93586cc8c678a/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [363c46dfb252](../../../../malware/vidar/versions/unknown/cases/363c46dfb252d7c40d9c3bb63bdc40c2eff0ce16c0c1b77f507d73058104c6e1/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [3a521823d796](../../../../malware/vidar/versions/unknown/cases/3a521823d79686fad0595f9e90940c8a7451f7343bf64f4dbfcdcbde9115957d/README.md) | データ | nested_or_protected_delivery | false | 0 | 0 |
| [416b40630daa](../../../../malware/vidar/versions/unknown/cases/416b40630daa924136b9d10e0faa8c800a7a882416f4e5b7944f9bc2553a414b/README.md) | pe | direct_pe_or_pe_loader | false | 9 | 0 |
| [49a7f82743a0](../../../../malware/vidar/versions/unknown/cases/49a7f82743a038d7a570d5d5d8ecb92f369f0e6dbba6532674c4789f0daf9b31/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [4c17f7ee55f9](../../../../malware/vidar/versions/unknown/cases/4c17f7ee55f9bf6fa9acaeeb9574feab39ba4a3cccd4426dfa85aaf58b90ae73/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [4d4f97f16213](../../../../malware/vidar/versions/unknown/cases/4d4f97f1621334e4075e0229265ac6c5da14754eff1378a7d77ea6d3821e8a33/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [532bc078a686](../../../../malware/vidar/versions/unknown/cases/532bc078a68683ce70cb765191a128fadee2a23180b1a8e8a16b72f1a8ee291a/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [5cd0759c1e56](../../../../malware/vidar/versions/unknown/cases/5cd0759c1e566b6e74ef3f29a49a34a08ded2dc44408fccd41b5a9845573a34c/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [7b217c20a30a](../../../../malware/vidar/versions/unknown/cases/7b217c20a30ab1bdc4534f4adb62df226d128ec4d03c0eb2feb5ab35d2b7dc9f/README.md) | pe | direct_pe_or_pe_loader | false | 8 | 0 |
| [87b92fcd04f6](../../../../malware/vidar/versions/unknown/cases/87b92fcd04f69f9c132c9f350dbb3686888a5e388b1f787f6a658f09582c0da6/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [931ac54db53c](../../../../malware/vidar/versions/unknown/cases/931ac54db53c787f4138e73535db1664fc22cfbd9957b53d4c5135bc8a0dabd5/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [99e733391ac4](../../../../malware/vidar/versions/unknown/cases/99e733391ac499e78e535a98551c4d27408abfad4e56fe4c46956636655df29c/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [b4c9aadd18c1](../../../../malware/vidar/versions/unknown/cases/b4c9aadd18c1b6f613bf9d6db71dcc010bbdfe8b770b4084eeb7d5c77d95f180/README.md) | pe | direct_pe_or_pe_loader | false | 3 | 0 |
| [b67bc7834791](../../../../malware/vidar/versions/unknown/cases/b67bc78347918209973d633287c4e1f514a0917b8678c2cf2066ba80b2004f78/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [b6b6df6abb52](../../../../malware/vidar/versions/unknown/cases/b6b6df6abb52d7d2e2eb8496c04d76e2a01e51703b7ce44aa127d60ce53a0be7/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [e3d16f3f69fa](../../../../malware/vidar/versions/unknown/cases/e3d16f3f69fa0857f966022387ee6f9408385ddf389d09ffe7dc44acc8ac1ad5/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [f1e8f4fba1da](../../../../malware/vidar/versions/unknown/cases/f1e8f4fba1da25cc02d0673f8cc3962c7419d769cb139f818f8f1e4d56a891df/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |

## 検知時の考慮事項

- **誤検知リスク高：** ブラウザーデータベース、ウォレット、`osascript`、Goランタイム文字列、高エントロピーPEセクションへの一般的なアクセス。バックアップ、移行、企業資産管理、インストーラー、正規Goアプリケーションも一致し得る。
- **誤検知リスク中：** スクリプトインタープリター、ネットワークダウンロード、実行の組み合わせ、または未署名プロセスによる複数のブラウザー／ウォレットストアの読み取り。管理自動化やソフトウェア配布と重なる場合がある。
- **誤検知リスク低：** ファミリー固有文字列、確認済み設定パス／ホスト、認証情報ストアの収集、異常な親子プロセスまたはネットワーク文脈を組み合わせる。ビルダー／バージョン変更による見逃しは残り得る。

次の場所にある検知ルール `rules/` は出発点であり、環境に応じた調整が必要である. リテラルC2は永続的なファミリー署名ではなく、短命な侵害指標一致として扱うべきである.

## 安全上の注意と制約

- 検体は実行しておらず、回収レイヤーもコミットしていない.
- 外部インフラには接続していない.
- 不明なパッカーとパスワード保護された入れ子書庫は未解決である。
- 情報源 attribution 保持した separately から validated 静的証拠.
