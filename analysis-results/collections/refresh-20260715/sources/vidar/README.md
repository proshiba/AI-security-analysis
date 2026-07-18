# Vidar 解析

MalwareBazaarの新規提出検体10件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。

## キャンペーン／配送形態

- `direct_pe_or_pe_loader`：10

## 静的解析で確認した挙動

- `wallet_collection`：7/10

## C2／設定の確認事項

| 値 (値) | 役割 (役割) | 確度 (確度) | 情報源 (情報源) |
|---|---|---|---|
| 回収なし | - | - | パック／暗号化済み、またはリテラル設定なし |

能動的なC2チェックインは行っていない。オフライン評価と受動照会の生成には `analysis-framework/common/c2_candidate_detector.py` を使用する。

## ケース一覧

| SHA-256 | 形式 (Format) | 配送形態 (キャンペーン) | パッキング (パック済み) | レイヤー数 (Layers) | 確認事項 (確認事項) |
|---|---|---|---:|---:|---:|
| [71911c8f6eac](../../../../malware/vidar/versions/unknown/cases/71911c8f6eacf5ba5414bc8a66ac83a981aaf4d1141f5117ed6c2ad196c558fc/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [1e13c2c9eac7](../../../../malware/vidar/versions/unknown/cases/1e13c2c9eac72daf63fd00a9946878949e159ae6ec51b54ec64f942d79d61913/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [398c75444639](../../../../malware/vidar/versions/unknown/cases/398c754446396f89ad511e95760c90f9b72e1ce96b105b642b1f853b874f80c5/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [8d90853120d1](../../../../malware/vidar/versions/unknown/cases/8d90853120d18cea4a8a1fa72116fb93db3887f98c330cee9519bc78f87eebf6/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [5bcc428f3765](../../../../malware/vidar/versions/unknown/cases/5bcc428f37655c7bc16110cc2127c510f66827a382cb1c9fa251b15a7d2c214b/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [ee1bddda91c3](../../../../malware/vidar/versions/unknown/cases/ee1bddda91c3a8a3ca8b3fcc077c373dc80da17b94ae6dc7f4219116a49fd7ac/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [0a8f1fa93f96](../../../../malware/vidar/versions/unknown/cases/0a8f1fa93f96182e78f5b95abd940d98bf53f06dc1fbe172bb913f821a3647d3/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [4c958205aa4c](../../../../malware/vidar/versions/unknown/cases/4c958205aa4c56b148377b2bd984a7b3b6525bbc914cf8e5aaa34ce91f71d4cc/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [4992cb5f2959](../../../../malware/vidar/versions/unknown/cases/4992cb5f29594ae1cea78e028a2e6a51d571a610ceeb4442b605953b916dd1c4/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [526efbd526d1](../../../../malware/vidar/versions/unknown/cases/526efbd526d1e0fa9ac6b9def17f1925774e3696595232e8e8d6801a8a302e36/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |

## 検知時の考慮事項

- **誤検知リスク高：** ブラウザーデータベース、ウォレット、`osascript`、Goランタイム文字列、高エントロピーPEセクションへの一般的なアクセス。バックアップ、移行、企業資産管理、インストーラー、正規Goアプリケーションも一致し得る。
- **誤検知リスク中：** スクリプトインタープリター、ネットワークダウンロード、実行の組み合わせ、または未署名プロセスによる複数のブラウザー／ウォレットストアの読み取り。管理自動化やソフトウェア配布と重なる場合がある。
- **誤検知リスク低：** ファミリー固有文字列、確認済み設定パス／ホスト、認証情報ストアの収集、異常な親子プロセスまたはネットワーク文脈を組み合わせる。ビルダー／バージョン変更による見逃しは残り得る。

次の場所にある検知ルール `rules/` は出発点であり、環境に応じた調整が必要である. リテラルC2は永続的なファミリー署名ではなく、短命な侵害指標一致として扱うべきである.

## 安全上の注意と制約

- 検体は実行しておらず、回収レイヤーもコミットしていない.
- 外部インフラには接続していない.
- 不明なパッカーとパスワード保護された入れ子書庫は未解決である。
- MalwareBazaarのシグネチャ帰属は手掛かりであり、静的証拠とは分離して保持した。
