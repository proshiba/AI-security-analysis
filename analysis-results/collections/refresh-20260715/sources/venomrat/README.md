# Venom 解析

MalwareBazaarの新規提出検体10件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。

## キャンペーン／配送形態

- `direct_pe_or_pe_loader`：6
- `script_delivery`：2
- `unknown_or_nested_delivery`：2

## 静的解析で確認した挙動

- none 静的に visible

## C2／設定の確認事項

| 値 (値) | 役割 (役割) | 確度 (確度) | 情報源 (情報源) |
|---|---|---|---|
| 回収なし | - | - | パック／暗号化済み、またはリテラル設定なし |

能動的なC2チェックインは行っていない。オフライン評価と受動照会の生成には `analysis-framework/common/c2_candidate_detector.py` を使用する。

## ケース一覧

| SHA-256 | 形式 (Format) | 配送形態 (キャンペーン) | パッキング (パック済み) | レイヤー数 (Layers) | 確認事項 (確認事項) |
|---|---|---|---:|---:|---:|
| [579085581348](../../../../malware/venomrat/versions/unknown/cases/579085581348296ae88419296edc6a8e91acf4463c7994112b5c3f7f3653710e/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [48b59f27da42](../../../../malware/venomrat/versions/unknown/cases/48b59f27da42cfe2d3b806a1c71cc8d8fce0441121a17cd8c1b30bf5e35ea776/README.md) | データ | unknown_or_nested_delivery | false | 0 | 0 |
| [d7de7d851061](../../../../malware/venomrat/versions/unknown/cases/d7de7d851061a99e6f2ca256aba5badf90778f566fc528db6396a4180901ac26/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [d6d876c73274](../../../../malware/venomrat/versions/unknown/cases/d6d876c7327482a6293fb5014393ace99e14aa7e0638bbda9fc602d35b8a72c9/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [9100e92ceb94](../../../../malware/venomrat/versions/unknown/cases/9100e92ceb94455d3159c4273b47a4d635f1d6b8add68e7c775e1849d3d1a9da/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [7215cbe8e5df](../../../../malware/venomrat/versions/unknown/cases/7215cbe8e5dfed7b22c8bbe8c5f7f35a7848e545d1cdeb60a378baf0be32cb0e/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [e4ea373bf70b](../../../../malware/venomrat/versions/unknown/cases/e4ea373bf70b008d51db2d707171a01a40c45e7e01d2ed61eef21199fd30c8dd/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [651859b30c79](../../../../malware/venomrat/versions/unknown/cases/651859b30c796cf59166ca018a2b4f18c996af4e688d302466ae56a5712b72a7/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [165b528fb02e](../../../../malware/venomrat/versions/unknown/cases/165b528fb02e35b12a59a311102a8bef74ec2f0bf908864fd7fa7ed8f917261e/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [ad6417ba292c](../../../../malware/venomrat/versions/unknown/cases/ad6417ba292c504cb7307ca0c520435739f87908f117cc2423cd4b7e81cc1ac8/README.md) | データ | unknown_or_nested_delivery | false | 0 | 0 |

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
