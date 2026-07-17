# Amos情報窃取型 解析

MalwareBazaarの新規提出検体10件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。

## キャンペーン／配送形態

- `direct_macho`：9
- `script_delivery`：1

## 静的解析で確認した挙動

- none 静的に visible

## C2／設定の確認事項

| 値 (値) | 役割 (役割) | 確度 (確度) | 情報源 (情報源) |
|---|---|---|---|
| `http://91.92.242.30/dx2w5j5bka6qkwxi` | candidate_infrastructure | 候補 | embedded_literal |

能動的なC2チェックインは行っていない。オフライン評価と受動照会の生成には `analysis-framework/common/c2_candidate_detector.py` を使用する。

## ケース一覧

| SHA-256 | 形式 (Format) | 配送形態 (キャンペーン) | パッキング (パック済み) | レイヤー数 (Layers) | 確認事項 (確認事項) |
|---|---|---|---:|---:|---:|
| [998c38b43009](../../../../malware/amosstealer/versions/unknown/cases/998c38b430097479b015a68d9435dc5b98684119739572a4dff11e085881187e/README.md) | macho | direct_macho | false | 0 | 0 |
| [fe3859f076f3](../../../../malware/amosstealer/versions/unknown/cases/fe3859f076f3b34efc4155b7d724b024d193dd20ad2e4638985ffbe15992f27d/README.md) | macho | direct_macho | false | 0 | 0 |
| [0e52566ccff4](../../../../malware/amosstealer/versions/unknown/cases/0e52566ccff4830e30ef45d2ad804eefba4ffe42062919398bf1334aab74dd65/README.md) | macho | direct_macho | false | 0 | 0 |
| [f0a54f2b44e5](../../../../malware/amosstealer/versions/unknown/cases/f0a54f2b44e557854b0a5001c4e10185884af945814786f78b86539014f78a16/README.md) | macho | direct_macho | false | 0 | 0 |
| [e3b5a5dbbcca](../../../../malware/amosstealer/versions/unknown/cases/e3b5a5dbbccab4cf36c7abf5cb5ae83062dd1b5dee7db04bddbf53fc9ebdb233/README.md) | データ | script_delivery | false | 0 | 1 |
| [a0e66f3067e4](../../../../malware/amosstealer/versions/unknown/cases/a0e66f3067e4aaf5b83e45b7845cc43b2fc96032a4398cab7cc9d11f4f962e91/README.md) | macho | direct_macho | false | 0 | 0 |
| [77d3ccb2ed3d](../../../../malware/amosstealer/versions/unknown/cases/77d3ccb2ed3d0dd7cda49a0aed4da7c46278e70995d8e6768b2188fedcb78703/README.md) | macho | direct_macho | false | 0 | 0 |
| [ab267488d2c0](../../../../malware/amosstealer/versions/unknown/cases/ab267488d2c0a6300b61b5c9046cb86fe4a9ac3fe9a615acd374465b3a4b26c2/README.md) | macho | direct_macho | false | 0 | 0 |
| [d3ad6c9325b7](../../../../malware/amosstealer/versions/unknown/cases/d3ad6c9325b71044134c77b1e0c97c392a1f8d27f0af041d48325815dc1516db/README.md) | macho | direct_macho | false | 0 | 0 |
| [84a71a9dde6b](../../../../malware/amosstealer/versions/unknown/cases/84a71a9dde6b087613f3036eefaf8ae53c575e0d067b3b5a8a68896438df3f6b/README.md) | macho | direct_macho | false | 0 | 0 |

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
