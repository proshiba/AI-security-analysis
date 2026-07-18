# Remus情報窃取型 解析

MalwareBazaarの新規提出検体10件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。

## キャンペーン／配送形態

- `direct_pe_or_pe_loader`：7
- `go_pe_loader`：3

## 静的解析で確認した挙動

- `archive_delivery`：7/10
- `go_runtime`：3/10

## C2／設定の確認事項

| 値 (値) | 役割 (役割) | 確度 (確度) | 情報源 (情報源) |
|---|---|---|---|
| `http://31.77.168.180:5000/umvbr.bin` | candidate_infrastructure | 候補 | embedded_literal |
| `http://31.77.168.180:5000/piva.exe` | payload_or_dependency_url | 候補 | embedded_literal |

能動的なC2チェックインは行っていない。オフライン評価と受動照会の生成には `analysis-framework/common/c2_candidate_detector.py` を使用する。

## ケース一覧

| SHA-256 | 形式 (Format) | 配送形態 (キャンペーン) | パッキング (パック済み) | レイヤー数 (Layers) | 確認事項 (確認事項) |
|---|---|---|---:|---:|---:|
| [d9824b3a6894](../../../../malware/remusstealer/versions/unknown/cases/d9824b3a6894de0606a03a23417f1c7e780ee0b5655f724dbfa455601e13eb8e/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [0b845b890586](../../../../malware/remusstealer/versions/unknown/cases/0b845b890586407658a6bfcb1030b32be641760120e304bdf372a835ca5d77a4/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [4049128f0308](../../../../malware/remusstealer/versions/unknown/cases/4049128f0308d05dcb8d24b668f69238d720199de32ba0d8304cd3c3b3bde1b9/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 1 |
| [746c06f05b8e](../../../../malware/remusstealer/versions/unknown/cases/746c06f05b8e3bc93d6495a6c447c3c1874bd77011c33b0bcfe74ae27addbfaf/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 1 |
| [ffa78f3d4b1d](../../../../malware/remusstealer/versions/unknown/cases/ffa78f3d4b1dafb9723e6a68456e42a57c0a109b9b8246196e1a8a6d6d2d6f5a/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 1 |
| [027004739726](../../../../malware/remusstealer/versions/unknown/cases/027004739726842d8e416672cb7da85c43a75357984f818e27db5eb0dee0b600/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [5e815731f67c](../../../../malware/remusstealer/versions/unknown/cases/5e815731f67cb070fb1b31272c45bd7f4ecd4a408cbbc68a9545bafc3292d72c/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [7ae44ecd94c5](../../../../malware/remusstealer/versions/unknown/cases/7ae44ecd94c5e10f560e78539d4dba8b10d2ddcaf551d1321d81f7d97b771d5d/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [5eb378956ee8](../../../../malware/remusstealer/versions/unknown/cases/5eb378956ee84899b8ec8a59d0b9d5e95bef39cfce2acdfe72b032ea4e704227/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [523dd77b85d0](../../../../malware/remusstealer/versions/unknown/cases/523dd77b85d0b0cedc99ca23bc7225d4137b9e562a71a2d6d5e163e703680e2e/README.md) | pe | go_pe_loader | true | 0 | 0 |

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
