# AgentTesla 解析

MalwareBazaarの新規提出検体10件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。

## キャンペーン／配送形態

- `script_delivery`：10

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
| [8a1326b0bee0](../../../../malware/agenttesla/versions/unknown/cases/8a1326b0bee029dd4470ab53bddc3202de54614ba58a54ee1dc4d60928b812e1/README.md) | スクリプト | script_delivery | false | 1 | 0 |
| [58274a188cad](../../../../malware/agenttesla/versions/unknown/cases/58274a188cad3b137585a3135b5d7044b84996c6e2d656fb533a14d229777959/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [58a54ec5f73f](../../../../malware/agenttesla/versions/unknown/cases/58a54ec5f73f0c32963ff751050dc2ccb3148a27d8b9c7f1bfe1bf03d1cda13d/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [ec28fa6cc4dc](../../../../malware/agenttesla/versions/unknown/cases/ec28fa6cc4dc26dc65e882b52dfbf497cd97ce7fe8b2b9438b4647401b38e0b3/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [6be55e959aff](../../../../malware/agenttesla/versions/unknown/cases/6be55e959aff450d4778e873773ca17ce470e5f1434c75aa1e8603f32fbfa058/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [7388727a3ff7](../../../../malware/agenttesla/versions/unknown/cases/7388727a3ff77ec25b2b858b7b357032dc543061b6cf8367ca4aa6e77bc3c8d2/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [9fd781d549ae](../../../../malware/agenttesla/versions/unknown/cases/9fd781d549aec0e884a9d90541e8d7e5802d0de0cc36fc9d3c8533deb44846ed/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [e49a106bc696](../../../../malware/agenttesla/versions/unknown/cases/e49a106bc6960b958ff9ae49c483ff636d3fdbc817229ef0c8c152c32aa3f611/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [46055195777c](../../../../malware/agenttesla/versions/unknown/cases/46055195777c8088c7800715c4561af2da0b7dd088cb12f5473af5281aec537c/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [02d99e737239](../../../../malware/agenttesla/versions/unknown/cases/02d99e737239cc7f05a3988add89ee3672080ca1ddb5e43b4ecf4e8891535ccd/README.md) | スクリプト | script_delivery | false | 0 | 0 |

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
