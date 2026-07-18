# Formbook 解析

MalwareBazaarの新規提出検体10件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。

## キャンペーン／配送形態

- `direct_pe_or_pe_loader`：4
- `macro_office_delivery`：1
- `script_delivery`：5

## 静的解析で確認した挙動

- `script_loader`：6/10

## C2／設定の確認事項

| 値 (値) | 役割 (役割) | 確度 (確度) | 情報源 (情報源) |
|---|---|---|---|
| 回収なし | - | - | パック／暗号化済み、またはリテラル設定なし |

能動的なC2チェックインは行っていない。オフライン評価と受動照会の生成には `analysis-framework/common/c2_candidate_detector.py` を使用する。

## ケース一覧

| SHA-256 | 形式 (Format) | 配送形態 (キャンペーン) | パッキング (パック済み) | レイヤー数 (Layers) | 確認事項 (確認事項) |
|---|---|---|---:|---:|---:|
| [42255ff19148](../../../../malware/formbook/versions/unknown/cases/42255ff1914882e20ddb9116b521287dccd2bee944e056bc8f1bd1c2970299a6/README.md) | 圧縮書庫 | macro_office_delivery | false | 1 | 0 |
| [09a78d4ca618](../../../../malware/formbook/versions/unknown/cases/09a78d4ca618d275809fa2af5f6f1b9b40d5ed2e552ba6ff1ef66b59ccaa1531/README.md) | データ | direct_pe_or_pe_loader | false | 0 | 0 |
| [7906d425e122](../../../../malware/formbook/versions/unknown/cases/7906d425e122ae7f4922dbeff8c261be021a921c5f13471a470c60c583280504/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [f913434f31b4](../../../../malware/formbook/versions/unknown/cases/f913434f31b44c0e9df986028468ed3d6d28fd86d6d88aab48f2ef3841609386/README.md) | データ | direct_pe_or_pe_loader | false | 0 | 0 |
| [e3ee5d56ae32](../../../../malware/formbook/versions/unknown/cases/e3ee5d56ae3281d15eb73228e5cd94d955b4f664ac73de9651a16d034f32c93b/README.md) | スクリプト | script_delivery | false | 1 | 0 |
| [0708ae4eb0d2](../../../../malware/formbook/versions/unknown/cases/0708ae4eb0d2957b40f9162d2fb35cc94a334a6a039860034c27e99b92c8f6e3/README.md) | スクリプト | direct_pe_or_pe_loader | false | 0 | 0 |
| [1a3ea22e0c4a](../../../../malware/formbook/versions/unknown/cases/1a3ea22e0c4a68379e164c35d8d5bc438d9624fb575756194c8419121e2d265a/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [5baa58fbd2a9](../../../../malware/formbook/versions/unknown/cases/5baa58fbd2a9309d6853cf1cd5be83adbced95bbdc1a7471c11ee5455f85bfa9/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [7d9512cf29b9](../../../../malware/formbook/versions/unknown/cases/7d9512cf29b9d9792a1018f41eaa156902a16e2f20e4da4f1c308501822b39ad/README.md) | スクリプト | script_delivery | false | 1 | 0 |
| [ba8a96319609](../../../../malware/formbook/versions/unknown/cases/ba8a96319609b430e9e976a639ae3af99a28cfbedb965ac67feb7482291b4a54/README.md) | スクリプト | script_delivery | false | 0 | 0 |

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
