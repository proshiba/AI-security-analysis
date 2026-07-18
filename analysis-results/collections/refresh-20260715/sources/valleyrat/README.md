# バレーラット 解析

MalwareBazaarの新規提出検体10件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。

## キャンペーン／配送形態

- `direct_pe_or_pe_loader`：7
- `macro_office_delivery`：3

## 静的解析で確認した挙動

- none 静的に visible

## C2／設定の確認事項

| 値 (値) | 役割 (役割) | 確度 (確度) | 情報源 (情報源) |
|---|---|---|---|
| `103.43.11.40:1443` | candidate_c2 | 確認済み | decoded_vvas_config |
| `https://xjsjkjdsjjd.s3.ap-southeast-1.amazonaws.com/11100.zip` | config_or_stage_url | 推定 | static_string |

能動的なC2チェックインは行っていない。オフライン評価と受動照会の生成には `analysis-framework/common/c2_candidate_detector.py` を使用する。

## ケース一覧

| SHA-256 | 形式 (Format) | 配送形態 (キャンペーン) | パッキング (パック済み) | レイヤー数 (Layers) | 確認事項 (確認事項) |
|---|---|---|---:|---:|---:|
| [fc397bf8ddae](../../../../malware/valleyrat/versions/unknown/cases/fc397bf8ddae5d01a16beb2076261b2a708b7cb3e8fea0898e56127a757153de/README.md) | ole | macro_office_delivery | false | 0 | 0 |
| [74dcd1f64bd3](../../../../malware/valleyrat/versions/unknown/cases/74dcd1f64bd3b43cf659359bff1f43131d43b4e07f3a3aa2a1f74d6e7970be09/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [1c82635c29f4](../../../../malware/valleyrat/versions/unknown/cases/1c82635c29f40e971971e150ebee6f36dabdd2a156f51214f20425315abb413f/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [ad4a584f5e62](../../../../malware/valleyrat/versions/unknown/cases/ad4a584f5e622c10703bca28c58ee8372899edb48cc1ccf28a2cff87d1afbf2d/README.md) | ole | macro_office_delivery | false | 0 | 0 |
| [81f68f61a8f7](../../../../malware/valleyrat/versions/unknown/cases/81f68f61a8f7cf1accca338fd196051020bf60885aad409332091b759ff818d9/README.md) | ole | macro_office_delivery | false | 0 | 0 |
| [b5af11fcbde5](../../../../malware/valleyrat/versions/unknown/cases/b5af11fcbde594f47706f4b5a8ee37a20fd4ed1ceb2537c9356ad5f0ff7300a9/README.md) | pe | direct_pe_or_pe_loader | false | 1 | 0 |
| [0fbe935d932c](../../../../malware/valleyrat/versions/unknown/cases/0fbe935d932ce6849224d77e3f32bdfd49910e5a34741ceab81ca8230d92a9da/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [272747b26622](../../../../malware/valleyrat/versions/unknown/cases/272747b26622bc9b084b36935efeeae8a63a388db00f94c6359b02368fd52d0d/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 0 |
| [42420ed30965](../../../../malware/valleyrat/versions/unknown/cases/42420ed30965b2e8cd0abfe59103f9352cf9e8bb9a1c75d340bf13b2660abda5/README.md) | pe | direct_pe_or_pe_loader | false | 0 | 1 |
| [dfacebad09d7](../../../../malware/valleyrat/versions/unknown/cases/dfacebad09d75d41ee5f477754815ae7e4afd926638d7b72a6a25338cd2479da/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 1 |

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
