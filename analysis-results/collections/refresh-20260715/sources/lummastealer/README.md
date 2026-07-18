# Lumma情報窃取型 解析

MalwareBazaarの新規提出検体10件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。

## キャンペーン／配送形態

- `go_pe_loader`：8
- `packed_native_pe`：2

## 静的解析で確認した挙動

- `browser_collection`：1/10
- `c2_api`：1/10
- `loader_or_packer`：9/10
- `wallet_collection`：1/10

## C2／設定の確認事項

| 値 (値) | 役割 (役割) | 確度 (確度) | 情報源 (情報源) |
|---|---|---|---|
| 回収なし | - | - | パック／暗号化済み、またはリテラル設定なし |

能動的なC2チェックインは行っていない。オフライン評価と受動照会の生成には `analysis-framework/common/c2_candidate_detector.py` を使用する。

## ケース一覧

| SHA-256 | 形式 (Format) | 配送形態 (キャンペーン) | パッキング (パック済み) | レイヤー数 (Layers) | 確認事項 (確認事項) |
|---|---|---|---:|---:|---:|
| [c1d067c076f8](../../../../malware/lummastealer/versions/unknown/cases/c1d067c076f8d0d818aca72cefa32df501a6a887d96e407bdfe08d712b6ff781/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [794a4e96a5f9](../../../../malware/lummastealer/versions/unknown/cases/794a4e96a5f9590ae52fc0b9fb8cffed73f8b4bdd915a55bb207bfcacb45b92d/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [4e5b2ae91379](../../../../malware/lummastealer/versions/unknown/cases/4e5b2ae91379b8069c04c6639bb0bca5ddea0dde567bea8cb9bc9822b9cdda0d/README.md) | pe | packed_native_pe | true | 0 | 0 |
| [84fdf69c7381](../../../../malware/lummastealer/versions/unknown/cases/84fdf69c7381701415d366808450de41e3127d15c497a196bd51cc3ecf3eeaea/README.md) | 圧縮書庫 | packed_native_pe | false | 1 | 0 |
| [b435de3e5071](../../../../malware/lummastealer/versions/unknown/cases/b435de3e50714d774f42cfdefd710519915e7f987f69da8d5fc1963961519844/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [060618b911a7](../../../../malware/lummastealer/versions/unknown/cases/060618b911a7022394c88e195aa477157d366363f76ed4b86f0cc3b635908cc3/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [817ac7a4ee5b](../../../../malware/lummastealer/versions/unknown/cases/817ac7a4ee5b546a812b129c9b9cfbb4581988bd95ac3e2a32a83b82f1bf430c/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [3368d54f3063](../../../../malware/lummastealer/versions/unknown/cases/3368d54f30631c9e305f6df3464e08b6b4f24eebdb605240c44b144deed717fa/README.md) | pe | go_pe_loader | true | 0 | 0 |
| [afa807cee34e](../../../../malware/lummastealer/versions/unknown/cases/afa807cee34e8b931688ccf2be76b7ea5337af3d64714a348bead839c756643a/README.md) | pe | go_pe_loader | false | 0 | 0 |
| [a6feb3ea4e8d](../../../../malware/lummastealer/versions/unknown/cases/a6feb3ea4e8dcff0eaea4c8b89b3dc728e0cfe7ea2729c5e25d1f0b6bbfc3453/README.md) | pe | go_pe_loader | true | 0 | 0 |

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
