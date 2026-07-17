# Remcos 解析

MalwareBazaarの新規提出検体10件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。

## キャンペーン／配送形態

- `direct_pe_or_pe_loader`：1
- `script_delivery`：7
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
| [99d0eb6047cc](../../../../malware/remcosrat/versions/unknown/cases/99d0eb6047cc8c9f8cd061a6fcd18bb1fb6a5d4cfb78dd626b7f90a2d90e11b2/README.md) | スクリプト | script_delivery | false | 2 | 0 |
| [76aae8a3bf92](../../../../malware/remcosrat/versions/unknown/cases/76aae8a3bf9207f51b4b0cadb7133e0fddd50306cf7030614c383040e9513721/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [ae41ff70e010](../../../../malware/remcosrat/versions/unknown/cases/ae41ff70e01087351812394f34575d4f5debac0e76888c16ebaf1c3ed7267bd6/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [2eabe71b1886](../../../../malware/remcosrat/versions/unknown/cases/2eabe71b18863d2044945eb371da1dbd5d12bc973538755b6177a235712db361/README.md) | スクリプト | script_delivery | false | 2 | 0 |
| [6cd42e6eb75c](../../../../malware/remcosrat/versions/unknown/cases/6cd42e6eb75c0bb98e9846b9faf9bdf66856658bae7209106ed8041d54f6cc2e/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [888625bb2887](../../../../malware/remcosrat/versions/unknown/cases/888625bb2887f6965cf6d46b7888f73d9d55c0f0caf0abe54221bc455e5534d1/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [55504df33a01](../../../../malware/remcosrat/versions/unknown/cases/55504df33a0196066494d26d6f8c0533391b220630a9c800c7f1eb0cbc776ce2/README.md) | スクリプト | script_delivery | false | 0 | 0 |
| [78b21599a83d](../../../../malware/remcosrat/versions/unknown/cases/78b21599a83dbfad39c17202d37dd2b6d552c9679755bc199a9826f3dd0e40db/README.md) | pe | direct_pe_or_pe_loader | true | 0 | 0 |
| [ae593f077393](../../../../malware/remcosrat/versions/unknown/cases/ae593f0773938ade4a4dfdd2f49d47b66482cd4090f269ef39549f12a90ee80c/README.md) | スクリプト | unknown_or_nested_delivery | false | 1 | 0 |
| [c478f13eefa7](../../../../malware/remcosrat/versions/unknown/cases/c478f13eefa74178e585ec29988ab6bc045077b3db9dea930109793716928fad/README.md) | スクリプト | unknown_or_nested_delivery | false | 1 | 0 |

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
