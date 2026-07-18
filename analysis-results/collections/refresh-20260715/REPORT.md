# MalwareBazaar 更新解析 — 2026年7月15日

既存ケースのSHA-256を除外し、9ファミリーから各10件、合計90件を新規取得して静的解析しました。90件すべてが既存解析結果と重複せず、定義ファイルベースの解析は全件 `ready` で完了しています。

## 概要

> 以下にある当初のヒューリスティックなパッキング件数は、
> [2026年7月15日のアンパッキング再評価](../../research/audits/unpacking-reassessment-20260715.md)
> により更新されています。再評価では、コンテナ、復元した中間レイヤー、
> 終端ペイロード、残る5件のネイティブ保護による未解決要因を区別しています。

| ファミリー | 新規ケース | 形式 | パッキングあり | レイヤー復元ケース | 設定／ネットワーク情報あり |
|---|---:|---|---:|---:|---:|
| [ValleyRAT](sources/valleyrat/README.md) | 10 | PE 7 / OLE 3 | 1 | 2 | 2 |
| [AgentTesla](sources/agenttesla/README.md) | 10 | スクリプト 10 | 0 | 1 | 0 |
| [RemcosRAT](sources/remcosrat/README.md) | 10 | スクリプト 9 / PE 1 | 1 | 4 | 0 |
| [VenomRAT](sources/venomrat/README.md) | 10 | PE 6 / スクリプト 2 / データ 2 | 6 | 0 | 0 |
| [Formbook](sources/formbook/README.md) | 10 | スクリプト 6 / データ 2 / PE 1 / ZIP 1 | 1 | 3 | 0 |
| [Vidar](sources/vidar/README.md) | 10 | PE 10 | 2 | 0 | 0 |
| [LummaStealer](sources/lummastealer/README.md) | 10 | PE 9 / ZIP 1 | 7 | 1 | 0 |
| [RemusStealer](sources/remusstealer/README.md) | 10 | PE 10 | 4 | 0 | 3 |
| [AMOS](sources/amosstealer/README.md) | 10 | Mach-O 9 / シェルスクリプト 1 | 0 | 0 | 1 |
| **合計** | **90** | — | **22** | **11** | **6** |

## 注目すべき静的解析結果

- ValleyRAT ケース [`42420ed30965…`](../../malware/valleyrat/versions/unknown/cases/42420ed30965b2e8cd0abfe59103f9352cf9e8bb9a1c75d340bf13b2660abda5/README.md): 逆順に格納された設定から `103.43.11.40:1443` を復元したため、埋め込み C2 値として確認済みです。現在の稼働状況と所有者は検証していません。
- ValleyRAT ケース [`dfacebad09d7…`](../../malware/valleyrat/versions/unknown/cases/dfacebad09d75d41ee5f477754815ae7e4afd926638d7b72a6a25338cd2479da/README.md): `https://xjsjkjdsjjd.s3.ap-southeast-1.amazonaws.com/11100.zip` は推定設定または段階 URL であり、確認済みの最終 C2 ではありません。
- RemusStealer ケース [`4049128f0308…`](../../malware/remusstealer/versions/unknown/cases/4049128f0308d05dcb8d24b668f69238d720199de32ba0d8304cd3c3b3bde1b9/README.md) と [`746c06f05b8e…`](../../malware/remusstealer/versions/unknown/cases/746c06f05b8e3bc93d6495a6c447c3c1874bd77011c33b0bcfe74ae27addbfaf/README.md): `http://31.77.168.180:5000/umvbr.bin` は埋め込みインフラ候補です。ケース [`ffa78f3d4b1d…`](../../malware/remusstealer/versions/unknown/cases/ffa78f3d4b1dafb9723e6a68456e42a57c0a109b9b8246196e1a8a6d6d2d6f5a/README.md) は `http://31.77.168.180:5000/piva.exe` をペイロードまたは依存要素の候補として参照しています。これらの値だけでは Remus の最終 C2 と確定できません。
- AMOS ケース [`e3b5a5dbbcca…`](../../malware/amosstealer/versions/unknown/cases/e3b5a5dbbccab4cf36c7abf5cb5ae83062dd1b5dee7db04bddbf53fc9ebdb233/README.md): `http://91.92.242.30/dx2w5j5bka6qkwxi` は、シェルスクリプトで配布する検体に埋め込まれたインフラ候補です。能動的な接続は行っていません。

AgentTesla、RemcosRAT、VenomRAT、Formbook、Vidar、LummaStealer では、今回提出されたレイヤーから妥当性を説明できる最終 C2 または設定値を得られませんでした。これはネットワーク挙動が存在しないという意味ではなく、静的解析上の制約として記録しています。

## 安全性と来歴

- MalwareBazaar への接続は、メタデータの照会とパスワード保護された提出物のダウンロードだけに限定しました。
- 検体は実行せず、実際の C2、段階、ペイロードの各インフラへ接続していません。
- 復元レイヤーは、暗号化した解析生成物としてリポジトリ外に保持しています。
- 公開用の取得マニフェストから、ローカルの `zip_path` 値を除去しています。
- 証明書／OCSP、ベンダー文書、外部 IP 照会、公開 DNS-over-HTTPS への参照は、誤検出の可能性が高い C2 候補として抑制しています。
