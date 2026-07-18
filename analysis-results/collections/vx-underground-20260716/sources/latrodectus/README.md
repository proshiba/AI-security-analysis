# Latrodectus 解析

`vx-underground` の提出検体54件を静的解析した。ローダー、パッカー、運用者は独立して変化し得るため、配布形態とマルウェアファミリーを分離して扱う。

## バッチ解析結果

- ケースs：54
- Errors：0
- パッキングの可能性：1
- ケースs を伴う から回収した値:rtifacts：10
- ケースs を伴う validated 静的 設定：33
- 検体の実行：false
- ネットワーク接続：false

## キャンペーン／配送形態

- `direct_dll_or_loader`：52
- `office_delivery`：2

## 静的解析で確認した挙動

- `domain_discovery`：29/54
- `host_discovery`：36/54
- `payload_download`：30/54
- `rundll32_execution`：32/54
- `scheduled_task_persistence`：29/54
- `security_discovery`：29/54

## C2／設定の確認事項

| 値 (値) | 役割 (役割) | 確度 (確度) | 情報源 (情報源) |
|---|---|---|---|
| `https://miistoria.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://plwskoret.top/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://jarinamaers.shop/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://startmast.shop/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://arsimonopa.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://lemonimonakio.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://skinnyjeanso.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://titnovacrion.top/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://grebiunti.top/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://saicetyapy.space/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://aytobusesre.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://scifimond.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://stratimasesstr.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://winarkamaps.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://grunzalom.fun/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://illoskanawer.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://workspacin.cloud/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://mazdakrichest.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://riverhasus.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://carflotyup.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://worlpquano.com/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://drifajizo.fun/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://fluraresto.me/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://mastralakkot.live/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://aprettopizza.world/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://peermangoz.me/live/` | c2 | 確認済み | latrodectus_string_decryption |
| `https://antyparkov.site/live/` | c2 | 確認済み | latrodectus_string_decryption |

能動的なC2チェックインは行っていない。オフライン評価と受動照会の生成には `analysis-framework/common/c2_candidate_detector.py` を使用する。

## 検証済み設定値

- `c2_urls`：`https://antyparkov.site/live/` (1), `https://aprettopizza.world/live/` (2), `https://arsimonopa.com/live/` (4), `https://aytobusesre.com/live/` (3), `https://carflotyup.com/live/` (1), `https://drifajizo.fun/live/` (2), `https://fluraresto.me/live/` (3), `https://grebiunti.top/live/` (1), `https://grunzalom.fun/live/` (2), `https://illoskanawer.com/live/` (1), `https://jarinamaers.shop/live/` (1), `https://lemonimonakio.com/live/` (4), `https://mastralakkot.live/live/` (3), `https://mazdakrichest.com/live/` (1), `https://miistoria.com/live/` (3), `https://peermangoz.me/live/` (2), `https://plwskoret.top/live/` (3), `https://riverhasus.com/live/` (1), `https://saicetyapy.space/live/` (2), `https://scifimond.com/live/` (5), `https://skinnyjeanso.com/live/` (4), `https://startmast.shop/live/` (1), `https://stratimasesstr.com/live/` (4), `https://titnovacrion.top/live/` (6), `https://winarkamaps.com/live/` (4), `https://workspacin.cloud/live/` (1), `https://worlpquano.com/live/` (1)
- `group_id`：`1053565364` (4), `1081065992` (5), `2020984416` (3), `2221766521` (1), `2441763523` (1), `3828029093` (5), `445271760` (3), `510584660` (11)
- `group_name`：`Electrol` (1), `Facial` (5), `Liniska` (3), `Littlehw` (11), `Neptun` (1), `Novik` (4), `Olimp` (3), `Supted` (5)
- `profile`：`latrodectus_legacy_prng_strings` (33)
- `version`：`1.1.10` (2), `1.1.11` (1), `1.1.12` (1), `1.1.14` (2), `1.1.2` (1), `1.1.3` (2), `1.1.4` (4), `1.1.5` (2), `1.1.6` (3), `1.1.8` (2), `1.2.12` (1), `1.2.16` (2), `1.2.17` (1), `1.2.19` (1), `1.2.2` (2), `1.2.24` (2), `1.2.3` (2), `1.3.1` (1), `1.3.4` (1)

## ケース一覧

| SHA-256 | 形式 (Format) | 配送形態 (キャンペーン) | パッキング (パック済み) | レイヤー数 (Layers) | 確認事項 (確認事項) |
|---|---|---|---:|---:|---:|
| [03e0ca10cbf0](../../../../malware/latrodectus/versions/v1.1.5/cases/03e0ca10cbf06f45fefd102dc8e42665729d8891e047348dea7dcceb9b5559cc/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [0822d4c51c46](../../../../malware/latrodectus/versions/unknown/cases/0822d4c51c466544072ac07dd5c2dbf4143431fb6955a05911600fed50d0229a/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [232adaf8b3b2](../../../../malware/latrodectus/versions/v1.2.12/cases/232adaf8b3b2680c04df97c19c7d81edeb80444936741859b1a1f27245ed90c0/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [23546ec67474](../../../../malware/latrodectus/versions/unknown/cases/23546ec67474ed6788a14c9410f3fc458b5c5ff8bd13885100fb4f3e930a30bf/README.md) | pe | direct_dll_or_loader | false | 1 | 0 |
| [2b44b68e36c3](../../../../malware/latrodectus/versions/unknown/cases/2b44b68e36c30aa9096429eeb0456e3b34b09dc3ea2ce0bd81aee2393bb3cfe4/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [3243e67a2eba](../../../../malware/latrodectus/versions/unknown/cases/3243e67a2ebad9bfd8746d7c2d48eb8a7241fd09ca19c4c9adfc08fa4923c212/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [326d297b441a](../../../../malware/latrodectus/versions/v1.1.12/cases/326d297b441a40bb3f53bb55cb727e0fbed422470977ca167b1c919029be746b/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [34aff1767909](../../../../malware/latrodectus/versions/v1.2.24/cases/34aff1767909ff582d15949922549fddb5849f163260ad3efdc32d4f869fdf09/README.md) | pe | direct_dll_or_loader | false | 1 | 2 |
| [38450cf93412](../../../../malware/latrodectus/versions/v1.1.8/cases/38450cf934121c9f92785beffb73602919014752310960768324029d9ba91e13/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [388021747b85](../../../../malware/latrodectus/versions/v1.1.4/cases/388021747b85453adff2680c8a0e13e230f4eeada1a1055e3fb8e09800d4fb79/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [3a950d7e6736](../../../../malware/latrodectus/versions/unknown/cases/3a950d7e6736f17c3df90844c76d934dc66c17ec76841a4ad58de07af7955f0f/README.md) | ole | office_delivery | false | 2 | 0 |
| [3e0524346e44](../../../../malware/latrodectus/versions/unknown/cases/3e0524346e447a3dcadc528ec3a009c8b34cf3c0d1c7423c4d168b432b2c8b72/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [465f931e8a44](../../../../malware/latrodectus/versions/v1.2.3/cases/465f931e8a44b7f8dff8435255240b88f88f11e23bc73741b21c20be8673b6b7/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [535da28d4c95](../../../../malware/latrodectus/versions/unknown/cases/535da28d4c95d3b379336314471f118dc99ce4a85d97fdf0b9cc6afb22da02d9/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [5562c6ad5765](../../../../malware/latrodectus/versions/v1.2.16/cases/5562c6ad5765792def276e009395a57a6bf841c87cddefb6f8e8d75b74076e83/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [5826867a6f14](../../../../malware/latrodectus/versions/unknown/cases/5826867a6f14d608cc6989f7d3cb47834c4893fe5a9e0c91169f3a02347c01e1/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [5cecb26a3f33](../../../../malware/latrodectus/versions/unknown/cases/5cecb26a3f33c24b92a0c8f6f5175da0664b21d7c4216a41694e4a4cad233ca8/README.md) | pe | direct_dll_or_loader | true | 0 | 0 |
| [5d36d2cbf0a9](../../../../malware/latrodectus/versions/v1.3.4/cases/5d36d2cbf0a92c31692861af5c43b7faee35a2c13a36a7d6f4bdca27d2fa1dbe/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [5edc39cbd89d](../../../../malware/latrodectus/versions/v1.1.4/cases/5edc39cbd89d3ba70a4737f823933af93f3c182134af8e34e0af9a316afaaca8/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [6091f2589fef](../../../../malware/latrodectus/versions/v1.2.17/cases/6091f2589fef42e0ab3d7975806cd8a0da012b519637c03b73f702f7586b21ef/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [62536e1486be](../../../../malware/latrodectus/versions/unknown/cases/62536e1486be7e31df6c111ed96777b9e3f2a912a2d7111253ae6a5519e71830/README.md) | pe | direct_dll_or_loader | false | 2 | 0 |
| [65da6d9f781f](../../../../malware/latrodectus/versions/v1.2.19/cases/65da6d9f781ff5fc2865b8850cfa64993b36f00151387fdce25859781c1eb711/README.md) | pe | direct_dll_or_loader | false | 1 | 2 |
| [7040402574a6](../../../../malware/latrodectus/versions/v1.2.2/cases/7040402574a686f031c3af5fed37509d8979855397787aab70b2d1059099d2da/README.md) | pe | direct_dll_or_loader | false | 1 | 2 |
| [72db19a5ccc7](../../../../malware/latrodectus/versions/v1.1.4/cases/72db19a5ccc7e378e72bd3cf8339280fc47f05b5ff65b1fb3893be6369a5c8bf/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [805b59e48af9](../../../../malware/latrodectus/versions/v1.2.24/cases/805b59e48af90504024f70124d850870a69b822b8e34d1ee551353c42a338bf7/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [80f167003759](../../../../malware/latrodectus/versions/unknown/cases/80f167003759e598fcd7cb868d90e60c77af4da5971afc9cda1f552d1325d2d7/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [81bc69a33b33](../../../../malware/latrodectus/versions/unknown/cases/81bc69a33b33949809d630e4fa5cdb89d8c60cf0783f447680c3677cae7bb9bb/README.md) | pe | direct_dll_or_loader | false | 1 | 0 |
| [8299972879ce](../../../../malware/latrodectus/versions/unknown/cases/8299972879ce911c095668360ea47e0be1dfaf17b62b64ada8a613eaaabd86ea/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [9645a12079ed](../../../../malware/latrodectus/versions/v1.2.2/cases/9645a12079edffd20560d4631160a6052ae5728d6f73b7366588166ad281c534/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [9e7fdc171504](../../../../malware/latrodectus/versions/v1.1.5/cases/9e7fdc17150409d594eeed12705788fbc74b5c7f482a64d121395df781820f46/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [9fad77b6c996](../../../../malware/latrodectus/versions/v1.1.2/cases/9fad77b6c9968ccf160a20fee17c3ea0d944e91eda9a3ea937027618e2f9e54e/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [a459ce4bfb5d](../../../../malware/latrodectus/versions/v1.3.1/cases/a459ce4bfb5d649410231bd4776c194b0891c8c5328bafc22184fe3111c0b3e7/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [a547cff9991a](../../../../malware/latrodectus/versions/v1.1.14/cases/a547cff9991a713535e5c128a0711ca68acf9298cc2220c4ea0685d580f36811/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [ac096895773a](../../../../malware/latrodectus/versions/v1.1.8/cases/ac096895773aab31910cee9d9611fbf3fcf7b2ba76678237ecd676d350c91c9c/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [acdf522657d5](../../../../malware/latrodectus/versions/unknown/cases/acdf522657d533e0dcf36501913f029e6e18ee20d756dbb666701657f4a2226a/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [aee22a35cbda](../../../../malware/latrodectus/versions/unknown/cases/aee22a35cbdac3f16c3ed742c0b1bfe9739a13469cf43b36fb2c63565111028c/README.md) | pe | direct_dll_or_loader | false | 1 | 0 |
| [b740a3215466](../../../../malware/latrodectus/versions/v1.1.6/cases/b740a321546671ad7ebdf540189cbea05a2307b0033f2e17535c23bb38217a91/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [bb7cb5aea419](../../../../malware/latrodectus/versions/v1.1.6/cases/bb7cb5aea4192a035376d380682716235fdb4809d06b63b63d6d6d1061a5c231/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [ca15d149f53a](../../../../malware/latrodectus/versions/v1.1.11/cases/ca15d149f53a51592c80c57e64de73e090777749422525d22b3b096a1ae75a4a/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [d38643133189](../../../../malware/latrodectus/versions/v1.1.3/cases/d38643133189bc880af537a371087e2e34fa36e0f96fd19a42969d3bc72fe95b/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [d458a1459e86](../../../../malware/latrodectus/versions/v1.1.4/cases/d458a1459e865ba6faeca30447fba1f7813cf8e3e5e4c454c4d93d1a2b345805/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [d8a5afdf8311](../../../../malware/latrodectus/versions/v1.2.16/cases/d8a5afdf8311eb92eae60c9774fc1b0b138f436affe99b2c64dbe93d8c07fcce/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [d8b902568386](../../../../malware/latrodectus/versions/v1.1.3/cases/d8b902568386f588fb2d42a77cd39062ada13c9a3fed0adf20ab6510f3b4a681/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [da6ca4c2fc0e](../../../../malware/latrodectus/versions/unknown/cases/da6ca4c2fc0ef28c2a59874164ce691e74a2f41329d59b0344282bfdf4eb2324/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [db03a34684fe](../../../../malware/latrodectus/versions/unknown/cases/db03a34684feab7475862080f59d4d99b32c74d3a152a53b257fd1a443e8ee77/README.md) | データ | direct_dll_or_loader | false | 0 | 0 |
| [e5aed4e2fdda](../../../../malware/latrodectus/versions/v1.1.14/cases/e5aed4e2fdda9242d6a723ece8c6d7b2b2a3f1f82abcac66e1480b6794c23bfc/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [e8263e35b926](../../../../malware/latrodectus/versions/v1.1.10/cases/e8263e35b92634d20e61a78c12bc95aab476381b5f03364d9fbb5d74b8fb2eb8/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [e99f3517a36a](../../../../malware/latrodectus/versions/unknown/cases/e99f3517a36a9f7a55335699cfb4d84d08b042d47146119156f7f3bab580b4d7/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [ead5ebf464c3](../../../../malware/latrodectus/versions/unknown/cases/ead5ebf464c313176174ff0fdc3360a3477f6361d0947221d31287eeb04691b3/README.md) | ole | office_delivery | false | 2 | 0 |
| [ef5db8b473e2](../../../../malware/latrodectus/versions/v1.1.10/cases/ef5db8b473e279620207777c42ef9ad14adf8b100ceb20dc4f7e1bd5271ecd3c/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |
| [f419c4f9ee51](../../../../malware/latrodectus/versions/unknown/cases/f419c4f9ee51391da7ef8b679683593ed76181b1a5702c58944ba64adeb25cd9/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [fbaa36fbd8f4](../../../../malware/latrodectus/versions/unknown/cases/fbaa36fbd8f43d80ecc3c8c26701de0beca3db8402af5e8ce27105a68e918082/README.md) | pe | direct_dll_or_loader | false | 0 | 0 |
| [fc21a125287c](../../../../malware/latrodectus/versions/v1.2.3/cases/fc21a125287c3539e11408587bcaa6f3b54784d9d458facbc54994f05d7ef1b0/README.md) | pe | direct_dll_or_loader | false | 1 | 2 |
| [fc4932314471](../../../../malware/latrodectus/versions/v1.1.6/cases/fc4932314471c91434fde050e85967de31701e0b391440c1c5f9aa5d6fde615d/README.md) | pe | direct_dll_or_loader | false | 0 | 2 |

## 検知時の考慮事項

- **誤検知リスク高：** ブラウザーデータベース、ウォレット、`osascript`、Goランタイム文字列、高エントロピーPEセクションへの一般的なアクセス。バックアップ、移行、企業資産管理、インストーラー、正規Goアプリケーションも一致し得る。
- **誤検知リスク中：** スクリプトインタープリター、ネットワークダウンロード、実行の組み合わせ、または未署名プロセスによる複数のブラウザー／ウォレットストアの読み取り。管理自動化やソフトウェア配布と重なる場合がある。
- **誤検知リスク低：** ファミリー固有文字列、確認済み設定パス／ホスト、認証情報ストアの収集、異常な親子プロセスまたはネットワーク文脈を組み合わせる。ビルダー／バージョン変更による見逃しは残り得る。

次の場所にある検知ルール `rules/` は出発点であり、環境に応じた調整が必要である. リテラルC2は永続的なファミリー署名ではなく、短命な侵害指標一致として扱うべきである.

## 安全上の注意と制約

- 検体は実行しておらず、回収レイヤーもコミットしていない.
- 外部インフラには接続していない.
- 不明なパッカーとパスワード保護された入れ子書庫は未解決である。
- 情報源 attribution 保持した separately から validated 静的証拠.
