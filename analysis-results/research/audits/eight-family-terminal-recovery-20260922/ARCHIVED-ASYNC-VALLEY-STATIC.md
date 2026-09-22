# 対象別保管物から復元した2検体の静的追補

調査日：2026-09-22。対象別の暗号化保管物から元検体を復元し、検体の実行、受領コードの実行、C2接続、新規サンドボックス投入を行わずに調べた。両対象とも、保管オブジェクトのサイズ・サーバー側暗号化属性・アーカイブSHA-256・内部目録SHA-256、ダウンロードしたZIPのSHA-256、復号後の全memberのサイズとSHA-256が一致した。対象ごとの安全確認は解析開始時に異常なしだった。保管場所や照合receiptは公開しない。

| 元検体SHA-256 | 復元した元検体 | 目録の全件照合 | 終端ファミリー | 設定・C2 |
|---|---:|---:|---|---|
| `5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761` | 3,939,840バイト、一致 | 24件 | 保護層の内側が未復元。AsyncRATとXWormの外部報告が競合 | 未確認 |
| `658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e` | 967,912バイト、一致 | 25件 | 元検体内のAV無効化機能は静的確認。ValleyRAT本体への帰属は未確認 | 未確認 |

## AsyncRAT報告検体 `5e84fd91…`

[既存ケース](../../../malware/asyncrat/versions/unknown/cases/5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761/README.md)の元検体を実際に復元してハッシュを再計算した。x86 PEのentry RVAは`0x674058`で、`.themida`は仮想サイズ5,939,200バイトに対してrawサイズ0、`.boot`はrawサイズ3,531,776バイトでentropy約7.96である。importは`GetModuleHandleA`と`_CorExeMain`だけである。後者のimportのみでは内側が.NET製RATであると確認できない。既存の[静的レイヤー記録](../../../malware/asyncrat/versions/unknown/cases/5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761/static-layers.json)もPE候補51件を構造検証で全件棄却し、復元子PEは0件だった。静的文字列から設定・endpoint・終端命令処理を得られていない。

[MalwareBazaarの完全ハッシュ一致ページ](https://bazaar.abuse.ch/sample/5e84fd9106777b85d5a60f4e607940730ba57ea2dcafaeaaadd6f21e38555761/)は主表示をAsyncRATとする一方、同ページに集約されたCAPE、Intezer、Threatrayの判定はXWorm、VMRayはBlackWormである。UnpacMeの解凍候補には`de0aa79373299d38e79f5895530c54d43970c18867212ee171580e5e28dca5eb`と`c3e152170af7d87ddaa0f915efac8db5c28c6a7e18f1d2a88ca0a1a092697b75`が載る。ただし前者は[別のQuasarRAT報告のThemida検体](https://bazaar.abuse.ch/sample/1b68d68b9fd200183c69084e91fe53bd5dca5c501bce1bbf1894034bc69fafe6/)の解凍候補とも同一であり、固有の終端RATとして扱えない。後者の実体は取得・ハッシュ再検証できていない。UnpacMe等の外部ラベルとYARA一致のみからXWorm、AsyncRAT、QuasarRATのいずれも内部確定しない。

公開Triageの完全SHA-256照会は、承認済みの上限付き成果物取得器で実施したが、取得可能な候補0件・取得エラー0件だった。これは公開解析の不存在ではなく、当該照会で取得可能な後段を確認できなかったという範囲の結果である。保護層内の終端コードを復元できていないため、このケースを「終端完了」へ移さない。次の最小手順は、独立に入手できる解凍候補の実体を親ハッシュと結び付けて取得・再ハッシュし、CLR構造、固有設定、通信関数を静的検証すること。保護解除のため検体を実行する方法には切り替えない。

## ValleyRAT報告検体 `658fc8b2…`

[既存ケース](../../../malware/valleyrat/versions/unknown/cases/658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e/README.md)の元検体を復元・再ハッシュした。x64 PEのentry RVAは`0x42218`、`.text`のrawサイズは431,104バイト、`.rdata`は497,664バイトでentropy約7.57。元検体には署名領域7,400バイトがあり、証明書の名義は`Nanjing Zhixiao Information Technology Co.,Ltd`、有効期間は2013–2014年である。現在の署名検証結果は期限に関する`UnknownError`であり、「現在有効な正規署名」とは判定しない。

保管済みの[Ghidra入口逆コンパイル](../../../malware/valleyrat/versions/unknown/cases/658fc8b2caf56d7572f065bdc7bcf248f1ba3e96901ba6ed3eee4291e524d46e/STATIC-LOGIC.md)と元PEを独立に照合した。入口`0x140042218`は初期化後に`0x140006340`を直接呼ぶ。元PEのx64命令を静的に追うと、同関数は`0x140011740`を直接呼ぶ。後者には「AV teardown pipeline」「Phase 1: Terminate all target processes」「Phase 2: IFEO hive paralyze」という文字列へのRIP相対参照と、Defenderのregistry policy、サービス制御、IFEO処理に対応する内部関数への直接callがある。`sc.exe stop`、`sc.exe config ... start= disabled`の形式、Defender／McAfee／Avira／中国語圏・欧米のAV製品の多数のprocess名も元PE内で確認した。これは単なる文字列列挙ではなく、少なくとも入口からAV停止・無効化処理群への静的呼出経路があることを示す。ただし実行条件・権限・保護製品の有無に依存するため、全操作の実行成功を観測したとは言わない。

既存の全1,339関数inventoryのうち代表逆コンパイルは32件に限られ、重要なAV処理の主要関数はその選定から漏れていた。既存の全体ロジック文書が`_guard_dispatch_icall`を受信commandの分配器とした記述は誤りで、同名関数はControl Flow Guardの間接呼出し補助である。元PEのimportと平文文字列には`ws2_32`、WinHTTP／WinINet、ValleyRAT／Winos固有marker、非証明書由来のURLを確認できなかった。見つかったHTTP URLは署名のCA／CRL／OCSPに属し、C2へ昇格しない。これは「C2能力がない」ことの全コード監査による証明ではない。

[火绒の一次報告](https://huorong.cn/document/info/classroom/2040)には類似名の中国語言語パック偽装サンプルと、AV製品停止・IFEO悪用が記載される。ただし同報告に本件の完全SHA-256はないため、同一検体・同一キャンペーン・同一ドライバーの使用を主張しない。本件の元PEには同報告が挙げる`dsark64.sys`と`LiveUpdate360.exe`の明文名も見つからなかった。

このケースで静的に確認したのはAV無効化機能を持つ元PEであり、提供元の`ValleyRAT`ラベルと終端RAT本体を結ぶ設定形式、復号済みペイロード、通信関数は確認できない。AV無効化ヘルパーとして独立しているのか、別のRAT配布チェーンに組み込まれた部品なのかも未検証である。次の最小手順は、`0x140006340`からの全到達可能関数・間接call・resource／高entropy領域のデータフローを追い、埋め込み層または外部後段の有無を判定すること。通信の不存在を主張する場合は、動的API解決も含む全経路の監査が必要である。

## 共通の完了境界

2件とも元検体・保管物の整合性は確認したが、終端ファミリー、設定、C2 protocolの完了基準は満たしていない。外部提供者のファミリー名、共有packer fingerprint、署名証明書、平文URLだけで解析完遂・C2確定へ昇格させない。後段候補を取得できた場合は親子の完全ハッシュ関係を固定し、別の隔離済み静的解析契約に渡す。
