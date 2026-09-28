# BSS初期化型のnative設定を静的に抽出する

`common/remus_disk_config.py` は、runtime stateがon-diskの文字列として存在しないnative形式を対象とする補助抽出器です。既存の `remus_memory_config.py` は変更せず、別の検証済みコードprofileとして扱います。

## 確認する構造

次の条件がすべて一致した場合だけ、`extract_remus_disk_config(data)` が `status: extracted` を返します。

- 初期化callerが同一BSS state、32byte key、8byte nonce、counter0をinitializerへ渡す。
- initializer、stream、memcpy、selector、URL assignment、POST transport、HTTP sinkが検証済みcompilerのコード形と一致する。
- selectorのXOR mask、slotの64byte間隔、後段4byte反復XORをコードの即値から取得できる。
- streamが64bit counterを持ち越し、3slotをcounter0、1、2で復号できる。
- selector rotationの整数式が0→1→2→resolver3への更新と一致する。
- URL assignmentとPOST transportが同じURL bufferを参照し、同じHTTP sinkを呼ぶ。
- CFF dispatch dataが検証済みprofileと一致し、jump tableを差し替えられていない。
- 3slotすべてが妥当なHTTP(S) URIとして構造検証できる。

入力SHA-256による特例や固定keyはありません。key、nonce、selector、XOR値、参照RVAは動的です。固定するのは検証済みcompilerの命令形で、算術opcode、内部branch、feedforward、counter更新は保持します。RIP relative pointerと裏付け済みの主要call relocationだけを正規化します。別compilerや未レビューのMBA変形は非対応として拒否します。

## 出力の意味

`config.endpoints` は選択設定とバックアップ設定、slot/counter、URIのhash、復号blockのhashを含みます。URLのuserinfoは拒否し、queryとfragmentは公開値から除去します。key、nonce、token、tag、expの生値は出力しません。

`config.resolver` は追加のblockchain resolver分岐を別に記録します。JSON-RPC `eth_call`、contract、function selector、responseの `result` を末尾64hex文字から32byteへ変換する構造を確認します。resolverのURIは `blockchain_c2_resolver_not_c2` とし、C2一覧へ混ぜません。外部RPCに接続していないため、resolverが現在返す最終C2は未取得です。

`family_attribution_confirmed`、`c2_liveness_confirmed`、`active_profile_generated` はいずれも `false` です。設定とHTTP利用の静的根拠が得られたことと、ファミリー帰属、現在の稼働、解析全体の完了を区別します。ファミリーの確定へ昇格するには、独立した帰属根拠と通常ジョブの品質ゲートが必要です。

## 通常の自動解析経路

`malware/remusstealer/detect.py` は初期化・selectorの命令形で候補を絞り、抽出器の完全なコード形・設定・HTTP利用の検証が通った場合だけ検証用の経路を返します。`supports_family_attribution: false`、`attribution_scope: handler_route_only` のため、ファミリー分類は未確定のままです。providerのラベル、入力SHAの特例、利用者によるファミリー指定は不要です。

通常の候補評価では `extractors/remusstealer/extractor.py` が既存memory抽出を先に試し、非一致の場合に独立したon-disk抽出を試します。復元できた3slot設定は `config.static_config_recovered`、`config.disk_config_analysis`、静的利用が確認されたendpointとして保存されます。外部resolverは別の `config.resolvers` に保持されます。`protocol_analysis.confirmed_c2` は空のままで、完全な通信profileや能動接続用profileの完成を意味しません。

handlerの事前監査は新moduleと呼出しを個別に許可します。単調時計の読み取りは全候補8秒の上限判定だけ、Capstoneは固定x64モード・検証済みsection内bytesの逆アセンブルだけに限定します。任意のreceiver、異なるモード、module loader差替え、入力差替えをAST形状検査で拒否します。source hash検証、隔離worker、CPU・メモリ・時間上限を変更しません。

## 上限と拒否条件

入力32MiB、PE section総量16MiB、code総量4MiB、コード候補各4件、関数命令4,096件、3slot合計192bytes、全呼出し8秒を上限にします。参照元は単一file-backed section、BSSへの参照は単一仮想sectionの境界で検証します。宣言されたsection数とparserの出力数を照合し、不正sectionの黙った除外、headerへの重複、raw・virtual範囲重複、範囲外entry、非実行section内entryを拒否します。巨大overlayは走査しません。

初期selector0だけを検証済みとします。初回counter0と非0 selectorを誤って対応させません。不正PE、重複section、コード改変、任意callee差替え、dispatch data変更、複数候補、URI不正は `RemusDiskConfigError` です。時間上限は `RemusDiskConfigLimitError` として明示し、成功や通常非一致へ丸めません。

検体の実行、CPU命令エミュレーション、外部通信、runtime API解決結果の呼出し、受信payloadの実行は行いません。暗号ライブラリで数学的変換だけを計算します。

## 検証

検体を同梱せず、RET/NOPの無害PEと合成設定だけで試験します。テスト中の合成コード形はfixtureへ限定して差し替え、製品profileへ追加しません。

```powershell
py -3.13 -m pytest analysis-framework\tests\test_remus_disk_config.py -q
```

正常抽出、key/nonce/XOR/mask/RVA変更、counter継続、resolverとの役割分離、opcode/immediate/counter/callee/sink/dispatch改変の拒否、PE範囲拒否、秘密値除去、初期selector制約、明示timeout、AST局所許可、通常隔離worker、未確定分類と検証用routingを試験します。実検体の全体的な抽出率を示す試験ではありません。
