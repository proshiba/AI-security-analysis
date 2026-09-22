# LummaStealer・RemusStealer 未完了検体の静的監査

2026-09-22 時点のリポジトリ成果物を再評価した。対象検体と復元層は実行せず、外部ホストへ接続していない。両検体とも元のバイナリが今回のローカル作業領域には見つからず、Ghidraでの新規関数レビューは実施できなかった。この文書は、既存成果物から確かめられる事項と未確認事項の境界を明示するものであり、解析完了を意味しない。また、両ハッシュを国内感染事例に直接結び付ける配布物・被害環境の証拠は、参照したケース成果物にはない。

## LummaStealer候補：`009b2025c43202f2c643e46d27b30ca5e0f33b7da37841a661838aa07ac34938`

根拠: [`analysis.json`](../../../malware/lummastealer/versions/unknown/cases/009b2025c43202f2c643e46d27b30ca5e0f33b7da37841a661838aa07ac34938/analysis.json)、[`static-logic.json`](../../../malware/lummastealer/versions/unknown/cases/009b2025c43202f2c643e46d27b30ca5e0f33b7da37841a661838aa07ac34938/static-logic.json)、[`features.json`](../../../malware/lummastealer/versions/unknown/cases/009b2025c43202f2c643e46d27b30ca5e0f33b7da37841a661838aa07ac34938/features.json)。

- 記録上は32-bitの非.NET PE、9,451,392 byte、44 import、6,293,888 byteのoverlayを持つ。`.rsrc`のエントロピーは7.9761で、静的処理はパッキングを疑っている。ただしこれだけで内包payloadや実行時の展開方法を確定できない。
- 追加レイヤーの復元数は0、静的設定とendpointの復元数は0。UPXの結果は`not_upx_or_failed`であり、UPX使用の証拠ではない。
- `go_pe_loader`は既存の配布形態ラベルで、関数レベルでGo製ローダーの動作を確認した結果ではない。`static-logic.json`はレビュー済み関数0、call edge 0、Ghidra program 0、状態`function_analysis_required`を明記している。
- `features.json`の`analysis_assessment.status=complete`は、同じファイルの`unresolved`に`packed_or_protected_inner_payload_not_recovered`が残り、設定・関数が未解決であることと整合しない。これは公開成果物の形式チェック完了と解釈し、マルウェアの動作解析完了とは扱わない。同ファイルは`browser_collection=false`を「ブラウザ情報の収集」という挙動欄へ、`not_upx_or_failed`を「UPX observed」へ転記しており、いずれも肯定的な挙動・パッカー証拠として利用してはならない。
- 現状では窃取対象、プロセス生成、永続化、C2要求内容、設定値、終端payload、LummaStealerへの検体固有の帰属根拠を確定できない。ケースのファミリー欄は分析上の候補・整理先とし、独立した静的判定とは区別する。

次の解析は、ハッシュ照合済み元検体を安全な私有保管から復元できた場合に限る。overlayとresourceの構造を先に検証し、成立した子PE・スクリプトのみ別レイヤーで記録する。子要素が成立しなければGhidraでエントリポイント、resource読取、復号・展開・実行へ至るcall関係を明示的なprogram選択子で追跡する。設定抽出は、実際のデータ参照と復号処理が確認されるまで保留する。

## RemusStealer候補：`e2bb18135f11abb5afa22fcd607183ff5cc5d2d499f8924a9a09dbe32ce7ecb9`

根拠: [`metadata.json`](../../../malware/remusstealer/versions/unknown/cases/e2bb18135f11abb5afa22fcd607183ff5cc5d2d499f8924a9a09dbe32ce7ecb9/metadata.json)、[`analysis.json`](../../../malware/remusstealer/versions/unknown/cases/e2bb18135f11abb5afa22fcd607183ff5cc5d2d499f8924a9a09dbe32ce7ecb9/analysis.json)、[`family-routing.json`](../../../malware/remusstealer/versions/unknown/cases/e2bb18135f11abb5afa22fcd607183ff5cc5d2d499f8924a9a09dbe32ce7ecb9/family-routing.json)、[`candidate-handler-assessment.json`](../../../malware/remusstealer/versions/unknown/cases/e2bb18135f11abb5afa22fcd607183ff5cc5d2d499f8924a9a09dbe32ce7ecb9/candidate-handler-assessment.json)、[`static-layers.json`](../../../malware/remusstealer/versions/unknown/cases/e2bb18135f11abb5afa22fcd607183ff5cc5d2d499f8924a9a09dbe32ce7ecb9/static-layers.json)。

- MalwareBazaarの報告signatureは`RemusStealer`。一方、内部classifierは`unknown`・`low`、detector一致はなし、候補handlerの証拠scoreは0、`candidate-handler-assessment.json`は`no_confirmed_family`である。したがって検体固有のRemusStealer帰属は未確認。ケースの`family=remusstealer`やREADMEの「正規分類」は提供元ラベルを整理したもので、独立確認として扱わない。
- 記録上は32-bitの非.NET PE、5,754,742 byte、11 section、150 import、4,863,862 byteのoverlayを持つ。`CreateProcessW`、`ReadFile`、`WriteFile`、`FindResourceW`、`LoadResource`、`VirtualAlloc`などがimportされるが、個々のAPIが到達可能な悪性経路で使われるかは関数解析未実施のため不明。`generic-triage.json`に`jrsoftware.org`へのヘルプURLと`/PASSWORD=`関連文字列があるため、Inno Setup系の外層を調べる価値はあるが、これだけではインストーラ形式や子payloadを確定できない。
- 全体の高いエントロピー7.9166をもってパック済みと断定しない。`analysis.json`の`packing_suspected=true`と、より詳細な`static-layers.json`のPE判定`classification=not_packed`／`packing_suspected=false`は食い違う。巨大なoverlayの影響と外層形式を分けて再評価する必要がある。
- 埋め込みPE候補は検査されたが、妥当な子PEの復元は0。資源31件が検査され、復元層はルート1件のみ。`static-logic.json`はレビュー済み関数0、call edge 0、状態`function_analysis_required`。内部の通信解析もendpoint・protocol・設定を未解決としている。汎用文字列走査で出た多数の「domain」はDelphi/ライブラリ文字列等を含む可能性があり、C2として昇格していない。
- プロセスツリー、終端payload、認証情報窃取、C2送信、実行時の後段取得は未確認。`CreateProcessW`のimportだけから子プロセスやコマンドラインを記述しない。

次の解析は、ハッシュ照合済み元検体の再取得後、overlayの境界・形式・圧縮/暗号化層を静的に識別し、妥当な内包物が確認できれば親子hashを固定して分離する。外層の`CreateProcessW`、resource API、ファイル書込みへの到達経路をGhidraで追い、外層と子payloadを混同しない。RemusStealer固有の復号済み設定や通信関数が見つかるまで、提供元のsignatureは未検証ラベルのまま保持する。

## 共通の判断

これら2件は現時点で「未完了」であり、国内感染キャンペーンとの結合、ファミリー確定、C2確定、プロセス挙動の断定に利用しない。原本の再取得または検証済み私有保管物の復元、関数レベルの静的解析、復元子要素の同一性確認が次のゲートとなる。公開レポートへ資格情報、生のpayload、逆コンパイル全文を転載しない。
