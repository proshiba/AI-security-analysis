# PureLogs／PureRAT固定コホート評価

`common/evaluate_purelogs_cohort.py`、`common/evaluate_purerat_cohort.py`、
`common/evaluate_pure_cohort.py`は、検体を実行せず、外部通信も行わずに、固定した
PureLogs／PureRATコホートを再評価するためのCLIです。provider labelは評価対象集合を
選ぶ用途だけに使い、family確定の根拠には使いません。

## 成功条件

`strict_success`は、同じ静的layerにterminal family証拠とfamily-bound設定があり、
静的走査がエラー、上限到達、unpacker失敗なしで完走し、別layerに競合設定がない場合
だけ成立します。detectorとextractorの結果は同じlayerへ束縛しますが、両者が独立した
実装であることは要件にも根拠にもしていません。共有decoderや共有parserを使う場合が
あるため、2つの独立検出による相互確認とは解釈できません。

主な指標の意味は次のとおりです。

- `route_stage_recovered`: review済みtransform名を持つ静的layerの復元です。family帰属や
  終端payload到達を意味しません。
- `terminal_payload_reached`: profileがterminal候補として静的検証したlayerです。後続
  stageが存在しないことまでは証明しません。
- `terminal_family_confirmed`: 同一layer上のprofile証拠を照合したfamily判定です。
- `validated_config_recovered`: family-bound静的設定の復元です。endpointの稼働確認では
  ありません。
- `qualified_c2_recovered`: 現在は`validated_config_recovered`と同じ静的predicateです。
  live C2接続やprotocol応答確認を意味しません。

機械可読な同じ説明は出力の`metric_definitions`と`strict_contract`にも記録します。

## 出力の機密性

endpoint、鍵、設定identityの生値と単純SHA-256は出力しません。単純hashは候補集合から
辞書照合できるため、評価開始時に生成した非公開のrun鍵を使うHMAC-SHA-256へ変換し、
`configured_endpoint_opaque_id`と`configuration_opaque_id`として記録します。このIDは
同じ評価run内の相関専用であり、別run間の恒久識別子ではありません。run鍵は出力にも
fileにも保存しません。

root検体と静的layerのSHA-256は、入力集合とlineageを検証する識別子として引き続き
出力します。これらはendpointや設定の秘匿用fingerprintではありません。

## 実装と外部toolの束縛

profileはdetector／extractor入口だけでなく、repo内のtransitive Python依存sourceを
import前に上限付きmemory snapshotへ固定します。profile用import finderはこの固定bytesだけを
compileするため、import中にlive sourceが差し替えられても、読み込まれるbytecodeと報告する
source hashが分離しません。import直後と評価開始時にも全snapshotのsource hashを再検証し、
実際に保持しているdetector、extractor、assessment callableのcode object hashを結果へ
記録します。全依存sourceは評価前後の`implementation_sha256`でも比較します。

`--sevenzip`で指定したreview済み7-Zipは、上限付きで読み、SHA-256を照合しながらprivate
temporary directoryへcopyします。Windowsの`7z.exe`に`7z.dll`が同伴する場合は両方を
同じsnapshotへ固定します。静的pipelineへ渡すのは元pathではなくsnapshot pathであり、
評価終了時に内容が変わっていないことを再検証します。sample root、digest directory、
入力fileの既存path componentにsymlink、junction、reparse pointがある場合は拒否します。
