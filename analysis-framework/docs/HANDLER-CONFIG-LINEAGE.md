# 認証済み設定とファミリー帰属の分離

`analyze_sample.py` は、選択された静的handlerの結果から、認証済み設定だけを `handler-config-candidates.json` に記録します。検体・復元層の実行、外部接続、追加payload取得は行いません。

対象は、handler成果物の選択層SHA-256と結果の検体SHA-256が一致し、既存のhandler品質判定を通過し、全期待設定項目とHMAC-SHA256認証が検証された場合だけです。公開するのは使用した解析profile、終端層SHA-256、自称製品名の限定的なラベル、host・portの候補です。鍵、salt、生設定、証明書本体は含めません。

解析profileの名前はファミリー名の確証ではありません。自称製品名も単独では確証になりません。たとえばDCRat互換の復号profileで認証に成功しても、設定内の自称名が `BwRat` なら、DCRatのdetector-only候補による自動確定だけを保留します。独立した既知hashによる帰属はこの保留で消しません。通信先は静的設定候補であり、C2としての稼働や接続成功を示しません。

従来の `route-config-candidates.json` は、帰属未確定のrouting候補を別途評価する成果物です。routing候補がなく `assessment_rejected` でも、選択handlerの認証済み設定は上記の別成果物へ残せます。両者を暗黙に統合せず、後続のfamily比較・設定重複調査では証拠の出所を分けて扱います。
