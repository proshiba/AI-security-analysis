# managed handlerの設定確定と動的設定originの契約

AsyncRAT、DCRat、VenomRATの通常静的handlerは、共通`dotnet_rat_config.recover()`の安全metadataを確認した後に公開projectionを構成します。検体、managed CIL、pluginを実行せず、通信や動的設定の追加取得を行いません。

## 設定とprotocolのtransaction

DCRatでは`candidate_recovery`と`candidate_protocol`が双方の検証を通過してから、公開用の`recovery`と`protocol`へcommitします。protocol拒否、import失敗、I/O失敗時は設定回収flag、終端managed client flag、確認済みendpoint、動的設定origin、certificate findingを残しません。失敗statusなのに設定成功が残る状態を防ぎます。

これはAsyncRATと同じ設定・protocolの一括確定方針です。VenomRATの既存設定抽出契約へ、新しいprotocol確定条件を勝手に追加する変更ではありません。静的設定の確認はlive C2の稼働確認を意味しません。

共通protocol回収では、選択対象の同じowner・method名に複数recordがあれば`protocol_method_selection_ambiguous`で拒否します。path key数や列挙順で候補を選ばず、AsyncRATの別variantへのfallbackでも曖昧性を隠しません。既知のmissing／partial状態に対する従来のcompact判定は維持します。これは読み取れたrecordの選択検査であり、全MethodDef・本文を完全走査した証明ではありません。

`recover()`とmethod record抽出は、hash／PE parserより前にexact immutable `bytes`と32 MiB入力上限を確認します。この入力上限は、その後の全metadata／CIL parserの作業量やメモリを同じ上限へ制限する保証ではありません。

## originだけを公開する動的設定値

共通recoverの`dynamic_config_url`は、秘密を含み得るpathを落とした**originのみ**です。非nullの値には`dynamic_config_url_scope="origin_only"`を必須とし、handlerでも実値がHTTP(S) originであることを確認します。

- userinfo、root以外のpath、query、fragment、制御文字、範囲外port、未知scopeは拒否します。失敗後に別経路でsanitizeして成功扱いしません。
- pathが空または`/`の値だけを受理し、公開表現を`/`へ正規化します。
- nullまたは値欠落の場合は、既存のscopeなし合成fixtureとの互換を維持します。公開scopeはnull、locator完備flagはfalseです。
- VenomRATとDCRatはconfigへscopeを保持し、URL findingにも`value_scope="origin_only"`、`retrieval_locator_complete=false`、`terminal_c2_endpoint=false`を残します。
- AsyncRATは従来どおりURL値を公開せず、存在有無と検証済みscopeだけを保持します。

originは取得に使える完全URLでも、確定した終端C2 endpointでもありません。公開originから元のpath、token、完全locatorを推測・補完しません。別の明示承認とprivateな原資料なしに追加取得、監視target化、jobへの自動投入へ転用しません。notesも、公開originから別取得できるという説明ではなく、この制限を明記します。

## 検証

```powershell
py -3.13 -B -m pytest analysis-framework/tests/test_managed_handler_recovery_contract.py analysis-framework/tests/test_venomrat_handler_integration.py analysis-framework/tests/test_dcrat_static_analysis.py analysis-framework/tests/test_asyncrat_static_analysis.py -q
```

新testは合成metadataだけで正常origin、scope欠落・矛盾、秘密path、query・fragment・userinfo、metadata不成立、DCRat rollback、publication境界の再検証、3handlerの通常preflightを確認します。既存Venom positive fixtureは現共通recoverと一致するorigin rootと明示scopeへ更新し、陰性testを弱めません。実検体の回収成功率やlive C2対応率は未測定です。

protocolの選択と入力境界は、`test_dotnet_rat_protocol_limits.py`および既存`test_dotnet_rat_protocol_evidence.py`の66件で確認しました。追加56件は人工recordと非実行digest anchorだけを使い、PE／CIL parserへ到達しないことも検証しています。
