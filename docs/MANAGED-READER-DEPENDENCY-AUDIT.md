# managed readerの固定依存監査

`analysis-framework/common/handler_catalog.py`は、Settings literal readerとsalt宣言照合について、固定source／context／instance methodだけを専用branchで監査します。同じ名前のmethod、一般的なclass推論、全readerへの`read`許可へ拡張しません。既存の汎用source限定例外の条件も緩和しません。

## 固定consumerと起点

| consumer | 許可する呼出し | 到達監査する固定callee |
| --- | --- | --- |
| `_collect_settings_literals` | `literal_reader.read(operand)` | `_LiteralReader.__init__`、`read`と内部helper |
| `static_salt` | `literal_reader.read(operands[1])` | 同じ`_LiteralReader` |
| `static_salt` | `resolver.coverage()` | `MetadataResolver.__init__`、`coverage` |
| `static_salt` | 固定getter／GetBytes profileの`match_framework_member` | `MetadataResolver.__init__`、照合methodと内部helper |

literal readerは、固定`_settings_initializer(data, 型引数)`から受け取る5要素tupleの第5要素に限定します。factoryのreturn第5要素も`_LiteralReader(pe)`でなければ拒否します。collectorのparameter起点では、`settings_literals`とprivate候補評価`assess_settings_literals`の2direct callerを両方検証し、factory結果が差替えなしで渡されることを確認します。private assessment API全体を新しいglobal安全入口として許可するものではありません。

resolverは唯一の`MetadataResolver(pe)`、exact import `unpackers.managed_metadata.MetadataResolver`に限定します。receiverやparameterの再代入、属性mutation、import差替え、tuple順序変更、profile変更、`*args`／`**kwargs`は固定形状へ一致しません。

## 実装とSHA commitment

consumerとcalleeにはレビュー時に固定したsource SHA-256を要求します。source snapshotは通常のdependency manifestと同じ仕組みで保持し、実行境界で変更検出・再検証されます。SHA一致だけで許可せず、ClassDef、constructor、選択methodの本体を明示的に再帰監査します。内部`self.method`も到達対象です。

`_SignatureReader`と`MetadataResolver`間の限定的な内部参照、および`id(table)`、固定metadata属性取得、例外型名の文字種判定も、calleeの固定SHAとscope・正確なAST式に限定します。一般builtin／object method／`getattr`の許可集合を広げません。未知のcallee、危険な内部call、監査上限、SHA不一致はpreflight拒否として残します。

calleeのコードを更新した場合は、通常の差分レビュー、陰性試験、固定起点・到達実装の再確認が必要です。SHAを機械的に更新して拒否を回避する運用ではありません。今回の固定点は`dotnet_rat_config.py`と`unpackers/managed_metadata.py`であり、別moduleの同名helperは対象外です。

## 合成試験と限界

`analysis-framework/tests/test_managed_reader_dependency_audit.py`は通常ソースを一時領域へコピーし、そのASTだけを監査します。コピーしたcalleeはimport／実行しません。factory、tuple、namespace、parameter、profile、source SHAの陰性に加え、constructor・method・内部`self.method`へファイル読取、network、process、CLR、`eval`のsynthetic callを挿入して拒否を確認します。通常Venom handlerのstatic preflightも検証します。

```powershell
& 'C:\Users\Administrator\Tools\Python313\python.exe' -B -m pytest -q analysis-framework/tests/test_managed_reader_dependency_audit.py analysis-framework/tests/test_managed_detector_preflight.py
```

これはhandlerコードの静的安全境界であり、検体の実行、CIL／CLR／VMの評価・エミュレーション、framework assemblyの実行時真正性、receiverのruntime意味論、ファミリーやC2の確認ではありません。既存の候補・証拠品質・後続解析のgateは維持されます。
