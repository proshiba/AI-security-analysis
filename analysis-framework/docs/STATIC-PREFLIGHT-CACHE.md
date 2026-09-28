# 起動前の静的監査で重複計算を抑える

`common/handler_catalog.py`の再帰的な副作用監査で、同じASTを繰り返し調べる際の計算だけを減らしました。ソース検証や未知呼出しの拒否を省く修正ではありません。

## 修正した原因と範囲

以前の`cache.setdefault(key, factory())`では、既存のkeyがあってもPythonが先に`factory()`を評価していました。保持した監査結果は使われる一方、同じimport binding、alias、definition一覧を毎回再計算していました。

次の3helperを、同じcacheへのmembership確認、必要時だけ計算・保存、保存値の返却という順序へ変更しました。

| helper | 同一audit内のkey | 保持する値 |
|---|---|---|
| `bindings` | scopeのAST object | import binding辞書 |
| `aliases` | moduleのAST object | import alias辞書 |
| `definitions` | moduleのAST object | function／classのAST参照辞書 |

cacheは一回の再帰auditのローカル変数です。module名、mtime、pathだけによるglobal cacheや、別auditへの許可結果の持越しはありません。初回の値とAST参照のidentity、空辞書や`None`のhit、factory例外時に未確定値を保存しない挙動を維持します。

source SHA、tree membership、file identity、サイズ、callee本文、caller context、receiver provenance、固定factory origin、未知呼出し拒否、TOCTOU再検証、解析processの隔離は変更しません。`audit_imports`の直接検査も残します。

## 比較結果と限界

既存の読取専用preflight 3parameterを、Python 3.13.14、同じprofile hook、同じplugin条件で比較しました。元実装は282.81秒、修正版は168.02秒で、約40.6%短縮しました。対応する3件の監査辞書全体をcanonical JSON化したSHA-256はすべて一致しました。

| 計数 | 元実装 | 修正版 |
|---|---:|---:|
| import bindingのfactory | 10,982 | 1,216 |
| aliasのfactory | 3,192 | 96 |
| definition一覧の再構築 | 3,777 | 80 |
| definition helperへの要求 | 3,777 | 3,777 |

これは計測hookの負荷を含む同条件の相対比較です。通常運用で常に同じ秒数や短縮率になること、全handlerや実検体の処理が約41%速くなることを保証しません。監査対象handlerや検体、CIL／CLR、networkを動かす試験でもありません。

専用の人工比較16件では監査辞書そのものも直接比較し、未知sink、callee内sink、import時sink、receiver再binding、同じ長さのsource差替え、別auditでの再検査を確認しました。通常回帰`test_handler_audit_lazy_cache.py`の10件は、旧実装で無駄な計算を検出し、修正後は全件成功しました。

```powershell
python -B -m pytest -q -p no:cacheprovider `
  .\analysis-framework\tests\test_handler_audit_lazy_cache.py `
  .\analysis-framework\tests\test_managed_reader_dependency_audit.py
```

専用試験の成功は、実検体のfamily／設定抽出率や全解析の完了を意味しません。通常入口・候補判定・handler・再解析計画の統合回帰も、固定source snapshotごとに別途実施します。

## 固定managed consumer契約の追加cache

上記3helperの辞書cacheとは別に、固定managed consumerの完全契約判定だけを一回の再帰audit内で再利用するcacheを追加しました。`bindings`、`aliases`、`definitions`はAST参照を含む辞書を保持しますが、この追加cacheが保持するのは契約のbool結果だけです。sourceやdispatch結果を新たな信頼済み入口として登録する仕組みではありません。

| 対象 | 同一audit内のkey | 保持する値 |
|---|---|---|
| 固定consumerの完全契約 | 実module AST objectとrelative文字列の組 | 契約の`True`／`False` |

このcacheは、同じaudit中に書き換えないASTと固定profileを前提にします。path、mtime、source hash、`id(tree)`だけをkeyにせず、実AST objectを強参照します。同じrelativeでも別AST objectなら再検査し、別auditには結果を持ち越しません。`False`も保存する一方、契約評価が例外になったときはboolを保存しません。敵対的なprocess内AST改変に対する新たなsandbox保証ではありません。

global互換入口の`_managed_resource_consumer_call_shape`は、完全契約を毎回検証する動作を維持します。audit内のlocal closureだけがcacheされた完全契約を確認してから、純粋な`_managed_resource_consumer_dispatch_shape`へ進みます。契約が`False`ならdispatchしません。契約が`True`でも、各callのreceiver、引数、scope、context、既知relativeを毎回確認し、dispatch結果やdispatchの例外はcacheしません。global入口に同じAST objectを渡して後から書き換えた場合も、完全契約の再検査を省きません。

対象は従来の固定2consumer、`unpackers/managed_il_triage.py`と`unpackers/managed_proxy_deobfuscator.py`だけです。一般allowlistや`trusted=True`引数、global／process cacheは追加していません。source pin、全calleeとclass本文、receiver provenance、namespaceとimportの検査、depth／file／call上限、source snapshotとTOCTOU再検証の分岐は変更しません。cacheの`True`を、解析器全体の安全承認やC2確認に昇格させません。

### 局所計測と回帰の状況

私有のordinary consumer ASTを使った単回microbenchmarkでは、triageの同じcallを10回、proxyを8回調べ、完全契約の評価回数がそれぞれ10→1回、8→1回になりました。dispatchの回数と結果は同一です。

| 対象 | 契約評価回数 | 元実装の秒 | 追加cacheの秒 |
|---|---|---:|---:|
| triageの10回反復 | 10→1 | 3.865468 | 0.424943 |
| proxyの8回反復 | 8→1 | 1.013943 | 0.122692 |

これは契約評価と毎回のdispatchを対象にした局所計測です。削減したのは契約評価の重複だけで、dispatch回数は削減していません。上記の既存3parameter比較とは計測範囲も負荷条件も異なり、数値を合算したり、全handlerが同じ割合で高速化すると一般化したりしません。実検体のfamily／設定／C2抽出率、終端payload復元率、全解析の完了を測定した結果ではありません。

通常catalogを直接importする`test_managed_resource_consumer_cache.py`の22件は成功しました。別audit／別tree、`False`、契約例外の非保存、dispatch再判定、global入口の完全契約、consumer AST書換え後の再検査、callee内sink、depth上限、consumer source pinの拒否を確認しています。private builder、固定base hash、before／after比較を通常testの前提にはしていません。

改修後、constructor依存93件・resource依存133件・深さ13件・namespace33件の通常272件は1645.14秒で成功しました。sourceを固定し、全110handlerの1051format別AST監査と検体なし隔離import110件も通りました。その後のファミリー別変更には新たな最終検証が必要です。広域71fileの途中実行は中断したため、完走・全回帰成功とは扱いません。通常22件の結果は、上記の既存3辞書cacheの比較と人工16件・通常10件の証拠とは区別して記録します。いずれも実検体の解析完了の証明ではありません。

```powershell
python -B -m pytest -q -p no:cacheprovider `
  .\analysis-framework\tests\test_managed_resource_consumer_cache.py
```
