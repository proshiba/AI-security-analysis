# PureRAT managed CILの静的semantic相関

`unpackers/managed_cil_cfg.py`は、managed PEをCLRへロードせず、CILの分岐operand、
resource consumer、復号配列の定義、PureRAT終端の役割を静的に相関する。検体、
CIL、復元payloadは実行せず、外部通信も行わない。

## 有界CFGと定数分岐

- `br*`、`leave*`のtargetと`switch`の全targetを保持し、命令境界に一致しないtargetを
  拒否する。命令、basic block、edge、switch targetにはそれぞれ上限がある。
- `ldnull; ldnull; ceq; ret`、`ldnull; ret`、`ldc.i4.0/1; ret`だけをexactな
  true／false proxyとして扱う。余分なcall、field access、分岐を持つmethodはproxyに
  しない。
- Assembly metadataのrowが一意で、`PublicKey` blobの有無を確定できた場合だけ、
  `GetPublicKey`とnullの比較をfoldできる。metadataが欠落、複数row、破損の場合は
  分岐を推測しない。

## key／IVのreaching definition

32-byteと16-byteの`System.Byte`配列は、決定可能なdispatcher path上で全indexへ
ちょうど1回、1つの定数値が書かれ、その同じ配列が`CreateDecryptor`または明示した
custom transform sinkへ渡る場合だけ復元済みとする。同じ値の重複書込みも一意な定義
ではないため拒否する。未知分岐、状態loop、複数sink、未対応callでstack効果を一意に
できない場合は値を推測しない。生のkey／IVは出力せず、完全に確定した配列の長さ、
書込み統計、SHA-256だけを保持する。

主なstable reason codeは次のとおり。

- `branch_operand_missing`: branch targetを保持できていない。
- `branch_target_not_instruction_boundary`: targetがCIL命令境界でない。
- `dispatcher_state_reaching_definition_ambiguous`: 次のdispatcher stateを一意に選べない。
- `dispatcher_state_reaching_definition_loop`: 同じ状態へ戻り、上限内で進展を証明できない。
- `dispatcher_state_budget_exceeded`: 状態探索上限へ到達した。
- `byte_array_sink_binding_missing`: 完全な32／16-byte配列とsinkの対応が成立しない。
- `byte_array_sink_binding_ambiguous`: 複数の対応が成立した。

## resourceと文字列cache

文字列cacheは、同一method内で次の順序を満たす場合だけ記録する。

1. `Assembly.GetManifestResourceStream`でresourceを読む。
2. internal decoder methodへ渡す。
3. `BitConverter.ToInt32`で4-byte長を読む。
4. `Array.Copy`後、`Encoding.Unicode.GetString`でUTF-16文字列を作る。
5. 文字列cacheとoffset cacheの両方へ追加する。
6. `BitConverter.GetBytes`と2回目の`Array.Copy`でprefixを更新する。

API名の存在だけ、順序違い、resourceからdecoderへの受渡し欠落では一致としない。

## PureRAT終端のsemantic evidence

PureRAT終端の相関には、同じmanaged rootから到達できる次の両方を要求する。

- 設定初期化: 複数の`Convert.FromBase64String`、`X509Certificate2`構築、internal
  config object生成、`castclass`、static fieldへの格納。
- transport: `Socket` API、`NetworkStream`、`SslStream`、
  `SslStream.AuthenticateAsClient`。

EXEではCLR headerのentry tokenをrootにする。反射ロードされるDLLのようにentry tokenが
ない場合は、internal callerを持たず、設定初期化とtransportの両方へ到達する単一の共通
rootだけを代替根拠にする。別々のrootにroleが分散した場合は一致としない。

このsemantic profileは`family_corroboration_allowed`にだけ使用する。既存の厳格な
protobuf／PKCS#12／version／campaign設定検証が成立していない入力をfamily確定へ
昇格させず、C2や稼働性も確認しない。provider名、protector名、Eaz／OMLXというlabel
だけは根拠に使わない。

## 検証

実検体や復号済みpayloadをfixtureへ含めず、人工CILだけで回帰試験する。

```powershell
python -m pytest -q unpackers/tests/test_managed_cil_cfg.py `
  analysis-framework/malware/purehvnc/tests/test_purehvnc_loader_detector.py `
  unpackers/tests/test_managed_il_triage.py
```
